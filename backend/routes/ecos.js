// ECOS / Kernel 8 rotaları — Mastercard Ecos kartına özgü uçlar.
//
// server.js 1380 satıra çıkmıştı; bu blok (5 uç, ~450 satır) kendi içinde
// tutarlı olduğu için ayrı modüle alındı. Davranış AYNEN korunur — yalnızca
// dosya sınırı değişti.
import express from 'express';
import pcsc from '../pcsc.js';
import { usingRealReader, tlvFromResponse, transmitChain } from '../apdu.js';
import { describeSw, findTag, findAllTags, parseAfl, parseTlv, parseDol, buildDol } from '../emv.js';
import { terminalDefaults } from '../terminal.js';
import { discoverCardContext } from '../carddiscover.js';
import { findExact } from '../sessionkeys.js';
import {
  deriveAcSessionKeyAes, deriveIccMasterKeyAes, buildEcosAcInput, ecosArqcAes,
  ecosArpcAes, parseEcosIad, verifyEcosArqcAes, bdhKdk, bdhSessionKeys, bdhDecrypt,
} from '../cryptoaes.js';
import { genEphemeralP256, ecdhSharedX, verifyEccCert } from '../odaecc.js';
import { findKey as findEccCaKey } from '../capkecc.js';
import { listProfiles, getProfile, compareWithProfile, expectedAip } from '../profilestore.js';

export const ecosRouter = express.Router();
const app = ecosRouter; // taşınan blokların `app.post(...)` çağrıları değişmeden çalışsın

// POST /api/ecos/verify-arqc — ECOS (Mastercard Kernel 8 / Ecos Contact) kartından
// GENERATE AC ile gerçek ARQC al, EMV CSK-AES yöntemiyle (kaynak: Ecos Issuer Impl.)
// AC input kur, seçilen AES anahtarıyla ARQC hesapla ve karttakiyle karşılaştır.
app.post('/api/ecos/verify-arqc', async (req, res) => {
  const preferReader = req.body?.reader || undefined;
  if (!usingRealReader() || !pcsc.getActiveCard(preferReader)?.connected) {
    return res.status(404).json({ error: 'Okuyucuda kart yok' });
  }
  try {
    // cda:true → GENERATE AC P1=90 (Combined DDA/AC) — CDA senaryosu teşhisi.
    const ctx = await discoverCardContext(preferReader, req.body?.cda ? { genP1: '90' } : {});
    if (ctx.error) return res.json({ error: ctx.error });
    if (!ctx.arqc || !ctx.atc) return res.json({ error: 'Karttan ARQC/ATC alınamadı (GENERATE AC başarısız)' });
    const td = terminalDefaults();
    const iad = parseEcosIad(ctx.iad || '');
    const cvn = iad?.cvnDecoded || null;
    const cvr = iad?.cvr || '';
    const ext = (cvn?.extendedInput && iad?.iadExt) ? iad.iadExt : '';
    const terminal = {
      amountAuth: td['9F02'], amountOther: td['9F03'], termCountry: td['9F1A'],
      tvr: td['95'], txnCurrency: td['5F2A'], txnDate: td['9A'], txnType: td['9C'], un: td['9F37'],
    };
    const mkInput = (cv) => buildEcosAcInput({ ...terminal, aip: ctx.aip, atc: ctx.atc, cvr: cv, iadExt: ext });
    const acInput = mkInput(cvr);
    // CDA'da CVR byte2'nin "Combined DDA/AC returned" bitleri (b8/b7) raporlanır ama
    // kriptograma girmemiş olabilir → maskeli CVR (byte2 & 0x3F) varyantı da hesapla.
    const cvrByte2 = cvr.length >= 4 ? parseInt(cvr.slice(2, 4), 16) : 0;
    const cvrMasked = (cvrByte2 & 0xC0) ? cvr.slice(0, 2) + (cvrByte2 & 0x3F).toString(16).padStart(2, '0').toUpperCase() + cvr.slice(4) : null;
    const out = {
      pan: ctx.pan, aid: ctx.aid, atc: ctx.atc, aip: ctx.aip, cardArqc: ctx.arqc,
      iad: ctx.iad, cvn, cvr, extendedInput: !!ext, terminal, acInput, genP1: req.body?.cda ? '90' : '80',
    };
    // Anahtar seçiliyse doğrula (icc=MKac · session=SKac · master=IMK→MKac→SKac)
    const { keyLabel, keyPan, arc } = req.body || {};
    if (keyLabel) {
      const k = findExact(keyLabel, keyPan || '');
      if (!k) out.keyError = 'Seçilen anahtar bulunamadı';
      else if ((k.keyType || '3des') === '3des') out.keyError = 'Seçilen anahtar 3DES — ECOS ARQC için AES anahtar gerekli';
      else {
        try {
          let mkac = null, skac = null;
          if (k.keyLevel === 'session') skac = k.acKey;
          else if (k.keyLevel === 'icc') { mkac = k.acKey; skac = deriveAcSessionKeyAes(mkac, ctx.atc); }
          else { mkac = deriveIccMasterKeyAes(k.acKey, ctx.pan, ctx.psn); skac = deriveAcSessionKeyAes(mkac, ctx.atc); }
          const card = (ctx.arqc || '').toUpperCase();
          const computed = ecosArqcAes(skac, acInput);
          out.keyLabel = k.label; out.keyLevel = k.keyLevel; out.mkac = mkac; out.skac = skac;
          out.computedArqc = computed;
          out.match = computed.toUpperCase() === card;
          // Maskeli CVR varyantını da dene (CDA teşhisi)
          if (cvrMasked) {
            out.cvrMasked = cvrMasked;
            out.computedArqcMaskedCvr = ecosArqcAes(skac, mkInput(cvrMasked));
            out.matchMaskedCvr = out.computedArqcMaskedCvr.toUpperCase() === card;
          }
          out.verdict = (out.match || out.matchMaskedCvr) ? 'PASS' : 'FAIL';
          const okSkac = out.match ? skac : (out.matchMaskedCvr ? skac : null);
          if ((out.match || out.matchMaskedCvr) && arc) {
            out.arpc = ecosArpcAes(okSkac, ctx.arqc, arc.replace(/\s/g, '')); // ARPC-RC = ARC (2 bayt)
          }
        } catch (e) { out.keyError = e.message; }
      }
    }
    res.json(out);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/ecos/full-transaction — ECOS AES kartı UÇTAN UCA test:
// SELECT→GPO→READ→GENERATE AC (ARQC) → AES ARQC doğrula → ARPC hesapla →
// 2. GENERATE AC (tag 91 issuer auth) ile ARPC'yi KARTA ilet → kart kabul (TC) /
// red (AAC) kararını raporla. Diferansiyel: doğru ARPC (TC bekle) + bozuk ARPC
// (AAC bekle) → kartın issuer authentication'ı KRİPTOGRAFİK doğruladığını kanıtlar.
app.post('/api/ecos/full-transaction', async (req, res) => {
  const preferReader = req.body?.reader || undefined;
  if (!usingRealReader() || !pcsc.getActiveCard(preferReader)?.connected) {
    return res.status(404).json({ error: 'Okuyucuda kart yok' });
  }
  const { keyLabel, keyPan } = req.body || {};
  const arc = (clean0(req.body?.arc) || '3030').slice(0, 4);
  const differential = req.body?.differential !== false;
  const flip1 = (h) => ((parseInt(h.slice(0, 2), 16) ^ 0xFF).toString(16).padStart(2, '0') + h.slice(2)).toUpperCase();
  const cidLabel = (t) => t === 0x40 ? 'TC' : t === 0x00 ? 'AAC' : t === 0x80 ? 'ARQC' : '?';
  try {
    const k = keyLabel ? findExact(keyLabel, keyPan || '') : null;
    if (!k) return res.json({ error: 'AES anahtar seti seçin (Oturum Anahtarları · Tip AES)' });
    if ((k.keyType || '3des') === '3des') return res.json({ error: 'Seçilen anahtar 3DES — ECOS için AES gerekli' });

    const steps = [];

    // Tek tur = TAZE bir işlem: SELECT→GPO→READ→GENERATE AC (ARQC) → ARQC doğrula →
    // ARPC hesapla → 2. GENERATE AC ile karta ilet.
    //
    // KRİTİK: her tur AYRI bir işlem olmalı. 2. GENERATE AC işlemi SONLANDIRIR;
    // aynı oturumda ikinci kez göndermek kartın "işlem bitti" demesine (6985) yol
    // açar ve bu yanlışlıkla "bozuk ARPC reddedildi" sanılır. Bu yüzden bozuk tur
    // kendi discoverCardContext'ini (yeni ATC/ARQC) çalıştırır — /api/arpc ile aynı
    // yaklaşım.
    const round = async (corrupt) => {
      const run = async (name, cmd) => { const { response, sw } = await transmitChain(clean0(cmd), preferReader); steps.push({ name, command: clean0(cmd), response, sw, swText: describeSw(sw), ok: sw === '9000' }); return { response: clean0(response), sw }; };
      const ctx = await discoverCardContext(preferReader);
      if (ctx.error) return { error: ctx.error };
      if (!ctx.arqc || !ctx.atc) return { error: 'Karttan ARQC/ATC alınamadı (GENERATE AC başarısız)' };
      steps.push(...(ctx.steps || []));
      const td = terminalDefaults();
      const iadP = parseEcosIad(ctx.iad || '');
      const cvn = iadP?.cvnDecoded || null;
      const cvr = iadP?.cvr || '';
      const ext = (cvn?.extendedInput && iadP?.iadExt) ? iadP.iadExt : '';
      const terminal = { amountAuth: td['9F02'], amountOther: td['9F03'], termCountry: td['9F1A'], tvr: td['95'], txnCurrency: td['5F2A'], txnDate: td['9A'], txnType: td['9C'], un: td['9F37'] };
      const vr = verifyEcosArqcAes({ key: k, atc: ctx.atc, pan: ctx.pan, psn: ctx.psn, aip: ctx.aip, cvr, iadExt: ext, terminal, cardArqc: ctx.arqc });
      if (!vr.match) return { error: 'ARQC eşleşmedi — issuer auth için doğru SKac gerekir (anahtar/PAN kontrol edin)', ctx, cvn, cvr, vr };
      // ARPC (AES CSK) = AES-CMAC(SKac)[ARQC‖ARPC-RC‖00×6]; tag 91 = ARPC(8)‖ARPC-RC(2)
      const arpc = ecosArpcAes(vr.skac, ctx.arqc, arc);
      const trueIad = arpc + arc;
      const sentIad = corrupt ? flip1(trueIad) : trueIad;
      const defs = { ...terminalDefaults(), '91': sentIad, '8A': arc };
      const cdol2Data = ctx.cdol2 ? buildDol(parseDol(ctx.cdol2), defs) : (sentIad + arc);
      const g2 = await run(`GENERATE AC 2 (issuer auth${corrupt ? ' · BOZUK ARPC' : ''})`, `80AE4000${(cdol2Data.length / 2).toString(16).padStart(2, '0').toUpperCase()}${cdol2Data}00`);
      const n2 = tlvFromResponse(g2.response).nodes;
      const t80 = findTag(n2, '80');
      const cid = t80 ? clean0(t80.value).slice(0, 2) : clean0(findTag(n2, '9F27')?.value);
      const acType = cid ? (parseInt(cid, 16) & 0xC0) : null;
      return {
        ctx, cvn, cvr, vr, arpc, trueIad,
        sent: { cid, acType, cidLabel: cidLabel(acType), sw: g2.sw, swText: describeSw(g2.sw), sentIssuerAuthData: sentIad, atc: ctx.atc, corrupt },
      };
    };

    // 1) Doğru ARPC turu
    const r1 = await round(false);
    if (r1.error) {
      const o = { error: r1.error, steps };
      if (r1.ctx) Object.assign(o, { pan: r1.ctx.pan, atc: r1.ctx.atc, aip: r1.ctx.aip, iad: r1.ctx.iad, cvn: r1.cvn, cvr: r1.cvr,
        arqc: { cardArqc: r1.ctx.arqc, computed: r1.vr?.computed, match: false, verdict: 'FAIL' } });
      return res.json(o);
    }
    const out = {
      pan: r1.ctx.pan, aid: r1.ctx.aid, atc: r1.ctx.atc, aip: r1.ctx.aip, iad: r1.ctx.iad, cvn: r1.cvn, cvr: r1.cvr, arc,
      arqc: { cardArqc: r1.ctx.arqc, computed: r1.vr.computed, match: true, usedMaskedCvr: r1.vr.usedMaskedCvr, verdict: 'PASS', acInput: r1.vr.acInput, skac: r1.vr.skac, mkac: r1.vr.mkac },
      arpc: { value: r1.arpc, arpcRc: arc, issuerAuthData: r1.trueIad },
    };
    const correct = r1.sent;
    correct.accepted = correct.acType === 0x40;
    const ia = { method: 'Method AES — 2. GENERATE AC · tag 91 (ARPC‖ARPC-RC)', correct };

    if (differential) {
      // 2) Bozuk ARPC turu — TAZE işlem (kendi ATC'si), yoksa 6985 sadece
      //    "işlem zaten bitti" demek olur ve reddi kanıtlamaz.
      const r2 = await round(true);
      if (r2.error) {
        ia.verdict = 'WARN';
        ia.note = `Bozuk-ARPC turu çalıştırılamadı (${r2.error}) — diferansiyel kanıt yok.`;
      } else {
        const corrupt = r2.sent;
        // TC almadı = reddedildi. AAC (0x00) ya da hata SW ikisi de geçerli reddir.
        corrupt.rejected = corrupt.acType === 0x00 || (corrupt.sw !== '9000' && corrupt.acType !== 0x40);
        ia.corrupt = corrupt;
        ia.sameTransaction = false;
        const rejWord = corrupt.acType === 0x00 ? 'AAC' : `SW ${corrupt.sw}`;
        if (correct.accepted && corrupt.rejected) { ia.verdict = 'PASS'; ia.note = `Diferansiyel ✓ — ayrı işlemlerde: doğru ARPC kabul (TC, ATC ${correct.atc}), bozuk ARPC red (${rejWord}, ATC ${corrupt.atc}). Kart issuer authentication'ı KRİPTOGRAFİK doğruluyor.`; }
        else if (correct.accepted && corrupt.acType === 0x40) { ia.verdict = 'NA'; ia.note = 'Kart bozuk ARPC\'ye de TC döndü → ARPC değeri kararı etkilemiyor (issuer auth uygulanmıyor); ARQC/SKac doğrulandı, kripto sorunu yok.'; }
        else if (!correct.accepted && correct.acType === corrupt.acType && correct.sw === corrupt.sw) { ia.verdict = 'NA'; ia.note = `Kart doğru ve bozuk ARPC'ye AYNI yanıtı (${correct.cidLabel || correct.sw}) verdi → ARPC kararı etkilemiyor. ARQC/SKac DOĞRULANDI — kripto sorunu yok, bu profilde issuer-auth gözlenemiyor.`; }
        else { ia.verdict = 'WARN'; ia.note = `Doğru ARPC → ${correct.cidLabel || correct.sw}, bozuk ARPC → ${corrupt.cidLabel || corrupt.sw}: beklenmedik, issuer-auth kesin doğrulanamadı.`; }
      }
    } else {
      ia.verdict = correct.accepted ? 'PASS' : 'WARN';
      ia.note = correct.accepted ? 'Kart TC döndü — kesin kanıt için diferansiyel testi açın (bozuk ARPC reddi).' : `Kart ${correct.cidLabel} döndü.`;
    }
    out.issuerAuth = ia;
    out.verdict = out.arqc.verdict === 'PASS' && (ia.verdict === 'PASS' || ia.verdict === 'NA') ? 'PASS' : (ia.verdict === 'WARN' ? 'WARN' : out.arqc.verdict);
    out.steps = steps;
    res.json(out);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/ecos/compute-arqc — ELLE ECOS ARQC hesapla (kart YOK). Terminalden
// yakalanan işlemi doğrulamak için: ya hazır acInput ver, ya da alanları ver
// (bunları Ecos Tablo 20/21 sırasına göre birleştiririz). ATC + AES anahtar zorunlu.
app.post('/api/ecos/compute-arqc', (req, res) => {
  try {
    const b = req.body || {};
    const clean = (s) => (s || '').replace(/\s/g, '').toUpperCase();
    const atc = clean(b.atc);
    if (!atc) return res.json({ error: 'ATC gerekli (SKac türetmesi için)' });
    // AC input: doğrudan verildiyse onu kullan, yoksa alanlardan kur.
    const fields = (cv) => ({
      amountAuth: b.amountAuth, amountOther: b.amountOther, termCountry: b.termCountry,
      tvr: b.tvr, txnCurrency: b.txnCurrency, txnDate: b.txnDate, txnType: b.txnType,
      un: b.un, aip: b.aip, atc, cvr: cv, iadExt: b.iadExt,
    });
    const pasted = !!clean(b.acInput);
    let acInput = pasted ? clean(b.acInput) : buildEcosAcInput(fields(b.cvr));
    // Alan modunda CVR'da CDA bitleri (byte2 b8/b7) varsa maskeli varyantı da dene.
    const cvr = clean(b.cvr);
    const cvrByte2 = cvr.length >= 4 ? parseInt(cvr.slice(2, 4), 16) : 0;
    const cvrMasked = (!pasted && (cvrByte2 & 0xC0)) ? cvr.slice(0, 2) + (cvrByte2 & 0x3F).toString(16).padStart(2, '0').toUpperCase() + cvr.slice(4) : null;
    const out = { acInput, acInputLen: acInput.length / 2, atc };
    const k = findExact(b.keyLabel, b.keyPan || '');
    if (!k) return res.json({ ...out, error: 'Seçilen anahtar bulunamadı' });
    if ((k.keyType || '3des') === '3des') return res.json({ ...out, error: 'Seçilen anahtar 3DES — ECOS için AES gerekli' });
    let mkac = null, skac = null;
    if (k.keyLevel === 'session') skac = k.acKey;
    else if (k.keyLevel === 'icc') { mkac = k.acKey; skac = deriveAcSessionKeyAes(mkac, atc); }
    else { if (!b.pan) return res.json({ ...out, error: 'master seviye için PAN gerekli (MKac türetmesi)' }); mkac = deriveIccMasterKeyAes(k.acKey, b.pan, b.psn || '00'); skac = deriveAcSessionKeyAes(mkac, atc); }
    out.keyLabel = k.label; out.keyLevel = k.keyLevel; out.mkac = mkac; out.skac = skac;
    out.computedArqc = ecosArqcAes(skac, acInput);
    if (cvrMasked) { out.cvrMasked = cvrMasked; out.computedArqcMaskedCvr = ecosArqcAes(skac, buildEcosAcInput(fields(cvrMasked))); }
    if (b.cardArqc) {
      out.cardArqc = clean(b.cardArqc);
      out.match = out.computedArqc === out.cardArqc;
      if (out.computedArqcMaskedCvr) out.matchMaskedCvr = out.computedArqcMaskedCvr === out.cardArqc;
      out.verdict = (out.match || out.matchMaskedCvr) ? 'PASS' : 'FAIL';
    }
    if (b.arc) out.arpc = ecosArpcAes(skac, out.computedArqc, clean(b.arc));
    res.json(out);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/ecos/contactless-oda — CANLI temassız Kernel 8 ECC ODA doğrulama.
// Efemer GPO (QT gönder) → 9F8103 (blinded key + E(r)) → BDH (z→Kdk→SKC/SKI) →
// kayıtları AES-CTR ile decrypt → EC-SDSA cert zinciri (CA→Issuer→Card) doğrula.
const clean0 = (s) => (s || '').replace(/\s/g, '').toUpperCase();
app.post('/api/ecos/contactless-oda', async (req, res) => {
  const preferReader = req.body?.reader || undefined;
  if (!usingRealReader() || !pcsc.getActiveCard(preferReader)?.connected) {
    return res.status(404).json({ error: 'Okuyucuda kart yok' });
  }
  const steps = [];
  const tx = async (name, cmd) => {
    const { response, sw } = await transmitChain(clean0(cmd), preferReader);
    const tlv = tlvFromResponse(response);
    steps.push({ name, command: clean0(cmd), response, sw, swText: describeSw(sw), ok: sw === '9000', tlv });
    return { response: clean0(response), sw, tlv };
  };
  try {
    const eph = genEphemeralP256();                 // {dT, qx, qy}
    const aid = clean0(req.body?.aid) || 'A0000000041010';
    await tx(`SELECT AID`, `00A40400${(aid.length / 2).toString(16).padStart(2, '0')}${aid}00`);
    // GPO: PDOL = 9F2B(2B, ECC tetikleyici) + 9E(64B = QT.x‖QT.y)
    const p9f2b = (clean0(req.body?.p9f2b) || '0200').padStart(4, '0').slice(-4);
    const pdolData = p9f2b + eph.qx + eph.qy;
    const gpoData = '83' + (pdolData.length / 2).toString(16).padStart(2, '0') + pdolData;
    const gpo = await tx(`GET PROCESSING OPTIONS (ECC)`, `80A80000${(gpoData.length / 2).toString(16).padStart(2, '0')}${gpoData}00`);
    const nodes = gpo.tlv.nodes;
    const ckd = clean0(findTag(nodes, '9F8103')?.value);   // 64B: blindedX(32)+E(r)(32)
    const aip = clean0(findTag(nodes, '82')?.value);
    const afl = clean0(findTag(nodes, '94')?.value);
    const out = { pan: null, aip, afl, ephemeral: { qx: eph.qx, qy: eph.qy }, cardKeyData: ckd, steps };
    if (!ckd || ckd.length < 128) return res.json({ error: 'ECC/BDH modu tetiklenemedi (9F8103 gelmedi). Bu kart RSA varyantı olabilir.', ...out });
    // ── BDH: shared secret → session keys ──
    const blindedX = ckd.slice(0, 64), Er = ckd.slice(64, 128);
    const z = ecdhSharedX(eph.dT, blindedX);
    const kdk = bdhKdk(z);
    const { skc, ski } = bdhSessionKeys(kdk);
    const blindingFactor = bdhDecrypt(skc, 0, Er);
    out.bdh = { blindedX, encryptedBlindingFactor: Er, z, kdk, skc, ski, blindingFactor };
    // ── AFL kayıtlarını oku + decrypt (DA container → AES-CTR, counter 1,2,…) ──
    // Kayıt okuma: kart READ RECORD sayacını her okumada artırır (counter = okuma sırası).
    // "local auth" AFL cert kayıtlarını (rec3-4) listemese de SFI4 rec1..6'yı tarayıp
    // decrypt ederek cert'leri buluruz (rec bulunamazsa kart 6A83 döner, atlanır).
    let counter = 1;
    const allNodes = [];
    out.records = [];
    const sfi = 4;
    for (let r = 1; r <= 6; r++) {
      const p2 = (((sfi << 3) | 4) & 0xff).toString(16).padStart(2, '0').toUpperCase();
      const rec = await tx(`READ RECORD SFI${sfi} #${r}`, `00B2${r.toString(16).padStart(2, '0').toUpperCase()}${p2}00`);
      if (rec.sw !== '9000') { steps.pop(); continue; } // 6A83 = kayıt yok
      const enc = clean0(findTag(rec.tlv.nodes, 'DA')?.value);
      let dec = null, plain = null;
      if (enc) {
        // Şifreli kayıt (gizlilik korumalı): AES-CTR ile çöz; sayaç yalnız şifreli
        // kayıtlarda artar (düz kayıtlar kart READ sayacını etkilemez).
        dec = bdhDecrypt(skc, counter, enc); counter++;
        // Çözülmüş veri saf TLV (SW yok); tlvFromResponse son 2 baytı SW sanıp
        // keser → dummy '9000' ekleyerek gerçek veriyi koru.
        const dt = tlvFromResponse(dec + '9000'); if (dt?.nodes) allNodes.push(...dt.nodes);
      } else if (rec.tlv?.nodes?.length) {
        // Düz-metin kayıt (public): Issuer cert (90) + CA index (8F) şifrelenmez.
        plain = clean0(rec.response); allNodes.push(...rec.tlv.nodes);
      }
      out.records.push({ sfi, record: r, encrypted: enc || null, decrypted: dec, plaintext: plain });
    }
    // ── Sertifikaları çıkar (decrypt edilmiş 70-template'lerden) ──
    const caIndex = clean0(findTag(allNodes, '8F')?.value);
    const issuerCert = clean0(findTag(allNodes, '90')?.value);      // Format 12 (ECC Issuer)
    const cardCert = clean0(findTag(allNodes, '9F46')?.value);      // Format 14 (ECC Card)
    const pan = clean0(findTag(allNodes, '5A')?.value) || clean0(findTag(allNodes, '57')?.value).split('D')[0];
    out.pan = pan;
    out.certs = { caIndex, issuerCert, cardCert };
    // ── CA ECC PK — depodan (RID + kartın 8F index'i); şema: C-8 Tablo 4.3 ──
    const rid = aid.slice(0, 10);
    const ca = findEccCaKey(rid, caIndex);
    const chain = { ca: !!ca };
    out.caKey = ca
      ? { rid: ca.rid, index: ca.index, scheme: ca.scheme, suite: ca.suite, curve: ca.curve, keyType: ca.keyType }
      : null;
    if (!ca) chain.caError = `ECC CA anahtarı yok: RID ${rid} index ${caIndex || '?'} — "CA Anahtarları" sekmesinden ekleyin`;
    if (ca && issuerCert) {
      const iv = verifyEccCert(issuerCert, ca.x);
      chain.issuer = iv.ok;
      // Issuer PK.x cert'ten: header(21B) sonrası 32B (imzadan önceki 32B daha güvenli)
      const issuerPkX = issuerCert.slice(issuerCert.length - 128 - 64, issuerCert.length - 128);
      chain.issuerPkX = issuerPkX;
      if (iv.ok && cardCert) {
        const cv = verifyEccCert(cardCert, issuerPkX);
        chain.card = cv.ok;
        chain.cardPkX = cardCert.slice(cardCert.length - 128 - 64, cardCert.length - 128);
      }
    }
    chain.ok = !!(chain.ca && chain.issuer && chain.card);
    out.chain = chain;
    out.verdict = chain.ok ? 'PASS' : 'PARTIAL';
    res.json(out);
  } catch (err) { res.status(500).json({ error: err.message, steps }); }
});

// İstenen profil → yoksa AID'i eşleşen ilk profil → yoksa tek profil varsa o.
// Hiçbiri yoksa null; karşılaştırma atlanır ama okuma çalışmaya devam eder.
function pickProfile(wantedId, aid) {
  if (wantedId) return getProfile(wantedId);
  const all = listProfiles();
  if (all.length === 0) return null;
  const a = (aid || '').toUpperCase();
  const byAid = all.find((p) => (p.aid || '').toUpperCase() === a);
  return getProfile((byAid || all[0]).id);
}

// POST /api/ecos/read-card — Ecos kartın EMV veri yapısını KERNEL-FARKINDA oku.
//
// Ecos çift kernel'dir: temassızda hem Kernel 2 (mevcut PayPass POS'ları) hem
// Kernel 8 (yeni ECC/AES POS'ları) desteklenir ve kart HER KERNEL İÇİN FARKLI
// kayıt seti döndürür. Terminal hangi kernel'i kullandığını GPO'daki PDOL
// verisinde 9F2B ile bildirir (perso profili: PDOL = 9F2B02‖9E40):
//   mode 'k2'      → 9F2B = 0000 : Kernel 2 yolu (klasik RSA, kayıtlar düz)
//   mode 'k8'      → 9F2B = 0280 : Kernel 8 yolu (ECC/BDH, kayıtlar DA-şifreli)
//   mode 'contact' → temaslı arayüz (PPSE yok, doğrudan SELECT AID)
//   mode 'auto'    → Kernel 8 dener; kart ECC vermezse klasik yanıtı raporlar
// PPSE (2PAY) okunarak kartın yayınladığı kernel girişleri (9F2A) de listelenir.
app.post('/api/ecos/read-card', async (req, res) => {
  const preferReader = req.body?.reader || undefined;
  if (!usingRealReader() || !pcsc.getActiveCard(preferReader)?.connected) {
    return res.status(404).json({ error: 'Okuyucuda kart yok' });
  }
  const steps = [];
  const tx = async (name, cmd) => {
    const { response, sw } = await transmitChain(clean0(cmd), preferReader);
    const tlv = tlvFromResponse(response);
    steps.push({ name, command: clean0(cmd), response, sw, swText: describeSw(sw), ok: sw === '9000', tlv });
    return { response: clean0(response), sw, tlv };
  };
  try {
    const aid = clean0(req.body?.aid) || 'A0000000041010';
    const mode = ['contact', 'k2', 'k8', 'auto'].includes(req.body?.mode) ? req.body.mode : 'auto';
    const contactless = mode !== 'contact';
    const out = { aid, mode, records: [] };

    // 1) PPSE (2PAY) — kartın yayınladığı kernel girişlerini keşfet (yalnız temassız).
    if (contactless) {
      const ppseAid = '325041592E5359532E4444463031'; // "2PAY.SYS.DDF01"
      const p = await tx('SELECT PPSE (2PAY)', `00A404000E${ppseAid}00`);
      if (p.sw === '9000') {
        // Her dizin girişi (61) bir AID + öncelik (87) + Kernel Identifier (9F2A) taşır.
        const entries = findAllTags(p.tlv.nodes, '61').map((n) => ({
          aid: clean0(findTag(n.children, '4F')?.value) || null,
          priority: clean0(findTag(n.children, '87')?.value) || null,
          kernelId: clean0(findTag(n.children, '9F2A')?.value) || null,
        }));
        out.ppse = {
          sw: p.sw, nodes: p.tlv.nodes, entries,
          kernels: entries.map((e) => e.kernelId).filter(Boolean),
        };
      } else { steps.pop(); }
    }

    // 2) SELECT AID → FCI (PDOL burada gelir)
    const sel = await tx('SELECT AID', `00A40400${(aid.length / 2).toString(16).padStart(2, '0')}${aid}00`);
    const fciNodes = sel.tlv.nodes;
    out.fci = { sw: sel.sw, nodes: fciNodes };

    // 3) GPO — PDOL'ü kartın istediği sıraya göre doldur. Kernel seçimi 9F2B ile.
    //    Kernel 8 için 9E = efemer terminal public key (QT.x‖QT.y); Kernel 2
    //    terminalinde ECC anahtarı yoktur → sıfır gönderilir.
    const eph = genEphemeralP256();
    const p9f2b = clean0(req.body?.p9f2b) || (mode === 'k2' ? '0000' : '0280');
    const use9e = mode === 'k2' ? '00'.repeat(64) : eph.qx + eph.qy;
    const pdolHex = clean0(findTag(fciNodes, '9F38')?.value);
    const pdolData = pdolHex
      ? buildDol(parseDol(pdolHex), { ...terminalDefaults(), '9F2B': p9f2b, '9E': use9e })
      : (contactless ? p9f2b + use9e : '');
    const gpoData = '83' + (pdolData.length / 2).toString(16).padStart(2, '0').toUpperCase() + pdolData;
    const g = await tx(`GET PROCESSING OPTIONS (${mode === 'k2' ? 'Kernel 2' : mode === 'contact' ? 'temaslı' : 'Kernel 8'})`,
      `80A80000${(gpoData.length / 2).toString(16).padStart(2, '0').toUpperCase()}${gpoData}00`);
    const gnodes = g.tlv.nodes;
    // Format 2 (77): AIP=82, AFL=94. Format 1 (80): 80 = AIP(2B)‖AFL(rest).
    let aip = clean0(findTag(gnodes, '82')?.value);
    let afl = clean0(findTag(gnodes, '94')?.value);
    const fmt1 = clean0(findTag(gnodes, '80')?.value);
    if (!aip && fmt1.length >= 4) { aip = fmt1.slice(0, 4); afl = fmt1.slice(4); }
    const ckd = clean0(findTag(gnodes, '9F8103')?.value);
    const eccMode = !!(ckd && ckd.length >= 128);
    out.eccMode = eccMode;
    out.pdol = { requested: pdolHex || null, sent: pdolData, p9f2b };
    out.gpo = { sw: g.sw, nodes: gnodes, aip, afl };
    // Fiilen hangi kernel yolunun çalıştığı — istenen mod değil, KARTIN yanıtı.
    out.kernelUsed = mode === 'contact' ? 'contact' : (eccMode ? 'k8' : 'k2');

    // 4) BDH oturum anahtarları (yalnız ECC/Kernel 8) → kayıt decrypt için
    let skc = null;
    if (eccMode) {
      const blindedX = ckd.slice(0, 64), Er = ckd.slice(64, 128);
      const z = ecdhSharedX(eph.dT, blindedX);
      const kdk = bdhKdk(z);
      ({ skc } = bdhSessionKeys(kdk));
      out.bdh = { z, kdk, skc, encryptedBlindingFactor: Er };
    }

    // 5) READ RECORD — AFL'den SFI/rec listesi (yoksa SFI1-4 rec1-8 tara)
    const plan = [];
    for (const e of parseAfl(afl)) {
      for (let r = e.firstRecord; r <= e.lastRecord && r > 0; r++) plan.push({ sfi: e.sfi, record: r });
    }
    if (plan.length === 0) {
      for (let sfi = 1; sfi <= 4; sfi++) for (let r = 1; r <= 8; r++) plan.push({ sfi, record: r });
    }
    let counter = 1;
    for (const { sfi, record } of plan) {
      const p2 = (((sfi << 3) | 4) & 0xff).toString(16).padStart(2, '0').toUpperCase();
      const rec = await tx(`READ RECORD SFI${sfi} #${record}`, `00B2${record.toString(16).padStart(2, '0').toUpperCase()}${p2}00`);
      if (rec.sw !== '9000') { steps.pop(); continue; }
      const enc = clean0(findTag(rec.tlv.nodes, 'DA')?.value);
      let nodes = rec.tlv.nodes, encrypted = null, decrypted = null;
      if (enc && skc) {
        // Gizlilik-korumalı kayıt: AES-CTR çöz (sayaç yalnız şifreli kayıtta artar).
        encrypted = enc;
        decrypted = bdhDecrypt(skc, counter, enc); counter++;
        nodes = parseTlv(decrypted + '9000').nodes;
      }
      out.records.push({ sfi, record, encrypted, decrypted, nodes });
    }

    // 6) Tüm tag'lerin düz listesi + perso profiliyle karşılaştırma
    const flat = [];
    const walk = (ns) => { for (const n of ns || []) { flat.push({ tag: n.tag, name: n.name || null, length: n.length, value: n.constructed ? null : n.value }); if (n.children) walk(n.children); } };
    walk(fciNodes); walk(gnodes); for (const r of out.records) walk(r.nodes);
    out.tagCount = flat.length;
    out.flatTags = flat;
    // Profil seçimi: istek belirtmişse o, yoksa AID'i eşleşen ilk profil.
    // Hiç profil yoksa karşılaştırma atlanır — okuma yine de çalışır.
    const prof = pickProfile(req.body?.profileId, aid);
    out.profileUsed = prof ? { id: prof.id, name: prof.name, source: prof.source || null } : null;
    if (!prof) out.profileNote = 'Yüklü perso profili yok — karşılaştırma yapılamadı (Profiller sekmesinden yükleyin).';
    if (prof) {
      out.profile = compareWithProfile(prof, out.kernelUsed, flat);
      const expAip = expectedAip(prof, out.kernelUsed);
      if (expAip) out.aipCheck = { expected: expAip, actual: aip || null, match: (aip || '').toUpperCase() === expAip };
    }
    out.steps = steps;
    res.json(out);
  } catch (err) { res.status(500).json({ error: err.message, steps }); }
});
