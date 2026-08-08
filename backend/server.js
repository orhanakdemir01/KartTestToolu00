import express from 'express';
import cors from 'cors';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { existsSync } from 'node:fs';
import { exec } from 'node:child_process';
import pcsc from './pcsc.js';
import { parseAtr, describeSw, findTag, parseDol, buildDol } from './emv.js';
import { terminalDefaults, TERMINAL_FIELDS, TERMINAL_PRESETS } from './terminal.js';
import { usingRealReader, describeApdu, tlvFromResponse, transmitChain, transmitOnce } from './apdu.js';
import { runEmvRead, runEmvFlow } from './emvflow.js';
import { interpretUid } from './emv.js';
import { BUILTIN_SUITES, swMatch } from './testsuites.js';
import { listKeys, keysForRid, findKey, schemes, verifyKey, addKey, updateKey, deleteKey } from './capk.js';
import {
  listKeys as listEccCaKeys, findKey as findEccCaKey, verifyKey as verifyEccCaKey,
  addKey as addEccCaKey, updateKey as updateEccCaKey, deleteKey as deleteEccCaKey,
} from './capkecc.js';
import { computeArpc, computeArpcMethod2, deriveIccMasterKey, verifyArqcAuto } from './crypto3des.js';
import { listKeysMasked, addKeySet, updateKeySet, deleteKeySet, getKeySet, findExact } from './sessionkeys.js';
import { deriveAcSessionKeyAes, deriveIccMasterKeyAes, buildEcosAcInput, ecosArqcAes, ecosArpcAes, parseEcosIad, verifyEcosArqcAes, bdhKdk, bdhSessionKeys, bdhDecrypt } from './cryptoaes.js';
import { genEphemeralP256, ecdhSharedX, verifyEccCert, ecSdsaVerifyP256, decompressP256 } from './odaecc.js';
import { findAllTags, parseAfl, parseTlv } from './emv.js';
import {
  listProfiles, getProfile, saveProfile, deleteProfile, validateProfile,
  compareWithProfile, expectedAip,
} from './profilestore.js';
import { listPacks, getPack, savePack, deletePack, validatePack, CHECK_TYPES } from './rulepacks.js';
import { buildTraceability } from './traceability.js';
import { buildPinChange, buildUnblockVariants, buildVerifyPlaintext } from './changepin.js';
import { discoverCardContext } from './carddiscover.js';
import { extractCardImage } from './cardimage.js';
import { runCompliance, ruleManifest, coverageMap } from './compliance.js';
import { runSelfTest } from './selftest.js';
import { parseProfilePdf } from './pdfprofile.js';
import { listSessions, saveSession, loadSession, deleteSession } from './sessions.js';
import { recordAndDiff, listCards, cardHistory, clearHistory } from './history.js';

const app = express();
const PORT = 3001;

app.use(cors());
// Oturum snapshot'ları (kart image + PDF + trace) büyük olabilir → varsayılan 100kb yetmez.
app.use(express.json({ limit: '25mb' }));

// ── Card / reader ───────────────────────────────────────────────────

// GET /api/readers — list connected readers + per-reader card status + health
app.get('/api/readers', (req, res) => {
  const readers = pcsc.available ? pcsc.listReaders() : [];
  res.json({
    readers,
    count: readers.length,
    status: pcsc.available ? pcsc.getReaderStatus() : [],
    mode: 'real',
    pcscAvailable: pcsc.available,
    health: pcsc.getHealth(),
  });
});

// POST /api/reader/recover — operatör tetiklemeli okuyucu kurtarma (backend
// restart yerine): PC/SC context'ini hemen yeniden kurar. Okuyucu sessizce
// düştüğünde (SDI011 combo) kullanılır.
app.post('/api/reader/recover', (req, res) => {
  res.json({ ok: true, health: pcsc.forceRecover() });
});

// GET /api/card — get card info + decoded ATR from the (optionally selected) reader
app.get('/api/card', (req, res) => {
  const preferReader = req.query.reader || undefined;
  if (!usingRealReader()) return res.status(404).json({ error: 'Okuyucu bulunamadı' });
  const card = pcsc.getActiveCard(preferReader);
  if (!card) return res.status(404).json({ error: 'Okuyucuda kart yok' });
  res.json({
    atr: card.atr || '',
    type: 'Ham kart (okuyucudan)',
    protocol: card.protocol,
    reader: card.reader,
    mode: 'real',
    atrDecoded: card.atr ? parseAtr(card.atr) : null,
  });
});

// POST /api/apdu — send APDU command, return decoded response
app.post('/api/apdu', async (req, res) => {
  const { command } = req.body;
  if (!command) return res.status(400).json({ error: 'APDU command required' });
  const clean = command.replace(/\s/g, '').toUpperCase();
  if (!/^[0-9A-F]+$/.test(clean) || clean.length < 8 || clean.length % 2 !== 0) {
    return res.status(400).json({ command, error: 'Geçersiz APDU (en az 4 bayt, çift sayıda hex hane)' });
  }

  const preferReader = req.body?.reader || undefined;
  const mode = 'real';
  try {
    const t0 = Date.now();
    const { response, sw } = await transmitChain(clean, preferReader);
    const durationMs = Date.now() - t0;
    res.json({
      command,
      response,
      sw,
      swText: describeSw(sw),
      description: describeApdu(clean, sw),
      tlv: tlvFromResponse(response),
      durationMs,
      mode,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ command, error: err.message, mode });
  }
});

// POST /api/uid — read contactless card UID (PC/SC pseudo-APDU FF CA 00 00 00)
app.post('/api/uid', async (req, res) => {
  const preferReader = req.body?.reader || undefined;
  if (!usingRealReader() || !pcsc.getActiveCard(preferReader)?.connected) {
    return res.status(404).json({ error: 'Okuyucuda kart yok' });
  }
  const mode = 'real';
  try {
    const t0 = Date.now();
    const { response, sw } = await transmitOnce('FFCA000000', preferReader);
    const durationMs = Date.now() - t0;
    if (sw !== '9000') {
      return res.json({ supported: false, sw, swText: describeSw(sw), mode, durationMs,
        note: 'Okuyucu/kart UID döndürmedi (temaslı kart olabilir veya desteklenmiyor)' });
    }
    const uidHex = response.replace(/\s/g, '').slice(0, -4);
    res.json({ supported: true, ...interpretUid(uidHex), raw: response, sw, mode, durationMs });
  } catch (err) {
    res.status(500).json({ error: err.message, mode });
  }
});

// POST /api/emv/read — full EMV read flow (see emvflow.js)
app.post('/api/emv/read', runEmvRead);

// POST /api/card/image — dump every personalised EMV tag (CPV/VPA perso image)
app.post('/api/card/image', async (req, res) => {
  const preferReader = req.body?.reader || undefined;
  if (!usingRealReader() || !pcsc.getActiveCard(preferReader)?.connected) {
    return res.status(404).json({ error: 'Okuyucuda kart yok' });
  }
  try {
    const t0 = Date.now();
    const img = await extractCardImage(preferReader, { maxSfi: req.body?.maxSfi });
    res.json({ ...img, mode: 'real', durationMs: Date.now() - t0, timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Kart image'ından ham PAN'ı çıkar (geçmiş anahtarı için) — 5A varsa ondan,
// yoksa Track2 (57) 'D' ayırıcısından.
function panFromImage(image) {
  const tags = image?.applications?.[0]?.tags || [];
  const val = (t) => tags.find((g) => g.tag === t)?.value;
  const p5a = val('5A');
  if (p5a) return p5a.replace(/\s/g, '').replace(/[Ff]+$/, '');
  const t2 = val('57');
  if (t2) { const s = t2.replace(/\s/g, '').toUpperCase(); const d = s.indexOf('D'); if (d > 0) return s.slice(0, d); }
  return null;
}

// POST /api/compliance — read the card image and run the perso compliance /
// certification rule engine (EMV core + scheme, e.g. Mastercard CPV) on it.
app.post('/api/compliance', async (req, res) => {
  const preferReader = req.body?.reader || undefined;
  if (!usingRealReader() || !pcsc.getActiveCard(preferReader)?.connected) {
    return res.status(404).json({ error: 'Okuyucuda kart yok' });
  }
  const iface = pcsc.getActiveCard(preferReader)?.contactless ? 'contactless' : 'contact';
  try {
    const t0 = Date.now();
    // Rich perso image (all GET DATA/record tags) for the tag-level rules …
    const image = await extractCardImage(preferReader, { maxSfi: req.body?.maxSfi });
    if (!image.applications?.length) return res.json({ error: 'Kart üzerinde EMV uygulaması bulunamadı', image });
    // … plus the live crypto flow (cert chain + CDA/DDA signature + GENERATE AC)
    // so the compliance engine can verify offline auth cryptographically, not
    // just check tag presence. Failure here is non-fatal (tag rules still run).
    let crypto = null;
    try {
      const emv = await runEmvFlow(preferReader, req.body || {});
      if (emv && !emv.__status) crypto = { oda: emv.oda, genac: emv.genac };
    } catch { /* crypto optional */ }
    const compliance = runCompliance(image, iface, crypto);
    // İzlenebilirlik: gereksinim → spec kaynağı → sonuç ekseni (lab raporu için).
    try { compliance.traceability = buildTraceability(compliance); }
    catch { /* matris opsiyonel — uyumluluk sonucunu düşürmesin */ }
    // Geçmişe kaydet + önceki koşuya göre regresyon/düzelme tespiti (kart başına).
    try {
      const pan = panFromImage(image);
      if (pan) compliance.regression = recordAndDiff(pan, compliance, iface);
    } catch { /* geçmiş kaydı opsiyonel */ }
    res.json({ mode: 'real', iface, durationMs: Date.now() - t0, image, crypto, compliance });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/profile/parse — parse an uploaded Mastercard Profile Advisor PDF
// (sent as raw application/pdf body) into EMV tag → value entries.
app.post('/api/profile/parse', express.raw({ type: ['application/pdf', 'application/octet-stream'], limit: '25mb' }), async (req, res) => {
  try {
    if (!req.body || !req.body.length) return res.status(400).json({ error: 'PDF verisi boş' });
    const r = await parseProfilePdf(req.body);
    if (!r.count) return res.json({ ...r, warning: 'PDF içinde tag/değer bulunamadı — Mastercard Profile Advisor raporu mu?' });
    res.json(r);
  } catch (err) {
    res.status(500).json({ error: 'PDF çözümlenemedi: ' + err.message });
  }
});

// GET /api/terminal/meta — editable terminal fields, defaults and scenario presets
app.get('/api/terminal/meta', (req, res) => {
  res.json({ fields: TERMINAL_FIELDS, defaults: terminalDefaults(), presets: TERMINAL_PRESETS });
});

// GET /api/manifest — aracın kabiliyet özeti (Genel Bakış panosu için).
app.get('/api/manifest', (req, res) => {
  const rm = ruleManifest();
  const keys = listKeys();
  const capkByScheme = {};
  for (const k of keys) capkByScheme[k.scheme] = (capkByScheme[k.scheme] || 0) + 1;
  // CAPK deposundaki şema adı ile manifest adı farklı olabilir (Amex ↔ American Express).
  const capkFor = (name) => (capkByScheme[name] || 0) + (name === 'Amex' ? (capkByScheme['American Express'] || 0) : 0);
  const schemes = [
    { name: 'Visa', rid: 'A000000003', kernel: 'K3 (payWave/qVSDC)' },
    { name: 'Mastercard', rid: 'A000000004', kernel: 'K2 (PayPass/M-Chip)' },
    { name: 'Amex', rid: 'A000000025', kernel: 'K4 (ExpressPay)' },
    { name: 'Discover', rid: 'A000000152', kernel: 'K6 (D-PAS)' },
    { name: 'Troy', rid: 'A000000672', kernel: '—' },
    { name: 'JCB', rid: 'A000000065', kernel: 'K5 (J/Speedy)' },
    { name: 'UnionPay', rid: 'A000000333', kernel: 'K7 (QuickPass)' },
  ].map((s) => ({ ...s, capks: capkFor(s.name) }));
  res.json({
    schemes,
    rules: { count: rm.count, categories: rm.categories.length, sev: rm.sev },
    capkCount: keys.length,
    scenarioCount: TERMINAL_PRESETS.length,
    coverage: coverageMap(),
  });
});

// GET /api/selftest — kripto öz-testi (karta ihtiyaç duymadan bağımsız vektörler).
app.get('/api/selftest', (req, res) => res.json(runSelfTest()));

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

// ── Perso profilleri (veri olarak; profiles/*.json) ─────────────────
app.get('/api/profiles', (req, res) => {
  if (req.query.id) {
    const p = getProfile(req.query.id);
    return p ? res.json({ profile: p }) : res.status(404).json({ error: 'Profil bulunamadı' });
  }
  const profiles = listProfiles();
  res.json({ profiles, count: profiles.length });
});

app.post('/api/profiles/validate', (req, res) => res.json(validateProfile(req.body?.profile ?? req.body)));

app.post('/api/profiles/save', (req, res) => {
  const r = saveProfile(req.body?.profile ?? req.body);
  res.status(r.ok ? 200 : 400).json(r);
});

app.post('/api/profiles/delete', (req, res) => {
  const r = deleteProfile(req.body?.id);
  res.status(r.ok ? 200 : 400).json(r);
});

// ── Kural paketleri (veri olarak; rulepacks/*.json) ─────────────────
app.get('/api/rulepacks', (req, res) => {
  if (req.query.id) {
    const p = getPack(req.query.id);
    return p ? res.json({ pack: p }) : res.status(404).json({ error: 'Paket bulunamadı' });
  }
  const packs = listPacks();
  res.json({ packs, count: packs.length, checkTypes: CHECK_TYPES });
});

app.post('/api/rulepacks/validate', (req, res) => res.json(validatePack(req.body?.pack ?? req.body)));

app.post('/api/rulepacks/save', (req, res) => {
  const r = savePack(req.body?.pack ?? req.body);
  res.status(r.ok ? 200 : 400).json(r);
});

app.post('/api/rulepacks/delete', (req, res) => {
  const r = deletePack(req.body?.id);
  res.status(r.ok ? 200 : 400).json(r);
});

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

// POST /api/scenario/run — run selected terminal-profile scenarios against the
// card and report the resulting card decision (TC/ARQC/AAC) vs the expectation.
app.post('/api/scenario/run', async (req, res) => {
  const preferReader = req.body?.reader || undefined;
  if (!usingRealReader() || !pcsc.getActiveCard(preferReader)?.connected) {
    return res.status(404).json({ error: 'Okuyucuda kart yok' });
  }
  const ids = Array.isArray(req.body?.ids) ? req.body.ids : null;
  const list = TERMINAL_PRESETS.filter((p) => !ids || ids.includes(p.id));
  const results = [];
  for (const p of list) {
    try {
      const emv = await runEmvFlow(preferReader, { ...req.body, terminal: p.over, requestAc: p.req });
      const g = emv?.genac || {};
      results.push({ id: p.id, name: p.name, cat: p.cat || null, expect: p.expect, decision: g.decision || null,
        cid: g.cid || null, ac: g.arqc || null, amount: p.over['9F02'] || null, error: emv?.error || null,
        match: p.expect === 'observe' ? null : (g.decision != null && g.decision === p.expect) });
    } catch (e) { results.push({ id: p.id, name: p.name, cat: p.cat || null, expect: p.expect, error: e.message }); }
  }
  res.json({ results });
});

// ── Test suites ─────────────────────────────────────────────────────

// GET /api/test/suites — list built-in test suites
app.get('/api/test/suites', (req, res) => res.json({ suites: BUILTIN_SUITES }));

// POST /api/test/run — run a test suite (built-in or custom) and report pass/fail
app.post('/api/test/run', async (req, res) => {
  const suite = req.body?.suite;
  if (!suite || !Array.isArray(suite.steps)) {
    return res.status(400).json({ error: 'Geçersiz test paketi (suite.steps gerekli)' });
  }
  const preferReader = req.body?.reader || undefined;
  if (!usingRealReader() || !pcsc.getActiveCard(preferReader)?.connected) {
    return res.status(404).json({ error: 'Okuyucuda kart yok' });
  }
  const mode = 'real';

  const results = [];
  for (const st of suite.steps) {
    const clean = (st.command || '').replace(/\s/g, '').toUpperCase();
    const r = { name: st.name, command: clean, expectedSw: st.expectedSw || '', expectTags: st.expectTags || [] };
    if (!/^[0-9A-F]+$/.test(clean) || clean.length < 8 || clean.length % 2 !== 0) {
      Object.assign(r, { actualSw: '', swText: '', pass: false, reason: 'Geçersiz APDU' });
      results.push(r);
      continue;
    }
    try {
      const { response, sw } = await transmitChain(clean, preferReader);
      const tlv = tlvFromResponse(response);
      const swOk = swMatch(st.expectedSw, sw);
      const missingTags = (st.expectTags || []).filter((t) => !findTag(tlv.nodes, t.toUpperCase()));
      const pass = swOk && missingTags.length === 0;
      Object.assign(r, {
        response, actualSw: sw, swText: describeSw(sw), pass,
        reason: pass ? 'OK'
          : !swOk ? `SW beklenen ${st.expectedSw}, gelen ${sw}`
          : `Eksik tag: ${missingTags.join(', ')}`,
      });
    } catch (err) {
      Object.assign(r, { actualSw: '', swText: '', pass: false, reason: `Hata: ${err.message}` });
    }
    results.push(r);
  }

  const passed = results.filter((r) => r.pass).length;
  res.json({
    name: suite.name, mode, results,
    passed, failed: results.length - passed, total: results.length,
    ok: passed === results.length,
    timestamp: new Date().toISOString(),
  });
});

// ── CA Public Keys ──────────────────────────────────────────────────
app.get('/api/capk', (req, res) => {
  if (req.query.rid) return res.json({ keys: keysForRid(req.query.rid) });
  res.json({ keys: listKeys(), schemes: schemes(), count: listKeys().length });
});

app.post('/api/capk/verify', (req, res) => res.json(verifyKey(req.body || {})));

app.post('/api/capk/add', (req, res) => {
  const r = addKey(req.body || {});
  res.status(r.added ? 200 : 400).json(r);
});

app.post('/api/capk/update', (req, res) => {
  const r = updateKey(req.body || {});
  res.status(r.updated ? 200 : 400).json(r);
});

app.post('/api/capk/delete', (req, res) => {
  const r = deleteKey(req.body?.rid, req.body?.index);
  res.status(r.deleted ? 200 : 400).json(r);
});

// ── ECC CA Public Keys (Kernel 8 · C-8 Tablo 4.3) ───────────────────
// RSA CAPK'den ayrı depo: ECC anahtarı eğri üzerinde bir NOKTA (x,y) ve
// Algorithm Suite Indicator taşır — modulus/exponent şemasına sığmaz.
app.get('/api/capk-ecc', (req, res) => {
  const keys = listEccCaKeys();
  res.json({ keys, count: keys.length });
});

app.post('/api/capk-ecc/verify', (req, res) => res.json(verifyEccCaKey(req.body || {})));

app.post('/api/capk-ecc/add', (req, res) => {
  const r = addEccCaKey(req.body || {});
  res.status(r.ok ? 200 : 400).json(r);
});

app.post('/api/capk-ecc/update', (req, res) => {
  const r = updateEccCaKey(req.body || {});
  res.status(r.ok ? 200 : 400).json(r);
});

app.post('/api/capk-ecc/delete', (req, res) => {
  const r = deleteEccCaKey(req.body?.rid, req.body?.index);
  res.status(r.ok ? 200 : 400).json(r);
});

// ── Session/Issuer 3DES keys (AC / MAC / ENC) ───────────────────────
app.get('/api/keys', (req, res) => res.json({ keys: listKeysMasked() }));

app.post('/api/keys/add', (req, res) => {
  const r = addKeySet(req.body || {});
  res.status(r.added ? 200 : 400).json(r);
});

app.post('/api/keys/update', (req, res) => {
  const r = updateKeySet(req.body || {});
  res.status(r.updated ? 200 : 400).json(r);
});

// Full (unmasked) key set for the edit form — local test tool only.
app.post('/api/keys/get', (req, res) => {
  const k = getKeySet(req.body?.label, req.body?.pan);
  res.status(k ? 200 : 404).json(k || { error: 'bulunamadı' });
});

app.post('/api/keys/delete', (req, res) => {
  res.json(deleteKeySet(req.body?.label, req.body?.pan));
});

// ── Oturum kaydet / yükle — test oturumunun tüm sonuçlarını dosyaya al ────
app.get('/api/sessions', (req, res) => {
  try { res.json({ sessions: listSessions() }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/session/save', (req, res) => {
  const { name, snapshot } = req.body || {};
  if (!name || !snapshot) return res.status(400).json({ error: 'name ve snapshot gerekli' });
  try { res.json(saveSession(name, snapshot)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/session/load', (req, res) => {
  const snapshot = loadSession(req.body?.file || '');
  if (!snapshot) return res.status(404).json({ error: 'Oturum bulunamadı' });
  res.json({ snapshot });
});

app.post('/api/session/delete', (req, res) => {
  res.json({ deleted: deleteSession(req.body?.file || '') });
});

// ── Uyumluluk geçmişi / regresyon ──────────────────────────────────────
app.get('/api/history', (req, res) => {
  try { res.json({ cards: listCards() }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/history/card', (req, res) => {
  res.json({ runs: cardHistory(req.body?.pan || '') });
});
app.post('/api/history/clear', (req, res) => {
  res.json({ cleared: clearHistory(req.body?.pan || null) });
});

// ── Change PIN (EMV PIN CHANGE/UNBLOCK, issuer script 84 24) ─────────
// The caller only picks a key set + new PIN; the AID, PAN, PSN and ATC are
// auto-read from the card (advanced overrides optional).
app.post('/api/pin/change', async (req, res) => {
  const preferReader = req.body?.reader || undefined;
  if (!usingRealReader() || !pcsc.getActiveCard(preferReader)?.connected) {
    return res.status(404).json({ error: 'Okuyucuda kart yok' });
  }
  const { newPin, keyLabel, keyPan, mode = 'change', p1, p2, scheme: schemeOv,
    aid: aidOv, pan: panOv, psn: psnOv, atc: atcOv } = req.body || {};
  const ks = findExact(keyLabel, keyPan || '');
  if (!ks) return res.status(400).json({ error: 'Anahtar seti bulunamadı — Oturum Anahtarları sekmesinden ekleyin/seçin' });
  if (!ks.macKey) return res.status(400).json({ error: 'Seçilen anahtar setinde MAC anahtarı yok (secure messaging için gerekli)' });
  if (mode === 'change' && !ks.encKey) return res.status(400).json({ error: 'PIN değişimi için anahtar setinde ENC anahtarı olmalı' });

  try {
    // 1) Auto-discover the card context (AID/PAN/PSN/ATC). Skip only if every
    //    field is overridden by the caller.
    let ctx = { steps: [] };
    const needDiscovery = !(aidOv && (panOv || ks.keyLevel !== 'master') && atcOv);
    if (needDiscovery) {
      ctx = await discoverCardContext(preferReader);
      if (ctx.error && !atcOv) return res.status(400).json({ error: ctx.error, steps: ctx.steps });
    }
    const aid = (aidOv || ctx.aid || '').replace(/\s/g, '').toUpperCase();
    const pan = panOv || ctx.pan || ks.pan;
    const psn = psnOv || ctx.psn || ks.psn;
    const atc = (atcOv || ctx.atc || '').replace(/\s/g, '').toUpperCase();

    // Scheme selects the PIN-change calculation method (Visa VIS vs Mastercard
    // M/Chip) — from the RID (AID prefix) unless the caller overrides it.
    const rid = aid.slice(0, 10);
    const scheme = (schemeOv || (rid === 'A000000003' ? 'visa'
      : rid === 'A000000004' ? 'mastercard'
      : rid === 'A000000025' ? 'amex'
      : rid === 'A000000672' ? 'troy' : 'mastercard')).toLowerCase();

    const steps = [...ctx.steps];
    const run = async (name, cmd) => {
      const { response, sw } = await transmitChain(cmd, preferReader);
      steps.push({ name, command: cmd, response, sw, swText: describeSw(sw) });
      return { response, sw };
    };
    if (!ctx.aidSelected && aid) {
      await run('SELECT AID', `00A40400${(aid.length / 2).toString(16).padStart(2, '0').toUpperCase()}${aid}00`);
    }

    // 2) The AC/ATC that key the PIN-change secure messaging.
    //    Mastercard: the 1st (only) GENERATE AC's ARQC.
    //    Visa: the card requires issuer authentication first — compute the ARPC
    //    (method 2) from the 1st ARQC and pass it back in a 2nd GENERATE AC
    //    (CDOL2, P1=40 TC). The PIN change then keys off that 2nd AC. Both
    //    GENERATE ACs share the transaction ATC.
    let smAtc = atc, smAc = ctx.arqc, issuer = null;
    if (scheme === 'visa' && ctx.arqc && mode === 'change') {
      const csu = (req.body?.csu || '03920000').replace(/\s/g, '').toUpperCase();
      const arc = (req.body?.arc || '3030').replace(/\s/g, '').toUpperCase();
      const ap = computeArpcMethod2({ acKey: ks.acKey, keyLevel: ks.keyLevel, pan, psn, atc, arqc: ctx.arqc, csu });
      const defs = { ...terminalDefaults(), '91': ap.issuerAuthData, '8A': arc };
      const cdol2Data = ctx.cdol2 ? buildDol(parseDol(ctx.cdol2), defs) : (ap.issuerAuthData + arc);
      const g2 = await run('GENERATE AC 2 (TC + issuer auth)', `80AE4000${(cdol2Data.length / 2).toString(16).padStart(2, '0').toUpperCase()}${cdol2Data}00`);
      const n2 = tlvFromResponse(g2.response).nodes;
      const t80 = findTag(n2, '80');
      let ac2, atc2;
      if (t80) { const v = t80.value.replace(/\s/g, ''); atc2 = v.slice(2, 6); ac2 = v.slice(6, 22); }
      else { ac2 = findTag(n2, '9F26')?.value.replace(/\s/g, ''); atc2 = findTag(n2, '9F36')?.value.replace(/\s/g, ''); }
      // The transaction ATC is shared by both GENERATE ACs. The PIN-change
      // script MAC keys off the online ARQC (1st GENERATE AC) — verified live
      // (SW 9000). The 2nd GENERATE AC only carries the issuer authentication.
      const acSource = req.body?.acSource || 'gen1';
      smAtc = atc2 || atc;
      smAc = acSource === 'gen2' ? (ac2 || ctx.arqc) : ctx.arqc;
      issuer = { arpc: ap.arpc, csu, arc, gen2Sw: g2.sw, ac1: ctx.arqc, ac2, atc: smAtc, acUsed: acSource };
    } else if (scheme === 'amex' && ctx.arqc && mode === 'change') {
      // Amex issuer authentication: ARPC method 1 (3DES over ARQC XOR ARC, keyed
      // with the ICC AC unique key) sent via EXTERNAL AUTHENTICATE. The PIN
      // change then keys off the online ARQC (1st GENERATE AC).
      const arc = (req.body?.arc || '3030').replace(/\s/g, '').toUpperCase();
      const udkAc = (ks.keyLevel === 'icc' || ks.keyLevel === 'session') ? ks.acKey : deriveIccMasterKey(ks.acKey, pan, psn);
      const ap = computeArpc({ acKey: udkAc, keyLevel: 'session', arqc: ctx.arqc, arc });
      const ea = await run('EXTERNAL AUTHENTICATE (ARPC M1)', `00820000${(ap.iad.length / 2).toString(16).padStart(2, '0').toUpperCase()}${ap.iad}`);
      // 2nd GENERATE AC (P1=40 TC) completes the transaction before the script.
      // Amex CDOL2 carries the ARC (8A) but no issuer auth data (done via EXT AUTH).
      const defs2 = { ...terminalDefaults(), '8A': arc };
      const cdol2Data = ctx.cdol2 ? buildDol(parseDol(ctx.cdol2), defs2) : arc;
      const g2 = await run('GENERATE AC 2 (TC)', `80AE4000${(cdol2Data.length / 2).toString(16).padStart(2, '0').toUpperCase()}${cdol2Data}00`);
      smAtc = atc; smAc = ctx.arqc;
      issuer = { arpc: ap.arpc, arc, extAuthSw: ea.sw, gen2Sw: g2.sw, ac1: ctx.arqc, atc: smAtc };
    }

    // 3) Build the scheme-specific PIN CHANGE/UNBLOCK APDU and send it.
    const pc = buildPinChange({
      scheme, macKey: ks.macKey, encKey: ks.encKey, acKey: ks.acKey, keyLevel: ks.keyLevel,
      pan, psn, atc: smAtc, arqc: smAc, newPin, mode, p1, p2,
    });
    if (pc.error) return res.status(400).json({ error: pc.error, steps, aid, pan, atc: smAtc });
    const r = await run(`PIN ${mode === 'unblock' ? 'UNBLOCK' : 'CHANGE'} (84 24)`, pc.apdu);
    res.json({
      ok: r.sw === '9000', mode, scheme: pc.scheme, steps, aid, pan, psn, atc: smAtc, atcSource: ctx.atcSource,
      arqc: smAc, issuer,
      keyLabel: ks.label, keyLevel: ks.keyLevel,
      apdu: pc.apdu, header: pc.header, lc: pc.lc, p1: pc.p1, p2: pc.p2,
      skmac: pc.skmac, skenc: pc.skenc, pinBlock: pc.pinBlock, encPin: pc.encPin, mac: pc.mac,
      sw: r.sw, swText: describeSw(r.sw),
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/arpc — bağımsız issuer authentication (ARPC) üretimi + karta doğrulatma.
// Kartın 1. GENERATE AC (ARQC) sonucundan ARPC üretir (Method 1: 3DES; Method 2:
// CSU-tabanlı Retail MAC), sonra kartın issuer auth'u KABUL edip etmediğini test
// eder: Amex EXTERNAL AUTHENTICATE (M1, SW 9000), diğerleri 2. GENERATE AC (M2,
// CDOL2 tag 91) → CID TC (0x40)=kabul / AAC (0x00)=red. Kartın ARPC/issuer
// authentication doğrulamasını gerçekten yaptığını kanıtlayan EMV testi.
app.post('/api/arpc', async (req, res) => {
  const preferReader = req.body?.reader || undefined;
  const send = req.body?.send !== false; // varsayılan: karta gönder ve doğrula
  const { keyLabel, keyPan, aid: aidOv, pan: panOv, psn: psnOv, atc: atcOv, arqc: arqcOv } = req.body || {};
  const arc = (req.body?.arc || '3030').replace(/\s/g, '').toUpperCase();
  const csu = (req.body?.csu || '03920000').replace(/\s/g, '').toUpperCase();
  const methodReq = (req.body?.method || 'auto').toLowerCase(); // 'auto' | 'm1' | 'm2'
  const explicitCorrupt = req.body?.corrupt === true;
  // Diferansiyel test (varsayılan, M2): doğru ARPC (TC bekle) + bozuk ARPC (AAC bekle).
  // Bu, kartın issuer auth'u GERÇEKTEN doğruladığını kanıtlar — AIP bitine güvenmez.
  const wantDifferential = req.body?.differential !== false && !explicitCorrupt;
  const ks = findExact(keyLabel, keyPan || '');
  if (!ks) return res.status(400).json({ error: 'Anahtar seti bulunamadı — Oturum Anahtarları sekmesinden seçin' });
  const cardPresent = usingRealReader() && pcsc.getActiveCard(preferReader)?.connected;
  const flip1 = (h) => ((parseInt(h.slice(0, 2), 16) ^ 0xFF).toString(16).padStart(2, '0') + h.slice(2)).toUpperCase();

  // Tek bir ARPC turu: taze keşif (ARQC/ATC) + ARPC hesabı + (opsiyonel) karta gönder.
  async function arpcRound(corrupt) {
    const steps = [];
    const run = async (name, cmd) => { const { response, sw } = await transmitChain(cmd, preferReader); steps.push({ name, command: cmd, response, sw, swText: describeSw(sw) }); return { response, sw }; };
    let ctx = { steps: [] };
    if (!(arqcOv && atcOv)) { ctx = await discoverCardContext(preferReader); if (ctx.error) return { error: ctx.error, steps: ctx.steps }; }
    const aid = (aidOv || ctx.aid || '').replace(/\s/g, '').toUpperCase();
    const pan = panOv || ctx.pan || ks.pan, psn = psnOv || ctx.psn || ks.psn;
    const atc = (atcOv || ctx.atc || '').replace(/\s/g, '').toUpperCase();
    const arqc = (arqcOv || ctx.arqc || '').replace(/\s/g, '').toUpperCase();
    const un = (req.body?.un || ctx.un || '').replace(/\s/g, '').toUpperCase();
    const aip = (req.body?.aip || ctx.aip || '').replace(/\s/g, '').toUpperCase();
    const rid = aid.slice(0, 10);
    const scheme = rid === 'A000000003' ? 'visa' : rid === 'A000000004' ? 'mastercard'
      : rid === 'A000000025' ? 'amex' : rid === 'A000000672' ? 'troy'
      : rid === 'A000000333' ? 'unionpay' : 'unknown';
    const lvl = ks.keyLevel === 'auto' ? 'master' : ks.keyLevel;
    if (!arqc) return { error: 'ARQC bulunamadı — kartın GENERATE AC ile ARQC üretmesi gerekir', steps: [...(ctx.steps || []), ...steps] };
    // ARQC'yi doğrula → kartın gerçekten kullandığı SKac'ı bul. ARPC AYNI SKac ile
    // hesaplanmalı (EMV Bk2 §8.2). Bu, şema/CVN-özel session-key türetimini otomatik
    // çözer (M/Chip UN-tabanlı, Visa CSK, CVN10 UDK-direct...) — tahmin yok.
    const td = terminalDefaults();
    // base = standart AC veri kompozisyonu (emvflow ile aynı); cdol = ham CDOL1 verisi.
    const base = td['9F02'] + td['9F03'] + td['9F1A'] + td['95'] + td['5F2A'] + td['9A'] + td['9C'] + td['9F37'];
    const av = verifyArqcAuto({ acKey: ks.acKey, keyLevel: lvl, pan, psn, atc, un,
      base, cdol: ctx.cdol1 || '', aip, iad: ctx.iad || '', cardArqc: arqc, aid,
      amount: td['9F02'], currency: td['5F2A'] });
    const skac = av && av.match ? av.sessionKey : null;
    // SKac doğrulandıysa onu doğrudan (session seviyesi) kullan; yoksa şema-farkında tahmin.
    const m1 = skac ? computeArpc({ acKey: skac, keyLevel: 'session', arqc, arc })
      : computeArpc({ acKey: ks.acKey, keyLevel: lvl, pan, psn, atc, arqc, arc, scheme, un });
    const m2 = skac ? computeArpcMethod2({ acKey: skac, keyLevel: 'session', arqc, csu })
      : computeArpcMethod2({ acKey: ks.acKey, keyLevel: lvl, pan, psn, atc, arqc, csu, scheme, un });
    // M/Chip (Mastercard/UnionPay) ARPC = Method 1 (3DES, ARQC⊕ARC) — paymentcardtools
    // CVN10 ref + EMV Bk2 §8.2.1. Visa/CCD = Method 2. Amex = Method 1 (EXT AUTH).
    const mUsed = methodReq === 'auto' ? (scheme === 'amex' ? 'm1' : 'm2') : methodReq;
    const out = { aid, scheme, pan, psn, atc, arqc, un, aip, m1, m2, mUsed, arqcVerified: !!skac, arqcMethod: av?.method || null, cid: null, acType: null, sw: null, sentIad: null };
    if (send && cardPresent) {
      if (mUsed === 'm1') {
        const ea = await run('EXTERNAL AUTHENTICATE (ARPC M1)', `00820000${(m1.iad.length / 2).toString(16).padStart(2, '0').toUpperCase()}${m1.iad}`);
        out.sw = ea.sw; out.eaAccepted = ea.sw === '9000'; out.sentIad = m1.iad;
      } else {
        // Tag 91 (Issuer Auth Data) ARPC yöntemi ŞEMA-FARKINDA: Mastercard/UnionPay
        // M/Chip → Method-1 (3DES, ARPC‖ARC = m1.iad; paymentcardtools CVN10 ref +
        // EMV Bk2 §8.2.1). Visa/CCD → Method-2 (Retail MAC, ARPC‖CSU). `arpcVariant`
        // (1|2) ile override edilebilir.
        const variant = req.body?.arpcVariant ? String(req.body.arpcVariant) : ((scheme === 'mastercard' || scheme === 'unionpay') ? '1' : '2');
        const base91 = variant === '1' ? m1.iad : m2.issuerAuthData;
        const iad91 = corrupt ? flip1(base91) : base91;
        out.arpcVariant = variant;
        const defs = { ...terminalDefaults(), '91': iad91, '8A': arc };
        const cdol2Data = ctx.cdol2 ? buildDol(parseDol(ctx.cdol2), defs) : (iad91 + arc);
        const g2 = await run(`GENERATE AC 2 (issuer auth · M${variant}${corrupt ? ' · BOZUK ARPC' : ''})`, `80AE4000${(cdol2Data.length / 2).toString(16).padStart(2, '0').toUpperCase()}${cdol2Data}00`);
        const n2 = tlvFromResponse(g2.response).nodes;
        const t80 = findTag(n2, '80');
        out.cid = t80 ? t80.value.replace(/\s/g, '').slice(0, 2) : findTag(n2, '9F27')?.value.replace(/\s/g, '');
        out.acType = out.cid ? (parseInt(out.cid, 16) & 0xC0) : null; out.sw = g2.sw; out.sentIad = iad91;
      }
    }
    out.steps = [...(ctx.steps || []), ...steps];
    return out;
  }

  try {
    if (!cardPresent && !(arqcOv && atcOv)) return res.status(404).json({ error: 'Okuyucuda kart yok (ARQC için gerekli)' });
    const cidLabel = (t) => t === 0x40 ? 'TC' : t === 0x00 ? 'AAC' : t === 0x80 ? 'ARQC' : '?';

    const r1 = await arpcRound(explicitCorrupt); // ilk tur (açıkça istenmedikçe DOĞRU ARPC)
    if (r1.error) return res.status(400).json({ error: r1.error, steps: r1.steps });

    let verdict = null, sent = null, negative = null, steps = r1.steps;
    if (send && cardPresent && r1.mUsed === 'm1') {
      // Amex EXTERNAL AUTHENTICATE tek başına doğrulayıcıdır: SW 9000 = ARPC kabul.
      const acc = r1.eaAccepted, unsupported = /^6[DE]00$/.test(r1.sw);
      sent = { method: 'Method 1 (3DES · EXTERNAL AUTHENTICATE)', arpc: r1.m1.arpc, iad: r1.sentIad, sw: r1.sw, swText: describeSw(r1.sw), accepted: acc,
        note: acc ? null : (unsupported ? 'Kart EXTERNAL AUTHENTICATE desteklemiyor — issuer auth 2. GENERATE AC ile yapılır.' : 'Kart EXTERNAL AUTHENTICATE\'i reddetti (ARPC doğrulanamadı).') };
      verdict = acc ? 'PASS' : (unsupported ? 'WARN' : 'FAIL');
    } else if (send && cardPresent) {
      const tc1 = r1.sw === '9000' && r1.acType === 0x40;
      sent = { method: `Method 2 (Retail MAC · 2. GENERATE AC)${explicitCorrupt ? ' · negatif test' : ''}`, arpc: r1.m2.arpc,
        issuerAuthData: r1.m2.issuerAuthData, sentIssuerAuthData: r1.sentIad, cid: r1.cid, cidLabel: cidLabel(r1.acType),
        sw: r1.sw, swText: describeSw(r1.sw), accepted: tc1, note: null };
      if (explicitCorrupt) {
        // Tek atış negatif test: bozuk ARPC reddedilmeli (AAC).
        verdict = r1.acType === 0x00 ? 'PASS' : 'FAIL';
        sent.note = r1.acType === 0x00 ? 'Negatif test ✓ — kart bozuk ARPC\'yi reddetti (AAC).' : 'Negatif test ✗ — kart bozuk ARPC\'ye rağmen TC döndü → ARPC\'yi doğrulamıyor.';
      } else if (wantDifferential) {
        // Diferansiyel: ikinci tur BOZUK ARPC ile. Kesin issuer-auth kanıtı, AIP'den bağımsız.
        const r2 = await arpcRound(true);
        steps = [...steps, ...(r2.steps || [])];
        negative = r2.error ? { error: r2.error } : { cid: r2.cid, cidLabel: cidLabel(r2.acType), sw: r2.sw, sentIssuerAuthData: r2.sentIad, rejected: r2.acType === 0x00 };
        const negAac = !r2.error && r2.acType === 0x00;
        if (tc1 && negAac) { verdict = 'PASS'; sent.note = 'Diferansiyel ✓ — doğru ARPC kabul (TC), bozuk ARPC red (AAC): kart issuer authentication\'ı KRİPTOGRAFİK olarak doğruluyor.'; }
        else if (tc1 && !r2.error && r2.acType === 0x40) { verdict = 'NA'; sent.note = 'Kart bozuk ARPC\'ye de TC döndü → ARPC\'yi doğrulamıyor; TC yalnızca risk-onay kararıdır (issuer auth uygulanmıyor).'; }
        else if (!tc1) {
          const same = !r2.error && r2.acType === r1.acType;
          if (r1.arqcVerified && same) {
            // Doğru ve bozuk ARPC AYNI sonucu verdi → ARPC değeri kartın kararını
            // ETKİLEMİYOR; session key de kesin doğru (ARQC eşleşti) → kripto sorunu YOK.
            // Kart offline TC vermiyor (online-zorunlu olabilir): test UYGULANAMAZ, kusur değil.
            verdict = 'NA';
            sent.note = `Kart doğru ve bozuk ARPC'ye AYNI yanıtı (${cidLabel(r1.acType)}) verdi → ARPC değeri kararı etkilemiyor. Session key DOĞRULANDI (${r1.arqcMethod}) — KRİPTO SORUNU YOK. Kart bu profilde offline TC vermiyor (online-zorunlu yapılandırma olabilir); issuer-auth bu kartta gözlenemez — KART KUSURU DEĞİL, test kapsam dışı. (Krş: Visa kartı offline TC verip PASS aldı.)`;
          } else if (!r1.arqcVerified) {
            verdict = 'WARN';
            sent.note = `Kart doğru ARPC'ye ${cidLabel(r1.acType)} döndü ve ARQC doğrulanamadı — bu PAN için doğru issuer anahtarı yüklü olmayabilir.`;
          } else {
            verdict = 'WARN';
            sent.note = `Kart doğru ARPC'ye ${cidLabel(r1.acType)}, bozuk ARPC'ye ${cidLabel(r2.acType)} döndü — beklenmedik; issuer-auth kesin doğrulanamadı.`;
          }
        }
        else { verdict = 'WARN'; sent.note = 'Diferansiyel sonuç belirsiz.'; }
      } else {
        verdict = tc1 ? 'PASS' : 'WARN';
        sent.note = tc1 ? 'TC — kesin kanıt için diferansiyel/negatif test önerilir (bozuk ARPC reddi).' : `Kart ${cidLabel(r1.acType)} döndü.`;
      }
    }

    const panMask = r1.pan ? String(r1.pan).replace(/^(\d{6})\d+(\d{4})$/, '$1••••••$2') : null;
    res.json({
      scheme: r1.scheme, aid: r1.aid, pan: panMask, atc: r1.atc, arqc: r1.arqc, un: r1.un, aip: r1.aip || null,
      issuerAuthAdvertised: r1.aip && r1.aip.length >= 2 ? !!(parseInt(r1.aip.slice(0, 2), 16) & 0x04) : null,
      arc, csu, keyLabel: ks.label, keyLevel: ks.keyLevel, differential: wantDifferential && r1.mUsed === 'm2',
      arqcVerified: r1.arqcVerified, arqcMethod: r1.arqcMethod,
      method1: { name: 'Method 1 — 3DES(SKac, ARQC ⊕ ARC‖00…)', arpc: r1.m1.arpc, iad: r1.m1.iad, sessionKey: r1.m1.sessionKey },
      method2: { name: 'Method 2 — Retail MAC(SKac, ARQC‖CSU)[:4]', arpc: r1.m2.arpc, issuerAuthData: r1.m2.issuerAuthData, sessionKey: r1.m2.sessionKey },
      methodUsed: r1.mUsed, sent, negative, verdict, steps, timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/pin/verify — plaintext offline PIN verification. Selects the AID +
// GPO (no cryptogram), reads the PIN Try Counter, sends VERIFY (00 20 00 80)
// with the entered PIN, and reports correct / wrong (tries left) / blocked.
app.post('/api/pin/verify', async (req, res) => {
  const preferReader = req.body?.reader || undefined;
  if (!usingRealReader() || !pcsc.getActiveCard(preferReader)?.connected) {
    return res.status(404).json({ error: 'Okuyucuda kart yok' });
  }
  const vp = buildVerifyPlaintext(req.body?.pin);
  if (vp.error) return res.status(400).json({ error: vp.error });
  try {
    const ctx = await discoverCardContext(preferReader, { skipCrypto: true });
    if (ctx.error) return res.status(400).json({ error: ctx.error, steps: ctx.steps });
    const steps = [...ctx.steps];
    const run = async (name, cmd) => {
      const { response, sw } = await transmitChain(cmd, preferReader);
      steps.push({ name, command: cmd, response, sw, swText: describeSw(sw) });
      return { response, sw };
    };
    const readPtc = async (label) => {
      const p = await run(label, '80CA9F1700');
      const v = findTag(tlvFromResponse(p.response).nodes, '9F17')?.value?.replace(/\s/g, '');
      return v ? parseInt(v, 16) : null;
    };
    const ptcBefore = await readPtc('GET DATA PTC (9F17)');
    const r = await run('VERIFY (plaintext PIN)', vp.apdu);
    const ptcAfter = await readPtc('GET DATA PTC (9F17)');
    const sw = r.sw;
    const m = /^63C([0-9A-F])$/i.exec(sw);
    const triesLeft = m ? parseInt(m[1], 16) : (sw === '6983' ? 0 : ptcAfter);
    res.json({
      correct: sw === '9000', wrong: /^63C/i.test(sw), blocked: sw === '6983' || sw === '6984',
      triesLeft, ptcBefore, ptcAfter,
      sw, swText: describeSw(sw), aid: ctx.aid, pan: ctx.pan,
      pinBlock: vp.pinBlock, apdu: vp.apdu, steps,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/pin/probe — find the M/Chip secure-messaging MAC format. Discovers
// the card context ONCE (single GENERATE AC → fixed ATC/ARQC), then sends a
// bounded set of PIN-UNBLOCK (MAC-only) variants. A 9000 pins down the correct
// SM format WITHOUT changing the PIN (unblock only resets the PIN try counter).
app.post('/api/pin/probe', async (req, res) => {
  const preferReader = req.body?.reader || undefined;
  if (!usingRealReader() || !pcsc.getActiveCard(preferReader)?.connected) {
    return res.status(404).json({ error: 'Okuyucuda kart yok' });
  }
  const { keyLabel, keyPan } = req.body || {};
  const ks = findExact(keyLabel, keyPan || '');
  if (!ks) return res.status(400).json({ error: 'Anahtar seti bulunamadı' });
  if (!ks.macKey) return res.status(400).json({ error: 'Seçilen anahtar setinde MAC anahtarı yok' });
  try {
    const ctx = await discoverCardContext(preferReader);
    if (ctx.error) return res.status(400).json({ error: ctx.error, steps: ctx.steps });
    if (!ctx.arqc) return res.status(400).json({ error: 'ARQC alınamadı (GENERATE AC)', ctx });

    // Try the PIN-UNBLOCK (MAC-only) format variants — a 9000 pins down the SM
    // format without changing the PIN (unblock just resets the PIN try counter).
    const variants = buildUnblockVariants({
      macKey: ks.macKey, keyLevel: ks.keyLevel, pan: ctx.pan || ks.pan, psn: ctx.psn || ks.psn,
      atc: ctx.atc, arqc: ctx.arqc, un: ctx.un,
    });
    const tried = [];
    let winner = null;
    for (const v of variants) {
      const { sw } = await transmitChain(v.apdu, preferReader);
      tried.push({ name: v.name, apdu: v.apdu, sw, swText: describeSw(sw) });
      if (sw === '9000') { winner = { ...v }; break; }
    }
    res.json({
      ok: !!winner, aid: ctx.aid, pan: ctx.pan, psn: ctx.psn, atc: ctx.atc, arqc: ctx.arqc, un: ctx.un,
      winner, tried, count: tried.length,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/health
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    mode: usingRealReader() ? 'real' : 'no-reader',
    pcscAvailable: pcsc.available,
    readers: pcsc.listReaders(),
    lastError: pcsc.lastError,
  });
});

// ── Standalone / packaged mode (KARTTEST_STANDALONE=1) ──────────────────
// Serve the built frontend from this one server and open the browser, so the
// whole app runs as a single process (no separate Vite dev server). Registered
// AFTER all /api routes so the SPA fallback never shadows the API.
if (process.env.KARTTEST_STANDALONE === '1') {
  const dist = join(dirname(fileURLToPath(import.meta.url)), '..', 'frontend', 'dist');
  if (existsSync(dist)) {
    app.use(express.static(dist));
    app.use((req, res, next) => {
      if (req.method === 'GET' && !req.path.startsWith('/api')) return res.sendFile(join(dist, 'index.html'));
      next();
    });
  } else {
    console.warn(`Frontend dist bulunamadı: ${dist}`);
  }
}

const standalone = process.env.KARTTEST_STANDALONE === '1';
const srv = app.listen(PORT, () => {
  console.log(`Backend running on http://localhost:${PORT}`);
  console.log(`PC/SC available: ${pcsc.available}`);
  if (standalone) {
    console.log('KartTest hazır — tarayıcı açılıyor.');
    exec(`start "" "http://localhost:${PORT}/"`, { windowsHide: true }, () => {});
  }
});
// Port çakışması: sessizce (frontend sunmayan) başka bir sunucuya düşüp "Cannot GET /"
// göstermek yerine, muhtemelen zaten çalışan KartTest örneğini tarayıcıda aç ve çık.
srv.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} kullanımda — KartTest zaten çalışıyor olabilir. Mevcut örnek açılıyor.`);
    if (standalone) exec(`start "" "http://localhost:${PORT}/"`, { windowsHide: true }, () => {});
    process.exit(0);
  }
  console.error(`Sunucu başlatılamadı: ${err.message}`);
  process.exit(1);
});
