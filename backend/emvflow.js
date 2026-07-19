// Full EMV read flow: PPSE/PSE → SELECT AID → GPO → READ RECORDS → cryptogram + ODA.
import pcsc from './pcsc.js';
import {
  findTag, findAllTags, parseAfl, parseTrack2, formatExpiry, hexToAscii,
  decodeAip, decodeCvmList, decodeServiceCode, detectScheme, luhnCheck,
  decodeAuc, countryName, currencyName, parseDol, buildDol, describeSw,
} from './emv.js';
import { usingRealReader, transmitChain, tlvFromResponse } from './apdu.js';
import { terminalDefaults, CANDIDATE_AIDS } from './terminal.js';
import { findKey } from './capk.js';
import { listKeys, findForPan, findExact } from './sessionkeys.js';
import { verifyArqcAuto } from './crypto3des.js';
import { recoverIssuerPK, recoverIccPK, verifySDAD } from './oda.js';

// Reusable EMV read flow — returns the result object (used by the /api/emv/read
// route wrapper below and by the compliance engine, which needs oda + genac).
// On failure returns an object with a __status field for the HTTP wrapper.
export async function runEmvFlow(preferReader, body = {}) {
  if (!usingRealReader() || !pcsc.getActiveCard(preferReader)?.connected) {
    return { __status: 404, error: 'Okuyucuda kart yok' };
  }
  const mode = 'real';
  const steps = [];
  // Single terminal profile for this run — the request may override amount,
  // currency, txn type, capabilities etc. so the card is exercised under a
  // specific terminal condition (offline / online / decline scenarios).
  const term = terminalDefaults(body.terminal || {});

  const step = async (name, cmd) => {
    const clean = cmd.replace(/\s/g, '').toUpperCase();
    const t0 = Date.now();
    const { response, sw } = await transmitChain(clean, preferReader);
    const durationMs = Date.now() - t0;
    const tlv = tlvFromResponse(response);
    const s = { name, command: clean, response, sw, swText: describeSw(sw), ok: sw === '9000', tlv, durationMs };
    steps.push(s);
    return s;
  };

  const toLen = (hexNoSpaces) => (hexNoSpaces.length / 2).toString(16).padStart(2, '0').toUpperCase();

  const collectApps = (nodes, source) => {
    const apps = [];
    for (const t of findAllTags(nodes, '61')) {
      const a = findTag([t], '4F'); const l = findTag([t], '50');
      if (a) apps.push({ aid: a.value.replace(/\s/g, ''), label: l ? hexToAscii(l.value) : null, source });
    }
    return apps;
  };

  // PPSE (2PAY) — apps directly in FCI (contactless payment environment)
  const selectPpse = async () => {
    const r = await step('SELECT PPSE (2PAY)', '00A404000E325041592E5359532E444446303100');
    return r.ok ? collectApps(r.tlv.nodes, 'PPSE') : [];
  };
  // PSE (1PAY) — apps in FCI or via directory SFI (88) (contact payment environment)
  const selectPse = async () => {
    const apps = [];
    const pse = await step('SELECT PSE (1PAY)', '00A404000E315041592E5359532E444446303100');
    if (pse.ok) {
      apps.push(...collectApps(pse.tlv.nodes, 'PSE'));
      const sfiNode = findTag(pse.tlv.nodes, '88');
      if (sfiNode && apps.length === 0) {
        const sfi = parseInt(sfiNode.value.replace(/\s/g, ''), 16);
        const p2 = ((sfi << 3) | 4).toString(16).padStart(2, '0').toUpperCase();
        for (let rec = 1; rec <= 10; rec++) {
          const dir = await step(`READ DIRECTORY SFI${sfi} #${rec}`, `00B2${rec.toString(16).padStart(2, '0').toUpperCase()}${p2}00`);
          if (!dir.ok) { dir.benign = true; break; } // 6A83 = end of directory (expected)
          apps.push(...collectApps(dir.tlv.nodes, 'PSE'));
        }
      }
    }
    return apps;
  };

  // Discovery order follows the reader interface: contact → PSE first, contactless → PPSE first
  const activeCard = usingRealReader() ? pcsc.getActiveCard(preferReader) : null;
  const isContactless = !!activeCard?.contactless;

  try {
    const applications = [];
    const discovery = isContactless ? [selectPpse, selectPse] : [selectPse, selectPpse];
    for (const discover of discovery) {
      if (applications.length) break;
      applications.push(...await discover());
    }

    // Select the application — from PPSE/PSE if found, else try candidate AIDs directly
    let aid = null, sel = null, label = null;
    if (applications.length > 0) {
      aid = applications[0].aid; label = applications[0].label;
      sel = await step(`SELECT AID (${label || aid})`, `00A40400${toLen(aid)}${aid}00`);
    } else {
      for (const [name, cand] of CANDIDATE_AIDS) {
        const s = await step(`AID dene: ${name}`, `00A40400${toLen(cand)}${cand}00`);
        if (s.ok) {
          sel = s; aid = cand; label = name;
          applications.push({ aid: cand, label: name, source: 'candidate' });
          break;
        }
      }
    }

    if (!sel || !sel.ok || !aid) {
      return { steps, mode, applications, error: 'Kart üzerinde EMV uygulaması bulunamadı (PPSE, PSE ve AID listesi denendi)' };
    }

    // GET PROCESSING OPTIONS — build PDOL from SELECT AID response (9F38).
    // Contactless cards require a populated PDOL; contact often accepts empty.
    let gpoData = '8300'; // default: empty PDOL template
    let gpoDefs = null;
    const pdol = findTag(sel.tlv.nodes, '9F38');
    if (pdol && pdol.value) {
      const entries = parseDol(pdol.value);
      gpoDefs = term;
      const val = buildDol(entries, gpoDefs);
      const valLen = (val.length / 2).toString(16).padStart(2, '0').toUpperCase();
      gpoData = `83${valLen}${val}`;
    }
    const gpoLc = (gpoData.length / 2).toString(16).padStart(2, '0').toUpperCase();
    const gpo = await step('GET PROCESSING OPTIONS', `80A80000${gpoLc}${gpoData}00`);

    // Parse AIP + AFL from GPO response (format 1 = tag 80, format 2 = tag 77)
    let aip = null, aflHex = null;
    const t80 = findTag(gpo.tlv.nodes, '80');
    if (t80) {
      const v = t80.value.replace(/\s/g, '');
      aip = v.slice(0, 4);
      aflHex = v.slice(4);
    } else {
      const t82 = findTag(gpo.tlv.nodes, '82');
      const t94 = findTag(gpo.tlv.nodes, '94');
      if (t82) aip = t82.value.replace(/\s/g, '');
      if (t94) aflHex = t94.value.replace(/\s/g, '');
    }

    // qVSDC fast-path: Visa (and some Mastercard) contactless return the Application
    // Cryptogram directly in the GPO response (9F26) — there is no separate GENERATE AC.
    let gpoCrypto = null;
    if (findTag(gpo.tlv.nodes, '9F26')) {
      const gg = (t) => { const n = findTag(gpo.tlv.nodes, t); return n ? n.value.replace(/\s/g, '') : null; };
      gpoCrypto = { cid: gg('9F27'), atc: gg('9F36'), arqc: gg('9F26'), iad: gg('9F10') };
    }
    // Signed Dynamic Application Data from the GPO response (Visa qVSDC fDDA / CDA)
    const t9F4Bgpo = findTag(gpo.tlv.nodes, '9F4B');
    const sdadFromGpo = t9F4Bgpo ? t9F4Bgpo.value.replace(/\s/g, '') : null;

    // READ RECORDS per AFL — also build the Static Data to be Authenticated (SDA)
    // from the offline-authentication records (AFL 4th byte) for ODA certificate hashing.
    const records = [];
    const collectedNodes = [];
    let sdaStaticData = '';
    // For SFI 1-10 the SDA input is the tag-'70' VALUE only; for SFI 11-30 the full record.
    const recordSdaInput = (respHex, sfi) => {
      let h = (respHex || '').replace(/\s/g, '').toUpperCase();
      if (h.length >= 4) h = h.slice(0, -4); // strip trailing SW
      if (sfi >= 1 && sfi <= 10 && h.slice(0, 2) === '70') {
        let p = 2; let len = parseInt(h.slice(p, p + 2), 16); p += 2;
        if (len & 0x80) { const n = len & 0x7f; len = parseInt(h.slice(p, p + n * 2), 16); p += n * 2; }
        return h.slice(p, p + len * 2);
      }
      return h;
    };
    if (aflHex) {
      const afl = parseAfl(aflHex);
      for (const e of afl) {
        for (let r = e.firstRecord; r <= e.lastRecord; r++) {
          const p2 = ((e.sfi << 3) | 4).toString(16).padStart(2, '0').toUpperCase();
          const rec = await step(`READ RECORD SFI${e.sfi} #${r}`, `00B2${r.toString(16).padStart(2, '0').toUpperCase()}${p2}00`);
          if (rec.ok && rec.tlv.ok) {
            records.push({ sfi: e.sfi, record: r, nodes: rec.tlv.nodes });
            collectedNodes.push(...rec.tlv.nodes);
            if (r - e.firstRecord < e.offlineRecords) sdaStaticData += recordSdaInput(rec.response, e.sfi);
          }
        }
      }
    }

    // Extract cardholder data from all collected TLVs
    const cardData = {};
    const t57 = findTag(collectedNodes, '57');
    if (t57) {
      const tr = parseTrack2(t57.value);
      if (tr) { cardData.pan = tr.pan; cardData.expiry = tr.expiry; cardData.serviceCode = tr.serviceCode; cardData.track2 = t57.value.replace(/\s/g, ''); }
    }
    const t5A = findTag(collectedNodes, '5A');
    if (t5A && !cardData.pan) cardData.pan = t5A.value.replace(/[\sF]/g, '');
    const t5F24 = findTag(collectedNodes, '5F24');
    if (t5F24) cardData.expiry = formatExpiry(t5F24.value);
    const t5F20 = findTag(collectedNodes, '5F20');
    if (t5F20) cardData.cardholderName = hexToAscii(t5F20.value);
    const t5F34 = findTag(collectedNodes, '5F34');
    if (t5F34) cardData.panSequence = t5F34.value.replace(/\s/g, '');

    if (cardData.pan) {
      cardData.panFormatted = cardData.pan.replace(/(.{4})/g, '$1 ').trim();
      cardData.scheme = detectScheme(cardData.pan);
      cardData.luhnValid = luhnCheck(cardData.pan);
    }

    // Application Cryptogram — from the GPO response (qVSDC) or via GENERATE AC (CDOL1).
    let genac = null;
    // Key selection: an explicit pick verifies with that one key only; "auto" (no pick)
    // tries the PAN-matched key first and then every other configured key set, so a card
    // whose key isn't PAN-bound (e.g. the Amex set) still verifies — like Collis/UL.
    const explicit = body?.keyLabel != null && body.keyLabel !== '';
    let keyList;
    if (explicit) {
      const ks = findExact(body.keyLabel, body.keyPan);
      keyList = ks ? [ks] : [];
    } else {
      const primary = cardData.pan ? findForPan(cardData.pan) : null;
      const rest = listKeys().filter((k) => k !== primary);
      keyList = [primary, ...rest].filter(Boolean);
    }
    // Run ARQC verification for a parsed cryptogram object using the terminal data (defs)
    // that produced it (PDOL data for qVSDC, CDOL1 data for GENERATE AC).
    // Kartın PAN'ına gerçekten bağlı (varsayılan/wildcard değil) bir anahtar var mı?
    // Bu bayrak, ARQC uyuşmazlığının "gerçek kripto hatası" mı yoksa "doğru issuer
    // anahtarı yüklü değil → doğrulanamadı" mı olduğunu ayırt etmek için raporlanır.
    const cleanPan = (x) => String(x || '').replace(/\D/g, '');
    const isPanKey = (k) => !!(k.pan && cleanPan(k.pan) === cleanPan(cardData.pan));
    const runVerify = (g, defs, cdolData) => {
      if (!g.arqc) return;
      if (!keyList.length) { g.verify = { noKey: true }; return; }
      const base = defs['9F02'] + defs['9F03'] + defs['9F1A'] + defs['95'] + defs['5F2A'] +
        defs['9A'] + defs['9C'] + defs['9F37'];
      let firstResult = null;
      for (const k of keyList) {
        try {
          const r = verifyArqcAuto({ acKey: k.acKey, keyLevel: k.keyLevel,
            pan: cardData.pan, psn: cardData.panSequence || k.psn, atc: g.atc, un: defs['9F37'],
            base, cdol: cdolData || '', aip: aip || '', iad: g.iad || '', cardArqc: g.arqc, aid,
            amount: defs['9F02'], currency: defs['5F2A'] });
          if (r.match) { g.verify = { ...r, keyLabel: k.label, keyPanMatch: isPanKey(k) }; return; }
          if (!firstResult) firstResult = { ...r, keyLabel: k.label };
        } catch (e) { if (!firstResult) firstResult = { error: e.message, keyLabel: k.label }; }
      }
      // Hiç eşleşme yok: karta PAN-bağlı anahtar denendiyse gerçek uyuşmazlık,
      // aksi halde (yalnızca varsayılan anahtarlar) "doğrulanamadı".
      g.verify = { ...firstResult, keyPanMatch: keyList.some(isPanKey) };
    };

    // ── ODA certificate chain (Issuer PK → ICC PK) — recovered BEFORE the cryptogram so the
    // ICC PK is available to recover the AC from a CDA Signed Dynamic Application Data (9F4B).
    let oda = null;       // full ODA result (chain + dynamic signature)
    let odaIccPK = null;  // recovered ICC public key, used for CDA AC recovery
    try {
      const gt = (t) => { const n = findTag(collectedNodes, t); return n ? n.value.replace(/\s/g, '') : null; };
      const cert90 = gt('90'), cert9F46 = gt('9F46');
      const idxNode = findTag(collectedNodes, '8F');
      const capkIndex = idxNode ? idxNode.value.replace(/\s/g, '') : null;
      const rid = aid ? aid.slice(0, 10) : null;
      if (cert90 && cert9F46 && capkIndex && rid) {
        const capk = findKey(rid, capkIndex);
        oda = { rid, capkIndex, capkFound: !!capk };
        if (capk) {
          let staticData = sdaStaticData;
          const t9F4A = findTag(collectedNodes, '9F4A');
          if (t9F4A && t9F4A.value.replace(/\s/g, '').toUpperCase().includes('82') && aip) staticData += aip;
          oda.staticData = staticData.toUpperCase();
          const issuer = recoverIssuerPK({ capk, cert90, remainder92: gt('92'), exp9F32: gt('9F32') });
          oda.issuerPK = { ok: issuer.ok, steps: issuer.steps, recovered: issuer.recovered };
          if (issuer.ok) {
            const icc = recoverIccPK({ issuerPK: issuer.issuerPK, cert9F46, remainder9F48: gt('9F48'),
              exp9F47: gt('9F47'), staticData, pan: cardData.pan });
            oda.iccPK = { ok: icc.ok, steps: icc.steps, recovered: icc.recovered };
            if (icc.ok) odaIccPK = icc.iccPK;
          }
          oda.ok = !!(oda.issuerPK && oda.issuerPK.ok && oda.iccPK && oda.iccPK.ok);
        }
      }
    } catch (e) { oda = { error: e.message }; }

    // Offline dynamic-authentication methods the card advertises in AIP byte 1:
    // bit 6 (0x20) = DDA, bit 1 (0x01) = CDA. A contact card may support BOTH
    // (e.g. AIP 3900) — we then validate EACH: DDA via INTERNAL AUTHENTICATE
    // (done here, before the cryptogram, per EMV Book 3), CDA via GENERATE AC
    // P1=0x90 below. qVSDC/contactless cards (gpoCrypto) don't do INTERNAL
    // AUTHENTICATE, so DDA is skipped there and CDA/fDDA come from GPO.
    const aipByte1 = aip ? parseInt(aip.slice(0, 2), 16) : 0;
    const ddaSupported = !!(aipByte1 & 0x20);
    const cdaSupported = !!(aipByte1 & 0x01);
    let ddaResult = null;
    if (oda && odaIccPK && ddaSupported && !gpoCrypto) {
      try {
        const ddolNode = findTag(collectedNodes, '9F49');
        const defsD = term;
        const ddolEntries = ddolNode && ddolNode.value ? parseDol(ddolNode.value) : [{ tag: '9F37', length: 4 }];
        const dynTermData = buildDol(ddolEntries, defsD);
        const lcia = (dynTermData.length / 2).toString(16).padStart(2, '0').toUpperCase();
        const ia = await step('INTERNAL AUTHENTICATE (DDA)', `00880000${lcia}${dynTermData}00`);
        if (ia.ok) {
          const t80ia = findTag(ia.tlv.nodes, '80');
          const t9F4Bia = findTag(ia.tlv.nodes, '9F4B');
          const sdad = t80ia ? t80ia.value.replace(/\s/g, '') : (t9F4Bia ? t9F4Bia.value.replace(/\s/g, '') : null);
          if (sdad) {
            const sig = verifySDAD({ iccPK: odaIccPK, sdad, terminalData: dynTermData, kind: 'DDA' });
            ddaResult = { kind: 'DDA', ok: sig.ok, structOk: sig.structOk, hashMatch: sig.hashMatch, steps: sig.steps, iccDynNumber: sig.iccDynNumber, recovered: sig.recovered };
          }
        } else { ddaResult = { kind: 'DDA', ok: false, error: `INTERNAL AUTHENTICATE SW ${ia.sw}` }; }
      } catch (e) { ddaResult = { kind: 'DDA', ok: false, error: e.message }; }
    }

    if (gpoCrypto && gpoCrypto.arqc) {
      // qVSDC: the cryptogram is already in the GPO response (no GENERATE AC sent)
      genac = { ...gpoCrypto, source: 'GPO (qVSDC)' };
      runVerify(genac, gpoDefs || term, null);
    } else {
      const t8C = findTag(collectedNodes, '8C');
      if (t8C && t8C.value) {
        const defs = term;
        const cdolData = buildDol(parseDol(t8C.value), defs);
        const lc = (cdolData.length / 2).toString(16).padStart(2, '0').toUpperCase();
        // Request CDA (P1 bit 0x10) when the card supports it (AIP byte 1 bit 1) and we
        // recovered the ICC PK — the AC then comes back inside the SDAD (9F4B), not 9F26.
        // Cryptogram type the terminal requests (scenario-driven): ARQC (online),
        // TC (offline approve) or AAC (decline). CDA (bit 0x10) only with TC/ARQC.
        const reqAc = String(body.requestAc || 'ARQC').toUpperCase();
        const acBase = reqAc === 'TC' ? 0x40 : reqAc === 'AAC' ? 0x00 : 0x80;
        const cdaWanted = !!(cdaSupported && odaIccPK) && reqAc !== 'AAC';
        const p1 = (acBase | (cdaWanted ? 0x10 : 0)).toString(16).padStart(2, '0').toUpperCase();
        const ac = await step(`GENERATE AC (istenen ${reqAc}${cdaWanted ? '+CDA' : ''})`, `80AE${p1}00${lc}${cdolData}00`);
        if (ac.ok) {
          let cid, atcv, arqc, iad, sdad = null;
          const t80ac = findTag(ac.tlv.nodes, '80');
          if (t80ac) {
            const v = t80ac.value.replace(/\s/g, '');
            cid = v.slice(0, 2); atcv = v.slice(2, 6); arqc = v.slice(6, 22); iad = v.slice(22);
          } else {
            const g = (t) => { const n = findTag(ac.tlv.nodes, t); return n ? n.value.replace(/\s/g, '') : null; };
            cid = g('9F27'); atcv = g('9F36'); arqc = g('9F26'); iad = g('9F10'); sdad = g('9F4B');
          }
          // CDA: recover the AC from the SDAD with the ICC PK (no plain 9F26 present)
          let cdaSig = null;
          if (!arqc && sdad && odaIccPK) {
            cdaSig = verifySDAD({ iccPK: odaIccPK, sdad, transactionData: defs['9F37'], kind: 'CDA' });
            if (cdaSig.cid) cid = cdaSig.cid;
            if (cdaSig.ac) arqc = cdaSig.ac;
          }
          genac = { cid, atc: atcv, arqc, iad, sdad, source: cdaWanted ? 'GENERATE AC (CDA)' : 'GENERATE AC', cdaSig };
          runVerify(genac, defs, cdolData);
        } else {
          genac = { error: `GENERATE AC başarısız (SW ${ac.sw})` };
        }
      }
    }

    // ── ODA dynamic signature(s). A card can validate more than one method
    // (AIP 3900 = DDA+CDA on contact) — collect EVERY one performed into
    // oda.dynamics. DDA was run before the cryptogram (ddaResult); CDA comes from
    // the GENERATE AC SDAD; fDDA from the GPO SDAD (contactless). oda.dynamic
    // stays the primary (CDA preferred) for callers expecting a single result.
    try {
      if (oda && odaIccPK) {
        oda.dynamics = [];
        if (ddaResult) oda.dynamics.push(ddaResult);
        if (genac && genac.cdaSig) {
          const s = genac.cdaSig;
          oda.dynamics.push({ kind: 'CDA', ok: s.ok, structOk: s.structOk, hashMatch: s.hashMatch, steps: s.steps, iccDynNumber: s.iccDynNumber, ac: s.ac, recovered: s.recovered });
        }
        if (sdadFromGpo) {
          // fDDA — terminal DD-input differs by scheme: Troy D-PAS → UN only;
          // Visa qVSDC → UN | Amount | Currency | Card Auth Related Data (9F69).
          // Try each and keep the one whose hash matches.
          const defs = gpoDefs || term;
          const n9F69 = findTag(gpo.tlv.nodes, '9F69') || findTag(collectedNodes, '9F69');
          const card9F69 = n9F69 ? n9F69.value.replace(/\s/g, '') : '';
          const un = defs['9F37'] || '';
          const ddCandidates = [un, un + (defs['9F02'] || '') + (defs['5F2A'] || '') + card9F69];
          let sig = null;
          for (const dd of ddCandidates) {
            const s = verifySDAD({ iccPK: odaIccPK, sdad: sdadFromGpo, transactionData: dd, kind: 'fDDA' });
            if (!sig) sig = s;
            if (s.hashMatch) { sig = s; break; }
          }
          oda.dynamics.push({ kind: 'fDDA', ok: sig.ok, structOk: sig.structOk, hashMatch: sig.hashMatch, steps: sig.steps, iccDynNumber: sig.iccDynNumber, recovered: sig.recovered, cardAuthData: card9F69 });
        }
        oda.dynamic = oda.dynamics.find((d) => d.kind === 'CDA') || oda.dynamics[0] || null;
      }
      // Nothing performed → explain why (qVSDC/D-PAS online path, or no INTERNAL AUTH).
      if (oda && oda.capkFound && (!oda.dynamics || !oda.dynamics.length)) {
        oda.dynamic = { kind: 'none', ok: null, notApplicable: true,
          note: gpoCrypto
            ? 'Kart bu online qVSDC/D-PAS işleminde dinamik imza (SDAD) sunmadı — offline data authentication yapılmaz; kart kimliği online ARQC + sertifika zinciriyle doğrulanır.'
            : 'Dinamik imza alınamadı — kart SDAD (9F4B) ve INTERNAL AUTHENTICATE sunmuyor. Sertifika zinciri geçerli.' };
        oda.dynamics = [oda.dynamic];
      }
    } catch (e) { if (oda) oda.dynamicError = e.message; }

    // Card decision from the Cryptogram Information Data (9F27) top 2 bits:
    // 00=AAC (decline), 01xxxxxx=TC (offline approve), 10xxxxxx=ARQC (online).
    if (genac && genac.cid) {
      const t = parseInt(genac.cid.slice(0, 2), 16) & 0xC0;
      genac.decision = t === 0x40 ? 'TC' : t === 0x80 ? 'ARQC' : t === 0x00 ? 'AAC' : 'RFU';
    }

    const totalMs = steps.reduce((a, s) => a + (s.durationMs || 0), 0);

    // Bit-level analysis of capabilities
    const analysis = {};
    if (aip) analysis.aip = decodeAip(aip);
    const t8E = findTag(collectedNodes, '8E');
    if (t8E) analysis.cvm = decodeCvmList(t8E.value);
    if (cardData.serviceCode) analysis.serviceCode = decodeServiceCode(cardData.serviceCode);

    // Usage control + issuer locale (contactless-relevant "nerede/nasıl kullanılır")
    const t9F07 = findTag(collectedNodes, '9F07');
    if (t9F07) analysis.usageControl = decodeAuc(t9F07.value);
    const t5F28 = findTag(collectedNodes, '5F28');
    if (t5F28) analysis.issuerCountry = countryName(t5F28.value);
    const t9F42 = findTag(collectedNodes, '9F42');
    if (t9F42) analysis.currency = currencyName(t9F42.value);

    // Match the card's CA Public Key: RID (first 5 bytes of AID) + index (tag 8F)
    let capk = null;
    const t8F = findTag(collectedNodes, '8F');
    const ridFromAid = aid ? aid.slice(0, 10) : null;
    if (ridFromAid && t8F) {
      const key = findKey(ridFromAid, t8F.value.replace(/\s/g, ''));
      if (key) capk = { rid: key.rid, index: key.index, scheme: key.scheme, keyLength: key.keyLength, hash: key.hash, found: true };
      else capk = { rid: ridFromAid, index: t8F.value.replace(/\s/g, ''), found: false };
    }

    return { steps, mode, applications, aip, afl: aflHex, records, cardData, analysis, totalMs, capk, genac, oda };
  } catch (err) {
    return { __status: 500, steps, mode, error: err.message };
  }
}

// POST /api/emv/read — HTTP wrapper around runEmvFlow.
export async function runEmvRead(req, res) {
  const result = await runEmvFlow(req.body?.reader || undefined, req.body || {});
  if (result && result.__status) { const { __status, ...rest } = result; return res.status(__status).json(rest); }
  res.json(result);
}
