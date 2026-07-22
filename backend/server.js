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
import { computeArpc, computeArpcMethod2, deriveIccMasterKey } from './crypto3des.js';
import { listKeysMasked, addKeySet, updateKeySet, deleteKeySet, getKeySet, findExact } from './sessionkeys.js';
import { buildPinChange, buildUnblockVariants, buildVerifyPlaintext } from './changepin.js';
import { discoverCardContext } from './carddiscover.js';
import { extractCardImage } from './cardimage.js';
import { runCompliance } from './compliance.js';
import { parseProfilePdf } from './pdfprofile.js';
import { listSessions, saveSession, loadSession, deleteSession } from './sessions.js';
import { recordAndDiff, listCards, cardHistory, clearHistory } from './history.js';

const app = express();
const PORT = 3001;

app.use(cors());
// Oturum snapshot'ları (kart image + PDF + trace) büyük olabilir → varsayılan 100kb yetmez.
app.use(express.json({ limit: '25mb' }));

// ── Card / reader ───────────────────────────────────────────────────

// GET /api/readers — list connected readers + per-reader card status
app.get('/api/readers', (req, res) => {
  const readers = pcsc.available ? pcsc.listReaders() : [];
  res.json({
    readers,
    count: readers.length,
    status: pcsc.available ? pcsc.getReaderStatus() : [],
    mode: 'real',
    pcscAvailable: pcsc.available,
  });
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
  if (!ks) return res.status(400).json({ error: 'Anahtar seti bulunamadı — İşlem Anahtarları sekmesinden ekleyin/seçin' });
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
