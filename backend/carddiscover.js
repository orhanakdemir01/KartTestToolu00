// Minimal EMV discovery for issuer scripts: auto-read the AID, PAN, PAN
// sequence number and current ATC from the card so the caller only supplies
// the key set. A lighter sibling of emvflow.js (no ODA / cryptogram verify).
import pcsc from './pcsc.js';
import { findTag, findAllTags, parseAfl, parseTrack2, hexToAscii, parseDol, buildDol, describeSw } from './emv.js';
import { usingRealReader, transmitChain, tlvFromResponse } from './apdu.js';
import { terminalDefaults, CANDIDATE_AIDS } from './terminal.js';

const toLen = (h) => (h.length / 2).toString(16).padStart(2, '0').toUpperCase();

export async function discoverCardContext(preferReader, opts = {}) {
  const steps = [];
  const step = async (name, cmd) => {
    const clean = cmd.replace(/\s/g, '').toUpperCase();
    const { response, sw } = await transmitChain(clean, preferReader);
    const tlv = tlvFromResponse(response);
    const s = { name, command: clean, response, sw, swText: describeSw(sw), ok: sw === '9000', tlv };
    steps.push(s);
    return s;
  };
  const collectApps = (nodes, source) => {
    const apps = [];
    for (const t of findAllTags(nodes, '61')) {
      const a = findTag([t], '4F'); const l = findTag([t], '50');
      if (a) apps.push({ aid: a.value.replace(/\s/g, ''), label: l ? hexToAscii(l.value) : null, source });
    }
    return apps;
  };
  const selectPpse = async () => {
    const r = await step('SELECT PPSE (2PAY)', '00A404000E325041592E5359532E444446303100');
    return r.ok ? collectApps(r.tlv.nodes, 'PPSE') : [];
  };
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
          if (!dir.ok) break;
          apps.push(...collectApps(dir.tlv.nodes, 'PSE'));
        }
      }
    }
    return apps;
  };

  const activeCard = usingRealReader() ? pcsc.getActiveCard(preferReader) : null;
  const isContactless = !!activeCard?.contactless;

  // Select an application (PPSE/PSE, else candidate AIDs) — same order as emvflow.
  const applications = [];
  for (const discover of (isContactless ? [selectPpse, selectPse] : [selectPse, selectPpse])) {
    if (applications.length) break;
    applications.push(...await discover());
  }
  let aid = null, sel = null, label = null;
  if (applications.length > 0) {
    aid = applications[0].aid; label = applications[0].label;
    sel = await step(`SELECT AID (${label || aid})`, `00A40400${toLen(aid)}${aid}00`);
  } else {
    for (const [name, cand] of CANDIDATE_AIDS) {
      const s = await step(`AID dene: ${name}`, `00A40400${toLen(cand)}${cand}00`);
      if (s.ok) { sel = s; aid = cand; label = name; applications.push({ aid: cand, label: name, source: 'candidate' }); break; }
    }
  }
  if (!sel || !sel.ok || !aid) return { steps, applications, error: 'Kart üzerinde EMV uygulaması bulunamadı (PPSE/PSE/AID denendi)' };

  // GET PROCESSING OPTIONS — populate PDOL (9F38) if present.
  let gpoData = '8300';
  const pdol = findTag(sel.tlv.nodes, '9F38');
  if (pdol && pdol.value) {
    const val = buildDol(parseDol(pdol.value), terminalDefaults());
    gpoData = `83${toLen(val)}${val}`;
  }
  const gpo = await step('GET PROCESSING OPTIONS', `80A80000${toLen(gpoData)}${gpoData}00`);

  // AFL → READ RECORDS (to reach PAN / PSN).
  let aflHex = null;
  const t80 = findTag(gpo.tlv.nodes, '80');
  if (t80) aflHex = t80.value.replace(/\s/g, '').slice(4);
  else { const t94 = findTag(gpo.tlv.nodes, '94'); if (t94) aflHex = t94.value.replace(/\s/g, ''); }

  const collected = [];
  if (aflHex) {
    for (const e of parseAfl(aflHex)) {
      for (let r = e.firstRecord; r <= e.lastRecord; r++) {
        const p2 = ((e.sfi << 3) | 4).toString(16).padStart(2, '0').toUpperCase();
        const rec = await step(`READ RECORD SFI${e.sfi} #${r}`, `00B2${r.toString(16).padStart(2, '0').toUpperCase()}${p2}00`);
        if (rec.ok && rec.tlv.ok) collected.push(...rec.tlv.nodes);
      }
    }
  }

  let pan = null, psn = null;
  const t57 = findTag(collected, '57');
  if (t57) { const tr = parseTrack2(t57.value); if (tr) pan = tr.pan; }
  const t5A = findTag(collected, '5A');
  if (t5A && !pan) pan = t5A.value.replace(/[\sF]/g, '');
  const t5F34 = findTag(collected, '5F34');
  if (t5F34) psn = t5F34.value.replace(/\s/g, '');

  // ATC + ARQC — from the GPO response (qVSDC), else GET DATA 9F36, else GENERATE AC.
  // The ARQC is used as the secure-messaging MAC ICV for the PIN change script.
  // Skipped for read-only flows (e.g. plaintext PIN VERIFY) that only need the
  // selected AID + GPO context, not a cryptogram.
  let atc = findTag(gpo.tlv.nodes, '9F36')?.value.replace(/\s/g, '') || null;
  let arqc = findTag(gpo.tlv.nodes, '9F26')?.value.replace(/\s/g, '') || null;
  let atcSource = atc ? 'GPO' : null;
  if (!opts.skipCrypto && !atc) {
    const g = await step('GET DATA ATC (9F36)', '80CA9F3600');
    atc = g.ok ? (findTag(tlvFromResponse(g.response).nodes, '9F36')?.value || null) : null;
    if (atc) atcSource = 'GET DATA';
  }
  if (!opts.skipCrypto && (!atc || !arqc)) {
    // Contact M/Chip cards expose the ATC/ARQC only through a cryptogram. Do a
    // GENERATE AC (ARQC) with CDOL1 — this also mirrors the real issuer-script
    // flow, where the script follows a GENERATE AC in the same transaction and
    // the card derives the SM session key from that transaction's ATC.
    const t8C = findTag(collected, '8C');
    if (t8C && t8C.value) {
      const cdolData = buildDol(parseDol(t8C.value), terminalDefaults());
      // Troy D-PAS keys its PIN-change secure messaging off an AAC (P1=00,
      // offline decline) — an online ARQC (P1=80) leaves the card expecting
      // issuer authentication and the script is refused (6985). Its ATC comes
      // from that GENERATE AC, so prefer it over the GET DATA value.
      const isTroy = (aid || '').slice(0, 10) === 'A000000672';
      const genP1 = isTroy ? '00' : '80';
      const ac = await step(`GENERATE AC (${isTroy ? 'AAC' : 'ARQC'})`, `80AE${genP1}00${toLen(cdolData)}${cdolData}00`);
      if (ac.ok) {
        const t80ac = findTag(ac.tlv.nodes, '80');
        if (t80ac) {
          const v = t80ac.value.replace(/\s/g, '');
          atc = isTroy ? v.slice(2, 6) : (atc || v.slice(2, 6));
          arqc = arqc || v.slice(6, 22);
        } else {
          const gacAtc = findTag(ac.tlv.nodes, '9F36')?.value.replace(/\s/g, '') || null;
          atc = isTroy ? (gacAtc || atc) : (atc || gacAtc);
          arqc = arqc || (findTag(ac.tlv.nodes, '9F26')?.value.replace(/\s/g, '') || null);
        }
        if (!atcSource && atc) atcSource = 'GENERATE AC';
      }
    }
  }

  // Unpredictable Number used in the GENERATE AC (needed for M/Chip UN-based
  // session-key derivation in the PIN script secure messaging).
  const un = terminalDefaults()['9F37'] || '';
  // CDOL2 (tag 8D) — for the 2nd GENERATE AC in the Visa issuer-authentication flow.
  const cdol2 = findTag(collected, '8D')?.value.replace(/\s/g, '') || '';
  return { steps, applications, aid, label, pan, psn, atc, arqc, un, cdol2, atcSource, aidSelected: true };
}
