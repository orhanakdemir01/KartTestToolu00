// Card image extraction — dumps every personalised EMV data element from the
// card for Mastercard CPV / Visa VPA style perso validation. For each payment
// application it selects the AID, runs GPO, reads the records the AFL (tag 94)
// declares — so a dual-interface card yields ONLY the tapped interface's data,
// not the other interface's — and sweeps GET DATA for the primitive objects a
// card exposes. All TLV leaves are flattened, named and (where known) decoded.
// (No AFL, or opts.deepScan, falls back to a full SFI/record brute-force.)
import pcsc from './pcsc.js';
import {
  findTag, findAllTags, parseAfl, parseDol, buildDol, describeSw, lookupTag,
  hexToAscii, decodeAip,
} from './emv.js';
import { usingRealReader, transmitChain, tlvFromResponse } from './apdu.js';
import { CANDIDATE_AIDS, terminalDefaults } from './terminal.js';

const clean = (s) => (s || '').replace(/\s/g, '').toUpperCase();
const toLen = (h) => (h.length / 2).toString(16).padStart(2, '0').toUpperCase();

// Primitive data objects to try via GET DATA (only 9000 answers are kept). A
// full perso image needs far more than FCI/GPO/records: cards expose issuer
// proprietary elements (C/D series — CIAC, counters, limits) and kernel/issuer
// config (DF series) only through GET DATA. Card-specific tags that the card
// does not support simply answer non-9000 and are skipped.
const GET_DATA_SWEEP = [
  // Standard EMV counters / limits / qVSDC / CPLC
  '9F36', '9F13', '9F17', '9F4F', '9F4D', '9F5C', '9F50', '9F51', '9F52', '9F53',
  '9F54', '9F55', '9F56', '9F57', '9F58', '9F59', '9F5B', '9F5D', '9F72', '9F73',
  '9F74', '9F75', '9F77', '9F78', '9F79', '9F6C', '9F6D', '9F6E', '9F71', '9F7F',
  '9F0A', '9F42', '9F45', '9F49', '9F5A', '9F6F', '9F70', '9F14', '9F23', '9F7E',
  // Issuer proprietary (C/D series — CIAC, ATC limits, control params, currency
  // conversion tables). Full C0-DF single-byte range so nothing readable is missed.
  'C0', 'C1', 'C2', 'C3', 'C4', 'C5', 'C6', 'C7', 'C8', 'C9', 'CA', 'CB', 'CC', 'CD', 'CE', 'CF',
  'D0', 'D1', 'D2', 'D3', 'D4', 'D5', 'D6', 'D7', 'D8', 'D9', 'DA', 'DB', 'DC', 'DD', 'DE',
  // Issuer / kernel config (DF series)
  'DF02', 'DF11', 'DF12', 'DF14', 'DF15', 'DF16', 'DF17', 'DF18', 'DF19', 'DF1A',
  'DF1B', 'DF1D', 'DF1E', 'DF1F', 'DF21', 'DF22', 'DF23', 'DF24', 'DF25', 'DF26',
  'DF27', 'DF28', 'DF29', 'DF2A', 'DF2B', 'DF2C', 'DF2D', 'DF2E', 'DF2F', 'DF30',
  'DF31', 'DF32', 'DF33', 'DF34', 'DF35', 'DF36', 'DF37', 'DF38', 'DF39', 'DF3A',
  'DF3B', 'DF3C', 'DF3D', 'DF3E', 'DF3F', 'DF40', 'DF60', 'DF61',
  // Constructed proprietary template
  'BF0C',
];

// Card Production Life Cycle (CPLC, tag 9F7F) — 42-byte perso fingerprint.
export function decodeCplc(hex) {
  const h = clean(hex);
  if (h.length < 84) return null;
  const at = (o, n) => h.slice(o * 2, o * 2 + n * 2);
  return {
    icFabricator: at(0, 2), icType: at(2, 2), osId: at(4, 2), osReleaseDate: at(6, 2),
    osReleaseLevel: at(8, 2), icFabricationDate: at(10, 2), icSerialNumber: at(12, 4),
    icBatchId: at(16, 2), icModuleFabricator: at(18, 2), icModulePackagingDate: at(20, 2),
    iccManufacturer: at(22, 2), icEmbeddingDate: at(24, 2), icPrePersonalizer: at(26, 2),
    icPrePersoDate: at(28, 2), icPrePersoEquipId: at(30, 4), icPersonalizer: at(34, 2),
    icPersonalizationDate: at(36, 2), icPersoEquipId: at(38, 4),
  };
}

export async function extractCardImage(preferReader, opts = {}) {
  const steps = [];
  const step = async (name, cmd) => {
    const c = clean(cmd);
    const { response, sw } = await transmitChain(c, preferReader);
    const tlv = tlvFromResponse(response);
    steps.push({ name, command: c, response, sw, swText: describeSw(sw), ok: sw === '9000', tlv });
    return { response, sw, ok: sw === '9000', tlv };
  };

  // Flatten TLV nodes to primitive leaves (the actual perso data elements).
  const flatten = (nodes, source, out) => {
    for (const n of (nodes || [])) {
      if (n.children && n.children.length) { flatten(n.children, source, out); continue; }
      out.push({
        tag: n.tag, name: n.name || lookupTag(n.tag) || null,
        value: clean(n.value), length: n.length,
        ascii: n.ascii || null, decoded: n.decoded || null, source,
      });
    }
  };

  // Application discovery (PPSE 2PAY, PSE 1PAY, then candidate AIDs).
  const collectApps = (nodes, src) => {
    const apps = [];
    for (const t of findAllTags(nodes, '61')) {
      const a = findTag([t], '4F'); const l = findTag([t], '50');
      if (a) apps.push({ aid: clean(a.value), label: l ? hexToAscii(l.value) : null, source: src });
    }
    return apps;
  };
  const found = [];
  const ppse = await step('SELECT PPSE (2PAY)', '00A404000E325041592E5359532E444446303100');
  if (ppse.ok) found.push(...collectApps(ppse.tlv.nodes, 'PPSE'));
  const pse = await step('SELECT PSE (1PAY)', '00A404000E315041592E5359532E444446303100');
  if (pse.ok) {
    found.push(...collectApps(pse.tlv.nodes, 'PSE'));
    const sfiN = findTag(pse.tlv.nodes, '88');
    if (sfiN) {
      const sfi = parseInt(clean(sfiN.value), 16);
      const p2 = ((sfi << 3) | 4).toString(16).padStart(2, '0').toUpperCase();
      for (let r = 1; r <= 10; r++) {
        const d = await step(`READ DIR SFI${sfi} #${r}`, `00B2${r.toString(16).padStart(2, '0').toUpperCase()}${p2}00`);
        if (!d.ok) break;
        found.push(...collectApps(d.tlv.nodes, 'PSE-DIR'));
      }
    }
  }
  // De-dup AIDs; fall back to candidate list if PPSE/PSE found nothing.
  let aidList = [...new Map(found.map((a) => [a.aid, a])).values()];
  if (!aidList.length) {
    for (const [name, cand] of CANDIDATE_AIDS) {
      const s = await step(`AID dene: ${name}`, `00A40400${toLen(cand)}${cand}00`);
      if (s.ok) aidList.push({ aid: clean(cand), label: name, source: 'candidate' });
    }
  }

  const applications = [];
  for (const app of aidList) {
    const sel = await step(`SELECT AID (${app.label || app.aid})`, `00A40400${toLen(app.aid)}${app.aid}00`);
    if (!sel.ok) continue;
    const appLeaves = [];
    flatten(sel.tlv.nodes, 'FCI', appLeaves);

    // GET PROCESSING OPTIONS (populate PDOL from 9F38 if present).
    let gpoData = '8300';
    const pdol = findTag(sel.tlv.nodes, '9F38');
    if (pdol && pdol.value) {
      const val = buildDol(parseDol(pdol.value), terminalDefaults());
      gpoData = `83${toLen(val)}${val}`;
    }
    const gpo = await step('GET PROCESSING OPTIONS', `80A80000${toLen(gpoData)}${gpoData}00`);
    let aip = null, afl = null;
    const t80 = findTag(gpo.tlv.nodes, '80');
    if (t80) { const v = clean(t80.value); aip = v.slice(0, 4); afl = v.slice(4); }
    else { aip = clean(findTag(gpo.tlv.nodes, '82')?.value || ''); afl = clean(findTag(gpo.tlv.nodes, '94')?.value || ''); }
    if (gpo.ok) flatten(gpo.tlv.nodes, 'GPO', appLeaves);

    // READ RECORDS — follow the AFL (tag 94) so ONLY this interface's records are
    // read. A dual-interface card returns a different AFL over contact vs
    // contactless; brute-forcing every SFI would pull in the other interface's
    // (and qVSDC-only) records and contaminate the image. If the card returned no
    // AFL we fall back to a bounded brute-force; opts.deepScan forces the sweep.
    const records = [];
    const readRec = async (sfi, rec) => {
      const p2 = ((sfi << 3) | 4).toString(16).padStart(2, '0').toUpperCase();
      const r = await step(`READ RECORD SFI${sfi} #${rec}`, `00B2${rec.toString(16).padStart(2, '0').toUpperCase()}${p2}00`);
      if (!r.ok) return false;
      const leaves = [];
      flatten(r.tlv.nodes, `SFI${sfi} #${rec}`, leaves);
      records.push({ sfi, record: rec, tags: leaves, raw: clean(r.response).slice(0, -4), nodes: r.tlv.nodes });
      appLeaves.push(...leaves);
      return true;
    };
    const aflEntries = afl ? parseAfl(afl) : [];
    if (aflEntries.length && !opts.deepScan) {
      // Canonical EMV: read exactly the SFI/record ranges the AFL declares.
      for (const e of aflEntries) {
        for (let rec = e.firstRecord; rec <= e.lastRecord; rec++) await readRec(e.sfi, rec);
      }
    } else {
      // No AFL (or deepScan) — brute-force every SFI/record until end-of-SFI.
      const maxSfi = opts.maxSfi || 31;
      for (let sfi = 1; sfi <= maxSfi; sfi++) {
        for (let rec = 1; rec <= 16; rec++) { if (!(await readRec(sfi, rec))) break; }
      }
    }

    // GET DATA sweep. P1-P2 hold the tag; a single-byte proprietary tag (Cx/Dx)
    // must be coded as P1='00', P2=tag (e.g. C3 → 80 CA 00 C3 00), NOT 80 CA C3
    // 00 — the latter answers 6A88. Two-byte tags (9Fxx/DFxx) go in P1-P2 as-is.
    const getData = [];
    for (const tag of GET_DATA_SWEEP) {
      const p1p2 = tag.length === 2 ? `00${tag}` : tag;
      const g = await step(`GET DATA ${tag}`, `80CA${p1p2}00`);
      if (!g.ok) continue;
      const node = findTag(g.tlv.nodes, tag) || (g.tlv.nodes || [])[0];
      const value = clean(node?.value || clean(g.response).slice(4, -4));
      if (!value) continue;
      const entry = { tag, name: lookupTag(tag) || node?.name || null, value, decoded: node?.decoded || null, source: 'GET DATA' };
      getData.push(entry);
      appLeaves.push({ ...entry, length: value.length / 2, ascii: node?.ascii || null });
    }

    // Per-app unique tag list (keep every distinct tag+value pair, note sources).
    const uniq = new Map();
    for (const l of appLeaves) {
      const k = `${l.tag}:${l.value}`;
      if (uniq.has(k)) { uniq.get(k).sources.push(l.source); }
      else uniq.set(k, { tag: l.tag, name: l.name, value: l.value, length: l.length ?? (l.value ? l.value.length / 2 : 0), ascii: l.ascii, decoded: l.decoded, sources: [l.source] });
    }
    const rid = app.aid.slice(0, 10);
    const scheme = rid === 'A000000003' ? 'Visa' : rid === 'A000000004' ? 'Mastercard'
      : rid === 'A000000025' ? 'Amex' : rid === 'A000000672' ? 'Troy'
      : (rid === 'A000000152' || rid === 'A000000324') ? 'Discover' : null;
    const cplcNode = getData.find((g) => g.tag === '9F7F');
    applications.push({
      aid: app.aid, label: app.label, source: app.source, scheme, rid,
      aip, aipDecoded: aip ? decodeAip(aip) : null, afl,
      records, getData, tags: [...uniq.values()],
      cplc: cplcNode ? decodeCplc(cplcNode.value) : null,
      recordCount: records.length, tagCount: uniq.size,
    });
  }

  // Card-wide unique tag list.
  const cardUniq = new Map();
  for (const a of applications) for (const t of a.tags) {
    const k = `${a.aid}:${t.tag}:${t.value}`;
    if (!cardUniq.has(k)) cardUniq.set(k, { ...t, aid: a.aid });
  }

  return {
    applications, allTags: [...cardUniq.values()], steps,
    appCount: applications.length,
    totalRecords: applications.reduce((n, a) => n + a.recordCount, 0),
    totalTags: applications.reduce((n, a) => n + a.tagCount, 0),
  };
}
