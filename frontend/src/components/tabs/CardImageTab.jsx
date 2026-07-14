// "Kart Image" tab: extracts every personalised EMV tag from the card (FCI, GPO,
// all records brute-forced across SFIs, and a GET DATA sweep) for Mastercard CPV
// / Visa VPA perso validation. Presents a flat named+decoded tag list per
// application plus CPLC, with JSON / TLV / text export, plus an expected-perso-
// profile comparison (expected vs actual diff).
import { useState } from 'react';
import { looksTextual } from '../TlvTree.jsx';
import { tlvTreeHtml, TLV_CSS } from '../../lib/report.js';

// Parse an expected perso profile: JSON object {tag:value} or lines "TAG VALUE"
// / "TAG=VALUE" / "TAG: VAL UE" (# comments ignored). Values are hex.
function parseProfile(text) {
  const t = (text || '').trim();
  if (!t) return { map: {}, bad: [] };
  if (t.startsWith('{')) {
    try {
      const o = JSON.parse(t); const map = {};
      for (const k in o) map[k.toUpperCase().replace(/\s/g, '')] = String(o[k]).toUpperCase().replace(/\s/g, '');
      return { map, bad: [] };
    } catch (e) { return { map: {}, bad: [], error: 'JSON hatası: ' + e.message }; }
  }
  const map = {}; const bad = [];
  for (let line of t.split(/\r?\n/)) {
    line = line.replace(/#.*$/, '').trim();
    if (!line) continue;
    const m = line.match(/^([0-9A-Fa-f]{2,8})[\s=:]+([0-9A-Fa-f][0-9A-Fa-f\s]*)$/);
    if (m) map[m[1].toUpperCase()] = m[2].toUpperCase().replace(/\s/g, '');
    else bad.push(line);
  }
  return { map, bad };
}

function compareProfile(text, applications) {
  const { map, bad, error } = parseProfile(text);
  if (error) return { error };
  // Card tags: tag -> [{value, sources, name}] across all applications.
  const cardTags = {};
  const nameOf = {};
  for (const a of applications || []) for (const t of a.tags) {
    (cardTags[t.tag] = cardTags[t.tag] || []).push({ value: t.value, sources: t.sources });
    if (t.name) nameOf[t.tag] = t.name;
  }
  const rows = [];
  for (const [tag, exp] of Object.entries(map)) {
    const occ = cardTags[tag];
    if (!occ) rows.push({ tag, name: nameOf[tag], expected: exp, status: 'missing' });
    else if (occ.some((o) => o.value === exp)) rows.push({ tag, name: nameOf[tag], expected: exp, actual: exp, status: 'match', sources: occ.find((o) => o.value === exp).sources });
    else rows.push({ tag, name: nameOf[tag], expected: exp, actual: occ.map((o) => o.value).join('  |  '), status: 'mismatch' });
  }
  const extras = [];
  for (const tag in cardTags) if (!(tag in map)) for (const o of cardTags[tag]) extras.push({ tag, name: nameOf[tag], actual: o.value, status: 'extra', sources: o.sources });
  const c = { match: 0, mismatch: 0, missing: 0 };
  for (const r of rows) c[r.status]++;
  return { rows, extras, counts: { ...c, extra: extras.length }, bad };
}

const STATUS = { match: { icon: '✓', cls: 'st-ok', label: 'Eşleşti' }, mismatch: { icon: '✗', cls: 'st-bad', label: 'Uyuşmadı' }, missing: { icon: '⚠', cls: 'st-warn', label: 'Eksik' }, extra: { icon: 'ℹ', cls: 'st-extra', label: 'Fazla' } };

// Card-to-card diff: build tag → {values, name} per card and compare value sets.
function diffCards(a, b) {
  const mapOf = (img) => {
    const m = {};
    for (const app of img?.applications || []) for (const t of app.tags) {
      if (!m[t.tag]) m[t.tag] = { vals: new Set(), name: t.name };
      m[t.tag].vals.add(t.value);
      if (t.name && !m[t.tag].name) m[t.tag].name = t.name;
    }
    return m;
  };
  const ma = mapOf(a), mb = mapOf(b);
  const tags = [...new Set([...Object.keys(ma), ...Object.keys(mb)])].sort();
  const rows = [];
  for (const tag of tags) {
    const va = ma[tag] ? [...ma[tag].vals].sort() : null;
    const vb = mb[tag] ? [...mb[tag].vals].sort() : null;
    const name = ma[tag]?.name || mb[tag]?.name || null;
    const status = va && vb ? (va.join('|') === vb.join('|') ? 'same' : 'diff') : va ? 'onlyA' : 'onlyB';
    rows.push({ tag, name, a: va ? va.join('  |  ') : null, b: vb ? vb.join('  |  ') : null, status });
  }
  const counts = { same: 0, diff: 0, onlyA: 0, onlyB: 0 };
  for (const r of rows) counts[r.status]++;
  return { rows, counts };
}

const CARD_STATUS = { same: { icon: '✓', cls: 'st-ok', label: 'Aynı' }, diff: { icon: '✗', cls: 'st-bad', label: 'Farklı' }, onlyA: { icon: '◑', cls: 'st-warn', label: 'Sadece A' }, onlyB: { icon: '◐', cls: 'st-extra', label: 'Sadece B' } };
const cardTip = (img) => img ? `${img.applications?.[0]?.scheme || '?'} · ${img.applications?.[0]?.aid?.slice(0, 14) || ''} · ${img.totalTags} tag` : 'yok';
const CPLC_FIELDS = [
  ['icFabricator', 'IC Fabricator'], ['icType', 'IC Type'], ['osId', 'OS ID'],
  ['osReleaseDate', 'OS Release Date'], ['osReleaseLevel', 'OS Release Level'],
  ['icFabricationDate', 'IC Fabrication Date'], ['icSerialNumber', 'IC Serial Number'],
  ['icBatchId', 'IC Batch ID'], ['icModuleFabricator', 'Module Fabricator'],
  ['icModulePackagingDate', 'Module Packaging Date'], ['iccManufacturer', 'ICC Manufacturer'],
  ['icEmbeddingDate', 'Embedding Date'], ['icPrePersonalizer', 'Pre-Personalizer'],
  ['icPrePersoDate', 'Pre-Perso Date'], ['icPrePersoEquipId', 'Pre-Perso Equip ID'],
  ['icPersonalizer', 'Personalizer'], ['icPersonalizationDate', 'Personalization Date'],
  ['icPersoEquipId', 'Perso Equip ID'],
];

// Build a self-contained, printable HTML report from labelled image sections
// ([{ label, img }]) — used for the combined dual-interface export.
function buildImageHtml(title, sections) {
  const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const appHtml = (a) => {
    const cplc = a.cplc ? `<h4>CPLC — Card Production Life Cycle</h4><table class="kv">${CPLC_FIELDS.map(([k, l]) => a.cplc[k] ? `<tr><td>${esc(l)}</td><td class="mono">${esc(a.cplc[k])}</td></tr>` : '').join('')}</table>` : '';
    const rows = a.tags.map((t) => `<tr><td class="mono b">${esc(t.tag)}</td><td class="src">${esc((t.sources || [t.source]).filter(Boolean).join(', '))}</td><td>${esc(t.name || '?')}</td><td class="mono val">${esc(t.value)}${looksTextual(t.ascii) ? ` <span class="asc">“${esc(t.ascii)}”</span>` : ''}</td></tr>`).join('');
    // Per-record TLV tree — every EMV tag in the record, nested (like the trace).
    const recs = (a.records || []).filter((r) => r.nodes?.length).map((r) =>
      `<div class="te ok"><div class="te-head"><b>SFI${r.sfi} · Kayıt ${r.record}</b></div>` +
      (r.raw ? `<div class="te-apdu">${esc(r.raw)}</div>` : '') +
      `<div class="te-tlv">${tlvTreeHtml(r.nodes, esc)}</div></div>`).join('');
    return `<div class="app"><h3>${esc(a.scheme || '?')} · <span class="mono">${esc(a.aid)}</span>${a.label ? ` <span class="muted">(${esc(a.label)})</span>` : ''}</h3>
      <p class="meta">AIP ${esc(a.aip || '-')} · ${a.recordCount} kayıt · ${a.tagCount} tag · kaynak ${esc(a.source || '')}</p>
      ${cplc}<table class="tags"><thead><tr><th>Tag</th><th>Kaynak</th><th>İsim</th><th>Değer</th></tr></thead><tbody>${rows}</tbody></table>
      ${recs ? `<h4>Kayıt TLV Ağacı</h4>${recs}` : ''}</div>`;
  };
  const secs = sections.filter((s) => s.img?.applications?.length).map((s) => {
    const img = s.img;
    return `<section class="iface"><h2>${esc(s.label)}</h2>
      <p class="meta">${img.appCount} uygulama · ${img.totalTags} tag · ${img.totalRecords} kayıt${img.durationMs != null ? ` · ${img.durationMs} ms` : ''}</p>
      ${img.applications.map(appHtml).join('')}</section>`;
  }).join('');
  return `<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8"><title>${esc(title)}</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:24px;color:#1a1d21;background:#fff;font-size:14px}
  h1{font-size:20px;margin:0 0 12px} h2{font-size:17px;margin:26px 0 6px;border-bottom:2px solid #444;padding-bottom:5px}
  h3{font-size:15px;margin:16px 0 4px} h4{font-size:12px;margin:14px 0 6px;color:#444;text-transform:uppercase;letter-spacing:.5px}
  .meta{color:#666;font-size:12px;margin:2px 0 8px} .muted{color:#888} .mono{font-family:ui-monospace,Consolas,monospace}
  .b{font-weight:600} .val{word-break:break-all} .asc{color:#0a7d3c} .src{color:#888;font-size:11px}
  table{border-collapse:collapse;width:100%;margin:4px 0 10px} th,td{border:1px solid #ddd;padding:4px 8px;text-align:left;vertical-align:top}
  th{background:#f4f5f7;font-size:11px;text-transform:uppercase;letter-spacing:.4px;color:#555}
  .tags td:first-child{white-space:nowrap} .kv td:first-child{width:40%;color:#555} tbody tr:nth-child(even){background:#fafbfc}
  ${TLV_CSS}
  @media print{body{margin:0} h2{page-break-after:avoid} tr{page-break-inside:avoid} .te{break-inside:avoid}}
</style></head><body><h1>${esc(title)}</h1>${secs}</body></html>`;
}

export function CardImageTab({ cardImage, imageBusy, cardPresent, extractImage, downloadImage,
  imageA, imageB, captureBusy, captureCard, clearA, clearB,
  imageContact, imageContactless, captureIface, clearContact, clearContactless,
  extractDual, cancelDual, dualPhase,
  imageAcl, imageBcl, captureCardDual, cancelCardDual, cardDualPhase, cardDualSlot }) {
  const d = cardImage;
  const [mode, setMode] = useState('image');
  const [profileText, setProfileText] = useState('');
  const [cmp, setCmp] = useState(null);
  const [profileName, setProfileName] = useState('');
  const [profFilter, setProfFilter] = useState('all');
  const [diff, setDiff] = useState(null);
  // Compare the expected profile against the card. If either interface was read
  // (dual mode), compare against contact and contactless separately; otherwise
  // fall back to the single Kart Image extraction.
  const buildCompare = (text) => {
    if (imageContact || imageContactless) return {
      dual: true,
      contact: imageContact ? compareProfile(text, imageContact.applications) : null,
      contactless: imageContactless ? compareProfile(text, imageContactless.applications) : null,
    };
    return { dual: false, single: compareProfile(text, d?.applications) };
  };
  const runCompare = () => setCmp(buildCompare(profileText));
  const runDiff = () => setDiff((imageA || imageAcl) && (imageB || imageBcl) ? {
    contact: imageA && imageB ? diffCards(imageA, imageB) : null,
    contactless: imageAcl && imageBcl ? diffCards(imageAcl, imageBcl) : null,
  } : null);

  const exportDiff = (fmt) => {
    if (!diff) return;
    const esc = (x) => `"${String(x ?? '').replace(/"/g, '""')}"`;
    const section = (dc, label) => {
      if (!dc?.rows) return `${fmt === 'csv' ? '# ' : '=== '}${label}${fmt === 'csv' ? '' : ' ==='} (okunmadı)`;
      const c = dc.counts;
      if (fmt === 'csv') return `# ${label}\ndurum;tag;isim;kartA;kartB\n` + dc.rows.map((r) => [CARD_STATUS[r.status].label, r.tag, r.name || '', r.a || '', r.b || ''].map(esc).join(';')).join('\n');
      return `=== ${label} ===\n# ${c.same} aynı · ${c.diff} farklı · ${c.onlyA} sadece A · ${c.onlyB} sadece B\n` +
        dc.rows.map((r) => `${CARD_STATUS[r.status].icon} ${CARD_STATUS[r.status].label.padEnd(9)} ${r.tag.padEnd(6)} ${(r.name || '').padEnd(42)} A=${r.a || '-'}  B=${r.b || '-'}`).join('\n');
    };
    const content = [section(diff.contact, '🔌 CONTACT'), section(diff.contactless, '📶 CONTACTLESS')].join('\n\n');
    const type = fmt === 'csv' ? 'text/csv;charset=utf-8' : 'text/plain'; const ext = fmt === 'csv' ? 'csv' : 'txt';
    const url = URL.createObjectURL(new Blob([fmt === 'csv' ? '﻿' + content : content], { type }));
    const a = document.createElement('a');
    a.href = url; a.download = `card-diff-${Date.now()}.${ext}`; a.click(); URL.revokeObjectURL(url);
  };

  const cardDiffTable = (dc, label) => (
    <div className="pin-result" style={{ marginTop: 14 }}>
      <p className="mono small" style={{ marginBottom: 6 }}><b>{label}</b> ·
        <span className="st-ok"> ✓ {dc.counts.same} aynı</span> ·
        <span className="st-bad"> ✗ {dc.counts.diff} farklı</span> ·
        <span className="st-warn"> ◑ {dc.counts.onlyA} sadece A</span> ·
        <span className="st-extra"> ◐ {dc.counts.onlyB} sadece B</span>
      </p>
      <table className="capk-table image-tags">
        <thead><tr><th>Durum</th><th>Tag</th><th>İsim</th><th>Kart A</th><th>Kart B</th></tr></thead>
        <tbody>
          {dc.rows.map((r, j) => (
            <tr key={j}>
              <td className={CARD_STATUS[r.status].cls}>{CARD_STATUS[r.status].icon} {CARD_STATUS[r.status].label}</td>
              <td className="mono b">{r.tag}</td>
              <td className="small">{r.name || <span className="muted">?</span>}</td>
              <td className="mono small val">{r.a || <span className="muted">—</span>}</td>
              <td className="mono small val">{r.b || <span className="muted">—</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );

  // One profile-comparison result card (used per interface in dual mode) — with
  // a pass/fail verdict banner, a match-rate bar, and clickable status filters.
  const profTable = (c, label) => {
    if (!c) return null;
    if (c.error) return <div className="prof-card fail" style={{ marginTop: 14 }}>{label && <div className="prof-iface">{label}</div>}<p className="err-text" style={{ margin: 8 }}>✗ Profil çözümlenemedi: {c.error}</p></div>;
    if (!c.counts) return null;
    const co = c.counts;
    const total = co.match + co.mismatch + co.missing; // beklenen (fazla hariç)
    const rate = total ? Math.round((co.match / total) * 100) : 100;
    const problems = co.mismatch + co.missing;
    const pass = problems === 0;
    const allRows = [...c.rows, ...c.extras];
    const rows = profFilter === 'all' ? allRows : allRows.filter((r) => r.status === profFilter);
    const CHIPS = [['all', 'Tümü', allRows.length, ''], ['match', 'Eşleşti', co.match, 'st-ok'], ['mismatch', 'Uyuşmadı', co.mismatch, 'st-bad'], ['missing', 'Eksik', co.missing, 'st-warn'], ['extra', 'Fazla', co.extra, 'st-extra']];
    return (
      <div className={`prof-card ${pass ? 'pass' : 'fail'}`} style={{ marginTop: 14 }}>
        {label && <div className="prof-iface">{label}</div>}
        <div className="prof-verdict">
          <span className={`prof-badge ${pass ? 'pass' : 'fail'}`}>{pass ? '✓ GEÇTİ' : `✗ ${problems} SORUN`}</span>
          <div className="prof-bar" title={`${rate}% eşleşme`}><span className={pass ? 'ok' : 'warn'} style={{ width: `${rate}%` }} /></div>
          <span className="prof-rate">{rate}%<span className="muted"> ({co.match}/{total} beklenen tag)</span></span>
        </div>
        <div className="prof-chips">
          {CHIPS.map(([k, lbl, n, cls]) => (
            <button key={k} className={`prof-chip ${cls} ${profFilter === k ? 'sel' : ''}`} disabled={k !== 'all' && !n} onClick={() => setProfFilter(profFilter === k ? 'all' : k)}>{lbl} <b>{n}</b></button>
          ))}
        </div>
        {c.bad?.length > 0 && <p className="muted small" style={{ margin: '4px 0 0' }}>⚠ Çözümlenemeyen {c.bad.length} satır atlandı.</p>}
        {rows.length === 0 ? <p className="muted small" style={{ padding: '10px 2px 2px' }}>Bu filtreyle gösterilecek satır yok.</p> : (
          <table className="capk-table image-tags prof-table">
            <thead><tr><th className="c">•</th><th>Tag</th><th>İsim</th><th>Beklenen</th><th>Kart</th><th>Kaynak</th></tr></thead>
            <tbody>
              {rows.map((r, j) => (
                <tr key={j} className={`prow ${r.status}`}>
                  <td className={`c ${STATUS[r.status].cls}`} title={STATUS[r.status].label}>{STATUS[r.status].icon}</td>
                  <td className="mono b">{r.tag}</td>
                  <td className="small">{r.name || <span className="muted">?</span>}</td>
                  <td className="mono small val">{r.expected || <span className="muted">—</span>}</td>
                  <td className="mono small val">{r.actual || <span className="muted">—</span>}</td>
                  <td className="small muted">{(r.sources || []).join(', ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    );
  };

  // Load an expected profile from a .txt/.json file and compare immediately.
  const loadFile = (e) => {
    const f = e.target.files?.[0]; if (!f) return;
    const reader = new FileReader();
    reader.onload = () => {
      const txt = String(reader.result || '');
      setProfileText(txt); setProfileName(f.name);
      setCmp(buildCompare(txt));
    };
    reader.readAsText(f); e.target.value = '';
  };

  // Export the comparison result as a CPV/VPA report (CSV or text). In dual mode
  // both interfaces are emitted as labelled sections.
  const exportCompare = (fmt) => {
    if (!cmp) return;
    const esc = (x) => `"${String(x ?? '').replace(/"/g, '""')}"`;
    const section = (c, label) => {
      if (!c?.rows) return '';
      const all = [...c.rows, ...c.extras]; const co = c.counts;
      if (fmt === 'csv') return `# ${label}\ndurum;tag;isim;beklenen;kart;kaynak\n` +
        all.map((r) => [STATUS[r.status].label, r.tag, r.name || '', r.expected || '', r.actual || '', (r.sources || []).join(' ')].map(esc).join(';')).join('\n');
      return `=== ${label} ===\n# ${co.match} eşleşti · ${co.mismatch} uyuşmadı · ${co.missing} eksik · ${co.extra} fazla\n\n` +
        all.map((r) => `${STATUS[r.status].icon} ${STATUS[r.status].label.padEnd(9)} ${r.tag.padEnd(6)} ${(r.name || '').padEnd(42)} beklenen=${r.expected || '-'}  kart=${r.actual || '-'}`).join('\n');
    };
    const sections = cmp.dual
      ? [section(cmp.contact, '🔌 CONTACT (temaslı)'), section(cmp.contactless, '📶 CONTACTLESS (temassız)')]
      : [section(cmp.single, 'KART')];
    const header = fmt === 'csv' ? '' : `# Perso karşılaştırma raporu — ${profileName || 'profil'}\n\n`;
    const content = header + sections.filter(Boolean).join('\n\n');
    const type = fmt === 'csv' ? 'text/csv;charset=utf-8' : 'text/plain'; const ext = fmt === 'csv' ? 'csv' : 'txt';
    const url = URL.createObjectURL(new Blob([fmt === 'csv' ? '﻿' + content : content], { type }));
    const a = document.createElement('a');
    a.href = url; a.download = `perso-compare-${Date.now()}.${ext}`; a.click(); URL.revokeObjectURL(url);
  };
  const MODES = [['image', 'Kart Image'], ['iface', 'Dual-Interface'], ['diff', 'Kart ↔ Kart'], ['profile', 'Profil Karşılaştır']];
  const PHASE_MSG = {
    contact: '🔌 Contact okunuyor…',
    remove: '✋ Kartı temaslı yuvadan ÇIKARIN — bekleniyor… (çıkarılmazsa sadece contact alınır)',
    place: '📶 Kartı temassız okuyucuya KOYUN — bekleniyor…',
    contactless: '📶 Temassız okunuyor…',
  };

  // Export the combined dual-interface image (both interfaces, labelled).
  const exportDual = (fmt) => {
    const sec = (img, label) => !img?.applications ? '' :
      `=== ${label} ===\n` + img.applications.map((a) =>
        `# ${a.scheme || '?'} · ${a.aid}\n` + a.tags.map((t) => `${t.tag.padEnd(6)} ${(t.name || '').padEnd(42)} ${t.value}`).join('\n')).join('\n');
    let content, type = 'text/plain', ext = 'txt';
    if (fmt === 'json') { content = JSON.stringify({ contact: imageContact, contactless: imageContactless }, null, 2); type = 'application/json'; ext = 'json'; }
    else if (fmt === 'html') {
      content = buildImageHtml('Dual-Interface Kart Image — Perso Raporu', [
        { label: '🔌 CONTACT (temaslı)', img: imageContact },
        { label: '📶 CONTACTLESS (temassız)', img: imageContactless },
      ]); type = 'text/html'; ext = 'html';
    }
    else content = [sec(imageContact, '🔌 CONTACT (temaslı)'), sec(imageContactless, '📶 CONTACTLESS (temassız)')].filter(Boolean).join('\n\n');
    const url = URL.createObjectURL(new Blob([content], { type }));
    const a = document.createElement('a');
    a.href = url; a.download = `dual-image-${Date.now()}.${ext}`; a.click(); URL.revokeObjectURL(url);
  };
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Kart Image {mode === 'image' && d?.appCount != null && !d.error && <span className="muted small">· {d.appCount} uygulama · {d.totalTags} tag · {d.totalRecords} kayıt · {d.durationMs}ms</span>}</h2>
        <div className="capk-filter">
          {MODES.map(([m, label]) => (
            <button key={m} className={`btn-ghost ${mode === m ? 'sel' : ''}`} onClick={() => setMode(m)}>{label}</button>
          ))}
        </div>
      </div>

      {/* ── Mod 1: Kart Image ── */}
      {mode === 'image' && <>
        <p className="muted small">
          Karttaki <b>tüm personalize edilmiş EMV tag'lerini</b> çıkarır (FCI, GPO/AIP-AFL, tüm SFI/kayıtlar brute-force,
          GET DATA taraması, CPLC). Mastercard <b>CPV</b> / Visa <b>VPA</b> perso doğrulama için tam kart image'ı.
        </p>
        <div className="capk-add-row" style={{ alignItems: 'center' }}>
          <button className="btn" disabled={imageBusy || !cardPresent} onClick={extractImage}>
            {imageBusy ? 'Çıkarılıyor… (tüm SFI/tag taranıyor)' : 'Kart Image Çıkart'}
          </button>
          {d?.applications?.length > 0 && <div className="capk-actions">
            <button className="btn-sm ghost" onClick={() => downloadImage('json')}>JSON</button>
            <button className="btn-sm ghost" onClick={() => downloadImage('html')}>HTML</button>
            <button className="btn-sm ghost" onClick={() => downloadImage('text')}>Metin</button>
          </div>}
          {!cardPresent && <span className="muted small">okuyucuda kart yok</span>}
        </div>
        {d?.error && <p className="err-text" style={{ marginTop: 12 }}>✗ {d.error}</p>}
        {d?.applications?.length === 0 && !d.error && <p className="muted small" style={{ marginTop: 12 }}>Kart üzerinde EMV uygulaması bulunamadı.</p>}
      </>}

      {/* ── Mod: Dual-Interface (contact + contactless birleşik image) ── */}
      {mode === 'iface' && <>
        <p className="muted small">Dual-interface kartın <b>her iki arayüzünü tek image'da</b> okur. <b>Dual-Interface Image Çıkart</b>'a bas: önce <b>🔌 temaslı</b> okunur, sonra tool seni <b>📶 temassıza yönlendirir</b> (kartı temassız okuyucuya koy) ve orayı da okur. Her tag hangi arayüzden okunduğu etiketlidir.</p>
        <div className="capk-add-row" style={{ alignItems: 'center' }}>
          <button className="btn" disabled={!!dualPhase} onClick={extractDual}>{dualPhase ? 'Okunuyor…' : '⇄ Dual-Interface Image Çıkart'}</button>
          {dualPhase && <button className="btn-sm ghost" onClick={cancelDual}>İptal</button>}
          {(imageContact || imageContactless) && !dualPhase && <div className="capk-actions">
            <button className="btn-sm ghost" onClick={() => exportDual('json')}>JSON</button>
            <button className="btn-sm ghost" onClick={() => exportDual('html')}>HTML</button>
            <button className="btn-sm ghost" onClick={() => exportDual('text')}>Metin</button>
          </div>}
        </div>
        {dualPhase && <p className="st-warn small" style={{ marginTop: 8 }}>{PHASE_MSG[dualPhase]}</p>}
        <p className="muted small" style={{ marginTop: 4 }}>Tek tek okumak için:
          <button className="btn-sm ghost" style={{ marginLeft: 6 }} disabled={!!captureBusy || !!dualPhase} onClick={() => captureIface('contact')}>🔌 Sadece Contact</button>
          <button className="btn-sm ghost" style={{ marginLeft: 6 }} disabled={!!captureBusy || !!dualPhase} onClick={() => captureIface('contactless')}>📶 Sadece Temassız</button>
        </p>

        {[['🔌 CONTACT (temaslı)', imageContact, clearContact], ['📶 CONTACTLESS (temassız)', imageContactless, clearContactless]].map(([label, img, clr], k) => (
          <div key={k} className={`pin-result ${img ? 'ok' : ''}`} style={{ marginTop: 14 }}>
            <div className="panel-head" style={{ border: 0, padding: 0, marginBottom: img ? 8 : 0 }}>
              <p className="capk-ok"><b>{label}</b> {img?.applications?.length ? <span className="muted small">· {img.appCount} uygulama · {img.totalTags} tag · {img.totalRecords} kayıt</span> : <span className="muted small">· henüz okunmadı</span>}</p>
              {img && <button className="btn-sm ghost" onClick={clr}>temizle</button>}
            </div>
            {img?.applications?.map((a, i) => (
              <details key={i} className="builder" open>
                <summary>{a.scheme || '?'} · {a.aid} — {a.tags.length} tag</summary>
                <table className="capk-table image-tags">
                  <thead><tr><th>Tag</th><th>Kaynak</th><th>İsim</th><th>Değer</th></tr></thead>
                  <tbody>
                    {a.tags.map((t, j) => (
                      <tr key={j}>
                        <td className="mono b">{t.tag}</td>
                        <td className="small muted">{(t.sources || [t.source]).join(', ')}</td>
                        <td className="small">{t.name || <span className="muted">?</span>}</td>
                        <td className="mono small val">{t.value}{looksTextual(t.ascii) ? <span className="muted"> · “{t.ascii}”</span> : null}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </details>
            ))}
          </div>
        ))}
      </>}

      {/* ── Mod 2: Kart ↔ Kart (her kart dual-interface okunur) ── */}
      {mode === 'diff' && <>
        <p className="muted small">İki kartın <b>her iki arayüzünü</b> okuyup karşılaştırır. <b>① Kart A Yakala</b> → kart A önce temaslı, sonra (yönlendirmeyle) temassız okunur; aynısını <b>② Kart B Yakala</b> ile yap; sonra <b>Karşılaştır</b>. Contact ve contactless <b>ayrı ayrı</b> diff'lenir (referans ↔ üretilen dual-interface kart doğrulaması).</p>
        <div className="capk-add-row" style={{ alignItems: 'center' }}>
          <button className="btn" disabled={!!cardDualPhase || !!captureBusy || !!dualPhase} onClick={() => captureCardDual('A')}>{cardDualSlot === 'A' ? 'Okunuyor…' : '① Kart A Yakala'}</button>
          <span className="muted small">A: 🔌 {cardTip(imageA)} · 📶 {cardTip(imageAcl)}</span>
          {(imageA || imageAcl) && <button className="btn-sm ghost" onClick={clearA}>temizle</button>}
        </div>
        <div className="capk-add-row" style={{ alignItems: 'center', marginTop: 6 }}>
          <button className="btn" disabled={!!cardDualPhase || !!captureBusy || !!dualPhase} onClick={() => captureCardDual('B')}>{cardDualSlot === 'B' ? 'Okunuyor…' : '② Kart B Yakala'}</button>
          <span className="muted small">B: 🔌 {cardTip(imageB)} · 📶 {cardTip(imageBcl)}</span>
          {(imageB || imageBcl) && <button className="btn-sm ghost" onClick={clearB}>temizle</button>}
        </div>
        {cardDualPhase && <p className="st-warn small" style={{ marginTop: 8 }}>Kart {cardDualSlot}: {PHASE_MSG[cardDualPhase]} <button className="btn-sm ghost" onClick={cancelCardDual}>İptal</button></p>}
        <div className="capk-add-row" style={{ marginTop: 8, alignItems: 'center' }}>
          <button className="btn" disabled={!((imageA || imageAcl) && (imageB || imageBcl))} onClick={runDiff}>Karşılaştır (A ↔ B)</button>
          {diff && <div className="capk-actions">
            <button className="btn-sm ghost" onClick={() => exportDiff('csv')}>CSV</button>
            <button className="btn-sm ghost" onClick={() => exportDiff('text')}>Metin</button>
          </div>}
        </div>

        {diff?.contact && cardDiffTable(diff.contact, '🔌 CONTACT (temaslı)')}
        {diff?.contactless && cardDiffTable(diff.contactless, '📶 CONTACTLESS (temassız)')}
        {diff && !diff.contact && !diff.contactless && <p className="muted small" style={{ marginTop: 12 }}>Karşılaştırılacak eşleşen arayüz yok — her iki kartın da aynı arayüzü (ör. ikisi de contact) okunmalı.</p>}
      </>}

      {/* ── Mod 3: Profil Karşılaştır ── */}
      {mode === 'profile' && <>
        <div className="prof-steps">
          {/* Adım ① — Beklenen profil */}
          <div className="prof-step s1">
            <div className="prof-step-head"><span className="prof-num">1</span> Beklenen profili girin
              <label className="prof-upload">↥ Dosya Yükle
                <input type="file" accept=".txt,.json,.tlv,.prof,.csv,text/plain,application/json" style={{ display: 'none' }} onChange={loadFile} />
              </label>
              {profileName && <span className="prof-file">📄 {profileName}</span>}
              {profileText && <button className="btn-sm ghost" onClick={() => { setProfileText(''); setProfileName(''); setCmp(null); }}>temizle</button>}
            </div>
            <textarea className="mono prof-textarea" value={profileText}
              onChange={(e) => setProfileText(e.target.value)}
              placeholder={'# her satır: TAG DEĞER  (ör. 9F07 FF00)\n# veya JSON: {"9F07":"FF00"}\n9F07 FF00\n5F24 301031\n9F42 0949'} />
            <p className="prof-hint">Her satır <span className="mono">TAG DEĞER</span> / <span className="mono">TAG=DEĞER</span> ya da JSON. <span className="mono">#</span> ile yorum.</p>
          </div>

          {/* Adım ② — Kartı oku */}
          <div className="prof-step">
            <div className="prof-step-head"><span className="prof-num">2</span> Kartı okuyun</div>
            <div className="capk-add-row" style={{ alignItems: 'center', flexWrap: 'wrap' }}>
              <button className="btn" disabled={!!dualPhase || !!captureBusy} onClick={extractDual}>{dualPhase ? 'Okunuyor…' : '⇄ Dual Oku (temaslı+temassız)'}</button>
              {dualPhase && <button className="btn-sm ghost" onClick={cancelDual}>İptal</button>}
            </div>
            {dualPhase && <p className="st-warn small" style={{ marginTop: 8 }}>{PHASE_MSG[dualPhase]}</p>}
            <div className="prof-read">
              <span className={`prof-pill ${imageContact ? 'on' : ''}`}>🔌 Temaslı: {imageContact ? `${imageContact.totalTags} tag` : 'okunmadı'}</span>
              <span className={`prof-pill ${imageContactless ? 'on' : ''}`}>📶 Temassız: {imageContactless ? `${imageContactless.totalTags} tag` : 'okunmadı'}</span>
              {!imageContact && !imageContactless && d?.applications?.length ? <span className="prof-pill on">🗂 Tek image: {d.totalTags} tag</span> : null}
            </div>
            {!imageContact && !imageContactless && !d?.applications?.length && <p className="err-text small" style={{ marginTop: 6 }}>⚠ Henüz kart okunmadı — yukarıdaki butonla okuyun veya <b>Kart Image</b> sekmesinden image çıkarın.</p>}
          </div>

          {/* Adım ③ — Karşılaştır */}
          <div className="prof-step">
            <div className="prof-step-head"><span className="prof-num">3</span> Karşılaştırın
              {cmp && <div className="capk-actions" style={{ marginLeft: 'auto' }}>
                <button className="btn-sm ghost" onClick={() => exportCompare('csv')}>↧ CSV</button>
                <button className="btn-sm ghost" onClick={() => exportCompare('text')}>↧ Metin</button>
              </div>}
            </div>
            <button className="btn btn-primary" disabled={!profileText.trim() || !(imageContact || imageContactless || d?.applications?.length)} onClick={runCompare}>✓ Karşılaştır</button>
            {!profileText.trim() && <span className="muted small" style={{ marginLeft: 8 }}>önce profil girin</span>}
          </div>
        </div>

        {cmp?.dual && <>
          {profTable(cmp.contact, '🔌 CONTACT (temaslı)')}
          {profTable(cmp.contactless, '📶 CONTACTLESS (temassız)')}
          {!cmp.contact && !cmp.contactless && <p className="muted small" style={{ marginTop: 12 }}>Okunmuş arayüz yok.</p>}
        </>}
        {cmp && !cmp.dual && profTable(cmp.single, null)}
      </>}

      {mode === 'image' && d?.applications?.map((a, i) => (
        <div key={i} className="pin-result ok" style={{ marginTop: 16 }}>
          <p className="capk-ok">
            <b>{a.scheme || '?'}</b> · <span className="mono">{a.aid}</span>{a.label ? ` (${a.label})` : ''}
            {' · '}<span className="muted small">AIP {a.aip || '-'} · {a.recordCount} kayıt · {a.tagCount} tag · {a.source}</span>
          </p>

          {a.cplc && (
            <details className="builder" open>
              <summary>CPLC — Card Production Life Cycle (perso parmak izi)</summary>
              <table className="kv-table"><tbody>
                {CPLC_FIELDS.map(([k, label]) => (
                  <tr key={k}><td>{label}</td><td className="mono">{a.cplc[k]}</td></tr>
                ))}
              </tbody></table>
            </details>
          )}

          <details className="builder" open>
            <summary>Tag listesi ({a.tags.length})</summary>
            <table className="capk-table image-tags">
              <thead><tr><th>Tag</th><th>Kaynak</th><th>İsim</th><th>Değer</th></tr></thead>
              <tbody>
                {a.tags.map((t, j) => (
                  <tr key={j}>
                    <td className="mono b">{t.tag}</td>
                    <td className="small muted">{(t.sources || [t.source]).join(', ')}</td>
                    <td className="small">{t.name || <span className="muted">?</span>}</td>
                    <td className="mono small val">{t.value}{looksTextual(t.ascii) ? <span className="muted"> · “{t.ascii}”</span> : null}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </details>

          <details className="builder">
            <summary>Kayıtlar ({a.records.length}) — ham SFI/record</summary>
            <table className="capk-table">
              <thead><tr><th>SFI</th><th>#</th><th>Ham veri</th></tr></thead>
              <tbody>
                {a.records.map((r, j) => (
                  <tr key={j}><td className="mono">{r.sfi}</td><td className="mono">{r.record}</td><td className="mono small val">{r.raw}</td></tr>
                ))}
              </tbody>
            </table>
          </details>

          {a.getData?.length > 0 && (
            <details className="builder">
              <summary>GET DATA ({a.getData.length})</summary>
              <table className="capk-table">
                <thead><tr><th>Tag</th><th>İsim</th><th>Değer</th></tr></thead>
                <tbody>
                  {a.getData.map((g, j) => (
                    <tr key={j}><td className="mono b">{g.tag}</td><td className="small">{g.name || '?'}</td><td className="mono small val">{g.value}</td></tr>
                  ))}
                </tbody>
              </table>
            </details>
          )}
        </div>
      ))}
    </section>
  );
}
