import { useState } from 'react';
import { tlvTreeHtml, TLV_CSS } from '../../lib/report.js';
import { VerdictBanner } from '../VerdictBanner.jsx';

// "Uyumluluk" tab: runs the personalisation compliance / certification rule
// engine (EMV core + scheme, e.g. Mastercard CPV) against the card and shows a
// structured PASS/FAIL report per interface — the requirement layer that makes
// this a Barnes/Collis/UL/Perceval-style tool rather than a raw analyser.

const STATUS = {
  pass: { icon: '✓', cls: 'st-ok', label: 'GEÇTİ' },
  fail: { icon: '✗', cls: 'st-bad', label: 'KALDI' },
  warn: { icon: '⚠', cls: 'st-warn', label: 'UYARI' },
  na: { icon: '—', cls: 'st-extra', label: 'İlgisiz' },
};
const SEV = { M: 'Zorunlu', R: 'Önerilen', C: 'Koşullu' };
const vShort = (v) => (v === 'PASS' ? 'PASS' : v === 'FAIL' ? 'FAIL' : 'UYARI');
const VERDICT = {
  PASS: { cls: 'pass', text: '✓ UYUMLU' },
  PASS_WITH_WARN: { cls: 'warn', text: '◐ UYARILARLA UYUMLU' },
  FAIL: { cls: 'fail', text: '✗ UYUMSUZ' },
};
const vClsShort = (v) => (v === 'FAIL' ? 'fail' : v === 'PASS' ? 'pass' : 'warn');
const shortDate = (iso) => { try { const d = new Date(iso); const p = (n) => String(n).padStart(2, '0'); return `${p(d.getDate())}.${p(d.getMonth() + 1)} ${p(d.getHours())}:${p(d.getMinutes())}`; } catch { return ''; } };

// Build a self-contained HTML certification report.
function reportHtml(res) {
  const c = res.compliance; const esc = (s) => String(s ?? '').replace(/[&<>]/g, (x) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[x]));
  const rows = c.categories.map((cat) => `<tr class="cat"><td colspan="5">${esc(cat.name)}</td></tr>` +
    cat.rules.map((r) => `<tr class="s-${r.status}"><td>${STATUS[r.status].icon}</td><td class="mono">${esc(r.id)}</td><td>${SEV[r.sev]}</td><td>${esc(r.req)}${r.spec ? `<div class="spec">${esc(r.spec)}</div>` : ''}</td><td class="mono">${esc(r.evidence || r.detail || '')}</td></tr>`).join('')).join('');
  // Appendix: per-record TLV tree (every EMV tag in each record, nested) so the
  // certification report shows the raw perso structure the rules were run on.
  const recsTlv = (res.image?.applications || []).flatMap((a) => (a.records || []).filter((r) => r.nodes?.length).map((r) =>
    `<div class="te ok"><div class="te-head"><b>SFI${r.sfi} · Kayıt ${r.record}</b></div>` +
    (r.raw ? `<div class="te-apdu">${esc(r.raw)}</div>` : '') +
    `<div class="te-tlv">${tlvTreeHtml(r.nodes, esc)}</div></div>`)).join('');
  return `<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8"><title>Uyumluluk Raporu — ${esc(c.scheme || 'EMV')} ${esc(c.iface)}</title>
<style>body{font-family:system-ui,Segoe UI,sans-serif;margin:24px;color:#1a1d21;font-size:13px}h1{font-size:19px;margin:0 0 4px}
.v{display:inline-block;font-weight:800;padding:5px 14px;border-radius:8px;margin:8px 0}.v.PASS{background:#d8f5df;color:#177a35}.v.PASS_WITH_WARN{background:#fbf2d0;color:#8a6d10}.v.FAIL{background:#fadadd;color:#a01523}
table{border-collapse:collapse;width:100%;margin-top:12px}th,td{border:1px solid #ddd;padding:5px 8px;text-align:left;vertical-align:top}th{background:#f4f5f7;font-size:11px;text-transform:uppercase}
tr.cat td{background:#eef1f5;font-weight:700}.mono{font-family:ui-monospace,Consolas,monospace}
tr.s-fail td{background:#fdecee}tr.s-warn td{background:#fdf6e3}tr.s-na td{color:#999}
.spec{color:#8a8f98;font-size:10px;margin-top:2px;font-style:italic}
h2{font-size:15px;margin:22px 0 6px;border-bottom:1px solid #ddd;padding-bottom:4px}
${TLV_CSS}
@media print{tr{page-break-inside:avoid}.te{break-inside:avoid}}</style></head><body>
<h1>Perso Uyumluluk / Sertifikasyon Raporu</h1>
<p>${esc(c.scheme || '?')} · ${esc(c.aid || '')} · Arayüz: ${esc(c.iface)} · AIP ${esc(c.aip || '-')}</p>
<div class="v ${c.summary.verdict}">${VERDICT[c.summary.verdict]?.text || c.summary.verdict}</div>
<p>${c.summary.pass} geçti · ${c.summary.fail} kaldı · ${c.summary.warn} uyarı · ${c.summary.na} ilgisiz (${c.summary.total} kural)</p>
<table><thead><tr><th></th><th>ID</th><th>Önem</th><th>Gereksinim</th><th>Kanıt / Not</th></tr></thead><tbody>${rows}</tbody></table>
${recsTlv ? `<h2>Ek · Kayıt TLV Ağacı</h2>${recsTlv}` : ''}
</body></html>`;
}

// Contact ↔ contactless compliance matrix: every rule side-by-side across both
// interfaces, differences highlighted — the dual-interface certification view.
function MatrixView({ contact, contactless }) {
  const [onlyDiff, setOnlyDiff] = useState(false);
  const map = new Map();
  const add = (comp, key) => { for (const cat of comp.categories) for (const r of cat.rules) { const e = map.get(r.id) || { id: r.id, cat: r.cat, req: r.req, sev: r.sev }; e[key] = r.status; map.set(r.id, e); } };
  add(contact, 'c'); add(contactless, 'cl');
  const all = [...map.values()];
  const isDiff = (e) => e.c && e.cl && e.c !== e.cl;
  const diffs = all.filter(isDiff);
  const rows = onlyDiff ? diffs : all;
  const cats = []; const byCat = new Map();
  for (const e of rows) { if (!byCat.has(e.cat)) { byCat.set(e.cat, []); cats.push(e.cat); } byCat.get(e.cat).push(e); }
  const cV = contact.summary.verdict, clV = contactless.summary.verdict;
  const dualPass = cV !== 'FAIL' && clV !== 'FAIL';
  const dv = dualPass ? (cV === 'PASS' && clV === 'PASS' && !diffs.length ? { cls: 'pass', text: '✓ HER İKİ ARAYÜZ UYUMLU' } : { cls: 'warn', text: '◐ UYUMLU · FARKLAR VAR' }) : { cls: 'fail', text: '✗ EN AZ BİR ARAYÜZ UYUMSUZ' };
  const cell = (s) => s ? <span className={STATUS[s].cls} title={STATUS[s].label}>{STATUS[s].icon}</span> : <span className="muted">·</span>;

  const dl = () => {
    const esc = (x) => String(x ?? '').replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
    const body = cats.map((cat) => `<tr class="cat"><td colspan="5">${esc(cat)}</td></tr>` + byCat.get(cat).map((e) => `<tr class="${isDiff(e) ? 'diff' : ''}"><td class="mono">${esc(e.id)}</td><td>${SEV[e.sev]}</td><td>${esc(e.req)}</td><td style="text-align:center">${e.c ? STATUS[e.c].icon : '·'}</td><td style="text-align:center">${e.cl ? STATUS[e.cl].icon : '·'}</td></tr>`).join('')).join('');
    const html = `<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8"><title>Uyumluluk Matrisi — ${esc(contact.scheme || 'EMV')}</title><style>body{font-family:system-ui,Segoe UI,sans-serif;margin:24px;font-size:13px}h1{font-size:19px}.v{display:inline-block;font-weight:800;padding:5px 14px;border-radius:8px;margin:8px 0}.v.pass{background:#d8f5df;color:#177a35}.v.warn{background:#fbf2d0;color:#8a6d10}.v.fail{background:#fadadd;color:#a01523}table{border-collapse:collapse;width:100%;margin-top:10px}th,td{border:1px solid #ddd;padding:5px 8px;text-align:left}th{background:#f4f5f7}tr.cat td{background:#eef1f5;font-weight:700}tr.diff td{background:#fff6df}.mono{font-family:ui-monospace,Consolas,monospace}</style></head><body><h1>Perso Uyumluluk Matrisi — Temaslı ↔ Temassız</h1><p>${esc(contact.scheme || '?')} · Temaslı: ${cV} · Temassız: ${clV} · ${diffs.length} fark</p><div class="v ${dv.cls}">${dv.text}</div><table><thead><tr><th>ID</th><th>Önem</th><th>Gereksinim</th><th>🔌 Temaslı</th><th>📶 Temassız</th></tr></thead><tbody>${body}</tbody></table></body></html>`;
    const url = URL.createObjectURL(new Blob([html], { type: 'text/html' })); const a = document.createElement('a'); a.href = url; a.download = `uyumluluk-matris-${contact.scheme || 'emv'}-${Date.now()}.html`; a.click(); URL.revokeObjectURL(url);
  };

  return (
    <div className={`oda-iface ${dv.cls}`} style={{ marginBottom: 14 }}>
      <div className="oda-iface-head">
        <b>⇄ Temaslı ↔ Temassız Matris</b>
        <button className="btn-sm ghost" onClick={dl}>↧ Matris (HTML)</button>
      </div>
      <VerdictBanner cls={dv.cls} text={dv.text} counts={[
        { n: vShort(cV), label: 'temaslı', cls: cV === 'FAIL' ? 'c-bad' : cV === 'PASS' ? 'c-ok' : 'c-warn' },
        { n: vShort(clV), label: 'temassız', cls: clV === 'FAIL' ? 'c-bad' : clV === 'PASS' ? 'c-ok' : 'c-warn' },
        { n: diffs.length, label: 'fark', cls: diffs.length ? 'c-warn' : 'c-ok' },
      ]} />
      <div className="oda-info">
        <span className="oda-chip">{contact.scheme || '?'}</span>
        <span className="mono small">🔌 {cV} · 📶 {clV}</span>
        <span className={`mono small ${diffs.length ? 'st-warn' : 'st-ok'}`}>· {diffs.length} fark</span>
        <button className={`prof-chip ${onlyDiff ? 'sel' : ''}`} style={{ marginLeft: 'auto' }} onClick={() => setOnlyDiff((v) => !v)}>Sadece farklar</button>
      </div>
      {rows.length === 0 ? <p className="muted small">Gösterilecek satır yok (fark bulunamadı).</p> : cats.map((cat) => (
        <div key={cat} className="comp-cat">
          <div className="comp-cat-head">{cat}</div>
          <table className="capk-table image-tags comp-table">
            <thead><tr><th>ID</th><th>Gereksinim</th><th className="c">🔌</th><th className="c">📶</th></tr></thead>
            <tbody>
              {byCat.get(cat).map((e) => (
                <tr key={e.id} className={isDiff(e) ? 's-warn' : ''}>
                  <td className="mono b">{e.id}</td>
                  <td className="small">{e.req}</td>
                  <td className="c">{cell(e.c)}</td>
                  <td className="c">{cell(e.cl)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
    </div>
  );
}

function ComplianceResult({ res, label, busy, onRun, clear, present }) {
  const [filter, setFilter] = useState('all');
  const c = res && !res.error ? res.compliance : null;
  const v = c ? VERDICT[c.summary.verdict] : null;
  const s = c?.summary;

  // Kapsam: bu denetimin hangi spec kaynaklarına karşı, kaç kuralla yapıldığı.
  const allRules = c ? c.categories.flatMap((cat) => cat.rules) : [];
  const sevCount = { M: 0, R: 0, C: 0 };
  const bySpec = {};
  for (const r of allRules) { if (sevCount[r.sev] != null) sevCount[r.sev]++; const k = r.spec || '—'; bySpec[k] = (bySpec[k] || 0) + 1; }
  const specRows = Object.entries(bySpec).sort((a, b) => b[1] - a[1]);

  const dl = () => {
    const url = URL.createObjectURL(new Blob([reportHtml(res)], { type: 'text/html' }));
    const a = document.createElement('a'); a.href = url; a.download = `uyumluluk-${c.scheme || 'emv'}-${c.iface}-${Date.now()}.html`; a.click(); URL.revokeObjectURL(url);
  };

  return (
    <div className={`oda-iface ${v ? v.cls : ''}`}>
      <div className="oda-iface-head">
        <button className="btn" disabled={!!busy || !present} onClick={onRun}
          title={!present ? `${label} yuvada kart yok` : undefined}>{busy ? 'Denetleniyor…' : `${label} Denetle`}</button>
        {!present && !busy && <span className="iface-nocard">○ yuvada kart yok</span>}
        {c && <button className="btn-sm ghost" onClick={dl}>↧ Rapor (HTML)</button>}
        {res && <button className="btn-sm ghost" onClick={clear}>temizle</button>}
      </div>

      {!res && <p className="muted small">Kartı bu arayüze koyup <b>{label} Denetle</b>'ye bas — kart image'ı çıkarılır ve EMV çekirdek + şema (Mastercard CPV) perso kuralları çalıştırılır.</p>}
      {res?.error && <p className="err-text">✗ {res.error}</p>}

      {c && <>
        <VerdictBanner cls={v.cls} text={v.text} counts={[
          { n: s.pass, label: 'geçti', cls: 'c-ok' },
          { n: s.fail, label: 'kaldı', cls: 'c-bad' },
          { n: s.warn, label: 'uyarı', cls: 'c-warn' },
          ...(s.na ? [{ n: s.na, label: 'ilgisiz', cls: 'c-na' }] : []),
        ]} />
        {c.regression && (
          <div className="regr">
            {c.regression.first ? (
              <span className="regr-line st-extra">◷ Bu kartın ilk denetimi — geçmiş başlatıldı ({c.regression.runCount}. koşu)</span>
            ) : c.regression.regressed.length ? (
              <span className="regr-line st-bad"><b>⚠ REGRESYON</b> · {c.regression.regressed.length} kural PASS→FAIL: {c.regression.regressed.map((x) => x.id).join(', ')}</span>
            ) : c.regression.fixed.length ? (
              <span className="regr-line st-ok">✓ {c.regression.fixed.length} düzelme (FAIL→PASS): {c.regression.fixed.map((x) => x.id).join(', ')} · regresyon yok</span>
            ) : (
              <span className="regr-line st-ok">✓ Önceki koşuya göre değişiklik yok ({c.regression.runCount}. koşu)</span>
            )}
            {c.regression.recent.length > 1 && (
              <div className="regr-hist" title="Bu kartın son denetimleri (soldan sağa: eskiden yeniye)">
                {c.regression.recent.map((r, i) => (
                  <span key={i} className={`regr-run v-${vClsShort(r.verdict)}`} title={`${shortDate(r.savedAt)} · ${r.iface} · ${r.verdict} · ${r.pass}✓/${r.fail}✗/${r.warn}⚠`}>
                    {shortDate(r.savedAt)}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}
        <div className="oda-info">
          <span className="oda-chip">{c.scheme || '?'}</span>
          {c.aid && <span className="mono small">{c.aid}</span>}
          <span className="mono small muted">· AIP {c.aip}</span>
        </div>
        <div className="prof-chips" style={{ marginBottom: 8 }}>
          {[['all', 'Tümü', s.total, ''], ['pass', 'Geçti', s.pass, 'st-ok'], ['fail', 'Kaldı', s.fail, 'st-bad'], ['warn', 'Uyarı', s.warn, 'st-warn'], ['na', 'İlgisiz', s.na, 'st-extra']].map(([k, lbl, n, cls]) => (
            <button key={k} className={`prof-chip ${cls} ${filter === k ? 'sel' : ''}`} disabled={k !== 'all' && !n} onClick={() => setFilter(filter === k ? 'all' : k)}>{lbl} <b>{n}</b></button>
          ))}
        </div>
        <details className="builder cov-panel">
          <summary>Kapsam · {s.total} gereksinim · {sevCount.M} zorunlu (M) / {sevCount.R} önerilen (R) / {sevCount.C} koşullu (C) · {specRows.length} spec kaynağı</summary>
          <p className="muted small">Bu denetimin dayandığı otoriter kaynaklar — her verdikt izlenebilir (rakiplerin kapalı kurallarının aksine):</p>
          <table className="capk-table image-tags comp-table">
            <thead><tr><th>Spec kaynağı</th><th className="c">Kural</th></tr></thead>
            <tbody>
              {specRows.map(([spec, n]) => (
                <tr key={spec}><td className="small">{spec}</td><td className="c b">{n}</td></tr>
              ))}
            </tbody>
          </table>
        </details>
        {c.categories.map((cat) => {
          const rules = filter === 'all' ? cat.rules : cat.rules.filter((r) => r.status === filter);
          if (!rules.length) return null;
          return (
            <div key={cat.name} className="comp-cat">
              <div className="comp-cat-head">{cat.name}</div>
              <table className="capk-table image-tags comp-table">
                <tbody>
                  {rules.map((r) => (
                    <tr key={r.id} className={`s-${r.status}`}>
                      <td className={`c ${STATUS[r.status].cls}`} title={STATUS[r.status].label}>{STATUS[r.status].icon}</td>
                      <td className="mono b">{r.id}</td>
                      <td className="small muted" title={SEV[r.sev]}>{r.sev}</td>
                      <td className="small">{r.req}{r.spec && <span className="rule-spec">{r.spec}</span>}</td>
                      <td className="mono small val">{r.evidence || <span className="muted">{r.detail || '—'}</span>}{r.evidence && r.detail ? <span className="muted"> · {r.detail}</span> : null}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          );
        })}
      </>}
    </div>
  );
}

export function ComplianceTab({ compContact, compContactless, compBusy, runComplianceCheck, clearCompliance, contactPresent, contactlessPresent }) {
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Perso Uyumluluk / Sertifikasyon</h2>
        <span className="muted small">EMV çekirdek + Mastercard CPV · kural motoru</span>
      </div>
      <p className="muted small">Kartın perso verisini <b>makine-okunur gereksinimlere</b> karşı denetler: yapı, AFL/kayıt bütünlüğü, ODA tutarlılığı (AIP ↔ sertifika alanları), CVM, kullanım kontrolü ve <b>Mastercard CPV</b> şema kuralları. Her kural için ID · önem · PASS/FAIL · kanıt. Sonucu HTML rapor olarak dışa aktar.</p>

      {compContact?.compliance && compContactless?.compliance &&
        <MatrixView contact={compContact.compliance} contactless={compContactless.compliance} />}

      <div className="oda-grid">
        <ComplianceResult res={compContact} label="🔌 Temaslı" busy={compBusy === 'contact'} present={contactPresent}
          onRun={() => runComplianceCheck('contact')} clear={() => clearCompliance('contact')} />
        <ComplianceResult res={compContactless} label="📶 Temassız" busy={compBusy === 'contactless'} present={contactlessPresent}
          onRun={() => runComplianceCheck('contactless')} clear={() => clearCompliance('contactless')} />
      </div>
    </section>
  );
}
