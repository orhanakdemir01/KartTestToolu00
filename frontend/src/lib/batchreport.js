// Parti (batch) raporu: bir perso QA partisinde sırayla işlenen tüm kartların
// tek birleşik HTML özeti — kart başına verdikt + PASS/FAIL dağılımı.
export function buildBatchReportHtml(rows, meta) {
  const esc = (s) => String(s ?? '').replace(/[&<>]/g, (x) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[x]));
  const n = rows.length;
  const pass = rows.filter((r) => r.verdict === 'PASS').length;
  const warn = rows.filter((r) => r.verdict === 'PASS_WITH_WARN').length;
  const fail = rows.filter((r) => r.verdict === 'FAIL').length;
  const vTxt = (v) => (v === 'FAIL' ? 'UYUMSUZ' : v === 'PASS' ? 'UYUMLU' : 'UYARILI');
  const vCls = (v) => (v === 'FAIL' ? 'fail' : v === 'PASS' ? 'pass' : 'warn');
  const body = rows.map((r, i) => `<tr class="v-${vCls(r.verdict)}"><td>${i + 1}</td><td class="mono">${esc(r.pan)}</td><td>${esc(r.scheme)}</td><td>${esc(r.iface)}</td><td><b>${vTxt(r.verdict)}</b></td><td>${r.pass}✓ ${r.fail}✗ ${r.warn}⚠</td><td>${r.regressed || ''}</td><td>${esc(r.time)}</td></tr>`).join('');
  const when = (() => { try { return new Date().toLocaleString('tr-TR'); } catch { return ''; } })();
  return `<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8"><title>Parti Raporu — ${n} kart</title>
<style>body{font-family:system-ui,Segoe UI,sans-serif;margin:24px;color:#1a1d21;font-size:13px}h1{font-size:19px;margin:0 0 4px}
.meta{color:#555;font-size:12px}.sum{display:flex;gap:10px;margin:14px 0;flex-wrap:wrap}
.chip{padding:6px 12px;border-radius:8px;font-weight:700}.chip.t{background:#eef1f5}.chip.p{background:#d8f5df;color:#177a35}.chip.w{background:#fbf2d0;color:#8a6d10}.chip.f{background:#fadadd;color:#a01523}
table{border-collapse:collapse;width:100%;margin-top:8px}th,td{border:1px solid #ddd;padding:5px 8px;text-align:left}th{background:#f4f5f7;font-size:11px;text-transform:uppercase}
tr.v-fail td{background:#fdecee}tr.v-warn td{background:#fdf6e3}.mono{font-family:ui-monospace,Consolas,monospace}
@media print{tr{page-break-inside:avoid}}</style></head><body>
<h1>KartTest — Parti / Batch Sertifikasyon Raporu</h1>
<p class="meta">${meta?.lab ? esc(meta.lab) + ' · ' : ''}${meta?.operator ? 'Operatör: ' + esc(meta.operator) + ' · ' : ''}${meta?.ref ? esc(meta.ref) + ' · ' : ''}${when}</p>
<div class="sum"><span class="chip t">${n} kart</span><span class="chip p">${pass} UYUMLU</span><span class="chip w">${warn} uyarılı</span><span class="chip f">${fail} UYUMSUZ</span></div>
<table><thead><tr><th>#</th><th>PAN (maskeli)</th><th>Şema</th><th>Arayüz</th><th>Verdikt</th><th>Sonuç</th><th>Regr.</th><th>Zaman</th></tr></thead><tbody>${body}</tbody></table>
</body></html>`;
}
