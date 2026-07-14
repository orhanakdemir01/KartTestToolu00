// Report/export helpers — pure functions, no React state.

// Flatten a trace entry to a single text line (for CSV/report export)
export function traceText(t) {
  if (t.apdu) {
    const a = t.apdu;
    return `${a.name}: → ${a.command} ← ${a.response} [${a.sw}] ${a.swText}${a.durationMs != null ? ` (${a.durationMs}ms)` : ''}`;
  }
  if (t.verify) {
    const v = t.verify;
    return `${v.match ? 'ARQC DOĞRULANDI' : 'ARQC UYUŞMUYOR'} (${v.keyLabel} · ${v.method}) hesaplanan=${v.computed} kart=${v.cardArqc} session=${v.sessionKey}`;
  }
  return t.msg || '';
}

// Structured column fields for one trace entry — for a clean multi-column CSV.
// Decorative symbols (═ → ← ◆ ↳ ▸) are stripped so no stray glyphs remain.
export function traceFields(t) {
  const strip = (s) => String(s || '').replace(/[═►◆↳▸▾→←•]/g, ' ').replace(/\s{2,}/g, ' ').trim();
  if (t.apdu) {
    const a = t.apdu;
    return { time: t.time, kind: t.kind, step: a.name || '', command: a.command || '', response: a.response || '', sw: a.sw || '', swText: a.swText || '', ms: a.durationMs != null ? String(a.durationMs) : '' };
  }
  if (t.verify) {
    const v = t.verify;
    return { time: t.time, kind: t.kind, step: `ARQC ${v.match ? 'DOĞRULANDI' : 'UYUŞMUYOR'} (${v.keyLabel || ''} ${v.method || ''})`.trim(), command: '', response: v.cardArqc || '', sw: '', swText: `hesaplanan=${v.computed || ''}`, ms: '' };
  }
  return { time: t.time, kind: t.kind, step: strip(t.msg), command: '', response: '', sw: '', swText: '', ms: '' };
}

// Build a UTF-8 CSV from the trace. Uses ';' as the delimiter (the list separator
// Excel expects in Turkish/European locales — a comma-delimited file lands in one
// column there) and a BOM so Turkish characters/symbols decode correctly.
export function traceCsv(trace) {
  const cols = ['Zaman', 'Tür', 'Adım / Mesaj', 'Komut', 'Yanıt', 'SW', 'Açıklama', 'Süre(ms)'];
  const esc = (s) => `"${String(s ?? '').replace(/"/g, '""')}"`;
  const line = (f) => [f.time, f.kind, f.step, f.command, f.response, f.sw, f.swText, f.ms].map(esc).join(';');
  return '﻿' + cols.map(esc).join(';') + '\r\n' + trace.map((t) => line(traceFields(t))).join('\r\n');
}

// Render a TLV node tree to indented HTML (shared by the session report and the
// card-image report). `esc` escapes HTML. Each node: tag · name · len + value.
export function tlvTreeHtml(nodes, esc) {
  const textual = (a) => { if (!a || !/[A-Za-z]/.test(a)) return false; const dots = (a.match(/\./g) || []).length; return dots / a.length < 0.25; };
  const rec = (list, depth) => (list || []).map((n) => {
    const pad = depth * 18;
    const head = `<div class="tl-row" style="margin-left:${pad}px"><span class="tl-tag">${esc(n.tag)}</span> <span class="tl-name">${esc(n.name || (n.constructed ? '(constructed)' : '(bilinmeyen tag)'))}</span> <span class="tl-len">len ${n.length}</span></div>`;
    const val = n.constructed ? '' : `<div class="tl-val" style="margin-left:${pad + 18}px">${esc(n.value || '—')}${textual(n.ascii) ? ` <span class="tl-ascii">"${esc(n.ascii)}"</span>` : ''}</div>`;
    const dec = (n.decoded || []).map((d) => `<div class="tl-dec" style="margin-left:${pad + 18}px">↳ ${esc(d)}</div>`).join('');
    const kids = (n.constructed && n.children?.length) ? rec(n.children, depth + 1) : '';
    return head + val + dec + kids;
  }).join('');
  return rec(nodes, 0);
}

// Shared CSS for the TLV tree blocks (used by both HTML reports).
export const TLV_CSS = `
  .te{border:1px solid #e2e6ee;border-radius:6px;margin:8px 0;padding:8px 10px;font-size:12.5px;}
  .te.ok{border-left:3px solid #15803d;}.te.warn{border-left:3px solid #d97706;}
  .te.benign{border-left:3px solid #cbd5e1;color:#64748b;}
  .te.event{background:#f6f8fc;border-style:dashed;padding:5px 10px;}
  .te-head{display:flex;gap:8px;align-items:center;flex-wrap:wrap;}
  .te-time{color:#888;font-family:'Consolas',monospace;font-size:11px;}
  .te-sw{font-family:'Consolas',monospace;font-weight:700;background:#e8f5ee;color:#15803d;padding:1px 6px;border-radius:4px;}
  .te-swt{color:#666;}.te-ms{color:#8b5cf6;font-size:11px;margin-left:auto;}
  .te-apdu{font-family:'Consolas',monospace;color:#444;margin-top:4px;word-break:break-all;font-size:11.5px;}
  .te-tlv{margin-top:6px;border-top:1px dashed #e2e6ee;padding-top:6px;}
  .tl-row{margin:2px 0;}
  .tl-tag{font-family:'Consolas',monospace;font-weight:700;background:#eef2fb;color:#2563eb;padding:0 5px;border-radius:3px;}
  .tl-name{color:#333;}.tl-len{color:#999;font-size:11px;}
  .tl-val{font-family:'Consolas',monospace;color:#555;word-break:break-all;font-size:11.5px;}
  .tl-ascii{color:#0a7d3c;}.tl-dec{color:#8b5cf6;font-size:11.5px;}`;

// Build a self-contained printable HTML report from the current session data.
// ctx: { card, emv, testResult, trace, readers, mode }
export function buildReportHtml(ctx) {
  const { card, emv, testResult, trace = [], readers = [], mode } = ctx;
  const ts = new Date().toLocaleString('tr-TR');
  const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const rows = (pairs) => pairs.filter(([, v]) => v != null && v !== '').map(([k, v]) => `<tr><td class="k">${esc(k)}</td><td class="v">${esc(v)}</td></tr>`).join('');

  let body = '';

  // Card / ATR
  if (card) {
    body += `<section><h2>1 · Kart Bilgisi</h2>
      <table>${rows([
        ['Okuyucu', card.reader], ['Mod', 'Gerçek okuyucu'],
        ['ATR', card.atr], ['Protokol', card.protocol],
        ['Desteklenen', card.atrDecoded?.protocols?.join(', ')],
        ['Tarihçe (ASCII)', card.atrDecoded?.historicalAscii],
      ])}</table>`;
    if (card.atrDecoded?.fields) {
      body += `<h3>ATR Bayt Çözümleme</h3><table class="grid"><tr><th>Bayt</th><th>Değer</th><th>Anlam</th></tr>` +
        card.atrDecoded.fields.map((f) => `<tr><td>${esc(f.name)}</td><td class="mono">${esc(f.value)}</td><td>${esc(f.desc)}</td></tr>`).join('') + `</table>`;
    }
    body += `</section>`;
  }

  // EMV card data + analysis
  if (emv?.cardData?.pan) {
    const cd = emv.cardData;
    body += `<section><h2>2 · EMV Kart Verisi</h2>
      <table>${rows([
        ['Uygulama', emv.applications?.[0]?.label], ['AID', emv.applications?.[0]?.aid],
        ['PAN', cd.panFormatted], ['Son Kullanma', cd.expiry], ['Kart Sahibi', cd.cardholderName],
        ['PAN Seq', cd.panSequence], ['Service Code', cd.serviceCode],
        ['AIP', emv.aip], ['AFL', emv.afl], ['Track 2', cd.track2], ['Okunan kayıt', emv.records?.length],
      ])}</table>`;
    if (emv.analysis) {
      const a = emv.analysis;
      if (a.aip?.length) body += `<h3>Kart Yetenekleri (AIP)</h3><ul>${a.aip.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>`;
      if (a.cvm?.length) body += `<h3>Doğrulama Yöntemleri (CVM)</h3><ol>${a.cvm.map((x) => `<li>${esc(x)}</li>`).join('')}</ol>`;
      if (a.serviceCode) body += `<h3>Service Code · ${esc(a.serviceCode.code)}</h3><ul>` +
        `<li>Değişim: ${esc(a.serviceCode.interchange)}</li><li>Yetkilendirme: ${esc(a.serviceCode.authorization)}</li><li>Hizmet: ${esc(a.serviceCode.services)}</li></ul>`;
      if (a.usageControl?.length) body += `<h3>Kullanım Kontrolü (AUC)</h3><ul>${a.usageControl.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>`;
      if (a.issuerCountry || a.currency) body += `<h3>Issuer / Para Birimi</h3><ul>` +
        `${a.issuerCountry ? `<li>Ülke: ${esc(a.issuerCountry)}</li>` : ''}${a.currency ? `<li>Para birimi: ${esc(a.currency)}</li>` : ''}</ul>`;
    }
    body += `</section>`;
  }

  // Test results
  if (testResult?.results) {
    body += `<section><h2>3 · Test Sonuçları — ${esc(testResult.name)}</h2>
      <p class="${testResult.ok ? 'pass' : 'fail'}"><b>${testResult.ok ? '✓ TÜM TESTLER GEÇTİ' : '✗ BAŞARISIZ'}</b> — ${testResult.passed}/${testResult.total} adım geçti</p>
      <table class="grid"><tr><th>Durum</th><th>Adım</th><th>Beklenen</th><th>Gelen</th><th>Açıklama</th></tr>` +
      testResult.results.map((r) => `<tr class="${r.pass ? 'rp' : 'rf'}"><td>${r.pass ? '✓' : '✗'}</td><td>${esc(r.name)}</td><td class="mono">${esc(r.expectedSw)}</td><td class="mono">${esc(r.actualSw)}</td><td>${esc(r.reason)}</td></tr>`).join('') +
      `</table></section>`;
  }

  // Trace — APDU steps with their parsed TLV tree (records show every EMV tag
  // sequentially, nested, exactly like the on-screen trace).
  if (trace.length) {
    body += `<section><h2>4 · İşlem Trace</h2>`;
    for (const t of trace) {
      if (t.apdu) {
        const a = t.apdu;
        const cls = a.ok ? 'ok' : (a.benign ? 'benign' : 'warn');
        body += `<div class="te ${cls}">`
          + `<div class="te-head"><span class="te-time">${esc(t.time)}</span> <b>${esc(a.name)}</b> <span class="te-sw">${esc(a.sw)}</span> <span class="te-swt">${esc(a.swText)}</span>${a.durationMs != null ? ` <span class="te-ms">${a.durationMs}ms</span>` : ''}</div>`
          + (a.command ? `<div class="te-apdu">→ ${esc(a.command)}</div>` : '')
          + (a.response ? `<div class="te-apdu">← ${esc(a.response)}</div>` : '')
          + (a.tlv?.nodes?.length ? `<div class="te-tlv">${tlvTreeHtml(a.tlv.nodes, esc)}</div>` : '')
          + `</div>`;
      } else {
        const strip = String(t.verify ? traceText(t) : (t.msg || '')).replace(/[═►◆↳▸▾•]/g, '').replace(/\s{2,}/g, ' ').trim();
        body += `<div class="te event"><span class="te-time">${esc(t.time)}</span> ${esc(strip)}</div>`;
      }
    }
    body += `</section>`;
  }

  if (!body) body = '<p>Rapora dahil edilecek veri yok. Önce kart okuyun veya test çalıştırın.</p>';

  return `<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8"><title>KartTest Raporu</title>
  <style>
    body{font-family:'Segoe UI',Arial,sans-serif;color:#1a1a1a;max-width:820px;margin:0 auto;padding:32px;}
    h1{font-size:22px;border-bottom:3px solid #2563eb;padding-bottom:8px;}
    .meta{color:#666;font-size:13px;margin:6px 0 24px;}
    h2{font-size:16px;color:#2563eb;margin-top:28px;border-bottom:1px solid #ddd;padding-bottom:4px;}
    h3{font-size:13px;color:#444;margin-top:16px;text-transform:uppercase;letter-spacing:.5px;}
    table{width:100%;border-collapse:collapse;font-size:13px;margin:8px 0;}
    td,th{padding:6px 10px;text-align:left;}
    table.grid td,table.grid th{border:1px solid #ddd;}
    th{background:#f0f4fa;}
    td.k{color:#666;width:160px;}td.v{font-family:monospace;}
    .mono,td.mono{font-family:'Consolas',monospace;}
    ul,ol{font-size:13px;line-height:1.6;}
    .pass{color:#15803d;}.fail{color:#b91c1c;}
    tr.rp td:first-child{color:#15803d;font-weight:bold;}tr.rf td:first-child{color:#b91c1c;font-weight:bold;}tr.rf{background:#fef2f2;}
    ${TLV_CSS}
    @media print{body{padding:0;}.te{break-inside:avoid;}}
  </style></head><body>
  <h1>▣ KartTest — Test Raporu</h1>
  <div class="meta">Oluşturulma: ${esc(ts)} · Okuyucu: ${esc(readers[0] || '—')} · Mod: ${esc(mode || '—')}</div>
  ${body}
  </body></html>`;
}
