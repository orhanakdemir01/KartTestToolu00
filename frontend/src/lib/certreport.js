// Konsolide sertifikasyon raporu — oturumdaki TÜM sonuçları (uyumluluk, ODA,
// EMV/kriptogram, PIN, senaryo, test, trace) tek arşivlenebilir/yazdırılabilir
// HTML rapora toplar: lab/operatör başlığı + DUT kimliği + genel verdikt.
// FIME Savvy / UL / Collis tarzı master rapor. Saf fonksiyon, React state yok.
import { tlvTreeHtml, TLV_CSS, traceText } from './report.js';

const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const RANK = { fail: 0, warn: 1, pass: 2 };

// ── Verdikt türetme ────────────────────────────────────────────────────────
function complianceVerdict(res) {
  const c = res && !res.error ? res.compliance : null;
  if (!c) return null;
  const v = c.summary.verdict;
  return v === 'FAIL' ? { cls: 'fail', text: '✗ UYUMSUZ' }
    : v === 'PASS_WITH_WARN' ? { cls: 'warn', text: '◐ UYARILARLA UYUMLU' }
      : { cls: 'pass', text: '✓ UYUMLU' };
}
function odaVerdict(res) {
  const oda = res && !res.error ? res.oda : null;
  if (!oda) return null;
  const dyns = oda.dynamics?.length ? oda.dynamics : (oda.dynamic ? [oda.dynamic] : []);
  const real = dyns.filter((d) => d.kind !== 'none');
  const dynOk = (d) => (d.hashMatch != null ? d.hashMatch : d.ok);
  const certOk = !!oda.ok;
  const allDynOk = real.length > 0 && real.every(dynOk);
  const anyPartial = real.some((d) => !dynOk(d) && d.structOk);
  if (!oda.capkFound) return { cls: 'fail', text: '✗ CAPK YOK' };
  if (certOk && allDynOk) return { cls: 'pass', text: '✓ GEÇTİ' };
  if (certOk && !real.length) return { cls: 'warn', text: '◐ ZİNCİR OK · İMZA YOK' };
  if (certOk && anyPartial && !real.some((d) => !dynOk(d) && !d.structOk)) return { cls: 'warn', text: '◐ KISMİ' };
  return { cls: 'fail', text: '✗ BAŞARISIZ' };
}
function cryptoVerdict(emv) {
  const v = emv?.genac?.verify;
  if (!v || v.match == null) return null;
  if (v.match) return { cls: 'pass', text: '✓ ARQC DOĞRULANDI' };
  // Uyuşmazlık: karta PAN-bağlı doğru anahtar denendiyse gerçek kripto hatası (FAIL);
  // yalnızca varsayılan anahtar denendiyse doğrulanamadı (WARN) — sertifikasyonu batırmaz.
  return v.keyPanMatch
    ? { cls: 'fail', text: '✗ ARQC UYUŞMUYOR' }
    : { cls: 'warn', text: '◐ ARQC DOĞRULANAMADI (PAN anahtarı yok)' };
}
function overall(verdicts) {
  const present = verdicts.filter(Boolean);
  if (!present.length) return { cls: 'warn', text: '◐ VERİ YETERSİZ' };
  const worst = Math.min(...present.map((v) => RANK[v.cls]));
  return worst === 0 ? { cls: 'fail', text: '✗ SERTİFİKASYON BAŞARISIZ' }
    : worst === 1 ? { cls: 'warn', text: '◐ UYARILARLA GEÇTİ' }
      : { cls: 'pass', text: '✓ SERTİFİKASYON GEÇTİ' };
}

// ── Bölüm üreticileri ──────────────────────────────────────────────────────
const kv = (pairs) => `<table>${pairs.filter(([, v]) => v != null && v !== '').map(([k, v]) => `<tr><td class="k">${esc(k)}</td><td class="v">${esc(v)}</td></tr>`).join('')}</table>`;

function complianceSection(res, ifaceLabel) {
  const c = res.compliance; const v = complianceVerdict(res); const s = c.summary;
  const ST = { pass: '✓', fail: '✗', warn: '⚠', na: '—' };
  const SEV = { M: 'Zorunlu', R: 'Önerilen', C: 'Koşullu' };
  const rows = c.categories.map((cat) => `<tr class="cat"><td colspan="5">${esc(cat.name)}</td></tr>` +
    cat.rules.map((r) => `<tr class="s-${r.status}"><td>${ST[r.status] || ''}</td><td class="mono">${esc(r.id)}</td><td>${esc(SEV[r.sev] || r.sev)}</td><td>${esc(r.req)}</td><td class="mono">${esc(r.evidence || r.detail || '')}</td></tr>`).join('')).join('');
  return `<h3>${esc(ifaceLabel)} · ${esc(c.scheme || '?')}${c.aid ? ` · ${esc(c.aid)}` : ''} <span class="vb ${v.cls}">${esc(v.text)}</span></h3>
    <p class="counts">${s.pass} geçti · ${s.fail} kaldı · ${s.warn} uyarı · ${s.na} ilgisiz (${s.total} kural)</p>
    <table class="grid"><tr><th></th><th>ID</th><th>Önem</th><th>Gereksinim</th><th>Kanıt / Not</th></tr>${rows}</table>`;
}

function odaSection(res, ifaceLabel) {
  const oda = res.oda; const v = odaVerdict(res);
  const dyns = oda.dynamics?.length ? oda.dynamics : (oda.dynamic ? [oda.dynamic] : []);
  const real = dyns.filter((d) => d.kind !== 'none');
  const dynOk = (d) => (d.hashMatch != null ? d.hashMatch : d.ok);
  const KIND = { CDA: 'CDA', DDA: 'DDA', fDDA: 'fast DDA (fDDA)' };
  const rows = [
    ['CAPK', oda.capkFound ? `✓ RID ${oda.rid} · idx ${oda.capkIndex}` : `✗ bulunamadı (RID ${oda.rid} idx ${oda.capkIndex})`],
    ['Issuer Public Key', oda.issuerPK?.ok ? '✓ sertifika zinciri doğrulandı' : '✗ doğrulanamadı'],
    ['ICC Public Key', oda.iccPK?.ok ? '✓ sertifika zinciri doğrulandı' : '✗ doğrulanamadı'],
    ...real.map((d) => [`${KIND[d.kind] || d.kind} dinamik imza`, dynOk(d) ? '✓ SDAD hash eşleşti' : d.structOk ? '◐ yapısal ✓, hash eşleşmedi' : '✗ doğrulanamadı']),
    ...(real.length ? [] : [['Dinamik imza', '— (kart AIP\'de DDA/CDA sunmuyor veya üretilmedi)']]),
  ];
  return `<h3>${esc(ifaceLabel)} · ${esc(res.scheme || '?')} <span class="vb ${v.cls}">${esc(v.text)}</span></h3>${kv(rows)}`;
}

function cryptoSection(emv) {
  const g = emv.genac; const v = g.verify;
  let out = `<h3>Kriptogram (${esc(g.source || 'GENERATE AC')})</h3>` + kv([
    ['CID', `${g.cid}${g.cid === '80' ? ' (ARQC)' : g.cid === '40' ? ' (TC)' : g.cid === '00' ? ' (AAC)' : ''}`],
    ['ATC', g.atc], ['ARQC / Cryptogram', g.arqc], ['IAD', g.iad],
  ]);
  if (v && v.match != null) {
    const realFail = !v.match && v.keyPanMatch;   // PAN-bağlı anahtar denendi, yine de tutmadı
    const cls = v.match ? 'pass' : realFail ? 'fail' : 'muted';
    const label = v.match ? '✓ ARQC DOĞRULANDI'
      : realFail ? '✗ ARQC UYUŞMUYOR'
        : '◐ ARQC DOĞRULANAMADI — bu PAN için doğru issuer anahtarı yüklü değil';
    out += `<p class="${cls}"><b>${label}</b> — ${esc(v.keyLabel || '')}${v.keyLevel ? ` (${esc(v.keyLevel)})` : ''}</p>` + kv([
      ['Hesaplanan', v.computed], ['Kart ARQC', v.cardArqc], ['Session Key', v.sessionKey], ['MAC girdisi', v.inputData],
    ]);
    if (!v.match && !realFail) out += `<p class="muted">Not: Kripto doğrulama tamamlanamadı (kart hatası değil). Doğru anahtarı "İşlem Anahtarları" sekmesinden yükleyip tekrar deneyin.</p>`;
  } else if (v?.noKey) {
    out += `<p class="muted">⚠ Bu PAN için işlem anahtarı yok — ARQC doğrulanamadı.</p>`;
  }
  return out;
}

function pinSection(pinResult, verifyResult) {
  let out = '';
  if (pinResult && !pinResult.error) {
    out += `<h3>PIN Değiştir (${esc(pinResult.scheme || '')})</h3>` +
      `<p class="${pinResult.ok ? 'pass' : 'fail'}"><b>${pinResult.ok ? '✓ BAŞARILI' : '✗ BAŞARISIZ'}</b> — SW ${esc(pinResult.sw)} ${esc(pinResult.swText || '')}</p>` +
      kv([['Şema / CVN', pinResult.scheme], ['Anahtar', pinResult.keyLabel], ['PAN', pinResult.pan], ['ATC', pinResult.atc], ['PIN Block', pinResult.pinBlock], ['MAC', pinResult.mac]]);
  }
  if (verifyResult && !verifyResult.error) {
    const okv = verifyResult.correct;
    out += `<h3>PIN Doğrula</h3>` +
      `<p class="${okv ? 'pass' : 'fail'}"><b>${verifyResult.blocked ? '⛔ PIN BLOKELİ' : okv ? '✓ PIN DOĞRU' : '✗ PIN YANLIŞ'}</b> — SW ${esc(verifyResult.sw)}</p>` +
      kv([['PAN', verifyResult.pan], ['Kalan deneme', verifyResult.triesLeft], ['PTC (önce→sonra)', verifyResult.ptcBefore != null ? `${verifyResult.ptcBefore} → ${verifyResult.ptcAfter}` : null]]);
  }
  return out;
}

function scenarioSection(sr) {
  const DEC = { TC: 'offline onay', ARQC: 'online', AAC: 'ret' };
  const rows = sr.results.map((s) => `<tr class="${s.error ? 'rf' : ''}"><td>${s.error ? '✗' : s.match ? '✓' : '≠'}</td><td>${esc(s.name)}</td><td class="mono">${esc(s.expect)}</td><td class="mono">${s.error ? 'HATA' : esc(s.decision || '—')}${s.decision && DEC[s.decision] ? ` (${DEC[s.decision]})` : ''}</td><td class="mono">${esc(s.ac || s.error || '—')}</td></tr>`).join('');
  return `<h3>Senaryo (L3) — Terminal koşulu × kart kararı</h3>
    <table class="grid"><tr><th></th><th>Senaryo</th><th>İstenen</th><th>Kart Kararı</th><th>Cryptogram</th></tr>${rows}</table>
    <p class="muted">≠ = kart, terminalin istediğinden farklı karar verdi (kartın gerçek risk davranışı — hata değil).</p>`;
}

function traceSection(trace) {
  let out = '';
  for (const t of trace) {
    if (t.apdu) {
      const a = t.apdu; const cls = a.ok ? 'ok' : (a.benign ? 'benign' : 'warn');
      out += `<div class="te ${cls}"><div class="te-head"><span class="te-time">${esc(t.time)}</span> <b>${esc(a.name)}</b> <span class="te-sw">${esc(a.sw)}</span> <span class="te-swt">${esc(a.swText)}</span>${a.durationMs != null ? ` <span class="te-ms">${a.durationMs}ms</span>` : ''}</div>`
        + (a.command ? `<div class="te-apdu">→ ${esc(a.command)}</div>` : '')
        + (a.response ? `<div class="te-apdu">← ${esc(a.response)}</div>` : '')
        + (a.tlv?.nodes?.length ? `<div class="te-tlv">${tlvTreeHtml(a.tlv.nodes, esc)}</div>` : '') + `</div>`;
    } else {
      const strip = String(t.verify ? traceText(t) : (t.msg || '')).replace(/[═►◆↳▸▾•]/g, '').replace(/\s{2,}/g, ' ').trim();
      out += `<div class="te event"><span class="te-time">${esc(t.time)}</span> ${esc(strip)}</div>`;
    }
  }
  return out;
}

// ── Ana rapor ──────────────────────────────────────────────────────────────
// Denetimin dayandığı spec kaynakları (kural id'sine göre tekilleştirilmiş, iki
// arayüz birleştirilmiş) → audit izlenebilirliği. [ [spec, kuralSayısı], … ]
function specCoverage(comps) {
  const ruleSpec = {};
  for (const res of comps) {
    const c = res && !res.error ? res.compliance : null;
    if (!c) continue;
    for (const cat of c.categories) for (const r of cat.rules) ruleSpec[r.id] = r.spec || '—';
  }
  const bySpec = {};
  for (const id in ruleSpec) { const k = ruleSpec[id]; bySpec[k] = (bySpec[k] || 0) + 1; }
  return Object.entries(bySpec).sort((a, b) => b[1] - a[1]);
}

export function buildCertReportHtml(ctx) {
  const {
    meta = {}, dut, card, emv, testResult, trace = [], readers = [], mode,
    compContact, compContactless, odaContact, odaContactless,
    pinResult, verifyResult, scenarioResult,
  } = ctx;
  const ts = new Date().toLocaleString('tr-TR');

  const compC = complianceVerdict(compContact), compCL = complianceVerdict(compContactless);
  const odaC = odaVerdict(odaContact), odaCL = odaVerdict(odaContactless);
  const cryptoV = cryptoVerdict(emv);
  const testV = testResult?.results ? (testResult.ok ? { cls: 'pass' } : { cls: 'fail' }) : null;
  const ov = overall([compC, compCL, odaC, odaCL, cryptoV, testV]);

  let n = 0; const H = (t) => `<h2>${++n} · ${esc(t)}</h2>`;
  let body = '';

  // DUT kimliği
  const kernel = compContactless?.compliance?.kernel || null;
  if (dut) {
    body += `<section class="dut">${H('Test Edilen Kart (DUT)')}${kv([
      ['Şema', dut.scheme], ['Temassız Kernel', kernel], ['PAN (maskeli)', dut.pan], ['AID', dut.aid],
      ['Son kullanma', dut.expiry], ['Kart sahibi', dut.cardholder], ['ATC', dut.atc], ['Protokol', dut.protocol], ['ATR', dut.atr],
    ])}</section>`;
  }

  // Denetim tabanı — hangi otoriter spec kaynaklarına karşı denetlendiği (audit izi)
  const specRows = specCoverage([compContact, compContactless]);
  if (specRows.length) {
    body += `<section>${H('Denetim Tabanı — Spec Kapsamı')}
      <p class="muted">Bu sertifikasyon aşağıdaki otoriter kaynaklara karşı yapıldı; her verdikt ilgili spec'e izlenebilir.</p>
      <table class="grid"><tr><th>Spec Kaynağı</th><th>Kural</th></tr>${specRows.map(([s, cnt]) => `<tr><td>${esc(s)}</td><td>${cnt}</td></tr>`).join('')}</table></section>`;
  }

  // Uyumluluk
  if (compContact?.compliance || compContactless?.compliance) {
    body += `<section>${H('Perso Uyumluluk / Sertifikasyon')}`;
    if (compContact?.compliance) body += complianceSection(compContact, '🔌 Temaslı');
    if (compContactless?.compliance) body += complianceSection(compContactless, '📶 Temassız');
    body += `</section>`;
  }

  // ODA
  if (odaContact?.oda || odaContactless?.oda) {
    body += `<section>${H('Offline Veri Doğrulama (ODA)')}`;
    if (odaContact?.oda) body += odaSection(odaContact, '🔌 Temaslı');
    if (odaContactless?.oda) body += odaSection(odaContactless, '📶 Temassız');
    body += `</section>`;
  }

  // EMV veri + kriptogram
  if (emv?.cardData?.pan) {
    const cd = emv.cardData;
    body += `<section>${H('EMV Kart Verisi & Kriptogram')}` + kv([
      ['Uygulama', emv.applications?.[0]?.label], ['AID', emv.applications?.[0]?.aid],
      ['PAN', cd.panFormatted], ['Son kullanma', cd.expiry], ['Kart sahibi', cd.cardholderName],
      ['Service Code', cd.serviceCode], ['AIP', emv.aip], ['AFL', emv.afl], ['Okunan kayıt', emv.records?.length],
    ]);
    if (emv.genac) body += cryptoSection(emv);
    body += `</section>`;
  }

  // PIN
  const pinBody = pinSection(pinResult, verifyResult);
  if (pinBody) body += `<section>${H('PIN İşlemleri')}${pinBody}</section>`;

  // Senaryo
  if (scenarioResult?.results?.length) body += `<section>${H('İşlem Senaryoları')}${scenarioSection(scenarioResult)}</section>`;

  // Test
  if (testResult?.results) {
    body += `<section>${H('Test Sonuçları — ' + (testResult.name || ''))}
      <p class="${testResult.ok ? 'pass' : 'fail'}"><b>${testResult.ok ? '✓ TÜM TESTLER GEÇTİ' : '✗ BAŞARISIZ'}</b> — ${testResult.passed}/${testResult.total} adım</p>
      <table class="grid"><tr><th></th><th>Adım</th><th>Beklenen</th><th>Gelen</th><th>Açıklama</th></tr>` +
      testResult.results.map((r) => `<tr class="${r.pass ? 'rp' : 'rf'}"><td>${r.pass ? '✓' : '✗'}</td><td>${esc(r.name)}</td><td class="mono">${esc(r.expectedSw)}</td><td class="mono">${esc(r.actualSw)}</td><td>${esc(r.reason)}</td></tr>`).join('') +
      `</table></section>`;
  }

  // Onay / imza bloğu (resmi sertifikasyon belgesi öğesi)
  body += `<section class="sign">${H('Onay')}
    <table class="sign-t"><tr>
      <td>Denetleyen (operatör): <b>${esc(meta.operator || '—')}</b><br><br>İmza: ____________________</td>
      <td>Laboratuvar / kurum: <b>${esc(meta.lab || '—')}</b><br>Referans: ${esc(meta.ref || '—')}<br>Tarih: ${esc(ts)}</td>
    </tr></table>
    <p class="muted">Bu rapor KartTest tarafından üretilmiştir; genel verdikt tüm denetlenen bölümlerin en kötüsüdür ve her kural yukarıdaki spec kaynaklarına izlenebilir.</p></section>`;

  // Trace eki
  if (trace.length) body += `<section>${H('Ek · İşlem Trace')}${traceSection(trace)}</section>`;

  if (!body) body = '<p>Rapora dahil edilecek veri yok. Önce kampanya çalıştırın veya kart okuyun.</p>';

  const metaLine = [
    meta.lab && `Lab: ${esc(meta.lab)}`, meta.operator && `Operatör: ${esc(meta.operator)}`,
    meta.ref && `Referans: ${esc(meta.ref)}`, `Tarih: ${esc(ts)}`,
    `Okuyucu: ${esc(readers[0] || '—')}`, `Mod: ${esc(mode || '—')}`,
  ].filter(Boolean).join(' · ');

  return `<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8"><title>KartTest — Sertifikasyon Raporu</title>
  <style>
    body{font-family:'Segoe UI',Arial,sans-serif;color:#1a1a1a;max-width:860px;margin:0 auto;padding:32px;}
    h1{font-size:23px;border-bottom:3px solid #15803d;padding-bottom:8px;margin-bottom:6px;}
    .meta{color:#555;font-size:12.5px;margin:6px 0 18px;}
    .overall{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;padding:14px 18px;border-radius:12px;border:1px solid;margin:0 0 22px;font-size:17px;font-weight:800;}
    .overall.pass{background:#e9f6ee;border-color:#c3e6d1;color:#157a43;}
    .overall.warn{background:#fdf4e3;border-color:#f2ddb0;color:#b45309;}
    .overall.fail{background:#fdecea;border-color:#f0cdc8;color:#c0392b;}
    .overall .sub{font-size:12px;font-weight:600;color:#555;}
    h2{font-size:16px;color:#15803d;margin-top:26px;border-bottom:1px solid #ddd;padding-bottom:4px;}
    h3{font-size:13.5px;color:#333;margin-top:16px;}
    .vb{display:inline-block;font-size:12px;font-weight:800;padding:2px 9px;border-radius:6px;vertical-align:middle;margin-left:6px;}
    .vb.pass{background:#d8f5df;color:#177a35;}.vb.warn{background:#fbf2d0;color:#8a6d10;}.vb.fail{background:#fadadd;color:#a01523;}
    .counts{font-size:12.5px;color:#555;margin:4px 0 8px;}
    table{width:100%;border-collapse:collapse;font-size:12.5px;margin:8px 0;}
    td,th{padding:6px 10px;text-align:left;vertical-align:top;}
    table.grid td,table.grid th{border:1px solid #ddd;}
    th{background:#eef4ef;font-size:11px;text-transform:uppercase;}
    tr.cat td{background:#eef1f5;font-weight:700;}
    tr.s-fail td{background:#fdecee;}tr.s-warn td{background:#fdf6e3;}tr.s-na td{color:#999;}
    td.k{color:#666;width:180px;}td.v{font-family:'Consolas',monospace;word-break:break-all;}
    .mono,td.mono{font-family:'Consolas',monospace;}
    .pass{color:#15803d;}.fail{color:#b91c1c;}.muted{color:#888;font-size:12px;}
    tr.rp td:first-child{color:#15803d;font-weight:bold;}tr.rf td:first-child{color:#b91c1c;font-weight:bold;}tr.rf{background:#fef2f2;}
    .sign-t td{border:1px solid #ccc;padding:16px;width:50%;font-size:12.5px;vertical-align:top;}
    ${TLV_CSS}
    @media print{body{padding:0;}.te,section,tr{break-inside:avoid;}}
  </style></head><body>
  <h1>▣ KartTest — Sertifikasyon Raporu</h1>
  <div class="meta">${metaLine}</div>
  <div class="overall ${ov.cls}"><span>${esc(ov.text)}</span><span class="sub">Genel verdikt — tüm bölümlerin en kötüsü</span></div>
  ${meta.notes ? `<p class="muted"><b>Not:</b> ${esc(meta.notes)}</p>` : ''}
  ${body}
  </body></html>`;
}
