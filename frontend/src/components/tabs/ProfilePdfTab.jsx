import { useRef, useState } from 'react';

// "PDF Profil" tab (under Sertifikasyon): upload a Mastercard Profile Advisor
// report PDF, extract its EMV tag → value entries (backend pdfjs parser), then
// compare against what the card returns on each interface — same value = match,
// otherwise the difference is listed.

const STATUS = {
  match: { icon: '✓', cls: 'st-ok', label: 'Aynı' },
  mismatch: { icon: '✗', cls: 'st-bad', label: 'Farklı' },
  missing: { icon: '○', cls: 'st-warn', label: 'Kartta yok' },
};
const VERDICT = {
  PASS: { cls: 'pass', text: '✓ PDF İLE AYNI' },
  PARTIAL: { cls: 'warn', text: '◐ FARK YOK · BAZILARI KARTTA YOK' },
  FAIL: { cls: 'fail', text: '✗ FARKLILIK VAR' },
};

// Which interface a PDF entry belongs to, from its name marker. The report tags
// interface-specific elements as "… (Contact)" / "… (Contactless)"; anything
// without a marker applies to both. (Check contactless first — it contains the
// substring "contact".)
function ifaceOf(name) {
  const n = (name || '').toLowerCase();
  if (n.includes('(contactless')) return 'contactless';
  if (n.includes('(contact')) return 'contact';
  return 'both';
}

// Compare the parsed PDF profile against a card image read on one interface.
// Only the PDF entries relevant to that interface (its own + interface-agnostic)
// are compared — a contact read is never diffed against contactless-only tags.
// A card tag is multi-value; match if any card value equals the PDF value.
function compare(pdfList, image, iface) {
  const cardTags = {};
  for (const a of image.applications || []) for (const t of (a.tags || [])) {
    (cardTags[t.tag] = cardTags[t.tag] || []).push((t.value || '').toUpperCase());
  }
  const rows = pdfList.filter((e) => e.value && (ifaceOf(e.name) === 'both' || ifaceOf(e.name) === iface)).map((e) => {
    const occ = cardTags[e.tag];
    let status, card = null;
    if (!occ) status = 'missing';
    else if (occ.includes(e.value)) { status = 'match'; card = e.value; }
    else { status = 'mismatch'; card = occ.join('  |  '); }
    return { tag: e.tag, name: e.name, section: e.section, pdf: e.value, card, status };
  });
  const counts = { match: 0, mismatch: 0, missing: 0 };
  for (const r of rows) counts[r.status]++;
  const verdict = counts.mismatch === 0 ? (counts.missing === 0 ? 'PASS' : 'PARTIAL') : 'FAIL';
  return { rows, counts, verdict };
}

function exportCsv(cmp, iface, scheme) {
  const esc = (x) => `"${String(x ?? '').replace(/"/g, '""')}"`;
  const head = ['durum', 'tag', 'isim', 'bolum', 'pdf_deger', 'kart_deger'];
  const body = cmp.rows.map((r) => [STATUS[r.status].label, r.tag, r.name, r.section || '', r.pdf, r.card || ''].map(esc).join(';'));
  const csv = '﻿' + head.map(esc).join(';') + '\r\n' + body.join('\r\n');
  const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
  const a = document.createElement('a'); a.href = url; a.download = `pdf-profil-${scheme || 'kart'}-${iface}-${Date.now()}.csv`; a.click(); URL.revokeObjectURL(url);
}

function CompareBlock({ label, iface, res, profilePdf, busy, onRun, clear }) {
  const [filter, setFilter] = useState('all');
  const cmp = res && !res.error && res.image ? compare(profilePdf.list, res.image, iface) : null;
  const v = cmp ? VERDICT[cmp.verdict] : null;
  const scheme = res?.image?.applications?.[0]?.scheme;
  const rows = cmp ? (filter === 'all' ? cmp.rows : cmp.rows.filter((r) => r.status === filter)) : [];

  return (
    <div className={`oda-iface ${v ? v.cls : ''}`}>
      <div className="oda-iface-head">
        <button className="btn" disabled={!!busy || !profilePdf} onClick={onRun}>{busy ? 'Okunuyor…' : `${label} Karşılaştır`}</button>
        {cmp && <span className={`oda-badge ${v.cls}`}>{v.text}</span>}
        {cmp && <button className="btn-sm ghost" onClick={() => exportCsv(cmp, label.replace(/[^A-Za-z]/g, ''), scheme)}>↧ CSV</button>}
        {res && <button className="btn-sm ghost" onClick={clear}>temizle</button>}
      </div>
      {!res && <p className="muted small">Kartı bu arayüze koyup <b>{label} Karşılaştır</b>'a bas — karttan okunan tag'ler PDF profiliyle karşılaştırılır.</p>}
      {res?.error && <p className="err-text">✗ {res.error}</p>}
      {cmp && <>
        <div className="oda-info">
          <span className="oda-chip">{scheme || '?'}</span>
          <span className="mono small muted">{res.image.totalTags} kart tag'i · {cmp.rows.length} PDF tag'i (bu arayüz)</span>
        </div>
        <div className="prof-chips" style={{ marginBottom: 8 }}>
          {[['all', 'Tümü', cmp.rows.length, ''], ['match', 'Aynı', cmp.counts.match, 'st-ok'], ['mismatch', 'Farklı', cmp.counts.mismatch, 'st-bad'], ['missing', 'Kartta yok', cmp.counts.missing, 'st-warn']].map(([k, lbl, n, cls]) => (
            <button key={k} className={`prof-chip ${cls} ${filter === k ? 'sel' : ''}`} disabled={k !== 'all' && !n} onClick={() => setFilter(filter === k ? 'all' : k)}>{lbl} <b>{n}</b></button>
          ))}
        </div>
        {rows.length === 0 ? <p className="muted small">Bu filtreyle satır yok.</p> : (
          <div className="pdf-cmp-scroll">
            <table className="capk-table image-tags comp-table pdf-cmp-table">
              <thead><tr><th className="c">•</th><th>Tag</th><th>İsim</th><th>PDF Değeri</th><th>Kart Değeri</th></tr></thead>
              <tbody>
                {rows.map((r, i) => (
                  <tr key={i} className={`s-${r.status === 'mismatch' ? 'fail' : r.status === 'missing' ? 'warn' : ''}`}>
                    <td className={`c ${STATUS[r.status].cls}`} title={STATUS[r.status].label}>{STATUS[r.status].icon}</td>
                    <td className="mono b">{r.tag}</td>
                    <td className="small">{r.name || <span className="muted">?</span>}{r.section ? <span className="muted small"> · {r.section}</span> : null}</td>
                    <td className="mono small val">{r.pdf}</td>
                    <td className="mono small val">{r.card || <span className="muted">—</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </>}
    </div>
  );
}

export function ProfilePdfTab({ profilePdf, pdfBusy, parsePdf, runPdfCompare, clearPdfCmp, cmpContact, cmpContactless }) {
  const fileRef = useRef(null);
  const onPick = (e) => { const f = e.target.files?.[0]; if (f) parsePdf(f); e.target.value = ''; };

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>PDF Profil ↔ Kart</h2>
        <span className="muted small">Mastercard Profile Advisor raporu · temaslı + temassız</span>
      </div>
      <p className="muted small">Profile Advisor'ın oluşturduğu <b>profil PDF'ini yükle</b>; içindeki EMV tag/değerleri çıkarılır, sonra karttan okunan (temaslı/temassız) değerlerle <b>karşılaştırılır</b>. Aynı olanlar ✓, farklılıklar listelenir. (Bazı perso-içi tag'ler wire'dan okunamaz → "kartta yok".)</p>

      <div className="capk-add-row" style={{ alignItems: 'center', flexWrap: 'wrap', marginBottom: 8 }}>
        <button className="btn" disabled={pdfBusy === 'parse'} onClick={() => fileRef.current?.click()}>{pdfBusy === 'parse' ? 'Çözümleniyor…' : '↥ Profil PDF Yükle'}</button>
        <input ref={fileRef} type="file" accept=".pdf,application/pdf" style={{ display: 'none' }} onChange={onPick} />
        {profilePdf && <span className="oda-chip alt">📄 {profilePdf.fileName}</span>}
        {profilePdf && <span className="muted small">{profilePdf.count} tag · {profilePdf.pages} sayfa</span>}
      </div>

      {!profilePdf && <p className="muted small">Henüz PDF yüklenmedi. Yükledikten sonra her iki arayüzü ayrı ayrı karşılaştırabilirsin.</p>}

      {profilePdf && (
        <div className="pdf-cmp-stack">
          <CompareBlock label="🔌 Temaslı" iface="contact" res={cmpContact} profilePdf={profilePdf} busy={pdfBusy === 'contact'}
            onRun={() => runPdfCompare('contact')} clear={() => clearPdfCmp('contact')} />
          <CompareBlock label="📶 Temassız" iface="contactless" res={cmpContactless} profilePdf={profilePdf} busy={pdfBusy === 'contactless'}
            onRun={() => runPdfCompare('contactless')} clear={() => clearPdfCmp('contactless')} />
        </div>
      )}
    </section>
  );
}
