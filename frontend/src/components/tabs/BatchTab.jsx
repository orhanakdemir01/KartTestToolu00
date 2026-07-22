// "Parti" sekmesi: çoklu-kart perso QA. Operatör kartları sırayla takar, her biri
// için "İşle"ye basar; araç uyumluluk denetimini koşup sonucu partiye ekler. Sonuçlar
// bir tabloda birikir ve tek birleşik rapora (HTML) dönüşür — cert laboratuvarının
// parti/kampanya iş akışı. Denetim mantığı App.jsx'te (mevcut /api/compliance).

const stCls = (v) => (v === 'FAIL' ? 'st-bad' : v === 'PASS' ? 'st-ok' : 'st-warn');
const vText = (v) => (v === 'FAIL' ? '✗ UYUMSUZ' : v === 'PASS' ? '✓ UYUMLU' : '◐ UYARILI');

export function BatchTab({ batch, batchBusy, processBatchCard, removeBatchRow, clearBatch, downloadBatchReport, contactPresent, contactlessPresent }) {
  const pass = batch.filter((r) => r.verdict === 'PASS').length;
  const warn = batch.filter((r) => r.verdict === 'PASS_WITH_WARN').length;
  const fail = batch.filter((r) => r.verdict === 'FAIL').length;

  return (
    <>
      <section className="panel">
        <div className="panel-head">
          <h2>Parti · Çoklu-Kart QA</h2>
          <span className="muted small">sırayla işle · birleşik rapor</span>
        </div>
        <p className="muted small">Perso QA partisi: her kartı okuyucuya koy, ilgili <b>İşle</b>'ye bas — uyumluluk denetimi koşulur ve sonuç (verdikt + regresyon) partiye eklenir. Kartı çıkar, sıradakini tak, tekrarla. Sonunda tek <b>birleşik rapor</b> al.</p>
        <div className="capk-add-row" style={{ alignItems: 'center' }}>
          <button className="btn" disabled={batchBusy || !contactPresent} title={!contactPresent ? 'Temaslı yuvada kart yok' : undefined}
            onClick={() => processBatchCard('contact')}>{batchBusy ? 'İşleniyor…' : '🔌 Temaslı kartı işle'}</button>
          <button className="btn" disabled={batchBusy || !contactlessPresent} title={!contactlessPresent ? 'Temassız yuvada kart yok' : undefined}
            onClick={() => processBatchCard('contactless')}>{batchBusy ? 'İşleniyor…' : '📶 Temassız kartı işle'}</button>
          {!contactPresent && !contactlessPresent && <span className="iface-nocard">○ okuyucuda kart yok</span>}
        </div>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Parti Sonuçları ({batch.length})</h2>
          <div className="trace-actions">
            <button className="btn-sm" disabled={!batch.length} onClick={downloadBatchReport}>↧ Birleşik Rapor (HTML)</button>
            <button className="btn-sm ghost" disabled={!batch.length} onClick={() => { if (confirm('Parti temizlensin mi?')) clearBatch(); }}>Temizle</button>
          </div>
        </div>
        {batch.length === 0 ? <p className="muted small">Parti boş — bir kart tak ve <b>İşle</b>'ye bas.</p> : (
          <>
            <div className="prof-chips" style={{ marginBottom: 10 }}>
              <span className="prof-chip">{batch.length} kart</span>
              <span className="prof-chip st-ok">✓ {pass} uyumlu</span>
              {warn > 0 && <span className="prof-chip st-warn">◐ {warn} uyarılı</span>}
              <span className="prof-chip st-bad">✗ {fail} uyumsuz</span>
            </div>
            <div className="capk-scroll">
              <table className="capk-table">
                <thead><tr><th>#</th><th>PAN</th><th>Şema</th><th>Arayüz</th><th>Verdikt</th><th>Sonuç</th><th>Regr.</th><th>Zaman</th><th></th></tr></thead>
                <tbody>
                  {batch.map((r, i) => (
                    <tr key={i} className={r.verdict === 'FAIL' ? 's-fail' : ''}>
                      <td className="b">{i + 1}</td>
                      <td className="mono b">{r.pan}</td>
                      <td>{r.scheme}</td>
                      <td className="small">{r.iface}</td>
                      <td><span className={stCls(r.verdict)}>{vText(r.verdict)}</span></td>
                      <td className="mono small">{r.pass}✓ {r.fail}✗ {r.warn}⚠</td>
                      <td className={r.regressed ? 'st-bad b' : 'muted'}>{r.regressed || '—'}</td>
                      <td className="small muted">{r.time}</td>
                      <td className="capk-actions"><button className="btn-sm ghost" onClick={() => removeBatchRow(i)}>×</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </section>
    </>
  );
}
