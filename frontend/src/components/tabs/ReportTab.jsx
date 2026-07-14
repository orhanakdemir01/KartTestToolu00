// "Rapor" tab: export/print buttons + contents checklist
export function ReportTab({ downloadReport, printReport, card, emv, testResult, trace }) {
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Rapor</h2>
        <div className="trace-actions">
          <button className="btn-sm" onClick={downloadReport}>⬇ HTML İndir</button>
          <button className="btn-sm" onClick={printReport}>🖨 Yazdır / PDF</button>
        </div>
      </div>
      <p className="muted small">Kart bilgisi, EMV verisi, analiz ve test sonuçlarını tek bir yazdırılabilir rapora toplar (mevcut oturum verisinden).</p>
      <ul className="report-contents">
        <li className={card ? 'on' : ''}>Kart & ATR {card ? '✓' : '—'}</li>
        <li className={emv?.cardData?.pan ? 'on' : ''}>EMV verisi & analiz {emv?.cardData?.pan ? '✓' : '—'}</li>
        <li className={testResult?.results ? 'on' : ''}>Test sonuçları {testResult?.results ? '✓' : '—'}</li>
        <li className={trace.length ? 'on' : ''}>Trace ({trace.length} satır)</li>
      </ul>
    </section>
  );
}
