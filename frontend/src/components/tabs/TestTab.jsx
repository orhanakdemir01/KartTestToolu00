// "Test" tab: suite picker + run + results table + editable JSON
export function TestTab({ suites, loadSuite, runTest, testBusy, cardPresent, testResult, suiteJson, setSuiteJson }) {
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Test Senaryoları</h2>
        <button id="run-test" className="btn" disabled={testBusy || !cardPresent} onClick={runTest}>
          {testBusy ? 'Çalışıyor…' : '▶ Testi Çalıştır'}
        </button>
      </div>

      <div className="suite-picker">
        {suites.map((s) => (
          <button key={s.id} className="btn-ghost" title={s.description} onClick={() => loadSuite(s)}>{s.name}</button>
        ))}
      </div>

      {testResult && !testResult.error && (
        <div className="test-summary">
          <span className={`test-badge ${testResult.ok ? 'pass' : 'fail'}`}>
            {testResult.ok ? '✓ TÜM TESTLER GEÇTİ' : '✗ BAŞARISIZ'}
          </span>
          <span className="test-count">{testResult.passed}/{testResult.total} adım geçti</span>
        </div>
      )}
      {testResult?.results && (
        <table className="test-table">
          <thead><tr><th>Durum</th><th>Adım</th><th>Beklenen</th><th>Gelen</th><th>Açıklama</th></tr></thead>
          <tbody>
            {testResult.results.map((r, i) => (
              <tr key={i} className={r.pass ? 'row-pass' : 'row-fail'}>
                <td>{r.pass ? '✓' : '✗'}</td>
                <td>{r.name}</td>
                <td className="mono">{r.expectedSw}</td>
                <td className="mono">{r.actualSw || '—'}</td>
                <td className="small">{r.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <details className="builder">
        <summary>Test paketi JSON (düzenlenebilir)</summary>
        <textarea className="suite-editor mono" value={suiteJson} onChange={(e) => setSuiteJson(e.target.value)} spellCheck={false} />
      </details>
    </section>
  );
}
