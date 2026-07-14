import { ApduTraceEntry, VerifyTraceEntry, TraceLine } from './TraceEntries.jsx';

// Always-visible trace dock at the bottom: APDU/verify/plain entries + export
export function TraceDock({ trace, traceOpen, setTraceOpen, exportTrace, clearTrace, traceRef }) {
  return (
    <section className="panel trace-dock">
      <div className="panel-head">
        <h2 className="trace-toggle" onClick={() => setTraceOpen((o) => !o)}>{traceOpen ? '▾' : '▸'} Trace <span className="trace-n">{trace.length}</span></h2>
        <div className="trace-actions">
          <button className="btn-sm" onClick={() => exportTrace('json')}>JSON</button>
          <button className="btn-sm" onClick={() => exportTrace('csv')}>CSV</button>
          <button className="btn-sm ghost" onClick={clearTrace}>Temizle</button>
        </div>
      </div>
      {traceOpen && (
        <div className="trace-box" ref={traceRef}>
          {trace.length === 0 && <p className="muted small">Trace boş.</p>}
          {trace.map((t, i) => (
            t.apdu ? <ApduTraceEntry key={i} t={t} />
              : t.verify ? <VerifyTraceEntry key={i} t={t} />
              : <TraceLine key={i} t={t} />
          ))}
        </div>
      )}
    </section>
  );
}
