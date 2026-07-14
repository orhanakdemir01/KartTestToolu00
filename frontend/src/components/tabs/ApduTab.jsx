import { TlvTree } from '../TlvTree.jsx';

// "APDU Konsolu" tab: raw send + quick commands + builder + response decode
export function ApduTab({ raw, setRaw, send, quick, builder, setBuilder, buildApdu, resp }) {
  return (
    <div className="grid">
      {/* APDU SEND */}
      <section className="panel">
        <div className="panel-head"><h2>APDU Gönder</h2></div>
        <div className="apdu-row">
          <input className="apdu-input mono" value={raw} onChange={(e) => setRaw(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && send()} placeholder="CLA INS P1 P2 Lc Data Le" />
          <button className="btn" onClick={() => send()}>Gönder ▸</button>
        </div>

        {quick.map((g) => (
          <div key={g.group} className="quick-group">
            <span className="quick-label">{g.group}</span>
            <div className="quick">
              {g.items.map((q) => (
                <button key={q.label} className="btn-ghost" title={q.cmd}
                  onClick={() => { setRaw(q.cmd); if (!q.fill) send(q.cmd); }}>{q.label}</button>
              ))}
            </div>
          </div>
        ))}

        <details className="builder">
          <summary>APDU Oluşturucu</summary>
          <div className="builder-grid">
            {['cla', 'ins', 'p1', 'p2'].map((k) => (
              <label key={k}>{k.toUpperCase()}
                <input className="mono" maxLength={2} value={builder[k]}
                  onChange={(e) => setBuilder({ ...builder, [k]: e.target.value })} />
              </label>
            ))}
            <label className="wide">Data
              <input className="mono" value={builder.data}
                onChange={(e) => setBuilder({ ...builder, data: e.target.value })} placeholder="(opsiyonel)" />
            </label>
            <label>Le
              <input className="mono" maxLength={2} value={builder.le}
                onChange={(e) => setBuilder({ ...builder, le: e.target.value })} placeholder="00" />
            </label>
            <button className="btn-sm" onClick={buildApdu}>↑ Oluştur</button>
          </div>
        </details>
      </section>

      {/* RESPONSE DECODE */}
      <section className="panel">
        <div className="panel-head"><h2>Yanıt · TLV Çözümleme</h2></div>
        {!resp && <p className="muted">Bir komut gönderin.</p>}
        {resp?.error && <p className="err-text">{resp.error}</p>}
        {resp && !resp.error && (
          <div className="resp">
            <div className="resp-line"><span className="lbl">Yanıt</span><span className="mono hl">{resp.response}</span></div>
            <div className="resp-line">
              <span className="lbl">SW</span>
              <span className={`sw ${resp.sw === '9000' ? 'sw-ok' : 'sw-warn'}`}>{resp.sw}</span>
              <span className="sw-text">{resp.swText}</span>
              {resp.durationMs != null && <span className="timing">⏱ {resp.durationMs} ms</span>}
            </div>
            <TlvTree nodes={resp.tlv?.ok ? resp.tlv.nodes : null} />
          </div>
        )}
      </section>
    </div>
  );
}
