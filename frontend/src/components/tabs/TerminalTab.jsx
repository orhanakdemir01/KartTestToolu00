// "Terminal / Senaryo" tab: configure the terminal data (amount, currency, txn
// type, capabilities) that the EMV/ODA/compliance flows use when building the
// PDOL/CDOL, and run scenario presets that request different cryptogram types
// (TC/ARQC/AAC) to observe the card's actual decision — L2/L3-style testing.

import { Fragment } from 'react';

const DEC = { TC: { cls: 'st-ok', label: 'offline onay' }, ARQC: { cls: 'st-warn', label: 'online' }, AAC: { cls: 'st-bad', label: 'red' } };

export function TerminalTab({ meta, profile, setProfile, runScenarios, scenarioBusy, scenarioResult, cardPresent }) {
  if (!meta) return <section className="panel"><p className="muted small">Terminal ayarları yükleniyor…</p></section>;
  const eff = (tag) => (profile[tag] != null ? profile[tag] : meta.defaults[tag] || '');
  const setField = (tag, val) => setProfile({ ...profile, [tag]: val.replace(/\s/g, '').toUpperCase() });
  const applyPreset = (over) => setProfile({ ...over });
  const groups = [...new Set(meta.fields.map((f) => f.group))];
  const overridden = Object.keys(profile).filter((k) => profile[k] != null && profile[k] !== '').length;

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Terminal Profili & Senaryo</h2>
        <span className="muted small">EMV/ODA/Uyumluluk akışlarının kullandığı terminal verisi</span>
      </div>
      <p className="muted small">Terminalin karta sunduğu verileri (tutar, para birimi, işlem tipi, yetenekler) düzenle — bu değerler <b>PDOL/CDOL</b>'a girip kartın kriptogramını ve kararını etkiler. <b>Senaryolar</b> farklı kriptogram tipleri (TC/ARQC/AAC) isteyip kartın gerçek kararını gösterir.</p>

      {/* ── Terminal profili editörü ── */}
      <div className="capk-add-row" style={{ alignItems: 'center', marginBottom: 8 }}>
        <span className="quick-label" style={{ margin: 0 }}>Hızlı profil:</span>
        {meta.presets.map((p) => (
          <button key={p.id} className="btn-sm ghost" title={p.name} onClick={() => applyPreset(p.over)}>{p.name.split(' (')[0]}</button>
        ))}
        {overridden > 0 && <button className="btn-sm ghost" style={{ color: '#e0b341' }} onClick={() => setProfile({})}>↺ Sıfırla ({overridden})</button>}
      </div>

      {groups.map((g) => (
        <div key={g} className="term-group">
          <div className="comp-cat-head">{g}</div>
          <div className="term-fields">
            {meta.fields.filter((f) => f.group === g).map((f) => {
              const isOver = profile[f.tag] != null && profile[f.tag] !== '';
              return (
                <label key={f.tag} className={`term-field ${isOver ? 'over' : ''}`}>
                  <span className="term-label">{f.label} <span className="mono muted">{f.tag}</span></span>
                  <input className="mono" value={eff(f.tag)} maxLength={f.bytes * 2}
                    onChange={(e) => setField(f.tag, e.target.value)}
                    placeholder={meta.defaults[f.tag]} />
                </label>
              );
            })}
          </div>
        </div>
      ))}

      {/* ── Senaryo runner ── */}
      <div className="term-group" style={{ marginTop: 16 }}>
        <div className="comp-cat-head">Senaryo Testi (kart kararı)</div>
        <div className="capk-add-row" style={{ alignItems: 'center', marginTop: 8 }}>
          <button className="btn" disabled={scenarioBusy || !cardPresent} onClick={runScenarios}>
            {scenarioBusy ? 'Çalışıyor… (her senaryo bir işlem)' : '▶ Senaryoları Çalıştır'}
          </button>
          {!cardPresent && <span className="muted small">okuyucuda kart yok</span>}
          <span className="muted small">Her senaryo farklı terminal koşuluyla GENERATE AC yapar.</span>
        </div>

        {scenarioResult?.error && <p className="err-text" style={{ marginTop: 10 }}>✗ {scenarioResult.error}</p>}
        {scenarioResult?.results && (
          <table className="capk-table image-tags comp-table" style={{ marginTop: 12 }}>
            <thead><tr><th></th><th>Senaryo</th><th>Beklenen</th><th>Kart Kararı</th><th>Cryptogram (AC)</th></tr></thead>
            <tbody>
              {[...new Set(scenarioResult.results.map((s) => s.cat || 'Diğer'))].map((cat) => (
                <Fragment key={cat}>
                  <tr className="cat"><td colSpan={5} className="comp-cat-head">{cat}</td></tr>
                  {scenarioResult.results.filter((s) => (s.cat || 'Diğer') === cat).map((s) => {
                    const d = s.decision && DEC[s.decision];
                    const mCls = s.error ? 'st-bad' : s.match === null ? 'st-extra' : s.match ? 'st-ok' : 'st-warn';
                    const mIcon = s.error ? '✗' : s.match === null ? '◈' : s.match ? '✓' : '≠';
                    const mTitle = s.error ? 'hata' : s.match === null ? 'gözlem (kart-bağımlı)' : s.match ? 'beklenenle aynı' : 'kart farklı karar verdi';
                    return (
                      <tr key={s.id}>
                        <td className={`c ${mCls}`} title={mTitle}>{mIcon}</td>
                        <td className="small">{s.name}</td>
                        <td className="mono small">{s.expect === 'observe' ? <span className="muted">gözlem</span> : s.expect}</td>
                        <td className="mono small">{s.error ? <span className="err-text">HATA</span> : s.decision ? <span className={d?.cls}>{s.decision} <span className="muted">· {d?.label}</span></span> : <span className="muted">—</span>}</td>
                        <td className="mono small val">{s.ac || (s.error ? s.error : <span className="muted">—</span>)}</td>
                      </tr>
                    );
                  })}
                </Fragment>
              ))}
            </tbody>
          </table>
        )}
        <p className="muted small" style={{ marginTop: 6 }}>✓ beklenenle aynı · ≠ kart farklı karar verdi (gerçek risk davranışı, hata değil) · ◈ gözlem (kart-bağımlı sonuç, pass/fail yok).</p>
      </div>
    </section>
  );
}
