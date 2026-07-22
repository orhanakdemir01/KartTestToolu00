import { useState } from 'react';

// "Geçmiş" sekmesi: kart bazlı uyumluluk denetim geçmişi + regresyon trendi.
// Her /api/compliance koşusu kart başına (maskeli PAN) otomatik kaydedilir (backend
// history.js). Burada tüm kartlar listelenir; bir kart seçilince koşuları zaman
// çizelgesinde, ardışık koşular arası PASS→FAIL (regresyon) / FAIL→PASS (düzelme)
// farklarıyla gösterilir — cert laboratuvarının "test yönetimi" panosu.

const stCls = (v) => (v === 'FAIL' ? 'st-bad' : v === 'PASS' ? 'st-ok' : 'st-warn');
const vCls = (v) => (v === 'FAIL' ? 'fail' : v === 'PASS' ? 'pass' : 'warn');
const vText = (v) => (v === 'FAIL' ? '✗ UYUMSUZ' : v === 'PASS' ? '✓ UYUMLU' : '◐ UYARILI');
const fmtDate = (iso) => { try { return new Date(iso).toLocaleString('tr-TR'); } catch { return iso; } };

// İki koşu arası kural durum farkı.
function diffRuns(prev, cur) {
  const regressed = [], fixed = [];
  if (!prev?.rules || !cur?.rules) return { regressed, fixed };
  for (const id in cur.rules) {
    const b = prev.rules[id], a = cur.rules[id];
    if (!b || b === a) continue;
    if (b === 'pass' && a === 'fail') regressed.push(id);
    else if (b === 'fail' && a === 'pass') fixed.push(id);
  }
  return { regressed, fixed };
}

export function HistoryTab({ cards, refresh, getCardRuns, clearCardHistory }) {
  const [sel, setSel] = useState(null);
  const [runs, setRuns] = useState([]);
  const [busy, setBusy] = useState(false);

  const openCard = async (card) => {
    setSel(card); setBusy(true);
    setRuns(await getCardRuns(card.key));
    setBusy(false);
  };

  return (
    <>
      <section className="panel">
        <div className="panel-head">
          <h2>Denetim Geçmişi ({cards.length} kart)</h2>
          <button className="btn-sm ghost" onClick={refresh}>↻ Yenile</button>
        </div>
        <p className="muted small">Her uyumluluk denetimi kart başına (maskeli PAN) otomatik kaydedilir. Bir kartı <b>Aç</b> → zaman içindeki koşuları, verdikt trendini ve <b>regresyonları</b> gör. Ham PAN saklanmaz.</p>
        {cards.length === 0 ? <p className="muted small">Henüz geçmiş yok — Uyumluluk sekmesinde bir denetim çalıştır.</p> : (
          <div className="capk-scroll">
            <table className="capk-table">
              <thead><tr><th>Kart (PAN)</th><th>Şema</th><th className="c">Koşu</th><th>Son verdikt</th><th>Son denetim</th><th></th></tr></thead>
              <tbody>
                {cards.map((cd) => (
                  <tr key={cd.key} className={sel?.key === cd.key ? 'capk-editing' : ''}>
                    <td className="mono b">{cd.panMasked}</td>
                    <td>{cd.scheme || '—'}</td>
                    <td className="c b">{cd.runs}</td>
                    <td><span className={stCls(cd.lastVerdict)}>{vText(cd.lastVerdict)}</span></td>
                    <td className="small muted">{fmtDate(cd.lastAt)}</td>
                    <td className="capk-actions">
                      <button className="btn-sm" onClick={() => openCard(cd)}>Aç</button>
                      <button className="btn-sm ghost" onClick={() => { if (confirm(`Geçmiş silinsin mi? ${cd.panMasked}`)) { clearCardHistory(cd.key); if (sel?.key === cd.key) { setSel(null); setRuns([]); } } }}>Sil</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {sel && (
        <section className="panel">
          <div className="panel-head">
            <h2><span className="mono">{sel.panMasked}</span> · zaman çizelgesi</h2>
            <span className="muted small">{sel.scheme || '?'} · {runs.length} koşu · en yeni üstte</span>
          </div>
          {busy ? <p className="muted small">Yükleniyor…</p> : runs.length === 0 ? <p className="muted small">Koşu yok.</p> : (
            <div className="hist-timeline">
              {runs.map((_, ri) => {
                const idx = runs.length - 1 - ri;   // en yeni üstte
                const run = runs[idx];
                const prev = idx > 0 ? runs[idx - 1] : null;
                const { regressed, fixed } = diffRuns(prev, run);
                return (
                  <div key={idx} className="hist-run">
                    <div className="hist-run-head">
                      <span className={`hist-badge v-${vCls(run.verdict)}`}>{vText(run.verdict)}</span>
                      <span className="mono small muted">{fmtDate(run.savedAt)} · {run.iface}</span>
                      <span className="mono small">{run.pass}✓ {run.fail}✗ {run.warn}⚠</span>
                    </div>
                    {!prev ? <div className="hist-diff muted small">ilk koşu</div>
                      : (regressed.length || fixed.length) ? (
                        <div className="hist-diff">
                          {regressed.length > 0 && <span className="st-bad"><b>⚠ Regresyon:</b> {regressed.join(', ')}</span>}
                          {fixed.length > 0 && <span className="st-ok"><b>✓ Düzelme:</b> {fixed.join(', ')}</span>}
                        </div>
                      ) : <div className="hist-diff muted small">önceki koşuya göre değişiklik yok</div>}
                  </div>
                );
              })}
            </div>
          )}
          <button className="btn-sm ghost" style={{ marginTop: 12 }} onClick={() => { setSel(null); setRuns([]); }}>Kapat</button>
        </section>
      )}
    </>
  );
}
