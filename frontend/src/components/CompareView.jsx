// İki oturumun karşılaştırma sonucunu (buildComparison çıktısı) render eder:
// kimlik + verdikt tablosu (farklı satırlar vurgulu) ve perso tag farkları.
export function CompareView({ comparison, labelA, labelB }) {
  if (!comparison) return null;
  const { identity, verdicts, tags, hasTags, diffCount } = comparison;

  const kvTable = (rows) => (
    <div className="capk-scroll">
      <table className="capk-table image-tags comp-table">
        <thead><tr><th></th><th>{labelA}</th><th>{labelB}</th></tr></thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className={r.diff ? 's-warn' : ''}>
              <td className="b small">{r.label}</td>
              <td className="mono small">{r.a}</td>
              <td className="mono small">{r.b}{r.diff ? <span className="st-warn"> ≠</span> : <span className="st-ok"> =</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Karşılaştırma</h2>
        <span className={`chip ${diffCount ? 'chip-off' : 'chip-on'}`}>{diffCount ? `${diffCount} fark` : 'fark yok'}</span>
      </div>

      <h3 className="cmp-h">Kimlik</h3>
      {kvTable(identity)}

      {verdicts.length > 0 && <>
        <h3 className="cmp-h">Verdiktler</h3>
        {kvTable(verdicts)}
      </>}

      <h3 className="cmp-h">Perso Tag Farkları</h3>
      {!hasTags ? (
        <p className="muted small">Perso tag karşılaştırması için her iki oturumda da <b>Kart Image</b> çıkarılmış olmalı.</p>
      ) : (
        <div className="cmp-tags">
          {tags.changed.length > 0 && (
            <div className="cmp-grp">
              <div className="comp-cat-head">Değişen değer ({tags.changed.length})</div>
              <div className="capk-scroll">
                <table className="capk-table image-tags comp-table">
                  <thead><tr><th>Tag</th><th>İsim</th><th>{labelA}</th><th>{labelB}</th></tr></thead>
                  <tbody>
                    {tags.changed.map((t) => (
                      <tr key={t.tag} className="s-warn">
                        <td className="mono b">{t.tag}</td>
                        <td className="small">{t.name || '?'}</td>
                        <td className="mono small val">{t.a}</td>
                        <td className="mono small val">{t.b}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
          {tags.onlyA.length > 0 && (
            <div className="cmp-grp">
              <div className="comp-cat-head">Yalnızca {labelA} ({tags.onlyA.length})</div>
              <TagList rows={tags.onlyA} />
            </div>
          )}
          {tags.onlyB.length > 0 && (
            <div className="cmp-grp">
              <div className="comp-cat-head">Yalnızca {labelB} ({tags.onlyB.length})</div>
              <TagList rows={tags.onlyB} />
            </div>
          )}
          <p className="muted small">{tags.same} tag her ikisinde de aynı.
            {tags.changed.length + tags.onlyA.length + tags.onlyB.length === 0 && ' Perso tag farkı yok.'}</p>
        </div>
      )}
    </section>
  );
}

function TagList({ rows }) {
  return (
    <div className="capk-scroll">
      <table className="capk-table image-tags comp-table">
        <thead><tr><th>Tag</th><th>İsim</th><th>Değer</th></tr></thead>
        <tbody>
          {rows.map((t) => (
            <tr key={t.tag}>
              <td className="mono b">{t.tag}</td>
              <td className="small">{t.name || '?'}</td>
              <td className="mono small val">{t.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
