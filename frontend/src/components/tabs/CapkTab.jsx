// "CA Anahtarları" tab: CAPK list + scheme filter + add/edit/delete form.
// SHA-1 is verified when supplied, otherwise recomputed from the modulus.
export function CapkTab({
  capks, capkSchemes, capkFilter, setCapkFilter,
  addForm, setAddForm, addCapk, addResult,
  capkEdit, startEditCapk, cancelEditCapk, updateCapk, deleteCapk,
}) {
  const editing = !!capkEdit;
  const set = (patch) => setAddForm({ ...addForm, ...patch });
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>CA Public Keys ({capks.length})</h2>
        <div className="capk-filter">
          <button className={`btn-ghost ${capkFilter === 'all' ? 'sel' : ''}`} onClick={() => setCapkFilter('all')}>Tümü</button>
          {Object.keys(capkSchemes).map((s) => (
            <button key={s} className={`btn-ghost ${capkFilter === s ? 'sel' : ''}`} onClick={() => setCapkFilter(s)}>{s} ({capkSchemes[s]})</button>
          ))}
        </div>
      </div>
      <p className="muted small">EMV offline veri doğrulama (SDA/DDA/CDA) için şema CA public key'leri. Satırdaki <b>Düzenle</b> ile mevcut anahtarı değiştirebilirsin.</p>
      <div className="capk-scroll">
        <table className="capk-table">
          <thead><tr><th>Şema</th><th>RID</th><th>Index</th><th>Exp</th><th>Bit</th><th>SHA-1</th><th></th></tr></thead>
          <tbody>
            {capks.filter((k) => capkFilter === 'all' || k.scheme === capkFilter).map((k, i) => {
              const isRow = capkEdit && capkEdit.origRid === k.rid && capkEdit.origIndex === k.index;
              return (
                <tr key={i} className={isRow ? 'capk-editing' : ''}>
                  <td>{k.scheme}</td>
                  <td className="mono">{k.rid}</td>
                  <td className="mono b">{k.index}</td>
                  <td className="mono">{k.exponent}</td>
                  <td>{k.keyLength}</td>
                  <td className="mono small capk-hash" title={`Modulus:\n${k.modulus}`}>{k.hash}</td>
                  <td className="capk-actions">
                    <button className="btn-sm ghost" onClick={() => startEditCapk(k)}>Düzenle</button>
                    <button className="btn-sm ghost" onClick={() => { if (confirm(`Silinsin mi? ${k.scheme} ${k.rid}/${k.index}`)) deleteCapk(k); }}>Sil</button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <details className="builder" open={editing}>
        <summary>{editing ? `✎ Düzenle: ${capkEdit.origRid} / ${capkEdit.origIndex}` : 'Yeni CA anahtarı ekle'}</summary>
        <div className="capk-add">
          <div className="capk-add-row">
            <label>Şema<input value={addForm.scheme} onChange={(e) => set({ scheme: e.target.value })} placeholder="Visa" /></label>
            <label>RID<input className="mono" value={addForm.rid} onChange={(e) => set({ rid: e.target.value })} placeholder="A000000003" /></label>
            <label>Index<input className="mono" value={addForm.index} onChange={(e) => set({ index: e.target.value })} placeholder="99" /></label>
            <label>Exponent<input className="mono" value={addForm.exponent} onChange={(e) => set({ exponent: e.target.value })} placeholder="03" /></label>
          </div>
          <label className="capk-wide">Modulus (hex)<textarea className="mono" value={addForm.modulus} onChange={(e) => set({ modulus: e.target.value })} /></label>
          <label className="capk-wide">SHA-1 Hash <span className="muted small">(boş bırakılırsa modülüsten otomatik hesaplanır)</span>
            <input className="mono" value={addForm.hash} onChange={(e) => set({ hash: e.target.value })} placeholder="40 hex — opsiyonel" /></label>
          <div className="capk-add-row">
            {editing ? (
              <>
                <button className="btn" onClick={updateCapk}>Güncelle</button>
                <button className="btn-ghost" onClick={cancelEditCapk}>Vazgeç</button>
              </>
            ) : (
              <button className="btn" onClick={addCapk}>Doğrula ve Ekle</button>
            )}
          </div>
          {addResult && (
            <p className={addResult.added ? 'capk-ok' : 'err-text'}>
              {addResult.added ? (editing ? '✓ Güncellendi' : '✓ Eklendi ve doğrulandı') : `✗ ${addResult.reason}`}
              {addResult.computedHash && !addResult.added && <span className="mono small"> (hesaplanan: {addResult.computedHash})</span>}
            </p>
          )}
        </div>
      </details>
    </section>
  );
}
