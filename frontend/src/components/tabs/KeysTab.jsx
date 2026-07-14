// "İşlem Anahtarları" tab: 3DES key sets (AC/MAC/ENC) list + add/edit/delete form
export function KeysTab({
  sessionKeys, deleteSessionKey, keyForm, setKeyForm, addSessionKey, keyAddResult,
  keyEdit, startEditKey, cancelEditKey, updateSessionKey,
}) {
  const editing = !!keyEdit;
  const set = (patch) => setKeyForm({ ...keyForm, ...patch });
  return (
    <section className="panel">
      <div className="panel-head"><h2>İşlem Anahtarları ({sessionKeys.length})</h2></div>
      <p className="muted small">Kriptogram işleme için 3DES anahtarları (AC / MAC / ENC). Anahtar seviyesi: <b>master</b> (issuer MDK → PAN/PSN ile ICC türetilir), <b>icc</b> (ICC anahtarı → ATC ile session), <b>session</b> (doğrudan kullanılır). Satırdaki <b>Düzenle</b> ile mevcut anahtarı değiştirebilirsin.</p>
      {sessionKeys.length > 0 && (
        <table className="capk-table">
          <thead><tr><th>Etiket</th><th>PAN</th><th>PSN</th><th>Seviye</th><th>AC</th><th>MAC</th><th>ENC</th><th></th></tr></thead>
          <tbody>
            {sessionKeys.map((k, i) => {
              const isRow = keyEdit && keyEdit.origLabel === k.label && (keyEdit.origPan || '') === (k.pan || '');
              return (
                <tr key={i} className={isRow ? 'capk-editing' : ''}>
                  <td>{k.label}</td><td className="mono">{k.pan || '(varsayılan)'}</td><td className="mono">{k.psn}</td>
                  <td>{k.keyLevel}</td>
                  <td className="mono small">{k.acKey}<br /><span className="kcv-tag">KCV {k.acKcv}</span></td>
                  <td className="mono small">{k.macKey || '—'}{k.macKcv && <><br /><span className="kcv-tag">KCV {k.macKcv}</span></>}</td>
                  <td className="mono small">{k.encKey || '—'}{k.encKcv && <><br /><span className="kcv-tag">KCV {k.encKcv}</span></>}</td>
                  <td className="capk-actions">
                    <button className="btn-sm ghost" onClick={() => startEditKey(k)}>Düzenle</button>
                    <button className="btn-sm ghost" onClick={() => { if (confirm(`Silinsin mi? ${k.label} ${k.pan || '(varsayılan)'}`)) deleteSessionKey(k.label, k.pan); }}>Sil</button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      <details className="builder" open={editing || sessionKeys.length === 0}>
        <summary>{editing ? `✎ Düzenle: ${keyEdit.origLabel}${keyEdit.origPan ? ' · ' + keyEdit.origPan : ''}` : 'Yeni anahtar seti ekle'}</summary>
        <div className="capk-add">
          <div className="capk-add-row">
            <label>Etiket<input value={keyForm.label} onChange={(e) => set({ label: e.target.value })} placeholder="Test kartı" /></label>
            <label>PAN<input className="mono" value={keyForm.pan} onChange={(e) => set({ pan: e.target.value })} placeholder="(boş = varsayılan)" /></label>
            <label>PSN<input className="mono" maxLength={2} value={keyForm.psn} onChange={(e) => set({ psn: e.target.value })} /></label>
            <label>Seviye
              <select value={keyForm.keyLevel} onChange={(e) => set({ keyLevel: e.target.value })}>
                <option value="auto">auto (hepsini dene)</option>
                <option value="master">master (MDK)</option>
                <option value="icc">icc</option>
                <option value="session">session</option>
              </select>
            </label>
          </div>
          <div className="capk-add-row">
            <label className="capk-wide">AC anahtarı (32 hex)<input className="mono" value={keyForm.acKey} onChange={(e) => set({ acKey: e.target.value })} /></label>
            <label>AC KCV (ops.)<input className="mono" maxLength={6} value={keyForm.acKcv || ''} onChange={(e) => set({ acKcv: e.target.value })} placeholder="6 hex" /></label>
          </div>
          <div className="capk-add-row">
            <label className="capk-wide">MAC anahtarı (opsiyonel)<input className="mono" value={keyForm.macKey} onChange={(e) => set({ macKey: e.target.value })} /></label>
            <label>MAC KCV<input className="mono" maxLength={6} value={keyForm.macKcv || ''} onChange={(e) => set({ macKcv: e.target.value })} placeholder="6 hex" /></label>
          </div>
          <div className="capk-add-row">
            <label className="capk-wide">ENC anahtarı (opsiyonel)<input className="mono" value={keyForm.encKey} onChange={(e) => set({ encKey: e.target.value })} /></label>
            <label>ENC KCV<input className="mono" maxLength={6} value={keyForm.encKcv || ''} onChange={(e) => set({ encKcv: e.target.value })} placeholder="6 hex" /></label>
          </div>
          <div className="capk-add-row">
            {editing ? (
              <>
                <button className="btn" onClick={updateSessionKey}>Güncelle</button>
                <button className="btn-ghost" onClick={cancelEditKey}>Vazgeç</button>
              </>
            ) : (
              <button className="btn" onClick={addSessionKey}>Ekle</button>
            )}
          </div>
          {keyAddResult && <p className={keyAddResult.added ? 'capk-ok' : 'err-text'}>{keyAddResult.added ? (editing ? '✓ Güncellendi' : '✓ Eklendi') : `✗ ${keyAddResult.reason}`}</p>}
        </div>
      </details>
    </section>
  );
}
