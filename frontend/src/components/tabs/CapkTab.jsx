// "CA Anahtarları" tab: CAPK list + scheme filter + add/edit/delete form.
// SHA-1 is verified when supplied, otherwise recomputed from the modulus.
export function CapkTab({
  capks, capkSchemes, capkFilter, setCapkFilter,
  addForm, setAddForm, addCapk, addResult,
  capkEdit, startEditCapk, cancelEditCapk, updateCapk, deleteCapk,
  eccCapks, eccAddForm, setEccAddForm, addEccCapk, deleteEccCapk, eccAddResult,
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

      {/* Ekleme/düzenleme formu listenin ÜSTÜNDE: liste uzun (80+ anahtar),
          formu altta tutmak her girişte sonuna kadar kaydırmayı zorunlu kılıyordu. */}
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

      <EccCapkPanel {...{ eccCapks, eccAddForm, setEccAddForm, addEccCapk, deleteEccCapk, eccAddResult }} />
    </section>
  );
}

// ECC CA public key deposu — Kernel 8 ECC ODA'nın zincir kökü.
// Şema: [EMV Book C-8 v1.2] Tablo 4.3. RSA'daki modulus+exponent yerine eğri
// üzerinde bir NOKTA (x,y) + Algorithm Suite Indicator tutulur.
function EccCapkPanel({ eccCapks, eccAddForm, setEccAddForm, addEccCapk, deleteEccCapk, eccAddResult }) {
  const set = (patch) => setEccAddForm({ ...eccAddForm, ...patch });
  return (
    <div style={{ marginTop: 22, borderTop: '1px solid var(--border)', paddingTop: 16 }}>
      <div className="panel-head"><h2>ECC CA Public Keys ({eccCapks?.length || 0}) · Kernel 8</h2></div>
      <p className="muted small">Kernel 8 (ECC) çevrimdışı veri doğrulamasının <b>zincir kökü</b>. RSA CAPK'den ayrı depo: ECC anahtarı eğri üzerinde bir <b>nokta (x, y)</b> ve <b>Algorithm Suite Indicator</b> taşır — spec <span className="mono">[C-8 Tablo 4.3]</span> y'nin de saklanmasını önerir ki her işlemde yeniden hesaplanmasın. Eklerken nokta <b>P-256 eğrisi üzerinde mi</b> diye sınanır; checksum verilirse SHA-256/SHA-1 ile doğrulanır, verilmezse hesaplanır.</p>
      {(!eccCapks || eccCapks.length === 0) && <p className="err-text small">⚠ ECC CA anahtarı yok — Kernel 8 ODA zinciri doğrulanamaz.</p>}

      {/* Form listenin ÜSTÜNDE — RSA bölümüyle aynı gerekçe (bkz. yukarısı). */}
      <details className="builder" style={{ marginBottom: 10 }}>
        <summary>ECC CA anahtarı ekle</summary>
        <div className="capk-add">
          <div className="capk-add-row">
            <label>Şema<input value={eccAddForm.scheme} onChange={(e) => set({ scheme: e.target.value })} placeholder="Mastercard" /></label>
            <label>RID<input className="mono" maxLength={10} value={eccAddForm.rid} onChange={(e) => set({ rid: e.target.value })} placeholder="A000000004" /></label>
            <label>Index (kartın 8F)<input className="mono" maxLength={2} value={eccAddForm.index} onChange={(e) => set({ index: e.target.value })} placeholder="E0" /></label>
            <label>Suite<input className="mono" maxLength={2} value={eccAddForm.suite} onChange={(e) => set({ suite: e.target.value })} placeholder="10" title="Algorithm Suite Indicator — bu spec sürümünde daima 10" /></label>
            <label>Tip
              <select value={eccAddForm.keyType} onChange={(e) => set({ keyType: e.target.value })}>
                <option value="Test">Test</option><option value="Live">Live</option>
              </select>
            </label>
          </div>
          <div className="capk-add-row">
            <label className="capk-wide">Public key X (32 bayt)<input className="mono" value={eccAddForm.x} onChange={(e) => set({ x: e.target.value })} placeholder="64 hex karakter" /></label>
          </div>
          <div className="capk-add-row">
            <label className="capk-wide">Public key Y (32 bayt)<input className="mono" value={eccAddForm.y} onChange={(e) => set({ y: e.target.value })} placeholder="64 hex karakter" /></label>
          </div>
          <div className="capk-add-row">
            <label className="capk-wide">Checksum (ops. — boşsa SHA-256 hesaplanır)<input className="mono" value={eccAddForm.hash} onChange={(e) => set({ hash: e.target.value })} placeholder="SHA-256 veya SHA-1" /></label>
            <button className="btn" onClick={addEccCapk} disabled={!eccAddForm.rid || !eccAddForm.index || !eccAddForm.x || !eccAddForm.y}>Doğrula ve Ekle</button>
          </div>
          {eccAddResult && (
            <p className={eccAddResult.ok ? 'capk-ok' : 'err-text'}>
              {eccAddResult.ok ? `✓ Eklendi — ${eccAddResult.verify?.reason || ''}` : `✗ ${eccAddResult.error}`}
              {eccAddResult.verify?.computedHash && <span className="mono small muted"> · SHA-256 {eccAddResult.verify.computedHash.slice(0, 24)}…</span>}
            </p>
          )}
        </div>
      </details>

      {eccCapks?.length > 0 && (
        <div className="capk-scroll">
          <table className="capk-table">
            <thead><tr><th>Şema</th><th>RID</th><th>Index</th><th>Suite</th><th>Eğri</th><th>Tip</th><th>Checksum</th><th></th></tr></thead>
            <tbody>
              {eccCapks.map((k, i) => (
                <tr key={i}>
                  <td>{k.scheme}</td>
                  <td className="mono small">{k.rid}</td>
                  <td className="mono">{k.index}</td>
                  <td className="mono small">{k.suite}</td>
                  <td className="small">{k.curve}</td>
                  <td><span className={`kcv-tag ${k.keyType === 'Live' ? '' : 'aes'}`}>{k.keyType}</span></td>
                  <td className="mono small muted" title={k.hash}>{(k.hash || '').slice(0, 16)}…</td>
                  <td><button className="btn-ghost" onClick={() => deleteEccCapk(k)}>Sil</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
