// "Oturum Anahtarları" tab: 3DES session key sets (AC/MAC/ENC) list + add/edit/delete
// form + Issuer Authentication (ARPC) üretimi/karta doğrulatma paneli.
export function KeysTab({
  sessionKeys, deleteSessionKey, keyForm, setKeyForm, addSessionKey, keyAddResult,
  keyEdit, startEditKey, cancelEditKey, updateSessionKey,
  arpcForm, setArpcForm, runArpc, arpcBusy, arpcResult, cardPresent,
}) {
  const editing = !!keyEdit;
  const set = (patch) => setKeyForm({ ...keyForm, ...patch });
  return (
    <>
    <section className="panel">
      <div className="panel-head"><h2>Oturum Anahtarları ({sessionKeys.length})</h2></div>
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

    <section className="panel">
      <div className="panel-head">
        <h2>Issuer Authentication (ARPC)</h2>
        {cardPresent ? <span className="chip chip-on">● Kart Bağlı</span> : <span className="chip chip-off">● Kart Yok</span>}
      </div>
      <p className="muted small">Kartın <b>ARQC</b>'sinden <b>ARPC</b> üretir (Method 1 · 3DES, EXTERNAL AUTHENTICATE — Amex · Method 2 · Retail MAC + CSU, 2. GENERATE AC — Visa/MC/Troy) ve issuer authentication'ı <b>diferansiyel testle</b> doğrular: <b>doğru</b> ARPC kabul (TC) <b>ve bozuk</b> ARPC red (AAC) ⇒ kart ARPC'yi kriptografik doğruluyor (PASS). Bozuk ARPC de TC alırsa kart doğrulamıyor (NA). Bu, AIP bildirimine güvenmeyen altın-standart negatif testtir. SKac şema-farkında (M/Chip UN-tabanlı / CSK). EMV Bk2 §8.2.</p>
      <div className="capk-add">
        <div className="capk-add-row">
          <label>Anahtar seti
            <select value={sessionKeys.findIndex((k) => k.label === arpcForm.keyLabel && (k.pan || '') === (arpcForm.keyPan || ''))}
              onChange={(e) => { const k = sessionKeys[+e.target.value]; setArpcForm({ ...arpcForm, keyLabel: k?.label || '', keyPan: k?.pan || '' }); }}>
              <option value={-1}>— seç —</option>
              {sessionKeys.map((k, i) => <option key={i} value={i}>{k.label}{k.pan ? ` · ${k.pan}` : ' (varsayılan)'}</option>)}
            </select>
          </label>
          <label>Yöntem
            <select value={arpcForm.method} onChange={(e) => setArpcForm({ ...arpcForm, method: e.target.value })}>
              <option value="auto">auto (şemaya göre)</option>
              <option value="m2">Method 2 (2. GEN AC)</option>
              <option value="m1">Method 1 (EXTERNAL AUTH)</option>
            </select>
          </label>
          <label>ARC<input className="mono" maxLength={4} value={arpcForm.arc} onChange={(e) => setArpcForm({ ...arpcForm, arc: e.target.value })} placeholder="3030" /></label>
          <label>CSU (M2)<input className="mono" maxLength={8} value={arpcForm.csu} onChange={(e) => setArpcForm({ ...arpcForm, csu: e.target.value })} placeholder="03920000" /></label>
        </div>
        <div className="capk-add-row">
          <button className="btn" disabled={arpcBusy || !cardPresent || !arpcForm.keyLabel} onClick={runArpc}
            title={!cardPresent ? 'Okuyucuda kart yok' : !arpcForm.keyLabel ? 'Anahtar seti seçin' : undefined}>
            {arpcBusy ? 'Doğrulanıyor…' : 'ARPC Üret & Karta Doğrulat'}</button>
          {!cardPresent && <span className="muted small">○ okuyucuda kart yok</span>}
        </div>
      </div>

      {arpcResult && (arpcResult.error
        ? <p className="err-text">✗ {arpcResult.error}</p>
        : <div className="genac" style={{ marginTop: 10 }}>
            {arpcResult.verdict && <p className={arpcResult.verdict === 'PASS' ? 'capk-ok' : arpcResult.verdict === 'FAIL' ? 'err-text' : 'oda-partial'} style={{ fontWeight: 600 }}>
              {arpcResult.verdict === 'PASS' ? '✓ KART ISSUER AUTH KABUL ETTİ' : arpcResult.verdict === 'FAIL' ? '✗ KART REDDETTİ' : arpcResult.verdict === 'NA' ? '○ UYGULANAMAZ (kart issuer auth bildirmiyor)' : '◐ BELİRSİZ'} · {arpcResult.methodUsed?.toUpperCase()}</p>}
            <div className="oda-info">
              <span className="oda-chip">{arpcResult.scheme}</span>
              {arpcResult.pan && <span className="mono small muted">{arpcResult.pan}</span>}
              <span className="mono small">ATC {arpcResult.atc}</span>
              {arpcResult.un && <span className="mono small muted">UN {arpcResult.un}</span>}
              {arpcResult.issuerAuthAdvertised != null && <span className={`oda-chip ${arpcResult.issuerAuthAdvertised ? 'alt' : ''}`}>Issuer Auth: {arpcResult.issuerAuthAdvertised ? 'evet' : 'hayır'}</span>}
              {arpcResult.arqcVerified != null && <span className={arpcResult.arqcVerified ? 'st-ok' : 'st-warn'}>{arpcResult.arqcVerified ? '✓ ARQC doğrulandı' : '○ ARQC doğrulanamadı'}</span>}
            </div>
            <table className="kv-table"><tbody>
              <tr><td>ARQC (karttan)</td><td className="mono">{arpcResult.arqc}</td></tr>
              <tr><td>{arpcResult.method1?.name}</td><td className="mono">{arpcResult.method1?.arpc} <span className="muted">· IAD {arpcResult.method1?.iad}</span></td></tr>
              <tr><td>{arpcResult.method2?.name}</td><td className="mono">{arpcResult.method2?.arpc} <span className="muted">· IAD {arpcResult.method2?.issuerAuthData}</span></td></tr>
              {arpcResult.sent && <tr><td>Doğru ARPC → kart</td><td className="mono small">{arpcResult.sent.method}{arpcResult.sent.cid ? ` · CID ${arpcResult.sent.cid} (${arpcResult.sent.cidLabel})` : ''} · SW {arpcResult.sent.sw}</td></tr>}
              {arpcResult.negative && !arpcResult.negative.error && <tr><td>Bozuk ARPC → kart <span className="muted">(negatif test)</span></td><td className="mono small">CID {arpcResult.negative.cid} ({arpcResult.negative.cidLabel}) · SW {arpcResult.negative.sw} · {arpcResult.negative.rejected ? '✓ reddetti' : '✗ reddetmedi'}</td></tr>}
              {arpcResult.sent?.note && <tr><td>Not</td><td className="muted small">{arpcResult.sent.note}</td></tr>}
              <tr><td>Session Key (SKac)</td><td className="mono small muted">{arpcResult.method2?.sessionKey}</td></tr>
            </tbody></table>
          </div>)}
    </section>
    </>
  );
}
