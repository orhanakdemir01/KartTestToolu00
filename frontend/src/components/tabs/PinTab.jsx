// "PIN Değiştir" tab: builds and sends an EMV PIN CHANGE/UNBLOCK (issuer
// script 84 24). The user only picks a key set + new PIN; the backend
// auto-reads the AID, PAN, PSN and ATC from the card. Shows the derived
// session keys, enciphered PIN block, MAC and the card's response.
const SCHEME_LABEL = { visa: 'Visa (VIS)', mastercard: 'Mastercard (M/Chip)', amex: 'American Express', troy: 'Troy (D-PAS)' };

export function PinTab({ pinForm, setPinForm, changePin, pinBusy, pinResult, sessionKeys, cardPresent,
  verifyForm, setVerifyForm, verifyPin, verifyBusy, verifyResult }) {
  const set = (patch) => setPinForm({ ...pinForm, ...patch });
  const isChange = pinForm.mode === 'change';
  const selectedIdx = sessionKeys.findIndex((k) => k.label === pinForm.keyLabel && (k.pan || '') === (pinForm.keyPan || ''));
  const sel = selectedIdx >= 0 ? sessionKeys[selectedIdx] : null;
  const missingEnc = sel && isChange && !sel.encKey;
  const missingMac = sel && !sel.macKey;

  const pickKey = (i) => {
    const k = sessionKeys[Number(i)];
    if (k) set({ keyLabel: k.label, keyPan: k.pan || '' });
    else set({ keyLabel: '', keyPan: '' });
  };

  return (
   <>
    <section className="panel">
      <div className="panel-head"><h2>PIN Değiştir</h2></div>
      <p className="muted small">
        EMV <b>PIN CHANGE / UNBLOCK</b> issuer script komutu (<span className="mono">84 24</span>) oluşturur ve karta gönderir.
        Sadece <b>anahtar setini</b> ve yeni PIN'i seçin — <b>AID, PAN, PSN ve ATC karttan otomatik okunur</b>.
        Seçilen setin <b>MAC</b> (bütünlük) ve <b>ENC</b> (gizlilik) anahtarlarıyla yeni PIN şifrelenir ve komut MAC'lenir.
        Sadece anahtarları elinizde olan test kartlarında çalışır.
      </p>

      <div className="capk-add">
        <div className="capk-add-row">
          <label>İşlem<select value={pinForm.mode} onChange={(e) => set({ mode: e.target.value })}>
            <option value="change">PIN Değiştir (yeni PIN)</option>
            <option value="unblock">PIN Blokaj Kaldır (PTC sıfırla)</option>
          </select></label>
          <label className="capk-wide">Anahtar seti
            <select value={selectedIdx >= 0 ? selectedIdx : ''} onChange={(e) => pickKey(e.target.value)}>
              <option value="">— seçin —</option>
              {sessionKeys.map((k, i) => (
                <option key={i} value={i}>
                  {k.label}{k.pan ? ` · ${k.pan}` : ' · (varsayılan)'} [{k.keyLevel}]
                  {k.macKey ? ' MAC✓' : ' MAC✗'}{k.encKey ? ' ENC✓' : ' ENC✗'}
                </option>
              ))}
            </select>
          </label>
          {isChange && (
            <label>Yeni PIN<input className="mono" inputMode="numeric" maxLength={12}
              value={pinForm.newPin} onChange={(e) => set({ newPin: e.target.value.replace(/\D/g, '') })} placeholder="4-12 rakam" /></label>
          )}
        </div>

        {(missingMac || missingEnc) && (
          <p className="err-text small">
            ⚠ Seçilen anahtar setinde {missingMac ? 'MAC' : ''}{missingMac && missingEnc ? ' ve ' : ''}{missingEnc ? 'ENC' : ''} anahtarı yok — İşlem Anahtarları sekmesinden ekleyin.
          </p>
        )}

        <button className="btn" disabled={pinBusy || !cardPresent} onClick={changePin}>
          {pinBusy ? 'Karttan okunuyor & gönderiliyor…' : (isChange ? 'PIN Değiştir' : 'Blokajı Kaldır')}
        </button>
        {!cardPresent && <span className="muted small"> — okuyucuda kart yok</span>}
      </div>

      {pinResult && (
        <div className={`pin-result ${pinResult.ok ? 'ok' : 'bad'}`}>
          {pinResult.error && <p className="err-text">✗ {pinResult.error}</p>}
          {pinResult.sw && (
            <p className={pinResult.ok ? 'capk-ok' : 'err-text'}>
              {pinResult.ok ? '✓ Kart kabul etti' : '✗ Kart reddetti'} — SW <span className="mono">{pinResult.sw}</span> · {pinResult.swText}
            </p>
          )}
          {(pinResult.apdu || pinResult.skmac) && (
            <table className="kv-table">
              <tbody>
                {pinResult.keyLabel && <tr><td>Anahtar seti</td><td className="mono">{pinResult.keyLabel} [{pinResult.keyLevel}]</td></tr>}
                {pinResult.scheme && <tr><td>Şema / metod</td><td className="mono">{SCHEME_LABEL[pinResult.scheme] || pinResult.scheme}</td></tr>}
                {pinResult.aid && <tr><td>AID (otomatik)</td><td className="mono">{pinResult.aid}</td></tr>}
                {pinResult.pan && <tr><td>PAN (otomatik)</td><td className="mono">{pinResult.pan}</td></tr>}
                {pinResult.atc && <tr><td>ATC (otomatik)</td><td className="mono">{pinResult.atc}{pinResult.atcSource && <span className="muted small"> · {pinResult.atcSource}</span>}</td></tr>}
                {pinResult.skmac && <tr><td>SK<sub>MAC</sub> (SMI)</td><td className="mono small">{pinResult.skmac}</td></tr>}
                {pinResult.skenc && <tr><td>SK<sub>ENC</sub> (SMC)</td><td className="mono small">{pinResult.skenc}</td></tr>}
                {pinResult.pinBlock && <tr><td>PIN bloğu (ISO-2)</td><td className="mono">{pinResult.pinBlock}</td></tr>}
                {pinResult.encPin && <tr><td>Şifreli PIN</td><td className="mono">{pinResult.encPin}</td></tr>}
                {pinResult.mac && <tr><td>Komut MAC</td><td className="mono">{pinResult.mac}</td></tr>}
                {pinResult.apdu && <tr><td>APDU</td><td className="mono b">{pinResult.apdu}</td></tr>}
              </tbody>
            </table>
          )}
          {pinResult.steps?.length > 0 && (
            <details className="builder" open>
              <summary>Kart komutları ({pinResult.steps.length} adım)</summary>
              <table className="capk-table">
                <thead><tr><th>Adım</th><th>Komut</th><th>Yanıt</th><th>SW</th></tr></thead>
                <tbody>
                  {pinResult.steps.map((s, i) => (
                    <tr key={i}>
                      <td>{s.name}</td>
                      <td className="mono small val">{s.command}</td>
                      <td className="mono small val">{s.response || '—'}</td>
                      <td className="mono">{s.sw} <span className="muted small">{s.swText}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </details>
          )}
        </div>
      )}
    </section>

    <section className="panel">
      <div className="panel-head"><h2>PIN Doğrula (offline)</h2></div>
      <p className="muted small">
        EMV <b>VERIFY</b> (<span className="mono">00 20 00 80</span>) ile girdiğiniz PIN'i karta gönderir; kart, içindeki
        <b> offline PIN</b> ile karşılaştırır. Kripto/anahtar gerekmez. ⚠ Yanlış PIN her denemede deneme sayacını (PTC)
        düşürür — sıfırlanınca PIN <b>bloklanır</b> (PIN Değiştir/Blokaj Kaldır ile sıfırlanır).
      </p>
      <div className="capk-add">
        <div className="capk-add-row">
          <label>PIN<input className="mono" inputMode="numeric" maxLength={12}
            value={verifyForm.pin} onChange={(e) => setVerifyForm({ pin: e.target.value.replace(/\D/g, '') })}
            placeholder="4-12 rakam" /></label>
          <button className="btn" disabled={verifyBusy || !cardPresent} onClick={verifyPin}>
            {verifyBusy ? 'Doğrulanıyor…' : 'PIN Doğrula'}
          </button>
          {!cardPresent && <span className="muted small"> — okuyucuda kart yok</span>}
        </div>
      </div>

      {verifyResult && (
        <div className={`pin-result ${verifyResult.correct ? 'ok' : 'bad'}`}>
          {verifyResult.error && <p className="err-text">✗ {verifyResult.error}</p>}
          {verifyResult.sw && (
            <p className={verifyResult.correct ? 'capk-ok' : 'err-text'}>
              {verifyResult.correct ? '✓ PIN DOĞRU — karttaki offline PIN ile eşleşti'
                : verifyResult.blocked ? '⛔ PIN BLOKLU — deneme hakkı bitti'
                : `✗ PIN YANLIŞ — kalan deneme hakkı: ${verifyResult.triesLeft ?? '?'}`}
              {' · SW '}<span className="mono">{verifyResult.sw}</span>
            </p>
          )}
          {(verifyResult.apdu || verifyResult.aid) && (
            <table className="kv-table"><tbody>
              {verifyResult.aid && <tr><td>AID (otomatik)</td><td className="mono">{verifyResult.aid}</td></tr>}
              {verifyResult.pan && <tr><td>PAN (otomatik)</td><td className="mono">{verifyResult.pan}</td></tr>}
              {verifyResult.pinBlock && <tr><td>PIN bloğu (ISO-2)</td><td className="mono">{verifyResult.pinBlock}</td></tr>}
              {verifyResult.apdu && <tr><td>APDU</td><td className="mono b">{verifyResult.apdu}</td></tr>}
              {(verifyResult.ptcBefore != null || verifyResult.ptcAfter != null) &&
                <tr><td>Deneme sayacı (PTC)</td><td className="mono">{verifyResult.ptcBefore ?? '?'} → {verifyResult.ptcAfter ?? '?'}</td></tr>}
            </tbody></table>
          )}
          {verifyResult.steps?.length > 0 && (
            <details className="builder">
              <summary>Kart komutları ({verifyResult.steps.length} adım)</summary>
              <table className="capk-table">
                <thead><tr><th>Adım</th><th>Komut</th><th>Yanıt</th><th>SW</th></tr></thead>
                <tbody>
                  {verifyResult.steps.map((s, i) => (
                    <tr key={i}><td>{s.name}</td><td className="mono small val">{s.command}</td>
                      <td className="mono small val">{s.response || '—'}</td>
                      <td className="mono">{s.sw} <span className="muted small">{s.swText}</span></td></tr>
                  ))}
                </tbody>
              </table>
            </details>
          )}
        </div>
      )}
    </section>
   </>
  );
}
