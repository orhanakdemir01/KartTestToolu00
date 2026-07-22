import { OdaPanel } from '../OdaPanel.jsx';

// "Kart & EMV" tab: EMV read flow + card mock + contactless UID + ATR decode
export function CardTab({
  emv, emvBusy, cardPresent, runEmv,
  sessionKeys, selectedKeyIdx, setSelectedKeyIdx,
  uid, uidBusy, readUid, card,
}) {
  return (
    <>
      {/* EMV READ */}
      <section className="panel">
        <div className="panel-head">
          <h2>EMV Kart Okuma</h2>
          <div className="emv-controls">
            <label className="keyset-pick">
              <span>Anahtar seti:</span>
              <select value={selectedKeyIdx} onChange={(e) => setSelectedKeyIdx(Number(e.target.value))}>
                <option value={-1}>Otomatik (PAN'a göre)</option>
                {sessionKeys.map((k, i) => (
                  <option key={i} value={i}>{k.label}{k.pan ? ` · ${k.pan}` : ' · (varsayılan)'}</option>
                ))}
              </select>
            </label>
            <button className="btn" disabled={emvBusy || !cardPresent} onClick={runEmv}>
              {emvBusy ? 'Okunuyor…' : '▶ EMV Akışını Çalıştır'}
            </button>
          </div>
        </div>
        {!emv && <p className="muted small">PPSE → SELECT AID → GPO → READ RECORD zincirini çalıştırır ve kart verisini çıkarır.</p>}
        {emv?.error && <p className="err-text">{emv.error}</p>}
        {emv?.cardData?.pan && (
          <div className="emv-result">
            <div className="emv-card">
              <div className="emv-top">
                <span className="emv-brand">{emv.cardData.scheme || emv.applications?.[0]?.label || 'EMV'}</span>
              </div>
              <div className="emv-chip" aria-label="çip">
                <svg width="38" height="28" viewBox="0 0 46 34" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <defs><linearGradient id="emvChip" x1="0" y1="0" x2="1" y2="1"><stop stopColor="#f5d97a" /><stop offset="1" stopColor="#c99a2e" /></linearGradient></defs>
                  <rect x="0.5" y="0.5" width="45" height="33" rx="6" fill="url(#emvChip)" stroke="rgba(0,0,0,0.18)" />
                  <rect x="6" y="5" width="34" height="24" rx="3" fill="none" stroke="rgba(0,0,0,0.28)" />
                  <line x1="6" y1="17" x2="40" y2="17" stroke="rgba(0,0,0,0.28)" />
                  <line x1="17" y1="5" x2="17" y2="29" stroke="rgba(0,0,0,0.28)" />
                  <line x1="29" y1="5" x2="29" y2="29" stroke="rgba(0,0,0,0.28)" />
                </svg>
              </div>
              <div className="emv-pan mono">{emv.cardData.panFormatted}</div>
              <div className="emv-bottom">
                <div><span className="emv-lbl">KART SAHİBİ</span><span>{emv.cardData.cardholderName || '—'}</span></div>
                <div><span className="emv-lbl">SKT</span><span className="mono">{emv.cardData.expiry || '—'}</span></div>
                <div><span className="emv-lbl">LUHN</span><span className={emv.cardData.luhnValid ? 'luhn-ok' : 'luhn-bad'}>{emv.cardData.luhnValid ? '✓ Geçerli' : '✗ Hatalı'}</span></div>
              </div>
            </div>
            <table className="kv-table">
              <tbody>
                <tr><td>AID</td><td className="mono">{emv.applications?.[0]?.aid}</td></tr>
                <tr><td>AIP</td><td className="mono">{emv.aip}</td></tr>
                <tr><td>AFL</td><td className="mono">{emv.afl}</td></tr>
                <tr><td>Service Code</td><td className="mono">{emv.cardData.serviceCode || '—'}</td></tr>
                <tr><td>PAN Seq</td><td className="mono">{emv.cardData.panSequence || '—'}</td></tr>
                <tr><td>Şema</td><td>{emv.cardData.scheme || '—'}</td></tr>
                <tr><td>Track 2</td><td className="mono small">{emv.cardData.track2 || '—'}</td></tr>
                <tr><td>Okunan kayıt</td><td>{emv.records?.length || 0}</td></tr>
                <tr><td>Toplam süre</td><td>{emv.totalMs != null ? `${emv.totalMs} ms` : '—'}</td></tr>
                {emv.capk && (
                  <tr><td>CA Anahtarı</td><td>
                    {emv.capk.found
                      ? <span className="capk-ok">✓ {emv.capk.scheme} idx {emv.capk.index} ({emv.capk.keyLength}-bit)</span>
                      : <span className="luhn-bad">RID {emv.capk.rid} idx {emv.capk.index} — kayıtlı değil</span>}
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
        {emv?.analysis && Object.keys(emv.analysis).length > 0 && (
          <div className="analysis">
            {emv.analysis.aip?.length > 0 && (
              <div className="ana-block">
                <h3>Kart Yetenekleri (AIP)</h3>
                <ul>{emv.analysis.aip.map((x, i) => <li key={i}>{x}</li>)}</ul>
              </div>
            )}
            {emv.analysis.cvm?.length > 0 && (
              <div className="ana-block">
                <h3>Doğrulama Yöntemleri (CVM)</h3>
                <ol>{emv.analysis.cvm.map((x, i) => <li key={i}>{x}</li>)}</ol>
              </div>
            )}
            {emv.analysis.serviceCode && (
              <div className="ana-block">
                <h3>Service Code · {emv.analysis.serviceCode.code}</h3>
                <ul>
                  <li><b>Değişim:</b> {emv.analysis.serviceCode.interchange}</li>
                  <li><b>Yetkilendirme:</b> {emv.analysis.serviceCode.authorization}</li>
                  <li><b>Hizmet:</b> {emv.analysis.serviceCode.services}</li>
                </ul>
              </div>
            )}
            {emv.analysis.usageControl?.length > 0 && (
              <div className="ana-block">
                <h3>Kullanım Kontrolü (AUC)</h3>
                <ul className="auc-list">
                  {emv.analysis.usageControl.map((x, i) => (
                    <li key={i} className={x.startsWith('✓') ? 'auc-yes' : 'auc-no'}>{x}</li>
                  ))}
                </ul>
              </div>
            )}
            {(emv.analysis.issuerCountry || emv.analysis.currency) && (
              <div className="ana-block">
                <h3>Issuer / Para Birimi</h3>
                <ul>
                  {emv.analysis.issuerCountry && <li><b>Ülke:</b> {emv.analysis.issuerCountry}</li>}
                  {emv.analysis.currency && <li><b>Para birimi:</b> {emv.analysis.currency}</li>}
                </ul>
              </div>
            )}
          </div>
        )}
        {emv?.genac && (
          <div className="genac">
            <h3>{emv.genac.source === 'GPO (qVSDC)' ? 'Kriptogram — qVSDC (GPO yanıtından)' : 'GENERATE AC — Kriptogram'}</h3>
            {emv.genac.error ? <p className="err-text">{emv.genac.error}</p> : (
              <table className="kv-table">
                <tbody>
                  <tr><td>CID</td><td className="mono">{emv.genac.cid} {emv.genac.cid === '80' ? '(ARQC)' : emv.genac.cid === '40' ? '(TC)' : emv.genac.cid === '00' ? '(AAC)' : ''}</td></tr>
                  <tr><td>ATC</td><td className="mono">{emv.genac.atc}</td></tr>
                  <tr><td>ARQC</td><td className="mono hl">{emv.genac.arqc}</td></tr>
                  <tr><td>IAD</td><td className="mono small">{emv.genac.iad || '—'}</td></tr>
                </tbody>
              </table>
            )}
            {emv.genac.verify?.noKey && <p className="muted small">⚠ Bu PAN için işlem anahtarı yok — ARQC doğrulanamadı. "İşlem Anahtarları" sekmesinden ekleyin.</p>}
            {emv.genac.verify?.error && <p className="err-text">ARQC hesaplama hatası: {emv.genac.verify.error}</p>}
            {emv.genac.verify && emv.genac.verify.match != null && (
              <div className="arqc-verify">
                <p className={emv.genac.verify.match ? 'capk-ok' : 'err-text'}>
                  {emv.genac.verify.match ? '✓ ARQC DOĞRULANDI' : '✗ ARQC UYUŞMUYOR'} — {emv.genac.verify.keyLabel} ({emv.genac.verify.keyLevel})
                </p>
                <table className="kv-table">
                  <tbody>
                    <tr><td>Hesaplanan</td><td className="mono">{emv.genac.verify.computed}</td></tr>
                    <tr><td>Kart ARQC</td><td className="mono">{emv.genac.verify.cardArqc}</td></tr>
                    {emv.genac.verify.iccMk && <tr><td>ICC MK</td><td className="mono small">{emv.genac.verify.iccMk}</td></tr>}
                    <tr><td>Session Key</td><td className="mono small">{emv.genac.verify.sessionKey}</td></tr>
                    <tr><td>MAC girdisi</td><td className="mono small">{emv.genac.verify.inputData}</td></tr>
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {emv?.oda && <OdaPanel oda={emv.oda} />}
      </section>

      {/* CONTACTLESS / PICC */}
      <section className="panel">
        <div className="panel-head">
          <h2>Temassız · PICC</h2>
          <button className="btn" disabled={uidBusy || !cardPresent} onClick={readUid}>
            {uidBusy ? 'Okunuyor…' : '◉ UID Oku'}
          </button>
        </div>
        {!uid && <p className="muted small">Temassız kartın anti-collision UID'sini okur (PC/SC <span className="mono">FF CA 00 00 00</span>).</p>}
        {uid?.error && <p className="err-text">{uid.error}</p>}
        {uid && uid.supported && (
          <div className="uid-result">
            <div className="uid-big mono">{uid.uid?.replace(/(.{2})/g, '$1 ').trim()}</div>
            <div className="uid-meta">{uid.tech} · {uid.durationMs} ms</div>
          </div>
        )}
        {uid && uid.supported === false && (
          <p className="muted small">⚠ Bu okuyucu/kart UID döndürmedi (SW {uid.sw}). {uid.note}</p>
        )}
      </section>

      {/* CARD / ATR */}
      <section className="card-panel">
        <div className="panel-head"><h2>Kart · ATR Çözümleme</h2></div>
        {!card && <p className="muted">Okuyucuya kart yerleştirin — ATR otomatik okunacak.</p>}
        {card && (
          <div className="atr-wrap">
            <div className="atr-hex"><span className="lbl">ATR</span><span className="mono hl">{card.atr}</span></div>
            <div className="atr-meta">
              <span>Protokol: <b>{card.protocol}</b></span>
              {card.atrDecoded?.protocols && <span>Desteklenen: <b>{card.atrDecoded.protocols.join(', ')}</b></span>}
              {card.atrDecoded?.historicalAscii && <span>Tarihçe: <b className="mono">"{card.atrDecoded.historicalAscii}"</b></span>}
            </div>
            {card.atrDecoded?.fields && (
              <details className="atr-details" open>
                <summary>ATR bayt çözümleme ({card.atrDecoded.fields.length} alan)</summary>
                <table className="atr-table">
                  <thead><tr><th>Bayt</th><th>Değer</th><th>Anlam</th></tr></thead>
                  <tbody>
                    {card.atrDecoded.fields.map((f, i) => (
                      <tr key={i}><td className="mono b">{f.name}</td><td className="mono">{f.value}</td><td>{f.desc}</td></tr>
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
