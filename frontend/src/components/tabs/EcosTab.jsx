// "ECOS (Kernel 8)" modülü — Mastercard Ecos AES kartları için ARQC/ARPC doğrulama.
// Normal (3DES) ARQC ile karışmasın diye ayrı modül. İki mod:
//  1) Karttan: okuyucudaki karttan GENERATE AC ile gerçek ARQC al ve doğrula.
//  2) Elle (Terminal): terminalden yakalanan işlem verisini yapıştır ve doğrula.
// Kripto: SKac = AES-CSK(MKac, ATC) → ARQC = AES-CMAC(SKac, AC input)[:8].
function EcosResultView({ r }) {
  if (!r) return null;
  if (r.error && !r.computedArqc) return <p className="err-text">✗ {r.error}</p>;
  const matched = r.match || r.matchMaskedCvr;
  return (
    <div className="genac" style={{ marginTop: 10 }}>
      {r.match != null && <p className={matched ? 'capk-ok' : 'err-text'} style={{ fontWeight: 600 }}>
        {matched ? `✓ ARQC DOĞRULANDI${r.matchMaskedCvr && !r.match ? ' (maskeli CVR — CDA)' : ''}` : '✗ ARQC EŞLEŞMEDİ'}</p>}
      {r.keyError && <p className="oda-partial" style={{ fontWeight: 600 }}>○ {r.keyError}</p>}
      <div className="oda-info">
        {r.pan && <span className="oda-chip">{r.pan}</span>}
        {r.atc && <span className="mono small">ATC {r.atc}</span>}
        {r.aip && <span className="mono small">AIP {r.aip}</span>}
        {r.genP1 && <span className="mono small muted">P1 {r.genP1}</span>}
        {r.cvn && <span className={`oda-chip ${r.cvn.isAes ? 'alt' : ''}`}>CVN {r.cvn.raw} · {r.cvn.sessionKey} ({r.cvn.cipher}){r.cvn.extendedInput ? ' · ext' : ''}</span>}
      </div>
      <table className="kv-table"><tbody>
        {r.cardArqc && <tr><td>Kart ARQC</td><td className="mono">{r.cardArqc}</td></tr>}
        {r.computedArqc && <tr><td>Hesaplanan ARQC</td><td className="mono">{r.computedArqc}</td></tr>}
        {r.computedArqcMaskedCvr && <tr><td>Hesaplanan (maskeli CVR)</td><td className="mono">{r.computedArqcMaskedCvr} {r.matchMaskedCvr ? '✓' : ''}</td></tr>}
        {r.cvr && <tr><td>CVR</td><td className="mono small">{r.cvr}{r.cvrMasked ? ` · maskeli ${r.cvrMasked}` : ''}</td></tr>}
        {r.mkac && <tr><td>MKac</td><td className="mono small muted">{r.mkac}</td></tr>}
        {r.skac && <tr><td>SKac</td><td className="mono small muted">{r.skac}</td></tr>}
        {r.arpc && <tr><td>ARPC (AES)</td><td className="mono">{r.arpc}</td></tr>}
        {r.acInput && <tr><td>AC input ({r.acInput.length / 2} bayt)</td><td className="mono small muted" style={{ wordBreak: 'break-all' }}>{r.acInput}</td></tr>}
        {r.iad && <tr><td>IAD</td><td className="mono small muted" style={{ wordBreak: 'break-all' }}>{r.iad}</td></tr>}
      </tbody></table>
    </div>
  );
}

// Temassız ECC ODA sonucu — BDH oturum anahtarları + EC-SDSA sertifika zinciri.
function EcosOdaResultView({ r }) {
  if (!r) return null;
  if (r.error) return (
    <div className="genac" style={{ marginTop: 10 }}>
      <p className="err-text" style={{ fontWeight: 600 }}>✗ {r.error}</p>
      {r.aip && <div className="oda-info"><span className="mono small">AIP {r.aip}</span>{r.afl && <span className="mono small">AFL {r.afl}</span>}</div>}
    </div>
  );
  const ch = r.chain || {};
  const bdh = r.bdh || {};
  const step = (ok, label) => <span className={`oda-chip ${ok ? '' : 'alt'}`} style={{ background: ok ? undefined : 'transparent' }}>{ok ? '✓' : '○'} {label}</span>;
  return (
    <div className="genac" style={{ marginTop: 10 }}>
      <p className={r.verdict === 'PASS' ? 'capk-ok' : 'oda-partial'} style={{ fontWeight: 600 }}>
        {r.verdict === 'PASS' ? '✓ ECC ODA DOĞRULANDI (CA → Issuer → Card)' : `○ Kısmi — ${r.verdict}`}</p>
      <div className="oda-info">
        {r.pan && <span className="oda-chip">{r.pan}</span>}
        {r.aip && <span className="mono small">AIP {r.aip}</span>}
        {r.afl && <span className="mono small">AFL {r.afl}</span>}
      </div>
      <div className="oda-info" style={{ marginTop: 6 }}>
        {step(ch.ca, `CA anahtarı (index ${r.certs?.caIndex || '?'})`)}
        {step(ch.issuer, 'Issuer cert (EC-SDSA)')}
        {step(ch.card, 'Card cert (EC-SDSA)')}
      </div>
      <table className="kv-table"><tbody>
        {bdh.z && <tr><td>BDH z (ECDH.x)</td><td className="mono small muted" style={{ wordBreak: 'break-all' }}>{bdh.z}</td></tr>}
        {bdh.kdk && <tr><td>Kdk</td><td className="mono small muted">{bdh.kdk}</td></tr>}
        {bdh.skc && <tr><td>SKC (gizlilik)</td><td className="mono small muted">{bdh.skc}</td></tr>}
        {bdh.ski && <tr><td>SKI (bütünlük)</td><td className="mono small muted">{bdh.ski}</td></tr>}
        {r.certs?.issuerCert && <tr><td>Issuer cert ({r.certs.issuerCert.length / 2}B)</td><td className="mono small muted" style={{ wordBreak: 'break-all' }}>{r.certs.issuerCert}</td></tr>}
        {r.certs?.cardCert && <tr><td>Card cert ({r.certs.cardCert.length / 2}B)</td><td className="mono small muted" style={{ wordBreak: 'break-all' }}>{r.certs.cardCert}</td></tr>}
      </tbody></table>
      {Array.isArray(r.records) && r.records.length > 0 && (
        <details className="builder" style={{ marginTop: 8 }}>
          <summary>Çözülen kayıtlar ({r.records.length})</summary>
          <table className="kv-table"><tbody>
            {r.records.map((rec, i) => (
              <tr key={i}><td>SFI{rec.sfi} #{rec.record} {rec.encrypted ? '🔒' : '·'}</td>
                <td className="mono small muted" style={{ wordBreak: 'break-all' }}>{rec.decrypted || rec.plaintext || '(boş)'}</td></tr>
            ))}
          </tbody></table>
        </details>
      )}
    </div>
  );
}

export function EcosTab({
  sessionKeys, cardPresent,
  ecosForm, setEcosForm, runEcosVerify, ecosBusy, ecosResult,
  ecosManForm, setEcosManForm, runEcosManual, ecosManBusy, ecosManResult,
  ecosOdaForm, setEcosOdaForm, runEcosOda, ecosOdaBusy, ecosOdaResult,
}) {
  const aesKeys = sessionKeys.filter((k) => (k.keyType || '3des') !== '3des');
  const keySelect = (form, setForm) => (
    <label>AES anahtar seti
      <select value={aesKeys.findIndex((k) => k.label === form.keyLabel && (k.pan || '') === (form.keyPan || ''))}
        onChange={(e) => { const k = aesKeys[+e.target.value]; setForm({ ...form, keyLabel: k?.label || '', keyPan: k?.pan || '' }); }}>
        <option value={-1}>— seç —</option>
        {aesKeys.map((k, i) => <option key={i} value={i}>{k.label}{k.pan ? ` · ${k.pan}` : ' (varsayılan)'} · {k.keyLevel} · {k.keyType}</option>)}
      </select>
    </label>
  );
  const m = (patch) => setEcosManForm({ ...ecosManForm, ...patch });
  return (
    <>
      <section className="panel">
        <div className="panel-head">
          <h2>ECOS (Kernel 8) · AES ARQC Doğrulama</h2>
          {cardPresent ? <span className="chip chip-on">● Kart Bağlı</span> : <span className="chip chip-off">● Kart Yok</span>}
        </div>
        <p className="muted small">Mastercard <b>ECOS / Kernel 8</b> (AES) kartları için ayrı modül — normal (3DES) ARQC ile karışmaz. Kripto: <span className="mono">SKac = AES-CSK(MKac, ATC)</span> → <span className="mono">ARQC = AES-CMAC(SKac, AC input)[:8]</span>. AC input = 9F02‖9F03‖9F1A‖95‖5F2A‖9A‖9C‖9F37‖AIP‖ATC‖CVR[‖EXT]. Anahtar seviyesi: <b>icc</b>=MKac · <b>session</b>=SKac · <b>master</b>=IMK→MKac. AES anahtar ekleme: <b>Oturum Anahtarları</b> sekmesi (Tip: AES).</p>
        {aesKeys.length === 0 && <p className="err-text small">⚠ AES anahtar seti yok — önce <b>Oturum Anahtarları</b>'nda Tip: AES-128/256 ile bir anahtar ekleyin.</p>}
      </section>

      <section className="panel">
        <div className="panel-head"><h2>1 · Karttan ARQC Doğrula</h2></div>
        <p className="muted small">Okuyucudaki karttan <b>GENERATE AC</b> ile gerçek ARQC alır, CVN'i çözer (b3-2=11 → AES) ve seçili AES anahtarıyla doğrular. CDA senaryosunda CVR'ın CDA bitleri otomatik maskelenip de denenir.</p>
        <div className="capk-add">
          <div className="capk-add-row">
            {keySelect(ecosForm, setEcosForm)}
            <label>ARC (ARPC, ops.)<input className="mono" maxLength={4} value={ecosForm.arc} onChange={(e) => setEcosForm({ ...ecosForm, arc: e.target.value })} placeholder="3030" /></label>
            <label className="capk-check"><input type="checkbox" checked={!!ecosForm.cda} onChange={(e) => setEcosForm({ ...ecosForm, cda: e.target.checked })} /> CDA iste (P1=90)</label>
            <button className="btn" disabled={ecosBusy || !cardPresent || !ecosForm.keyLabel} onClick={runEcosVerify}
              title={!cardPresent ? 'Okuyucuda kart yok' : !ecosForm.keyLabel ? 'AES anahtar seç' : undefined}>
              {ecosBusy ? 'Doğrulanıyor…' : 'Karttan ARQC Al & Doğrula'}</button>
          </div>
        </div>
        <EcosResultView r={ecosResult} />
      </section>

      <section className="panel">
        <div className="panel-head"><h2>2 · Elle ARQC Doğrula (Terminal)</h2></div>
        <p className="muted small">Terminalden yakalanan işlemi doğrula — kartı yeniden okumaz (kart farklı bir işlem/ATC üretir). <b>AC input</b>'u doğrudan yapıştır <i>veya</i> alanları gir. Kart ARQC'sini de girersen ✓/✗ verdikti verir. <b>master</b> seviye için PAN gerekir.</p>
        <div className="capk-add">
          <div className="capk-add-row">
            {keySelect(ecosManForm, setEcosManForm)}
            <label>ATC<input className="mono" maxLength={4} value={ecosManForm.atc} onChange={(e) => m({ atc: e.target.value })} placeholder="001D" /></label>
            <label>Kart ARQC (ops.)<input className="mono" maxLength={16} value={ecosManForm.cardArqc} onChange={(e) => m({ cardArqc: e.target.value })} placeholder="karşılaştır" /></label>
            <label>ARC (ops.)<input className="mono" maxLength={4} value={ecosManForm.arc} onChange={(e) => m({ arc: e.target.value })} placeholder="3030" /></label>
          </div>
          <div className="capk-add-row">
            <label className="capk-wide">AC input (hazır — varsa alanlar yok sayılır)<input className="mono" value={ecosManForm.acInput} onChange={(e) => m({ acInput: e.target.value })} placeholder="61/47 baytlık AC input hex" /></label>
          </div>
          <details className="builder">
            <summary>Alan alan gir (AC input boşsa)</summary>
            <div className="capk-add-row">
              <label>9F02 Tutar<input className="mono" value={ecosManForm.amountAuth} onChange={(e) => m({ amountAuth: e.target.value })} placeholder="000000001000" /></label>
              <label>9F03 Diğer<input className="mono" value={ecosManForm.amountOther} onChange={(e) => m({ amountOther: e.target.value })} placeholder="000000000000" /></label>
              <label>9F1A Ülke<input className="mono" maxLength={4} value={ecosManForm.termCountry} onChange={(e) => m({ termCountry: e.target.value })} placeholder="0792" /></label>
              <label>95 TVR<input className="mono" maxLength={10} value={ecosManForm.tvr} onChange={(e) => m({ tvr: e.target.value })} placeholder="0000000000" /></label>
            </div>
            <div className="capk-add-row">
              <label>5F2A Para<input className="mono" maxLength={4} value={ecosManForm.txnCurrency} onChange={(e) => m({ txnCurrency: e.target.value })} placeholder="0949" /></label>
              <label>9A Tarih<input className="mono" maxLength={6} value={ecosManForm.txnDate} onChange={(e) => m({ txnDate: e.target.value })} placeholder="260803" /></label>
              <label>9C Tip<input className="mono" maxLength={2} value={ecosManForm.txnType} onChange={(e) => m({ txnType: e.target.value })} placeholder="00" /></label>
              <label>9F37 UN<input className="mono" maxLength={8} value={ecosManForm.un} onChange={(e) => m({ un: e.target.value })} placeholder="12345678" /></label>
            </div>
            <div className="capk-add-row">
              <label>82 AIP<input className="mono" maxLength={4} value={ecosManForm.aip} onChange={(e) => m({ aip: e.target.value })} placeholder="3900" /></label>
              <label>CVR<input className="mono" maxLength={12} value={ecosManForm.cvr} onChange={(e) => m({ cvr: e.target.value })} placeholder="A00003A20000" /></label>
              <label className="capk-wide">EXT (extended input, ops.)<input className="mono" value={ecosManForm.iadExt} onChange={(e) => m({ iadExt: e.target.value })} placeholder="IAD[11..son]" /></label>
            </div>
          </details>
          <div className="capk-add-row">
            <label>PAN (master için)<input className="mono" value={ecosManForm.pan} onChange={(e) => m({ pan: e.target.value })} placeholder="MKac türetmesi" /></label>
            <label>PSN<input className="mono" maxLength={2} value={ecosManForm.psn} onChange={(e) => m({ psn: e.target.value })} placeholder="00" /></label>
            <button className="btn" disabled={ecosManBusy || !ecosManForm.keyLabel || !ecosManForm.atc} onClick={runEcosManual}
              title={!ecosManForm.keyLabel ? 'AES anahtar seç' : !ecosManForm.atc ? 'ATC gir' : undefined}>
              {ecosManBusy ? 'Hesaplanıyor…' : 'ARQC Hesapla & Doğrula'}</button>
          </div>
        </div>
        <EcosResultView r={ecosManResult} />
      </section>

      <section className="panel">
        <div className="panel-head"><h2>3 · Temassız ECC ODA (Kernel 8 · BDH)</h2></div>
        <p className="muted small">Temassız <b>Kernel 8</b> kartın çevrimdışı veri doğrulaması (ODA) — RSA yerine <b>ECC (P-256 · EC-SDSA)</b> sertifika zinciri. Akış: efemer GPO (QT gönder) → kart <span className="mono">9F8103</span> (blinded key + E(r)) döner → <b>BDH</b> ile <span className="mono">z → Kdk → SKC/SKI</span> → gizlilik-korumalı kayıtları <b>AES-CTR</b> ile çöz → <b>EC-SDSA</b> zinciri <span className="mono">CA → Issuer(90) → Card(9F46)</span> doğrula. Kartı <b>temassız okuyucuya</b> koyun.</p>
        <div className="capk-add">
          <div className="capk-add-row">
            <label>AID<input className="mono" value={ecosOdaForm.aid} onChange={(e) => setEcosOdaForm({ ...ecosOdaForm, aid: e.target.value })} placeholder="A0000000041010" /></label>
            <label>9F2B (ECC tetik)<input className="mono" maxLength={4} value={ecosOdaForm.p9f2b} onChange={(e) => setEcosOdaForm({ ...ecosOdaForm, p9f2b: e.target.value })} placeholder="0280" title="0280/FFFF = local-auth AFL (cert kayıtları)" /></label>
            <button className="btn" disabled={ecosOdaBusy || !cardPresent} onClick={runEcosOda}
              title={!cardPresent ? 'Okuyucuda kart yok' : undefined}>
              {ecosOdaBusy ? 'Doğrulanıyor…' : 'Temassız ECC ODA Çalıştır'}</button>
          </div>
        </div>
        <EcosOdaResultView r={ecosOdaResult} />
      </section>
    </>
  );
}
