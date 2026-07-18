import { OdaPanel } from '../OdaPanel.jsx';
import { VerdictBanner } from '../VerdictBanner.jsx';

// "Offline Sertifika" tab: focused offline data-authentication / CDA certificate
// verification for Mastercard / Visa / Amex on BOTH contact and contactless. It
// reuses the full /api/emv/read flow (cert chain recovery + CDA GENERATE AC +
// SDAD verify) but surfaces only the certificate chain and the dynamic-signature
// result — the perso/cryptogram detail lives in the Kart & EMV tab.

const KIND_LABEL = { CDA: 'CDA', DDA: 'DDA', fDDA: 'fast DDA (fDDA)', none: 'dinamik imza yok' };

const dynState = (d) => {
  const done = d.kind !== 'none';
  const ok = d.hashMatch != null ? d.hashMatch : d.ok;
  return { done, ok: done && !!ok, partial: done && !ok && !!d.structOk };
};

// One interface's verification result: verdict banner + reused OdaPanel detail.
function OdaResult({ res, label, busy, onRun, clear, present }) {
  const oda = res && !res.error ? res.oda : null;
  const dynamics = oda ? (oda.dynamics && oda.dynamics.length ? oda.dynamics : (oda.dynamic ? [oda.dynamic] : [])) : [];
  const realDyns = dynamics.filter((d) => d.kind !== 'none');
  const certOk = !!oda?.ok;
  const allDynOk = realDyns.length > 0 && realDyns.every((d) => dynState(d).ok);
  const anyPartial = realDyns.some((d) => dynState(d).partial);
  // Overall verdict for the interface (cert chain + every offline method the AIP advertises).
  let verdict = null;
  if (oda) {
    if (!oda.capkFound) verdict = { cls: 'fail', text: '✗ CAPK YOK' };
    else if (certOk && allDynOk) verdict = { cls: 'pass', text: '✓ GEÇTİ' };
    else if (certOk && !realDyns.length) verdict = { cls: 'warn', text: '◐ ZİNCİR OK · İMZA YOK' };
    else if (certOk && anyPartial && !realDyns.some((d) => !dynState(d).ok && !dynState(d).partial)) verdict = { cls: 'warn', text: '◐ KISMİ' };
    else verdict = { cls: 'fail', text: '✗ BAŞARISIZ' };
  }

  return (
    <div className={`oda-iface ${verdict ? verdict.cls : ''}`}>
      <div className="oda-iface-head">
        <button className="btn" disabled={!!busy || !present} onClick={onRun}
          title={!present ? `${label} yuvada kart yok` : undefined}>{busy ? 'Doğrulanıyor…' : `${label} Doğrula`}</button>
        {!present && !busy && <span className="iface-nocard">○ yuvada kart yok</span>}
        {res && <button className="btn-sm ghost" onClick={clear}>temizle</button>}
      </div>

      {!res && <p className="muted small">Kartı bu arayüze koyup <b>{label} Doğrula</b>'ya bas — CAPK ile sertifika zinciri (Issuer PK → ICC PK) çözülür ve kartın AIP'de (tag 82) desteklediği <b>tüm offline yöntemler</b> (DDA/CDA) doğrulanır.</p>}
      {res?.error && <p className="err-text">✗ {res.error}</p>}

      {oda && <>
        <VerdictBanner cls={verdict.cls} text={verdict.text} />
        <div className="oda-info">
          <span className="oda-chip">{res.scheme || '?'}</span>
          {res.aid && <span className="mono small">{res.aid}</span>}
          {res.pan && <span className="mono small muted">· {res.pan}</span>}
          {realDyns.map((d, i) => <span key={i} className="oda-chip alt">{KIND_LABEL[d.kind] || d.kind}</span>)}
        </div>
        {/* Compact summary: cert chain + one badge per offline method performed */}
        <div className="oda-summary">
          <span className={oda.issuerPK?.ok ? 'st-ok' : 'st-bad'}>{oda.issuerPK?.ok ? '✓' : '✗'} Issuer PK</span>
          <span className={oda.iccPK?.ok ? 'st-ok' : 'st-bad'}>{oda.iccPK?.ok ? '✓' : '✗'} ICC PK</span>
          {realDyns.length ? realDyns.map((d, i) => {
            const s = dynState(d);
            return <span key={i} className={s.ok ? 'st-ok' : s.partial ? 'st-warn' : 'st-bad'}>{s.ok ? '✓' : s.partial ? '◐' : '✗'} {KIND_LABEL[d.kind] || d.kind} imza</span>;
          }) : <span className="st-warn">— imza yok</span>}
        </div>
        <OdaPanel oda={oda} />
      </>}
    </div>
  );
}

export function OdaTab({ odaContact, odaContactless, odaBusy, runOdaVerify, clearOda, contactPresent, contactlessPresent }) {
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Offline Sertifika Doğrulama</h2>
        <span className="muted small">CDA · Mastercard / Visa / Amex · temaslı + temassız</span>
      </div>
      <p className="muted small">Kartın <b>offline sertifika zincirini</b> (CAPK → Issuer PK → ICC PK) ve <b>CDA dinamik imzasını</b> (GENERATE AC P1=0x90 → SDAD) doğrular. Her iki arayüzü ayrı ayrı test et. CAPK'ler <b>CA Anahtarları</b> sekmesinden yönetilir.</p>

      <div className="oda-grid">
        <OdaResult res={odaContact} label="🔌 Temaslı" busy={odaBusy === 'contact'} present={contactPresent}
          onRun={() => runOdaVerify('contact')} clear={() => clearOda('contact')} />
        <OdaResult res={odaContactless} label="📶 Temassız" busy={odaBusy === 'contactless'} present={contactlessPresent}
          onRun={() => runOdaVerify('contactless')} clear={() => clearOda('contactless')} />
      </div>
    </section>
  );
}
