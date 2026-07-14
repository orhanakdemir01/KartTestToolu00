import { useState } from 'react';

// One expandable certificate/signature block with its verification steps.
// status: 'ok' | 'fail' | 'partial' overrides the header icon/colour (default from cert.ok).
function OdaCertBlock({ title, cert, status }) {
  const [open, setOpen] = useState(false);
  if (!cert) return null;
  const st = status || (cert.ok ? 'ok' : 'fail');
  const icon = st === 'ok' ? '✓' : st === 'partial' ? '◐' : '✗';
  const cls = st === 'ok' ? 'capk-ok' : st === 'partial' ? 'oda-partial' : 'err-text';
  return (
    <div className="oda-cert">
      <div className="oda-cert-head" onClick={() => setOpen((o) => !o)}>
        <span className="apdu-caret">{open ? '▾' : '▸'}</span>
        <span className={cls}>{icon} {title}</span>
      </div>
      {open && (
        <table className="kv-table oda-steps">
          <tbody>
            {(cert.steps || []).map((s, i) => (
              <tr key={i}>
                <td className={s.ok ? 'capk-ok' : 'err-text'}>{s.ok ? '✓' : '✗'} {s.label}</td>
                <td className="mono small">{s.value}{s.note && <span className="oda-note"> — {s.note}</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

const KIND_LABEL = { DDA: 'DDA', CDA: 'CDA', fDDA: 'fast DDA (fDDA)', none: 'online (dinamik imza yok)' };

// One dynamic-signature block (DDA / CDA / fDDA) with its verification steps.
function OdaDynamicBlock({ dyn }) {
  if (dyn.kind === 'none') {
    return <p className="muted small oda-fdda-note">ℹ️ <b>Dinamik imza (SDAD) yapılmadı.</b> {dyn.note}</p>;
  }
  const steps = dyn.steps || [];
  const structOk = dyn.structOk != null ? dyn.structOk : steps.filter((s) => !/ Hash$| Data Hash$/i.test(s.label)).every((s) => s.ok);
  const hashOk = dyn.hashMatch != null ? dyn.hashMatch : (steps.find((s) => /Data Hash|Hash Result/i.test(s.label)) || {}).ok;
  const isFdda = dyn.kind === 'fDDA';
  const status = hashOk ? 'ok' : (structOk && isFdda ? 'partial' : 'fail');
  return (
    <>
      <OdaCertBlock
        title={`Dinamik İmza — ${KIND_LABEL[dyn.kind] || dyn.kind} (SDAD)${dyn.iccDynNumber ? ` · ICC Dyn No ${dyn.iccDynNumber}` : ''}`}
        cert={dyn}
        status={status}
      />
      {dyn.error && <p className="err-text small">✗ {dyn.error}</p>}
      {isFdda && structOk && !hashOk && (
        <p className="muted small oda-fdda-note">◐ <b>fDDA yapısal doğrulama tamam.</b> Sertifika zinciri (Issuer PK → ICC PK) geçerli ve SDAD'ın tüm yapısal testleri geçti: Data Header (6A) · Signed Data Format · Hash Algorithm Indicator · Signed Dynamic Application Data Length · Pad Pattern (BB) · Data Trailer (BC). Son adım "<b>Match Signed Static Application Data Hash</b>" için gereken terminal <b>DD-input</b> verisi VCPS'e (Visa Contactless Payment Spec) özel/gizli olup kartın public APDU yanıtından türetilemiyor — kriptografik/lisans kısıtı, araç eksikliği değil. FIME/Collis bu adımı VCPS erişimiyle yapar.</p>
      )}
    </>
  );
}

// Offline Data Authentication panel: cert chain + dynamic signature(s) (DDA/CDA/fDDA)
export function OdaPanel({ oda }) {
  const dynamics = oda.dynamics && oda.dynamics.length ? oda.dynamics : (oda.dynamic ? [oda.dynamic] : []);
  const label = dynamics.filter((d) => d.kind !== 'none').map((d) => KIND_LABEL[d.kind] || d.kind).join(' + ');
  return (
    <div className="genac oda-panel">
      <h3>Offline Veri Doğrulama (ODA){label ? ` — ${label}` : ''}</h3>
      {oda.error && <p className="err-text">ODA hatası: {oda.error}</p>}
      {!oda.capkFound && oda.rid && <p className="err-text">⚠ CAPK bulunamadı (RID {oda.rid}, index {oda.capkIndex}) — "CA Anahtarları" sekmesinden ekleyin.</p>}
      {oda.capkFound && (
        <>
          <p className={oda.ok ? 'capk-ok' : 'err-text'}>
            {oda.ok ? '✓ Sertifika zinciri DOĞRULANDI' : '✗ Sertifika zinciri doğrulanamadı'} · CAPK RID {oda.rid} idx {oda.capkIndex}
          </p>
          <OdaCertBlock title="Issuer Public Key Certificate (90)" cert={oda.issuerPK} />
          <OdaCertBlock title="ICC Public Key Certificate (9F46)" cert={oda.iccPK} />
          {dynamics.map((dyn, i) => <OdaDynamicBlock key={i} dyn={dyn} />)}
        </>
      )}
    </div>
  );
}
