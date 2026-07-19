// "Rapor" tab: sertifikasyon kampanyası runner + lab/operatör başlığı +
// konsolide master rapor (uyumluluk, ODA, EMV/kriptogram, PIN, senaryo, test,
// trace) HTML/PDF dışa aktarımı. Barnes/Collis/UL/FIME tarzı tek arşiv çıktısı.
export function ReportTab({
  downloadReport, printReport, reportMeta, setReportMeta,
  runCampaign, campaignBusy, contactPresent, contactlessPresent,
  card, emv, testResult, trace,
  compContact, compContactless, odaContact, odaContactless,
  pinResult, verifyResult, scenarioResult,
}) {
  const setMeta = (patch) => setReportMeta({ ...reportMeta, ...patch });
  const busy = !!campaignBusy;
  const sections = [
    ['Test edilen kart (DUT) & EMV', !!emv?.cardData?.pan],
    ['Uyumluluk — Temaslı', !!compContact?.compliance],
    ['Uyumluluk — Temassız', !!compContactless?.compliance],
    ['Offline sertifika (ODA) — Temaslı', !!odaContact?.oda],
    ['Offline sertifika (ODA) — Temassız', !!odaContactless?.oda],
    ['Kriptogram / ARQC', !!emv?.genac],
    ['PIN işlemleri', !!(pinResult && !pinResult.error) || !!(verifyResult && !verifyResult.error)],
    ['İşlem senaryoları (L3)', !!scenarioResult?.results?.length],
    ['Test paketi sonuçları', !!testResult?.results],
    [`Trace (${trace.length} satır)`, trace.length > 0],
  ];
  const ready = sections.some(([, on]) => on);

  return (
    <>
      <section className="panel">
        <div className="panel-head">
          <h2>Sertifikasyon Kampanyası</h2>
          <span className="muted small">tek akışta tam batarya · tek rapor</span>
        </div>
        <p className="muted small">Seçili arayüzde <b>EMV oku → uyumluluk → offline sertifika (ODA)</b> zincirini sırayla çalıştırır; sonuçlar aşağıdaki master rapora toplanır. Kart takılı olan arayüzü seç.</p>
        <div className="oda-iface-head" style={{ marginTop: 6 }}>
          <button className="btn" disabled={busy || !contactPresent} onClick={() => runCampaign('contact')}
            title={!contactPresent ? 'Temaslı yuvada kart yok' : undefined}>
            {campaignBusy === 'contact' ? 'Çalışıyor…' : '🔌 Temaslı Kampanya'}
          </button>
          <button className="btn" disabled={busy || !contactlessPresent} onClick={() => runCampaign('contactless')}
            title={!contactlessPresent ? 'Temassız yuvada kart yok' : undefined}>
            {campaignBusy === 'contactless' ? 'Çalışıyor…' : '📶 Temassız Kampanya'}
          </button>
          {!contactPresent && !contactlessPresent && <span className="iface-nocard">○ okuyucuda kart yok</span>}
        </div>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Master Rapor</h2>
          <div className="trace-actions">
            <button className="btn-sm" disabled={!ready} onClick={downloadReport}>⬇ HTML İndir</button>
            <button className="btn-sm" disabled={!ready} onClick={printReport}>🖨 Yazdır / PDF</button>
          </div>
        </div>
        <p className="muted small">Oturumdaki tüm sonuçları genel verdikt + DUT kimliği + lab başlığıyla tek yazdırılabilir rapora toplar.</p>

        <div className="report-meta">
          <label>Laboratuvar / Kurum<input value={reportMeta.lab} onChange={(e) => setMeta({ lab: e.target.value })} placeholder="ör. Perso QA Lab" /></label>
          <label>Operatör<input value={reportMeta.operator} onChange={(e) => setMeta({ operator: e.target.value })} placeholder="ör. O. Akdemir" /></label>
          <label>Referans / İş No<input value={reportMeta.ref} onChange={(e) => setMeta({ ref: e.target.value })} placeholder="ör. JOB-2026-014" /></label>
          <label className="report-notes">Not<input value={reportMeta.notes} onChange={(e) => setMeta({ notes: e.target.value })} placeholder="opsiyonel açıklama" /></label>
        </div>

        <ul className="report-contents">
          {sections.map(([label, on]) => (
            <li key={label} className={on ? 'on' : ''}>{on ? '✓' : '—'} {label}</li>
          ))}
        </ul>
        {!ready && <p className="muted small">Henüz veri yok — yukarıdan bir kampanya çalıştır ya da ilgili sekmelerden denetimleri koştur.</p>}
      </section>
    </>
  );
}
