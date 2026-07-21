import { useState } from 'react';

// "Oturum" sekmesi: test oturumunun tüm sonuçlarını tek dosyaya kaydet / geri yükle.
// Sertifikasyon iş akışı: test et → kaydet → ara ver → yükle → devam et / karşılaştır.
// Kaydetme/yükleme mantığı App.jsx'te (buildSnapshot/applySnapshot); bu bileşen sadece UI.

const RESULT_LABELS = [
  ['emv', 'EMV Okuma'],
  ['cardImage', 'Kart Image'],
  ['compContact', 'Uyumluluk · Temaslı'],
  ['compContactless', 'Uyumluluk · Temassız'],
  ['odaContact', 'ODA · Temaslı'],
  ['odaContactless', 'ODA · Temassız'],
  ['pdfCmpContact', 'PDF · Temaslı'],
  ['pdfCmpContactless', 'PDF · Temassız'],
  ['scenarioResult', 'Senaryo (L3)'],
  ['pinResult', 'PIN İşlemi'],
  ['verifyResult', 'PIN Doğrulama'],
  ['testResult', 'Test Paketi'],
];

export function SessionTab({ sessions, sessionBusy, saveSessionAs, loadSessionFile, deleteSessionFile, refresh, snapshot }) {
  const st = snapshot?.state || {};
  const dut = st.emv?.cardData || {};
  const present = RESULT_LABELS.filter(([k]) => st[k]);

  const suggested = () => {
    const scheme = dut.scheme || 'oturum';
    const last4 = dut.panFormatted ? dut.panFormatted.replace(/\D/g, '').slice(-4) : '';
    const day = new Date().toISOString().slice(0, 10);
    return [scheme, last4, day].filter(Boolean).join('-');
  };
  const [name, setName] = useState(suggested());
  const fmtDate = (iso) => { try { return new Date(iso).toLocaleString('tr-TR'); } catch { return iso; } };

  return (
    <>
      <section className="panel">
        <div className="panel-head">
          <h2>Test Oturumu</h2>
          <span className="muted small">sonuçları tek dosyada sakla · sonra devam et / karşılaştır</span>
        </div>
        <p className="muted small">Ekrandaki tüm sonuçları (DUT, EMV, uyumluluk, ODA, PDF, senaryo, PIN, rapor başlığı, seçili anahtar seti) tek bir <span className="mono">.ktsession.json</span>'a kaydeder. <b>Gizli anahtarlar saklanmaz.</b> Yükleyince ekran aynen geri gelir.</p>

        <div className="oda-info" style={{ marginBottom: 10 }}>
          {dut.scheme && <span className="oda-chip">{dut.scheme}</span>}
          {dut.panFormatted && <span className="mono small">{dut.panFormatted}</span>}
          <span className="muted small">· {present.length} sonuç bellekte</span>
        </div>

        {present.length > 0 ? (
          <div className="prof-chips" style={{ marginBottom: 12 }}>
            {present.map(([k, lbl]) => <span key={k} className="prof-chip st-ok">✓ {lbl}</span>)}
          </div>
        ) : <p className="muted small">Henüz kaydedilecek sonuç yok — önce bir okuma/denetim çalıştırın.</p>}

        <div className="capk-add-row">
          <label style={{ flex: 1 }}>Oturum adı
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="ör. Mastercard-0019-2026-07-21" />
          </label>
          <button className="btn" disabled={sessionBusy === 'save' || !name.trim() || !present.length}
            onClick={() => saveSessionAs(name)}>{sessionBusy === 'save' ? 'Kaydediliyor…' : '💾 Oturumu Kaydet'}</button>
        </div>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Kayıtlı Oturumlar ({sessions.length})</h2>
          <button className="btn-sm ghost" onClick={refresh}>↻ Yenile</button>
        </div>
        {sessions.length === 0 ? <p className="muted small">Henüz kayıtlı oturum yok.</p> : (
          <div className="capk-scroll">
            <table className="capk-table">
              <thead><tr><th>Ad</th><th>Kart</th><th>Kaydedildi</th><th></th></tr></thead>
              <tbody>
                {sessions.map((s) => (
                  <tr key={s.file}>
                    <td className="b">{s.name}</td>
                    <td className="small">{s.scheme || '—'}{s.pan ? <span className="mono muted"> · {s.pan}</span> : ''}</td>
                    <td className="small muted">{fmtDate(s.savedAt)}</td>
                    <td className="capk-actions">
                      <button className="btn-sm" disabled={sessionBusy === s.file} onClick={() => loadSessionFile(s.file)}>
                        {sessionBusy === s.file ? 'Yükleniyor…' : 'Yükle'}
                      </button>
                      <button className="btn-sm ghost" onClick={() => { if (confirm(`Silinsin mi? ${s.name}`)) deleteSessionFile(s.file); }}>Sil</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
