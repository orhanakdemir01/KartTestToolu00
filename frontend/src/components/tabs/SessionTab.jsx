import { useState } from 'react';
import { buildComparison } from '../../lib/compare.js';
import { CompareView } from '../CompareView.jsx';

// "Oturum" sekmesi: test oturumunun tüm sonuçlarını tek dosyaya kaydet / geri yükle
// ve iki oturumu karşılaştır. Sertifikasyon iş akışı: test et → kaydet → ara ver →
// yükle → devam et / karşılaştır. Kaydet/yükle mantığı App.jsx'te; bu bileşen UI.

const CURRENT = '__current__';

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

export function SessionTab({ sessions, sessionBusy, saveSessionAs, loadSessionFile, deleteSessionFile, refresh, snapshot, getSnapshotState }) {
  const st = snapshot?.state || {};
  const dut = st.emv?.cardData || {};
  const present = RESULT_LABELS.filter(([k]) => st[k]);

  // ── Karşılaştırma ──
  const [selA, setSelA] = useState(CURRENT);
  const [selB, setSelB] = useState('');
  const [cmpBusy, setCmpBusy] = useState(false);
  const [comparison, setComparison] = useState(null);
  const [cmpLabels, setCmpLabels] = useState({ a: 'A', b: 'B' });
  const labelFor = (v) => (v === CURRENT ? 'Mevcut' : (sessions.find((s) => s.file === v)?.name || v));
  const stateFor = async (v) => (v === CURRENT ? st : await getSnapshotState(v));
  const runCompare = async () => {
    if (!selA || !selB || selA === selB) return;
    setCmpBusy(true);
    try {
      const [a, b] = await Promise.all([stateFor(selA), stateFor(selB)]);
      setCmpLabels({ a: labelFor(selA), b: labelFor(selB) });
      setComparison(buildComparison(a, b));
    } catch { setComparison(null); }
    setCmpBusy(false);
  };

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

      <section className="panel">
        <div className="panel-head">
          <h2>Oturumları Karşılaştır</h2>
          <span className="muted small">kimlik · verdikt · perso tag farkları</span>
        </div>
        <p className="muted small">İki oturum seç, farkları gör. <b>Mevcut</b> = şu an bellekteki (kaydedilmemiş) oturum.</p>
        <div className="capk-add-row" style={{ alignItems: 'flex-end' }}>
          <label style={{ flex: 1 }}>A
            <select value={selA} onChange={(e) => setSelA(e.target.value)}>
              <option value={CURRENT}>Mevcut oturum</option>
              {sessions.map((s) => <option key={s.file} value={s.file}>{s.name}</option>)}
            </select>
          </label>
          <label style={{ flex: 1 }}>B
            <select value={selB} onChange={(e) => setSelB(e.target.value)}>
              <option value="">— seç —</option>
              <option value={CURRENT}>Mevcut oturum</option>
              {sessions.map((s) => <option key={s.file} value={s.file}>{s.name}</option>)}
            </select>
          </label>
          <button className="btn" disabled={cmpBusy || !selB || selA === selB} onClick={runCompare}>
            {cmpBusy ? 'Karşılaştırılıyor…' : '⇄ Karşılaştır'}
          </button>
        </div>
        {selB && selA === selB && <p className="err-text small">Aynı oturumu seçtin — farklı iki oturum seç.</p>}
      </section>

      {comparison && <CompareView comparison={comparison} labelA={cmpLabels.a} labelB={cmpLabels.b} />}
    </>
  );
}
