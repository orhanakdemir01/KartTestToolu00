// "Genel Bakış" — aracın kabiliyet manifesti (şema/kernel/kural/CAPK/senaryo) +
// hızlı erişim. Olgunlaşan araca profesyonel bir giriş; breadth'i tek yerde gösterir.
import { useState } from 'react';

const KERNEL_SHORT = (k) => (k && k !== '—' ? k.split(' ')[0] : '—');

// Kripto öz-testi paneli — karta ihtiyaç duymadan bağımsız vektörlerle aracın
// kendi kriptosunu doğrular ("kalibrasyon sertifikası").
function SelfTestPanel({ api }) {
  const [res, setRes] = useState(null);
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true);
    try { const r = await fetch(`${api}/selftest`); setRes(await r.json()); }
    catch { setRes({ error: 'Backend bağlantısı başarısız' }); }
    setBusy(false);
  };
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Kripto Öz-testi</h2>
        {res && !res.error && <span className={res.failed === 0 ? 'chip chip-on' : 'chip chip-off'}>{res.passed}/{res.total} geçti · {res.independent.passed}/{res.independent.total} bağımsız</span>}
      </div>
      <p className="muted small">Aracın kendi kripto matematiğini (3DES · Retail MAC · ARQC/ARPC) <b>karta ihtiyaç duymadan</b>, bağımsız referans vektörlere (NIST/klasik DES + kart ground-truth) karşı doğrular. Bir ölçüm aletinin kalibrasyon sertifikası gibi: "bir kartta çalıştı" değil, <b>kanıtlanabilir biçimde doğru</b>.</p>
      <button className="btn" disabled={busy} onClick={run}>{busy ? 'Çalışıyor…' : 'Öz-testi Çalıştır'}</button>
      {res?.error && <p className="err-text" style={{ marginTop: 8 }}>✗ {res.error}</p>}
      {res && !res.error && (
        <table className="kv-table" style={{ marginTop: 10 }}>
          <tbody>
            {res.results.map((r, i) => (
              <tr key={i}>
                <td className={r.ok ? 'st-ok' : 'st-bad'} style={{ whiteSpace: 'nowrap' }}>{r.ok ? '✓' : '✗'} <span className={`oda-chip ${r.kind === 'independent' ? 'alt' : ''}`}>{r.kind === 'independent' ? 'bağımsız' : 'regresyon'}</span></td>
                <td className="small">{r.name}<br /><span className="muted small">{r.ref}</span></td>
                <td className="mono small">{r.ok ? r.expected : `beklenen ${r.expected} · gelen ${r.got || '—'}`}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

export function OverviewTab({ manifest, cardPresent, emv, selectTab, api }) {
  const m = manifest || {};
  const r = m.rules || {};
  const dut = emv?.cardData;

  const nav = [
    ['card', '💳 Kart & EMV', 'Kart oku · kriptogram · ODA'],
    ['compliance', '✔ Uyumluluk', 'Perso denetim · spec-izlenebilir'],
    ['batch', '🗃 Parti', 'Çoklu-kart QA'],
    ['history', '📈 Geçmiş', 'Regresyon trendi'],
    ['report', '📊 Rapor', 'Audit-grade sertifika'],
  ];

  return (
    <>
      <section className="panel">
        <div className="panel-head">
          <h2>KartTest — Sertifikasyon Konsolu</h2>
          <span className="muted small">EMV perso · kernel · ODA · çok-şemalı</span>
        </div>
        <p className="muted small">Barnes / Collis-UL / FIME-Perceval ölçütünde, <b>spec-izlenebilir</b> bir EMV sertifikasyon aracı — her verdikt otoriter kaynağa bağlı, tam şeffaf kapsam.</p>
        <div className="ov-cards">
          <div className="ov-card"><div className="ov-big">{m.schemes?.length ?? 8}</div><div className="ov-lbl">ödeme şeması</div></div>
          <div className="ov-card"><div className="ov-big">{r.count ?? 80}</div><div className="ov-lbl">uyumluluk kuralı<br /><span className="muted">{r.categories ?? 16} kategori</span></div></div>
          <div className="ov-card"><div className="ov-big">{m.capkCount ?? 83}</div><div className="ov-lbl">CA public key</div></div>
          <div className="ov-card"><div className="ov-big">{m.scenarioCount ?? 13}</div><div className="ov-lbl">L2/L3 senaryo</div></div>
        </div>
        {r.sev && <p className="muted small" style={{ marginTop: 4 }}>Kural önemi: <b className="st-bad">{r.sev.M}</b> zorunlu (M) · <b className="st-warn">{r.sev.R}</b> önerilen (R) · <b>{r.sev.C}</b> koşullu (C)</p>}
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Hızlı Erişim</h2>
          {cardPresent
            ? <span className="chip chip-on">● Kart Bağlı{dut?.scheme ? ` · ${dut.scheme}` : ''}</span>
            : <span className="chip chip-off">● Kart Yok</span>}
        </div>
        <div className="ov-nav">
          {nav.map(([id, label, desc]) => (
            <button key={id} className="ov-navbtn" onClick={() => selectTab(id)}>
              <span className="ov-navlbl">{label}</span>
              <span className="ov-navdesc">{desc}</span>
            </button>
          ))}
        </div>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Desteklenen Şemalar & Kernel'ler</h2>
          <span className="muted small">{m.schemes?.length ?? 0} şema · EMVCo Book C-2…C-8</span>
        </div>
        <div className="capk-scroll">
          <table className="capk-table">
            <thead><tr><th>Şema</th><th>RID</th><th>Temassız Kernel</th><th className="c">CA Anahtarı</th></tr></thead>
            <tbody>
              {(m.schemes || []).map((s) => (
                <tr key={s.rid} className={dut?.scheme === s.name ? 'capk-editing' : ''}>
                  <td className="b">{s.name}</td>
                  <td className="mono small">{s.rid}</td>
                  <td className="small">{s.kernel === '—' ? <span className="muted">—</span> : s.kernel}</td>
                  <td className={`c ${s.capks ? 'st-ok b' : 'muted'}`}>{s.capks || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="muted small" style={{ marginTop: 6 }}>CA anahtarı 0 olan şemalarda ODA kripto doğrulaması için "CA Anahtarları" sekmesinden anahtar eklenmeli.</p>
      </section>

      {m.coverage && (
        <section className="panel">
          <div className="panel-head">
            <h2>Kapsam Haritası</h2>
            <span className="muted small">
              <b className="st-ok">{m.coverage.summary.full}</b> tam · <b className="st-warn">{m.coverage.summary.partial}</b> kısmi · <b className="muted">{m.coverage.summary.out}</b> kapsam dışı
            </span>
          </div>
          <p className="muted small">EMV sertifikasyon katmanlarına göre aracın neyi test ettiği <b>ve neyi etmediği</b> — tam şeffaf, dürüst kapsam. Bu bir <b>analiz/QA aracıdır</b>; resmi sertifika (L1 elektriksel, lisanslı L2/L3 test paketleri, akreditasyon) üretmez.</p>
          <div className="capk-scroll">
            <table className="capk-table">
              <thead><tr><th>Alan</th><th className="c">Kapsam</th><th>Araç ne yapar</th><th>Kapsam dışı</th></tr></thead>
              <tbody>
                {m.coverage.areas.map((a, i) => {
                  const badge = a.scope === 'full' ? { cls: 'st-ok', t: '✓ tam' } : a.scope === 'partial' ? { cls: 'st-warn', t: '◐ kısmi' } : { cls: 'muted', t: '○ dışı' };
                  return (
                    <tr key={i}>
                      <td className="b small">{a.area}</td>
                      <td className={`c small ${badge.cls} b`}>{badge.t}</td>
                      <td className="small">{a.tool}</td>
                      <td className="small muted">{a.out}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      )}

      <SelfTestPanel api={api} />
    </>
  );
}
