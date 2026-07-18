// Belirgin PASS/FAIL/WARN sonuç afişi — Uyumluluk & ODA sonuçlarının tepesinde,
// FIME Savvy / UL Brand Test Tool tarzı "bir bakışta genel karar" bandı.
// cls: 'pass' | 'warn' | 'fail'. counts: [{ n, label, cls }] (opsiyonel sayaç çipleri).
export function VerdictBanner({ cls, text, counts }) {
  return (
    <div className={`verdict-banner v-${cls}`}>
      <span className="vb-verdict">{text}</span>
      {counts && counts.length > 0 && (
        <div className="vb-counts">
          {counts.map((c, i) => (
            <span key={i} className={`vb-count ${c.cls || ''}`}><b>{c.n}</b>{c.label}</span>
          ))}
        </div>
      )}
    </div>
  );
}
