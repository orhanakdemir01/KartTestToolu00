// İzlenebilirlik matrisi — hangi gereksinim, hangi spec kaynağından geliyor ve
// bu koşuda ne oldu?
//
// Sertifikasyon laboratuvarı raporlarının beklediği eksen budur: kural listesi
// değil, *gereksinim → kaynak → sonuç* izi. Uyumluluk motoru zaten her kuralda
// `spec` atıfı taşıyor; bu modül onu ikinci bir eksen olarak toplulaştırır.
//
// ⚠️ DÜRÜST KAPSAM: Buradaki "kapsam", ARACIN KURAL KÜMESİ üzerindendir —
// EMVCo/şema gereksinim setinin tamamı üzerinden DEĞİL. "EMV Book 3 %100
// kapsandı" gibi bir iddia üretilmez; üretilebilecek tek dürüst ifade
// "bu koşuda EMV Bk3 kaynaklı N denetim çalıştı, M'si uygulanabilirdi"dir.
// Akredite sertifikasyon lisanslı test materyali gerektirir (bkz. Book C-8/C-2
// spec notları) ve bu araç ön-sertifikasyon/QA kapsamındadır.

// Spec metninden belge kimliğini çıkar: "EMV Bk3 · §10.7 (…)" → "EMV Bk3".
// Bilinen belge kalıpları tanınır; tanınmayan ilk segment olduğu gibi kaynak sayılır.
export function sourceOf(spec) {
  const head = String(spec || '').split('·')[0].trim();
  if (!head) return '(kaynak belirtilmemiş)';
  const m = head.match(/^(EMV\s+Bk\s*\d+|EMV\s+Book\s*\d+|ISO\/IEC\s*\d+(?:-\d+)?|ISO\s*\d+(?:-\d+)?)/i);
  return m ? m[1].replace(/\s+/g, ' ').trim() : head;
}

const empty = () => ({ rules: 0, pass: 0, fail: 0, warn: 0, na: 0, mandatory: 0, mandatoryFail: 0, ruleIds: [] });

// compliance sonucundan (categories[].rules[]) izlenebilirlik matrisi üret.
export function buildTraceability(compliance) {
  const rows = [];
  for (const cat of compliance?.categories || []) {
    for (const r of cat.rules || []) rows.push(r);
  }
  const bySource = new Map();
  for (const r of rows) {
    const src = sourceOf(r.spec);
    if (!bySource.has(src)) bySource.set(src, { source: src, ...empty() });
    const e = bySource.get(src);
    e.rules++;
    e[r.status] = (e[r.status] || 0) + 1;
    e.ruleIds.push(r.id);
    if (r.sev === 'M') {
      e.mandatory++;
      if (r.status === 'fail') e.mandatoryFail++;
    }
  }
  // "Uygulanabilir" = NA olmayan. NA, kuralın bu kart/arayüz için geçerli
  // olmadığını gösterir — başarısızlık değildir, ama kapsam da saymaz.
  const sources = [...bySource.values()].map((e) => ({
    ...e,
    applicable: e.rules - e.na,
    // Uygulanabilir kuralların ne kadarı geçti (fail/warn hariç).
    passRate: e.rules - e.na > 0 ? Math.round((e.pass / (e.rules - e.na)) * 100) : null,
  })).sort((a, b) => b.rules - a.rules || a.source.localeCompare(b.source));

  const t = rows.reduce((a, r) => {
    a.rules++; a[r.status] = (a[r.status] || 0) + 1;
    if (r.sev === 'M') { a.mandatory++; if (r.status === 'fail') a.mandatoryFail++; }
    return a;
  }, { rules: 0, pass: 0, fail: 0, warn: 0, na: 0, mandatory: 0, mandatoryFail: 0 });
  t.applicable = t.rules - t.na;
  t.passRate = t.applicable > 0 ? Math.round((t.pass / t.applicable) * 100) : null;
  t.sourceCount = sources.length;

  // Kural başına düz iz — rapor/CSV için asıl "matris" bu.
  const matrix = rows.map((r) => ({
    id: r.id, cat: r.cat, sev: r.sev, req: r.req,
    spec: r.spec || null, source: sourceOf(r.spec),
    status: r.status, evidence: r.evidence || null, detail: r.detail || null,
    origin: r.source ? `paket:${r.source.packId}` : 'yerleşik',
  }));

  return {
    sources, totals: t, matrix,
    scopeNote: 'Kapsam bu ARACIN kural kümesi üzerinden hesaplanır — EMVCo/şema gereksinim setinin tamamı üzerinden değil. '
      + 'Akredite sertifikasyon lisanslı test materyali ve akreditasyon gerektirir; bu araç ön-sertifikasyon / perso QA kapsamındadır.',
  };
}
