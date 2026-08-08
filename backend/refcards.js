// Referans ("altın") kart deposu — onaylı bir kartın perso parmak izini alıp
// üretim kartlarını ona karşı doğrulama.
//
// Perso bürosunun günlük işi: bir kart onaylanır, sonra binlercesi basılır.
// Soru "EMV'ye uygun mu" değil, "ONAYLANANLA AYNI mı". Kural motoru ilkini,
// bu modül ikincisini yanıtlar.
//
// Tasarım kararı — KİMLİK ALANLARININ DEĞERİ SAKLANMAZ:
// PAN, kart sahibi adı, sertifikalar, sayaçlar zaten her kartta farklıdır;
// referansta tutmak kıyaslamaya hiçbir şey katmaz, yalnızca dosyalarda PII
// biriktirir. Bu alanlar "vardı/yoktu" olarak kaydedilir, değerleri atılır.
//
// Varsayılan sınıflandırma: kimlik listesinde OLMAYAN her tag "yapısal"dır,
// yani referansla birebir eşleşmelidir. Yeni/bilinmeyen bir tag'in sessizce
// göz ardı edilmesindense fark olarak raporlanması QA açısından doğrudur.
import { readFileSync, writeFileSync, readdirSync, unlinkSync, existsSync, mkdirSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const HERE = dirname(fileURLToPath(import.meta.url));
const DIR = join(HERE, 'references');
if (!existsSync(DIR)) mkdirSync(DIR, { recursive: true });

const norm = (h) => (h || '').replace(/\s/g, '').toUpperCase();
const idSafe = (s) => String(s || '').trim().toLowerCase().replace(/[^a-z0-9._-]/g, '-').slice(0, 64) || `ref-${Date.now()}`;
const fileFor = (id) => join(DIR, `${idSafe(id)}.json`);

// Karttan karta DEĞİŞMESİ BEKLENEN alanlar — fark = kusur değil.
export const DEFAULT_IDENTITY_TAGS = [
  '5A', '57', '56',            // PAN / Track2 / Track1
  '5F20', '5F34',              // Kart sahibi adı, PAN sıra no
  '5F24', '5F25',              // Son kullanma / geçerlilik başlangıcı
  '9F46', '9F48', '90', '92', '93', '9F4B', // Sertifikalar, remainder'lar, imzalar
  '9F26', '9F27', '9F36', '9F10', '9F4C',   // Kriptogram, ATC, IAD, ICC dinamik no
  '9F13', '9F17', '9F36', '9F41',           // Sayaçlar
  '9F7F', '9F4F', '9F63',                   // Üretim verisi / CPLC / proprietary
  '5F50', '9F5B',                           // Issuer URL, issuer script sonucu
];

// Kart image'ından (extractCardImage çıktısı) parmak izi üret.
export function buildFingerprint(image, { name, iface, identityTags } = {}) {
  const app = image?.applications?.[0] || {};
  const ident = new Set((identityTags || DEFAULT_IDENTITY_TAGS).map(norm));
  const tags = {};
  const identityPresent = [];
  for (const t of app.tags || []) {
    const tag = norm(t.tag);
    if (ident.has(tag)) { identityPresent.push(tag); continue; } // değeri SAKLANMAZ
    tags[tag] = { name: t.name || null, value: norm(t.value) };
  }
  const panRaw = (app.tags || []).find((t) => norm(t.tag) === '5A')?.value;
  const pan = panRaw ? norm(panRaw).replace(/F+$/, '') : null;
  return {
    schemaVersion: 1,
    id: idSafe(name),
    name: name || 'Referans kart',
    iface: iface || null,
    scheme: app.scheme || null,
    aid: app.aid ? norm(app.aid) : null,
    // Yalnızca maskeli PAN — hangi karttan alındığını ayırt etmek için.
    sourcePanMasked: pan ? pan.replace(/^(\d{6})\d+(\d{4})$/, '$1••••••$2') : null,
    identityTags: [...ident],
    identityPresent: [...new Set(identityPresent)].sort(),
    tags,
    structuralCount: Object.keys(tags).length,
  };
}

export function validateReference(r) {
  const errors = [];
  if (!r || typeof r !== 'object') return { valid: false, errors: ['Referans bir JSON nesnesi olmalı'] };
  if (r.schemaVersion !== 1) errors.push(`Desteklenmeyen schemaVersion: ${r.schemaVersion} (beklenen 1)`);
  if (!r.id) errors.push('id zorunlu');
  if (!r.name) errors.push('name zorunlu');
  if (!r.tags || typeof r.tags !== 'object') errors.push('tags zorunlu');
  if (r.tags && Object.keys(r.tags).length === 0) errors.push('tags boş — karşılaştırılacak yapısal alan yok');
  return { valid: errors.length === 0, errors, structuralCount: Object.keys(r.tags || {}).length };
}

export function listReferences() {
  let files = [];
  try { files = readdirSync(DIR).filter((f) => f.endsWith('.json')); } catch { return []; }
  const out = [];
  for (const f of files) {
    try {
      const r = JSON.parse(readFileSync(join(DIR, f), 'utf-8'));
      out.push({
        id: r.id, name: r.name, iface: r.iface, scheme: r.scheme, aid: r.aid,
        sourcePanMasked: r.sourcePanMasked || null, capturedAt: r.capturedAt || null,
        structuralCount: Object.keys(r.tags || {}).length,
        identityCount: (r.identityPresent || []).length,
      });
    } catch { /* bozuk dosya listeyi düşürmesin */ }
  }
  return out.sort((a, b) => String(a.name).localeCompare(String(b.name)));
}

export function getReference(id) {
  const f = fileFor(id);
  if (!existsSync(f)) return null;
  try { return JSON.parse(readFileSync(f, 'utf-8')); } catch { return null; }
}

export function saveReference(r) {
  const v = validateReference(r);
  if (!v.valid) return { ok: false, errors: v.errors };
  const id = idSafe(r.id);
  writeFileSync(fileFor(id), JSON.stringify({ ...r, id }, null, 2), 'utf-8');
  return { ok: true, id, structuralCount: v.structuralCount };
}

export function deleteReference(id) {
  const f = fileFor(id);
  if (!existsSync(f)) return { ok: false, error: 'Referans bulunamadı' };
  unlinkSync(f);
  return { ok: true };
}

// Üretim kartını referansa karşı kıyasla.
// status: match | differs | missing (kartta yok) | extra (referansta yok)
//         identity (kimlik alanı — farklı olması beklenir, kusur değil)
export function compareToReference(ref, image) {
  const app = image?.applications?.[0] || {};
  const ident = new Set((ref.identityTags || DEFAULT_IDENTITY_TAGS).map(norm));
  const cardByTag = new Map();
  for (const t of app.tags || []) cardByTag.set(norm(t.tag), { name: t.name || null, value: norm(t.value) });

  const rows = [];
  for (const [tag, exp] of Object.entries(ref.tags || {})) {
    const got = cardByTag.get(tag);
    rows.push({
      tag, name: exp.name, expected: exp.value, actual: got ? got.value : null,
      status: !got ? 'missing' : (got.value === exp.value ? 'match' : 'differs'),
    });
  }
  // Kartta olup referansta olmayanlar — kimlikse bilgilendirme, değilse 'extra'.
  for (const [tag, got] of cardByTag) {
    if (ref.tags?.[tag]) continue;
    if (ident.has(tag)) { rows.push({ tag, name: got.name, expected: null, actual: null, status: 'identity' }); continue; }
    rows.push({ tag, name: got.name, expected: null, actual: got.value, status: 'extra' });
  }
  rows.sort((a, b) => a.tag.localeCompare(b.tag));

  const c = (s) => rows.filter((r) => r.status === s).length;
  const counts = { match: c('match'), differs: c('differs'), missing: c('missing'), extra: c('extra'), identity: c('identity') };
  // Kusur = yapısal fark, eksik alan veya fazladan alan. Kimlik farkı SAYILMAZ.
  const defects = counts.differs + counts.missing + counts.extra;
  return {
    referenceId: ref.id, referenceName: ref.name, referenceIface: ref.iface || null,
    rows, counts, defects,
    verdict: defects === 0 ? 'PASS' : 'FAIL',
    note: 'Kimlik alanları (PAN, sertifikalar, sayaçlar…) karttan karta değişir; karşılaştırmaya katılmaz. '
      + 'Referansta tutulmayan bir tag kartta çıkarsa "fazladan" olarak raporlanır — sessizce yok sayılmaz.',
  };
}
