// Perso profili deposu — profiller VERİDİR, kod değil.
//
// Önceki tasarımda Ecos profili JS modülüne gömülüydü: her yeni issuer profili
// bir kod değişikliği + sürüm gerektiriyordu. Barnes / FIME Perceval sınıfı
// araçların ayırt edici özelliği tam tersidir — motor sabittir, profil dışarıdan
// yüklenir. Bu dosya `profiles/*.json` altındaki profilleri okur ve okunan kartla
// karşılaştırır.
//
// Profil şeması (schemaVersion 1):
//   { schemaVersion, id, name, scheme, aid, source, note,
//     sections: { <bölümAdı>: { name, tags: { <TAG>: { name, value, note? } } } },
//     expectations: { <mod>: { recordSection, aip: { section, tag } } } }
// <mod> = okuma modu: 'contact' | 'k2' | 'k8'. Kart hangi kernel'i çalıştırdıysa
// o modun beklentileri uygulanır.
import { readFileSync, writeFileSync, readdirSync, unlinkSync, existsSync, mkdirSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const HERE = dirname(fileURLToPath(import.meta.url));
const DIR = join(HERE, 'profiles');
if (!existsSync(DIR)) mkdirSync(DIR, { recursive: true });

const norm = (h) => (h || '').replace(/\s/g, '').toUpperCase();
const idSafe = (s) => String(s || '').trim().toLowerCase().replace(/[^a-z0-9._-]/g, '-').slice(0, 64);

function fileFor(id) { return join(DIR, `${idSafe(id)}.json`); }

// ── Yükleme ────────────────────────────────────────────────────────
export function listProfiles() {
  let files = [];
  try { files = readdirSync(DIR).filter((f) => f.endsWith('.json')); } catch { return []; }
  const out = [];
  for (const f of files) {
    try {
      const p = JSON.parse(readFileSync(join(DIR, f), 'utf-8'));
      out.push({
        id: p.id || f.replace(/\.json$/, ''),
        name: p.name || p.id || f,
        scheme: p.scheme || null,
        aid: p.aid || null,
        source: p.source || null,
        schemaVersion: p.schemaVersion || null,
        modes: Object.keys(p.expectations || {}),
        tagCount: Object.values(p.sections || {}).reduce((a, s) => a + Object.keys(s?.tags || {}).length, 0),
      });
    } catch { /* bozuk dosya listeyi düşürmesin */ }
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

export function getProfile(id) {
  const f = fileFor(id);
  if (!existsSync(f)) return null;
  try { return JSON.parse(readFileSync(f, 'utf-8')); } catch { return null; }
}

// ── Doğrulama ──────────────────────────────────────────────────────
// Profil kabul edilmeden önce yapısal olarak sınanır; bozuk profil sessizce
// "hiçbir kural eşleşmedi" sonucuna yol açmasın.
export function validateProfile(p) {
  const errors = [];
  if (!p || typeof p !== 'object') return { valid: false, errors: ['Profil bir JSON nesnesi olmalı'] };
  if (p.schemaVersion !== 1) errors.push(`Desteklenmeyen schemaVersion: ${p.schemaVersion} (beklenen 1)`);
  if (!p.id) errors.push('id zorunlu');
  if (!p.name) errors.push('name zorunlu');
  if (!p.sections || typeof p.sections !== 'object') errors.push('sections zorunlu');
  if (!p.expectations || typeof p.expectations !== 'object') errors.push('expectations zorunlu');

  let tagCount = 0;
  for (const [sk, sec] of Object.entries(p.sections || {})) {
    if (!sec || typeof sec !== 'object' || !sec.tags) { errors.push(`sections.${sk}: tags eksik`); continue; }
    for (const [tag, v] of Object.entries(sec.tags)) {
      tagCount++;
      if (!/^[0-9A-Fa-f]{2,8}$/.test(tag) && tag !== 'CVN') errors.push(`sections.${sk}.${tag}: geçersiz tag`);
      if (v?.value == null) { errors.push(`sections.${sk}.${tag}: value eksik`); continue; }
      if (!/^[0-9A-Fa-f]*$/.test(norm(v.value))) errors.push(`sections.${sk}.${tag}: value hex olmalı`);
    }
  }
  // expectations'ın işaret ettiği bölümler gerçekten var mı
  for (const [mode, e] of Object.entries(p.expectations || {})) {
    if (e?.recordSection && !p.sections?.[e.recordSection]) errors.push(`expectations.${mode}: '${e.recordSection}' bölümü yok`);
    if (e?.aip) {
      const s = p.sections?.[e.aip.section];
      if (!s) errors.push(`expectations.${mode}.aip: '${e.aip.section}' bölümü yok`);
      else if (!s.tags?.[e.aip.tag]) errors.push(`expectations.${mode}.aip: ${e.aip.section}.${e.aip.tag} yok`);
    }
  }
  return { valid: errors.length === 0, errors, tagCount, sectionCount: Object.keys(p.sections || {}).length };
}

export function saveProfile(p) {
  const v = validateProfile(p);
  if (!v.valid) return { ok: false, errors: v.errors };
  const id = idSafe(p.id);
  if (!id) return { ok: false, errors: ['id geçersiz'] };
  writeFileSync(fileFor(id), JSON.stringify({ ...p, id }, null, 2), 'utf-8');
  return { ok: true, id, ...v };
}

export function deleteProfile(id) {
  const f = fileFor(id);
  if (!existsSync(f)) return { ok: false, error: 'Profil bulunamadı' };
  unlinkSync(f);
  return { ok: true };
}

// ── Karşılaştırma ──────────────────────────────────────────────────
// Okuma modunun beklediği bölümü bul.
export function expectedSectionFor(profile, mode) {
  const key = profile?.expectations?.[mode]?.recordSection;
  return key ? profile.sections?.[key] || null : null;
}

// Beklenen AIP (mod → bölüm+tag eşlemesi profilde tanımlı).
export function expectedAip(profile, mode) {
  const a = profile?.expectations?.[mode]?.aip;
  if (!a) return null;
  const v = profile.sections?.[a.section]?.tags?.[a.tag]?.value;
  return v ? norm(v) : null;
}

// Karttan okunan tag'leri profille karşılaştır.
// Döner: { section, rows[{tag,name,expected,actual,status}], extra[], counts }
// status: match | differs | missing. Kartta olup profilde olmayanlar 'extra'.
export function compareWithProfile(profile, mode, flatTags) {
  const section = expectedSectionFor(profile, mode);
  if (!section) return null;
  // TLV değerleri baytlar arası boşlukla gelir ("09 49") — normalize edilmezse
  // her alan yanlışlıkla "farklı" görünür.
  const actualByTag = new Map();
  for (const t of flatTags || []) {
    if (t.value && !actualByTag.has(t.tag)) actualByTag.set(t.tag, norm(t.value));
  }
  const rows = [];
  for (const [tag, exp] of Object.entries(section.tags)) {
    const actual = actualByTag.get(tag) || null;
    const expected = norm(exp.value);
    rows.push({
      tag, name: exp.name, note: exp.note || null, expected, actual,
      status: !actual ? 'missing' : (actual === expected ? 'match' : 'differs'),
    });
  }
  const expectedTags = new Set(Object.keys(section.tags));
  const extra = [...actualByTag.entries()]
    .filter(([tag]) => !expectedTags.has(tag))
    .map(([tag, value]) => ({ tag, value }));
  return {
    section: section.name,
    profileId: profile.id, profileName: profile.name, note: profile.note || null,
    rows, extra,
    counts: {
      match: rows.filter((r) => r.status === 'match').length,
      differs: rows.filter((r) => r.status === 'differs').length,
      missing: rows.filter((r) => r.status === 'missing').length,
    },
  };
}
