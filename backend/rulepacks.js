// Kural paketleri — uyumluluk kuralları VERİ olarak (rulepacks/*.json).
//
// compliance.js'teki yerleşik RULES dizisi keyfi JS `run(ctx)` fonksiyonları
// içerir; güçlüdür ama her yeni issuer/şema gereksinimi kod değişikliği + sürüm
// demektir. Bu modül bildirimsel bir kontrol sözlüğü sunar: motor sabit, kural
// paketi dışarıdan yüklenir. İkisi BİRLİKTE çalışır — yerleşik kurallar aynen
// durur, paketler onların üstüne eklenir.
//
// JSON'dan keyfi kod ÇALIŞTIRILMAZ; yalnızca aşağıdaki `type` değerleri
// yorumlanır. Bilinmeyen tip = kural hatası (sessiz geçiş yok).
//
// Paket şeması (schemaVersion 1):
//   { schemaVersion, id, name, scheme?, spec?, description?,
//     rules: [ { id, cat, sev, req, spec?, when?, check } ] }
//   sev: 'M' zorunlu · 'R' önerilen · 'C' koşullu
//   when: { iface?, scheme?, aipBit?{byte,mask}, tagPresent? } → sağlanmazsa NA
//   check: { type, ... }  (vokabüler aşağıda)
import { readFileSync, writeFileSync, readdirSync, unlinkSync, existsSync, mkdirSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const HERE = dirname(fileURLToPath(import.meta.url));
const DIR = join(HERE, 'rulepacks');
if (!existsSync(DIR)) mkdirSync(DIR, { recursive: true });

const norm = (h) => (h || '').replace(/\s/g, '').toUpperCase();
const idSafe = (s) => String(s || '').trim().toLowerCase().replace(/[^a-z0-9._-]/g, '-').slice(0, 64);
const fileFor = (id) => join(DIR, `${idSafe(id)}.json`);

// Desteklenen kontrol tipleri — paket doğrulaması ve motor bunu paylaşır.
export const CHECK_TYPES = {
  presentAny: 'Verilen tag\'lerden en az biri mevcut',
  presentAll: 'Verilen tag\'lerin hepsi mevcut',
  absent: 'Tag mevcut DEĞİL',
  equals: 'Tag değeri beklenen değere eşit',
  oneOf: 'Tag değeri verilen kümede',
  format: 'Tag değeri regex kalıbına uyar',
  lengthBytes: 'Tag uzunluğu (bayt) exact/min/max',
  aipBit: 'AIP baytında maske bitleri set/clear',
  requiredIfAipBit: 'AIP biti set ise verilen tag\'ler zorunlu',
};

// ── Depo ───────────────────────────────────────────────────────────
export function listPacks() {
  let files = [];
  try { files = readdirSync(DIR).filter((f) => f.endsWith('.json')); } catch { return []; }
  const out = [];
  for (const f of files) {
    try {
      const p = JSON.parse(readFileSync(join(DIR, f), 'utf-8'));
      out.push({
        id: p.id || f.replace(/\.json$/, ''), name: p.name || p.id || f,
        scheme: p.scheme || null, spec: p.spec || null, description: p.description || null,
        schemaVersion: p.schemaVersion || null,
        ruleCount: (p.rules || []).length,
        enabled: p.enabled !== false,
      });
    } catch { /* bozuk dosya listeyi düşürmesin */ }
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

export function getPack(id) {
  const f = fileFor(id);
  if (!existsSync(f)) return null;
  try { return JSON.parse(readFileSync(f, 'utf-8')); } catch { return null; }
}

function loadAllPacks() {
  return listPacks().map((p) => getPack(p.id)).filter((p) => p && p.enabled !== false);
}

// ── Doğrulama ──────────────────────────────────────────────────────
function validateCheck(chk, path, errors) {
  if (!chk || typeof chk !== 'object') { errors.push(`${path}: check eksik`); return; }
  if (!CHECK_TYPES[chk.type]) { errors.push(`${path}: bilinmeyen check.type '${chk.type}' (geçerli: ${Object.keys(CHECK_TYPES).join(', ')})`); return; }
  const needTag = ['equals', 'oneOf', 'format', 'lengthBytes', 'absent'];
  const needTags = ['presentAny', 'presentAll', 'requiredIfAipBit'];
  if (needTag.includes(chk.type) && !chk.tag) errors.push(`${path}: '${chk.type}' için tag zorunlu`);
  if (needTags.includes(chk.type) && !Array.isArray(chk.tags)) errors.push(`${path}: '${chk.type}' için tags dizisi zorunlu`);
  if (chk.type === 'equals' && chk.value == null) errors.push(`${path}: equals için value zorunlu`);
  if (chk.type === 'oneOf' && !Array.isArray(chk.values)) errors.push(`${path}: oneOf için values dizisi zorunlu`);
  if (chk.type === 'format') {
    if (!chk.pattern) errors.push(`${path}: format için pattern zorunlu`);
    else { try { new RegExp(chk.pattern); } catch { errors.push(`${path}: geçersiz regex`); } }
  }
  if (chk.type === 'lengthBytes' && chk.exact == null && chk.min == null && chk.max == null) {
    errors.push(`${path}: lengthBytes için exact/min/max'tan biri zorunlu`);
  }
  if ((chk.type === 'aipBit' || chk.type === 'requiredIfAipBit') && chk.mask == null) {
    errors.push(`${path}: '${chk.type}' için mask zorunlu`);
  }
}

export function validatePack(p) {
  const errors = [];
  if (!p || typeof p !== 'object') return { valid: false, errors: ['Paket bir JSON nesnesi olmalı'] };
  if (p.schemaVersion !== 1) errors.push(`Desteklenmeyen schemaVersion: ${p.schemaVersion} (beklenen 1)`);
  if (!p.id) errors.push('id zorunlu');
  if (!p.name) errors.push('name zorunlu');
  if (!Array.isArray(p.rules) || p.rules.length === 0) errors.push('rules dizisi zorunlu (en az 1 kural)');
  const seen = new Set();
  (p.rules || []).forEach((r, i) => {
    const path = `rules[${i}]`;
    if (!r.id) errors.push(`${path}: id zorunlu`);
    else if (seen.has(r.id)) errors.push(`${path}: yinelenen kural id '${r.id}'`);
    else seen.add(r.id);
    if (!r.cat) errors.push(`${path}: cat zorunlu`);
    if (!r.req) errors.push(`${path}: req (gereksinim metni) zorunlu`);
    if (!['M', 'R', 'C'].includes(r.sev)) errors.push(`${path}: sev 'M' | 'R' | 'C' olmalı`);
    validateCheck(r.check, `${path}.check`, errors);
  });
  return { valid: errors.length === 0, errors, ruleCount: (p.rules || []).length };
}

export function savePack(p) {
  const v = validatePack(p);
  if (!v.valid) return { ok: false, errors: v.errors };
  const id = idSafe(p.id);
  if (!id) return { ok: false, errors: ['id geçersiz'] };
  writeFileSync(fileFor(id), JSON.stringify({ ...p, id }, null, 2), 'utf-8');
  return { ok: true, id, ruleCount: v.ruleCount };
}

export function deletePack(id) {
  const f = fileFor(id);
  if (!existsSync(f)) return { ok: false, error: 'Paket bulunamadı' };
  unlinkSync(f);
  return { ok: true };
}

// ── Değerlendirme ──────────────────────────────────────────────────
const PASS = (evidence) => ({ status: 'pass', evidence });
const WARN = (evidence, detail) => ({ status: 'warn', evidence, detail });
const NA = (detail) => ({ status: 'na', detail });
// Zorunlu (M) ve koşullu (C) kural başarısızlığı FAIL; önerilen (R) yalnızca WARN.
const bad = (sev, evidence, detail) => (sev === 'R' ? WARN(evidence, detail) : { status: 'fail', evidence, detail });

const aipByte = (ctx, n) => {
  const a = norm(ctx.aip);
  const i = (Number(n) || 1) - 1;
  return a.length >= (i + 1) * 2 ? parseInt(a.slice(i * 2, i * 2 + 2), 16) : null;
};
const maskOf = (m) => (typeof m === 'string' ? parseInt(m, m.startsWith('0x') || m.startsWith('0X') ? 16 : 16) : Number(m));

// `when` sağlanmıyorsa kural uygulanamaz (NA) — yanlışlıkla FAIL üretmesin.
function applicable(ctx, when) {
  if (!when) return { ok: true };
  if (when.iface && ctx.iface && when.iface !== ctx.iface) return { ok: false, why: `yalnızca ${when.iface}` };
  if (when.scheme && ctx.scheme !== when.scheme) return { ok: false, why: `yalnızca ${when.scheme}` };
  if (when.tagPresent && !ctx.has(when.tagPresent)) return { ok: false, why: `${when.tagPresent} yok` };
  if (when.aipBit) {
    const b = aipByte(ctx, when.aipBit.byte);
    if (b == null) return { ok: false, why: 'AIP yok' };
    if (!(b & maskOf(when.aipBit.mask))) return { ok: false, why: 'AIP biti set değil' };
  }
  return { ok: true };
}

function runCheck(ctx, chk, sev) {
  const V = (t) => norm(ctx.val(t));
  switch (chk.type) {
    case 'presentAny': {
      const hit = chk.tags.find((t) => ctx.has(t));
      return hit ? PASS(`tag ${hit}`) : bad(sev, '—', `Hiçbiri yok: ${chk.tags.join(', ')}`);
    }
    case 'presentAll': {
      const miss = chk.tags.filter((t) => !ctx.has(t));
      return miss.length === 0 ? PASS(chk.tags.join(' + ')) : bad(sev, '—', `Eksik: ${miss.join(', ')}`);
    }
    case 'absent':
      return ctx.has(chk.tag) ? bad(sev, V(chk.tag), `${chk.tag} bulunmamalıydı`) : PASS(`${chk.tag} yok`);
    case 'equals': {
      if (!ctx.has(chk.tag)) return bad(sev, '—', `${chk.tag} yok`);
      const a = V(chk.tag), e = norm(chk.value);
      return a === e ? PASS(a) : bad(sev, a, `Beklenen ${e}`);
    }
    case 'oneOf': {
      if (!ctx.has(chk.tag)) return bad(sev, '—', `${chk.tag} yok`);
      const a = V(chk.tag), set = chk.values.map(norm);
      return set.includes(a) ? PASS(a) : bad(sev, a, `Beklenen değerlerden biri: ${set.join(', ')}`);
    }
    case 'format': {
      if (!ctx.has(chk.tag)) return bad(sev, '—', `${chk.tag} yok`);
      const a = V(chk.tag);
      return new RegExp(chk.pattern).test(a) ? PASS(a) : bad(sev, a, chk.desc || `Kalıba uymuyor: ${chk.pattern}`);
    }
    case 'lengthBytes': {
      if (!ctx.has(chk.tag)) return bad(sev, '—', `${chk.tag} yok`);
      const n = V(chk.tag).length / 2;
      if (chk.exact != null && n !== chk.exact) return bad(sev, `${n} bayt`, `Beklenen tam ${chk.exact} bayt`);
      if (chk.min != null && n < chk.min) return bad(sev, `${n} bayt`, `En az ${chk.min} bayt olmalı`);
      if (chk.max != null && n > chk.max) return bad(sev, `${n} bayt`, `En çok ${chk.max} bayt olmalı`);
      return PASS(`${n} bayt`);
    }
    case 'aipBit': {
      const b = aipByte(ctx, chk.byte);
      if (b == null) return NA('AIP yok');
      const set = !!(b & maskOf(chk.mask));
      const want = chk.expect !== false; // varsayılan: set olmalı
      return set === want ? PASS(`AIP b${chk.byte || 1}=${b.toString(16).padStart(2, '0').toUpperCase()}`)
        : bad(sev, `AIP b${chk.byte || 1}=${b.toString(16).padStart(2, '0').toUpperCase()}`, want ? 'Bit set değil' : 'Bit set olmamalıydı');
    }
    case 'requiredIfAipBit': {
      const b = aipByte(ctx, chk.byte);
      if (b == null) return NA('AIP yok');
      if (!(b & maskOf(chk.mask))) return NA('Koşul sağlanmıyor (AIP biti set değil)');
      const miss = chk.tags.filter((t) => !ctx.has(t));
      return miss.length === 0 ? PASS(chk.tags.join(' + ')) : bad(sev, '—', `AIP biti set ama eksik: ${miss.join(', ')}`);
    }
    default:
      return bad(sev, '—', `Bilinmeyen check tipi: ${chk.type}`);
  }
}

// Yüklü paketleri ctx'e karşı çalıştır → yerleşik kurallarla aynı sonuç şekli.
export function evaluatePacks(ctx) {
  const out = [];
  for (const pack of loadAllPacks()) {
    if (pack.scheme && ctx.scheme && pack.scheme !== ctx.scheme) continue;
    for (const rule of pack.rules || []) {
      let r;
      try {
        const app = applicable(ctx, rule.when);
        r = app.ok ? runCheck(ctx, rule.check, rule.sev) : NA(`Uygulanamaz — ${app.why}`);
      } catch (e) { r = { status: 'fail', evidence: '—', detail: 'Kural hatası: ' + e.message }; }
      out.push({
        id: rule.id, cat: rule.cat, req: rule.req, sev: rule.sev,
        spec: rule.spec || pack.spec || null,
        source: { packId: pack.id, packName: pack.name },
        ...r, evidence: r.evidence ?? null, detail: r.detail ?? null,
      });
    }
  }
  return out;
}
