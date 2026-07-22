// Uyumluluk denetim geçmişi + regresyon tespiti. Her /api/compliance koşusu kart
// başına (maskeli PAN anahtarıyla) otomatik kaydedilir; bir sonraki koşu, önceki
// koşuya göre PASS→FAIL (regresyon) ve FAIL→PASS (düzelme) değişimlerini raporlar.
// Sertifikasyon iş akışı: aynı kartı zaman içinde izle, bir düzeltmenin başka bir
// kuralı bozup bozmadığını yakala — cert laboratuvarlarının "test yönetimi" tarafı.
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'history');
const MAX_RUNS = 60;

function ensureDir() { if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true }); }

// Maskeli PAN → dosya-güvenli kart anahtarı (ilk 6 BIN + son 4). Ham PAN saklanmaz.
const maskPan = (pan) => {
  const d = String(pan || '').replace(/\D/g, '');
  if (d.length < 10) return d || null;
  return d.slice(0, 6) + '•'.repeat(d.length - 10) + d.slice(-4);
};
const cardKey = (pan) => {
  const d = String(pan || '').replace(/\D/g, '');
  if (!d) return null;
  return (d.length < 10 ? d : d.slice(0, 6) + '_' + d.slice(-4));
};

const fileFor = (pan) => { const k = cardKey(pan); return k ? path.join(dir, k + '.json') : null; };

function readRuns(pan) {
  const f = fileFor(pan);
  if (!f || !fs.existsSync(f)) return [];
  try { const j = JSON.parse(fs.readFileSync(f, 'utf8')); return Array.isArray(j.runs) ? j.runs : []; }
  catch { return []; }
}
function writeRuns(pan, runs, meta) {
  ensureDir();
  const f = fileFor(pan);
  if (!f) return;
  fs.writeFileSync(f, JSON.stringify({ key: cardKey(pan), panMasked: maskPan(pan), ...meta, runs }, null, 1));
}

// Bir koşuyu diğerinden ayırırken kural-durum haritası (id → status).
const rulesMap = (compliance) => {
  const m = {};
  for (const cat of compliance.categories || []) for (const r of cat.rules || []) m[r.id] = r.status;
  return m;
};

// Yeni koşuyu kaydet ve önceki koşuya göre regresyon/düzelme + mini geçmiş döndür.
export function recordAndDiff(pan, compliance, iface) {
  if (!pan) return null;
  const runs = readRuns(pan);
  const prev = runs.length ? runs[runs.length - 1] : null;
  const cur = rulesMap(compliance);
  const regressed = [], fixed = [];
  if (prev && prev.rules) {
    for (const id in cur) {
      const before = prev.rules[id], after = cur[id];
      if (!before || before === after) continue;
      if (before === 'pass' && after === 'fail') regressed.push({ id, from: before, to: after });
      else if (before === 'fail' && after === 'pass') fixed.push({ id, from: before, to: after });
    }
  }
  const s = compliance.summary || {};
  const rec = {
    savedAt: new Date().toISOString(), iface, scheme: compliance.scheme || null,
    verdict: s.verdict, pass: s.pass, fail: s.fail, warn: s.warn, na: s.na, total: s.total,
    rules: cur,
  };
  runs.push(rec);
  while (runs.length > MAX_RUNS) runs.shift();
  writeRuns(pan, runs, { scheme: compliance.scheme || null });
  const recent = runs.slice(-8).map((r) => ({ savedAt: r.savedAt, iface: r.iface, verdict: r.verdict, pass: r.pass, fail: r.fail, warn: r.warn }));
  return { first: !prev, prevAt: prev?.savedAt || null, regressed, fixed, recent, runCount: runs.length };
}

export function listCards() {
  ensureDir();
  return fs.readdirSync(dir).filter((f) => f.endsWith('.json')).map((f) => {
    try {
      const j = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
      const last = j.runs?.[j.runs.length - 1] || {};
      return { key: j.key, panMasked: j.panMasked, scheme: j.scheme, runs: j.runs?.length || 0, lastAt: last.savedAt || null, lastVerdict: last.verdict || null };
    } catch { return null; }
  }).filter(Boolean).sort((a, b) => String(b.lastAt).localeCompare(String(a.lastAt)));
}

export function cardHistory(pan) { return readRuns(pan); }

export function clearHistory(pan) {
  ensureDir();
  if (pan) { const f = fileFor(pan); if (f && fs.existsSync(f)) { fs.unlinkSync(f); return true; } return false; }
  for (const f of fs.readdirSync(dir)) if (f.endsWith('.json')) fs.unlinkSync(path.join(dir, f));
  return true;
}
