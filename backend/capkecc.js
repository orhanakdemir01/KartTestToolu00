// ECC CA Public Key deposu — Kernel 8 (ECC) çevrimdışı veri doğrulaması için.
//
// Şema: [EMV Book C-8 v1.2] Tablo 4.3 "ECC Certification Authority Public Key
// Related Data". RSA karşılığı (capk.js / Tablo 4.2) modulus+exponent tutarken
// ECC anahtarı eğri üzerindeki bir NOKTA'dır ve spec (x,y) koordinatlarının
// İKİSİNİN de saklanmasını önerir — böylece Kernel her işlemde y'yi yeniden
// hesaplamak zorunda kalmaz.
//
// Alanlar (Tablo 4.3):
//   rid    (5B)  — ödeme şeması
//   index  (1B)  — kartın 8F tag'i; RID ile birlikte anahtarı tekiller
//   suite  (1B)  — CA PK Algorithm Suite Indicator; bu spec sürümünde daima '10'
//   x, y   (NFIELD her biri) — CA public key noktası (P-256 → 32'şer bayt)
//   hash         — checksum: yukarıdakilerin birleşimi üzerinden SHA-256 (veya SHA-1).
//                  Spec: "RID checksum hesabına HER ZAMAN dahildir."
import crypto from 'crypto';
import { readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const HERE = dirname(fileURLToPath(import.meta.url));
const FILE = join(HERE, 'capkecc.json');

let keys = [];
try { keys = JSON.parse(readFileSync(FILE, 'utf-8')); } catch { keys = []; }

const clean = (h) => (h || '').replace(/\s/g, '').toUpperCase();
const SUITE_DEFAULT = '10'; // Tablo 4.3: bu spec sürümünde daima '10'

// Checksum girdisi = RID ‖ Index ‖ Suite ‖ X ‖ Y
function checksumInput(k) {
  return Buffer.from(clean(k.rid) + clean(k.index) + clean(k.suite || SUITE_DEFAULT) + clean(k.x) + clean(k.y), 'hex');
}
export function computeHash(k, algo = 'sha256') {
  return crypto.createHash(algo).update(checksumInput(k)).digest('hex').toUpperCase();
}

// Doğrulama: alan/format kontrolü + noktanın gerçekten eğri üzerinde olması +
// (hash verilmişse) SHA-256 veya SHA-1 ile checksum eşleşmesi.
export function verifyKey(k) {
  if (!k?.rid || !k?.index || !k?.x || !k?.y) {
    return { valid: false, reason: 'Eksik alan (rid/index/x/y)' };
  }
  const x = clean(k.x), y = clean(k.y);
  if (!/^[0-9A-F]+$/.test(x) || !/^[0-9A-F]+$/.test(y)) return { valid: false, reason: 'x/y geçersiz hex' };
  if (x.length !== y.length) return { valid: false, reason: `x (${x.length / 2}B) ve y (${y.length / 2}B) uzunlukları farklı` };
  if (x.length !== 64) return { valid: false, reason: `P-256 için x/y 32 bayt olmalı (gelen ${x.length / 2}B)` };
  if (!onCurveP256(x, y)) return { valid: false, reason: 'Nokta P-256 eğrisi üzerinde değil (x/y hatalı)' };
  const sha256 = computeHash(k, 'sha256');
  const sha1 = computeHash(k, 'sha1');
  if (!k.hash) return { valid: true, computedHash: sha256, sha1, reason: 'Nokta eğri üzerinde — checksum verilmedi, hesaplandı' };
  const exp = clean(k.hash);
  const valid = exp === sha256 || exp === sha1;
  return {
    valid, computedHash: sha256, sha1, expectedHash: exp,
    reason: valid ? `Checksum doğrulandı (${exp === sha256 ? 'SHA-256' : 'SHA-1'})` : 'Checksum uyuşmuyor',
  };
}

// y² ≡ x³ − 3x + b (mod p) — noktanın P-256 üzerinde olup olmadığını sağlar.
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const A = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffcn;
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
function onCurveP256(xHex, yHex) {
  try {
    const x = BigInt('0x' + xHex), y = BigInt('0x' + yHex);
    if (x >= P || y >= P) return false;
    const lhs = (y * y) % P;
    const rhs = (((x * x % P) * x % P) + A * x % P + B) % P;
    return lhs === ((rhs % P) + P) % P;
  } catch { return false; }
}

export function listKeys() { return keys; }
export function keysForRid(rid) { return keys.filter((k) => clean(k.rid) === clean(rid)); }

// Kartın 8F tag'i + AID'in RID'i ile anahtarı bul (ECC ODA zincirinin kökü).
export function findKey(rid, index) {
  const r = clean(rid), i = clean(index).padStart(2, '0');
  return keys.find((k) => clean(k.rid) === r && clean(k.index).padStart(2, '0') === i) || null;
}

function buildKey(input) {
  const k = {
    scheme: input.scheme || 'Custom',
    rid: clean(input.rid),
    index: clean(input.index).padStart(2, '0'),
    suite: clean(input.suite) || SUITE_DEFAULT,
    curve: input.curve || 'P-256',
    x: clean(input.x),
    y: clean(input.y),
    keyType: input.keyType || 'Test',
  };
  k.hash = clean(input.hash) || computeHash(k, 'sha256');
  return k;
}

export function addKey(input) {
  const k = buildKey(input);
  const v = verifyKey({ ...k, hash: clean(input.hash) || null });
  if (!v.valid) return { ok: false, error: v.reason, verify: v };
  if (findKey(k.rid, k.index)) return { ok: false, error: `RID ${k.rid} index ${k.index} zaten var` };
  keys.push(k);
  persist();
  return { ok: true, key: k, verify: v };
}

export function updateKey(input) {
  const k = buildKey(input);
  const v = verifyKey({ ...k, hash: clean(input.hash) || null });
  if (!v.valid) return { ok: false, error: v.reason, verify: v };
  const i = keys.findIndex((e) => clean(e.rid) === k.rid && clean(e.index) === k.index);
  if (i < 0) return { ok: false, error: 'Anahtar bulunamadı' };
  keys[i] = k;
  persist();
  return { ok: true, key: k, verify: v };
}

export function deleteKey(rid, index) {
  const r = clean(rid), i = clean(index).padStart(2, '0');
  const before = keys.length;
  keys = keys.filter((k) => !(clean(k.rid) === r && clean(k.index).padStart(2, '0') === i));
  if (keys.length === before) return { ok: false, error: 'Anahtar bulunamadı' };
  persist();
  return { ok: true };
}

function persist() {
  writeFileSync(FILE, JSON.stringify(keys, null, 2), 'utf-8');
}
