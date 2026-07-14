// CA Public Key store: load, look up, verify (SHA-1) and add EMV CA public keys.
import crypto from 'crypto';
import { readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const HERE = dirname(fileURLToPath(import.meta.url));
const FILE = join(HERE, 'capk.json');

let keys = [];
try {
  keys = JSON.parse(readFileSync(FILE, 'utf-8'));
} catch {
  keys = [];
}

// EMV CA Public Key checksum = SHA-1( RID || Index || Modulus || Exponent )
export function computeHash({ rid, index, modulus, exponent }) {
  const data = Buffer.from(rid + index + modulus + exponent, 'hex');
  return crypto.createHash('sha1').update(data).digest('hex').toUpperCase();
}

export function verifyKey(k) {
  if (!k.rid || !k.index || !k.modulus || !k.exponent || !k.hash) {
    return { valid: false, reason: 'Eksik alan (rid/index/modulus/exponent/hash)' };
  }
  if (!/^[0-9A-Fa-f]+$/.test(k.modulus) || k.modulus.length % 2) {
    return { valid: false, reason: 'Modulus geçersiz hex' };
  }
  let calc;
  try { calc = computeHash(k); } catch (e) { return { valid: false, reason: 'Hesaplama hatası: ' + e.message }; }
  const valid = calc === k.hash.toUpperCase();
  return { valid, computedHash: calc, expectedHash: k.hash.toUpperCase(),
           reason: valid ? 'SHA-1 doğrulandı' : 'SHA-1 uyuşmuyor' };
}

export function listKeys() { return keys; }

export function keysForRid(rid) {
  return keys.filter((k) => k.rid.toUpperCase() === (rid || '').toUpperCase());
}

// Find a specific CA public key by RID + index (the card's 8F tag).
export function findKey(rid, index) {
  const r = (rid || '').toUpperCase();
  const i = (index || '').toUpperCase().padStart(2, '0');
  return keys.find((k) => k.rid.toUpperCase() === r && k.index.toUpperCase() === i) || null;
}

export function schemes() {
  const m = {};
  for (const k of keys) m[k.scheme] = (m[k.scheme] || 0) + 1;
  return m;
}

// Normalise raw input into a key object. If no hash is supplied it is computed
// (trust/edit mode); if a hash is supplied it must match (SHA-1 verification).
function buildKey(input) {
  const k = {
    scheme: input.scheme || 'Custom',
    rid: (input.rid || '').toUpperCase().replace(/\s/g, ''),
    index: (input.index || '').toUpperCase().replace(/\s/g, '').padStart(2, '0'),
    exponent: (input.exponent || '03').replace(/\s/g, ''),
    modulus: (input.modulus || '').toUpperCase().replace(/\s/g, ''),
    keyLength: input.modulus ? (input.modulus.replace(/\s/g, '').length / 2) * 8 : 0,
    hash: (input.hash || '').toUpperCase().replace(/\s/g, ''),
    keyType: input.keyType || '',
  };
  if (!k.rid || !k.index || !k.modulus || !k.exponent) {
    return { error: 'Eksik alan (rid/index/modulus/exponent)' };
  }
  if (!/^[0-9A-Fa-f]+$/.test(k.modulus) || k.modulus.length % 2) {
    return { error: 'Modulus geçersiz hex' };
  }
  if (k.hash) {
    const v = verifyKey(k);
    if (!v.valid) return { error: v.reason, ...v };
  } else {
    k.hash = computeHash(k); // no hash provided → compute and trust
  }
  return { key: k };
}

function persist() {
  keys.sort((a, b) => (a.scheme + a.index).localeCompare(b.scheme + b.index));
  writeFileSync(FILE, JSON.stringify(keys, null, 1));
}

// Add a new key. SHA-1 verified if a hash is given, otherwise computed. Persists.
export function addKey(input) {
  const { key: k, error } = buildKey(input);
  if (error) return { added: false, valid: false, reason: error };
  if (keys.find((x) => x.rid === k.rid && x.index === k.index && x.modulus === k.modulus)) {
    return { added: false, valid: true, reason: 'Bu anahtar zaten mevcut' };
  }
  if (findKey(k.rid, k.index)) {
    return { added: false, valid: true, reason: `Bu RID+index (${k.rid}/${k.index}) zaten var — düzenlemek için "Düzenle" kullanın` };
  }
  keys.push(k);
  try { persist(); } catch (e) { keys.pop(); return { added: false, valid: true, reason: 'Diske yazılamadı: ' + e.message }; }
  return { added: true, valid: true, key: k };
}

// Update an existing key (found by origRid+origIndex, or rid+index). SHA-1 verified
// if a hash is given, otherwise recomputed from the new modulus. Persists.
export function updateKey(input) {
  const origRid = (input.origRid || input.rid || '').toUpperCase().replace(/\s/g, '');
  const origIndex = (input.origIndex || input.index || '').toUpperCase().replace(/\s/g, '').padStart(2, '0');
  const at = keys.findIndex((x) => x.rid.toUpperCase() === origRid && x.index.toUpperCase() === origIndex);
  if (at < 0) return { updated: false, reason: `Düzenlenecek anahtar bulunamadı (${origRid}/${origIndex})` };
  const { key: k, error } = buildKey(input);
  if (error) return { updated: false, reason: error };
  // Guard against colliding with a different existing entry (changed RID/index).
  const clash = keys.findIndex((x) => x.rid === k.rid && x.index === k.index);
  if (clash >= 0 && clash !== at) return { updated: false, reason: `${k.rid}/${k.index} zaten başka bir kayıtta var` };
  const prev = keys[at];
  keys[at] = k;
  try { persist(); } catch (e) { keys[at] = prev; return { updated: false, reason: 'Diske yazılamadı: ' + e.message }; }
  return { updated: true, key: k };
}

// Delete a key by RID + index. Persists.
export function deleteKey(rid, index) {
  const r = (rid || '').toUpperCase().replace(/\s/g, '');
  const i = (index || '').toUpperCase().replace(/\s/g, '').padStart(2, '0');
  const before = keys.length;
  keys = keys.filter((x) => !(x.rid.toUpperCase() === r && x.index.toUpperCase() === i));
  if (keys.length === before) return { deleted: false, reason: `Anahtar bulunamadı (${r}/${i})` };
  try { persist(); } catch (e) { return { deleted: false, reason: 'Diske yazılamadı: ' + e.message }; }
  return { deleted: true };
}
