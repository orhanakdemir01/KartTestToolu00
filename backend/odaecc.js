// ECOS / Kernel 8 offline veri doğrulama (ODA) — ECC (Curve P-256) tabanlı.
// Klasik EMV RSA (oda.js) yerine Kernel 8 kartları ECDSA/ECC sertifika zinciri
// kullanır (CA ECC PK → Issuer ECC cert → ICC ECC cert; bkz. Book C-8 Ek B).
// Bu dosya ECDSA P-256 imza doğrulama ilkelini içerir; bağımsız RFC 6979 vektörüyle
// öz-teste tabidir (selftest.js). Sertifika-zinciri çözümü, kart formatı (Ek B) +
// CA ECC public key sağlandığında bunun üzerine kurulur.
import crypto from 'crypto';

const clean = (h) => h.replace(/\s/g, '');
const b64url = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// Ham (x,y) koordinatlarından P-256 public key nesnesi (JWK üzerinden).
export function p256PublicKeyFromXY(xHex, yHex) {
  return crypto.createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: b64url(Buffer.from(clean(xHex), 'hex')), y: b64url(Buffer.from(clean(yHex), 'hex')) },
    format: 'jwk',
  });
}

// ECDSA P-256 imza doğrulama. Public key ham x/y; imza r||s (IEEE P1363, ham);
// mesaj Buffer veya string. hash varsayılan SHA-256. Boolean döner.
export function ecdsaVerifyP256(xHex, yHex, message, rHex, sHex, hash = 'sha256') {
  const pub = p256PublicKeyFromXY(xHex, yHex);
  const sig = Buffer.concat([Buffer.from(clean(rHex), 'hex'), Buffer.from(clean(sHex), 'hex')]);
  const msg = Buffer.isBuffer(message) ? message : Buffer.from(message);
  return crypto.verify(hash, msg, { key: pub, dsaEncoding: 'ieee-p1363' }, sig);
}

// ── P-256 (secp256r1) nokta aritmetiği — Ecos ECC ODA (EC-SDSA) için. ──
// Node built-in genel EC nokta toplama sunmaz; saf BigInt ile implemente edildi.
const P256 = {
  p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
  a: 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffcn,
  b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
  n: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
  Gx: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  Gy: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
};
const bmod = (x, m) => ((x % m) + m) % m;
function powmod(b, e, m) { let r = 1n; b = bmod(b, m); while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; }
const finv = (x, m) => powmod(bmod(x, m), m - 2n, m); // modüler ters (Fermat)
function pDouble(P) {
  if (!P) return null;
  const { p, a } = P256;
  const s = bmod((3n * P.x * P.x + a) * finv(2n * P.y, p), p);
  const x = bmod(s * s - 2n * P.x, p);
  return { x, y: bmod(s * (P.x - x) - P.y, p) };
}
function pAdd(P, Q) {
  if (!P) return Q; if (!Q) return P;
  const { p } = P256;
  if (P.x === Q.x) { if (bmod(P.y + Q.y, p) === 0n) return null; return pDouble(P); }
  const s = bmod((Q.y - P.y) * finv(Q.x - P.x, p), p);
  const x = bmod(s * s - P.x - Q.x, p);
  return { x, y: bmod(s * (P.x - x) - P.y, p) };
}
function pMul(P, k) {
  k = bmod(k, P256.n); let R = null, A = P;
  while (k > 0n) { if (k & 1n) R = pAdd(R, A); A = pDouble(A); k >>= 1n; }
  return R;
}
const pNeg = (P) => (P ? { x: P.x, y: bmod(-P.y, P256.p) } : null);
const hexToBig = (h) => BigInt('0x' + (clean(h) || '0'));
const big32 = (x) => x.toString(16).padStart(64, '0').toUpperCase();

// EC-SDSA imza doğrulama (Ecos ECC sertifika zinciri — Schnorr tipi, BSI TR-03111).
// İmza (R,S); public key Q (x,y); mesaj M. Doğrulama: T = S·G − R·Q; R' = SHA-256(T.x ‖ M);
// geçerli ⇔ R' == R. (İmza kuralı S = k + R·d; T = k·G'yi kurtarır.)
export function ecSdsaVerifyP256(qxHex, qyHex, msgHex, rHex, sHex) {
  const Q = { x: hexToBig(qxHex), y: hexToBig(qyHex) };
  const r = bmod(hexToBig(rHex), P256.n);
  const s = bmod(hexToBig(sHex), P256.n);
  const T = pAdd(pMul({ x: P256.Gx, y: P256.Gy }, s), pNeg(pMul(Q, r)));
  if (!T) return false;
  const rPrime = crypto.createHash('sha256').update(Buffer.from(big32(T.x) + clean(msgHex), 'hex')).digest('hex').toUpperCase();
  return rPrime === clean(rHex).toUpperCase();
}

// P-256 nokta açma (decompress): x'ten y. y² = x³ − 3x + b; p ≡ 3 mod 4 → y = (y²)^((p+1)/4).
// wantOdd verilmezse çift y döner. Ecos cert'lerinde PK yalnız x saklanır → y kurtarılır.
export function decompressP256(xHex, wantOdd = false) {
  const { p, a, b } = P256;
  const x = hexToBig(xHex);
  const y2 = bmod(x * x * x + a * x + b, p);
  let y = powmod(y2, (p + 1n) / 4n, p);
  if (powmod(y, 2n, p) !== y2) return null; // x eğri üzerinde değil
  if ((y & 1n) !== (wantOdd ? 1n : 0n)) y = bmod(-y, p);
  return big32(y);
}

// EC-SDSA cert doğrulama — parent PK x'ten y'yi (iki pariteyi de) deneyerek.
// Ecos cert: son 64 bayt imza (R‖S); geri kalan mesaj M. childPkXHex sonraki adım için.
export function verifyEccCert(certHex, parentPkXHex) {
  const cert = clean(certHex);
  if (cert.length < 128 + 2) return { ok: false, error: 'cert çok kısa' };
  const M = cert.slice(0, cert.length - 128);
  const R = cert.slice(cert.length - 128, cert.length - 64);
  const S = cert.slice(cert.length - 64);
  for (const odd of [false, true]) {
    const py = decompressP256(parentPkXHex, odd);
    if (py && ecSdsaVerifyP256(parentPkXHex, py, M, R, S)) return { ok: true, parentYodd: odd, M, R, S };
  }
  return { ok: false, M, R, S, error: 'EC-SDSA imza doğrulanamadı' };
}

// ECDH shared secret x-koordinatı (BDH): z = (dT · Pub).x. Pub ham x (+ops. y).
// Not: y-paritesi z'yi değiştirmez (−P ile P aynı x) → yalnız x yeterli.
export function ecdhSharedX(dTHex, pubXHex, pubYHex) {
  const y = pubYHex ? hexToBig(pubYHex) : hexToBig(decompressP256(pubXHex) || '0');
  const S = pMul({ x: hexToBig(pubXHex), y }, hexToBig(dTHex));
  return S ? big32(S.x) : null;
}

// Efemer terminal anahtar çifti (dT rastgele, QT = dT·G). GPO'da QT gönderilir.
export function genEphemeralP256() {
  const dT = bmod(BigInt('0x' + crypto.randomBytes(32).toString('hex')), P256.n - 1n) + 1n;
  const Q = pMul({ x: P256.Gx, y: P256.Gy }, dT);
  return { dT: big32(dT), qx: big32(Q.x), qy: big32(Q.y) };
}

export const _ecc = { pAdd, pMul, pNeg, P256, decompressP256 };
