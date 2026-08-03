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
