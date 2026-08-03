// ECOS / Kernel 8 modern kripto — AES tabanlı ARQC ve MAC ilkelleri.
// EMV/Kernel 8 kartları 3DES yerine AES, RSA yerine ECC kullanır (bkz. odaecc.js).
// Bu dosya AES-CMAC (NIST SP 800-38B / RFC 4493) ve AES oturum-anahtarı/ARQC
// yardımcılarını içerir. AES-CMAC bağımsız RFC 4493 vektörleriyle öz-teste tabidir
// (selftest.js) — kalibrasyon disiplini: kart sırrına ihtiyaç duymadan matematiği kanıtla.
import crypto from 'crypto';

const hexToBuf = (h) => Buffer.from(h.replace(/\s/g, ''), 'hex');
const bufToHex = (b) => Buffer.from(b).toString('hex').toUpperCase();

// Tek 16-baytlık bloğu AES-ECB ile şifrele (padding kapalı). CMAC alt-anahtar ve
// CBC-MAC adımları için temel yapı taşı. Anahtar 16/24/32 bayt (AES-128/192/256).
function aesEcbBlock(key, block) {
  const algo = key.length === 16 ? 'aes-128-ecb' : key.length === 24 ? 'aes-192-ecb' : 'aes-256-ecb';
  const c = crypto.createCipheriv(algo, key, null);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(block), c.final()]);
}

// Blok'u 1 bit sola kaydır (128-bit big-endian). CMAC alt-anahtar türetmesi için.
function shiftLeft1(buf) {
  const out = Buffer.alloc(buf.length);
  let carry = 0;
  for (let i = buf.length - 1; i >= 0; i--) {
    const v = (buf[i] << 1) | carry;
    out[i] = v & 0xff;
    carry = (buf[i] & 0x80) ? 1 : 0;
  }
  return out;
}

const xorBuf = (a, b) => { const o = Buffer.alloc(a.length); for (let i = 0; i < a.length; i++) o[i] = a[i] ^ b[i]; return o; };

// CMAC alt-anahtarları K1, K2 (RFC 4493 §2.3). Rb = 0x00..0x87 (128-bit için).
function cmacSubkeys(key) {
  const Rb = Buffer.alloc(16); Rb[15] = 0x87;
  const L = aesEcbBlock(key, Buffer.alloc(16));
  let K1 = shiftLeft1(L); if (L[0] & 0x80) K1 = xorBuf(K1, Rb);
  let K2 = shiftLeft1(K1); if (K1[0] & 0x80) K2 = xorBuf(K2, Rb);
  return { K1, K2 };
}

// AES-CMAC (RFC 4493). key/msg hex; tam 16-baytlık MAC'i hex döner.
export function aesCmac(keyHex, msgHex) {
  const key = hexToBuf(keyHex);
  const msg = hexToBuf(msgHex || '');
  const { K1, K2 } = cmacSubkeys(key);
  const n = Math.ceil(msg.length / 16);
  let lastBlock;
  if (n === 0) {
    // boş mesaj → tek dolgulu blok, K2 ile
    const pad = Buffer.alloc(16); pad[0] = 0x80;
    lastBlock = xorBuf(pad, K2);
  } else {
    const lastLen = msg.length - (n - 1) * 16;
    const last = msg.slice((n - 1) * 16);
    if (lastLen === 16) {
      lastBlock = xorBuf(last, K1);           // tam blok
    } else {
      const pad = Buffer.alloc(16);
      last.copy(pad); pad[lastLen] = 0x80;    // 10* dolgu
      lastBlock = xorBuf(pad, K2);
    }
  }
  // CBC-MAC (sıfır IV): önceki blokları zincirle, son bloğu şifrele.
  let x = Buffer.alloc(16);
  for (let i = 0; i < n - 1; i++) {
    x = aesEcbBlock(key, xorBuf(x, msg.slice(i * 16, i * 16 + 16)));
  }
  const tag = aesEcbBlock(key, xorBuf(x, lastBlock));
  return bufToHex(tag);
}

const clean = (h) => (h || '').replace(/\s/g, '').toUpperCase();

// EMV AES KCV = AES-ECB(key, 0^128) ilk 3 bayt (16/24/32 baytlık anahtar).
export function aesKcv(keyHex) {
  return bufToHex(aesEcbBlock(hexToBuf(keyHex), Buffer.alloc(16))).slice(0, 6);
}

// ── ECOS (Mastercard) AES ARQC/ARPC — kaynak: Ecos v1.0 Issuer Implementation ──
// AC oturum anahtarı (EMV CSK · AES): 128-bit → SKAC = AES(MKAC)[ATC‖00×14].
// 256-bit → SKACL=AES[R0R1 F0 R3..R15], SKACR=AES[R0R1 0F R3..R15], SKAC=L‖R.
// MKAC = kartın "AC Master Key"i (perso). ATC 2 bayt (hex 4 hane).
export function deriveAcSessionKeyAes(mkacHex, atcHex) {
  const mk = hexToBuf(mkacHex);
  const atc = clean(atcHex).padStart(4, '0').slice(-4);
  const R = hexToBuf(atc + '00'.repeat(14)); // 16 bayt
  if (mk.length === 16) return bufToHex(aesEcbBlock(mk, R));      // AES-128 tek blok
  if (mk.length === 32) {                                        // AES-256 iki blok
    const rl = Buffer.from(R); rl[2] = 0xF0;
    const rr = Buffer.from(R); rr[2] = 0x0F;
    return bufToHex(Buffer.concat([aesEcbBlock(mk, rl), aesEcbBlock(mk, rr)]));
  }
  throw new Error('MKAC 16 (AES-128) veya 32 (AES-256) bayt olmalı');
}

// AES ICC Master Key türetme (IMK→MKac) — Ecos Appendix B.
// X=PAN‖PSN; Y=X sola 00 ile 16 bayt; Y*=Y XOR FF..FF.
// AES-128: MK=AES(IMK,Y). AES-256: MK=AES(IMK,Y)‖AES(IMK,Y*).
export function deriveIccMasterKeyAes(imkHex, panHex, psnHex) {
  const imk = hexToBuf(imkHex);
  const X = clean(panHex) + (clean(psnHex) || '00');
  const Y = hexToBuf(X.slice(-32).padStart(32, '0')); // 16 bayt, sola 00
  if (imk.length === 16) return bufToHex(aesEcbBlock(imk, Y));           // AES-128
  if (imk.length === 32) {                                              // AES-256
    const Ys = Buffer.alloc(16); for (let i = 0; i < 16; i++) Ys[i] = Y[i] ^ 0xFF;
    return bufToHex(Buffer.concat([aesEcbBlock(imk, Y), aesEcbBlock(imk, Ys)]));
  }
  throw new Error('IMK 16 (AES-128) veya 32 (AES-256) bayt olmalı');
}

// AC Input Data (Tablo 20; Extended ise Tablo 21 → sona IAD[11..son]). Ham birleştirme.
export function buildEcosAcInput(f) {
  const base = clean(f.amountAuth) + clean(f.amountOther) + clean(f.termCountry)
    + clean(f.tvr) + clean(f.txnCurrency) + clean(f.txnDate) + clean(f.txnType)
    + clean(f.un) + clean(f.aip) + clean(f.atc) + clean(f.cvr);
  return f.iadExt ? base + clean(f.iadExt) : base;
}

// ARQC = AES-CMAC(SKAC)[AC Input Data] → ilk 8 bayt.
export function ecosArqcAes(skacHex, acInputHex) {
  return aesCmac(skacHex, clean(acInputHex)).slice(0, 16);
}

// ARPC (EMV CSK · AES) = AES-CMAC(SKAC)[ ARQC ‖ ARPC-RC ‖ 00×6 ] → ilk 8 bayt.
export function ecosArpcAes(skacHex, arqcHex, arpcRcHex) {
  const M = clean(arqcHex) + clean(arpcRcHex) + '00'.repeat(6); // 8+2+6 = 16 bayt
  return aesCmac(skacHex, M).slice(0, 16);
}

// ECOS AES ARQC doğrulama (yeniden kullanılabilir) — EMV akışı + endpoint'ler için.
// key: { acKey, keyLevel, keyType }. terminal: AC input terminal alanları.
// CVR'da CDA bitleri (byte2 b8/b7) varsa maskeli varyant da denenir (CDA senaryosu).
// Döner: { match, computed, acInput, skac, mkac, usedMaskedCvr?, cvrMasked?, computedMaskedCvr? }.
export function verifyEcosArqcAes({ key, atc, pan, psn, aip, cvr, iadExt, terminal, cardArqc }) {
  let mkac = null, skac = null;
  if (key.keyLevel === 'session') skac = clean(key.acKey);
  else if (key.keyLevel === 'icc') { mkac = clean(key.acKey); skac = deriveAcSessionKeyAes(mkac, atc); }
  else { mkac = deriveIccMasterKeyAes(key.acKey, pan, psn); skac = deriveAcSessionKeyAes(mkac, atc); }
  const card = clean(cardArqc);
  const build = (cv) => buildEcosAcInput({ ...terminal, aip, atc, cvr: cv, iadExt });
  const acInput = build(cvr);
  const computed = ecosArqcAes(skac, acInput);
  if (computed === card) return { match: true, computed, acInput, skac, mkac, usedMaskedCvr: false };
  // Maskeli CVR (CDA: byte2 b8/b7 raporlanır ama kriptograma girmemiş olabilir)
  const b2 = cvr && clean(cvr).length >= 4 ? parseInt(clean(cvr).slice(2, 4), 16) : 0;
  if (b2 & 0xC0) {
    const cvrM = clean(cvr).slice(0, 2) + (b2 & 0x3F).toString(16).padStart(2, '0').toUpperCase() + clean(cvr).slice(4);
    const computedM = ecosArqcAes(skac, build(cvrM));
    if (computedM === card) return { match: true, computed: computedM, acInput: build(cvrM), skac, mkac, usedMaskedCvr: true, cvrMasked: cvrM };
    return { match: false, computed, computedMaskedCvr: computedM, cvrMasked: cvrM, acInput, skac, mkac };
  }
  return { match: false, computed, acInput, skac, mkac };
}

// Script secure-messaging MAC (AES) = AES-CMAC(SKSMI)[CLA‖INS‖P1‖P2‖Lc‖ATC‖Rand‖CmdData].
export function ecosSmMacAes(sksmiHex, p) {
  const M = clean(p.cla) + clean(p.ins) + clean(p.p1) + clean(p.p2) + clean(p.lc)
    + clean(p.atc) + clean(p.rand) + clean(p.cmdData);
  return aesCmac(sksmiHex, M).slice(0, 16);
}

// CVN (Cryptogram Version Number) çöz — kaynak: Ecos Issuer Impl.
// Byte1: b8-5 Version, b3-2 Session Key Used For AC (00 MC-Prop / 10 EMV CSK /
// 11 AES), b1 Extended Input In AC Computation. AES tespitinin kalbi.
export function decodeEcosCvn(cvnHex) {
  const b = parseInt(clean(cvnHex).slice(0, 2) || '0', 16);
  const skBits = (b >> 1) & 0x03; // b3-2
  // 00=MC-Prop(3DES) · 01=RFU(→MC-Prop) · 10=EMV CSK(3DES) · 11=EMV CSK(AES)
  const MAP = {
    0: { sk: 'Mastercard Proprietary SKD', cipher: '3DES' },
    1: { sk: 'RFU (→ MC-Prop 3DES)', cipher: '3DES' },
    2: { sk: 'EMV CSK', cipher: '3DES' },
    3: { sk: 'EMV CSK', cipher: 'AES' },
  };
  const m = MAP[skBits];
  return {
    raw: b.toString(16).padStart(2, '0').toUpperCase(),
    version: (b >> 4) & 0x0F,
    sessionKey: m.sk, cipher: m.cipher, isAes: skBits === 3,
    extendedInput: (b & 0x01) === 1,
  };
}

// CVR (Card Verification Results, 6 bayt) çöz — Tablo 13 / veri sözlüğü.
export function decodeEcosCvr(cvrHex) {
  const h = clean(cvrHex);
  const B = (i) => parseInt(h.slice(i * 2, i * 2 + 2) || '0', 16);
  const b1 = B(0), b2 = B(1);
  const ac1 = (b1 >> 4) & 0x03;
  return {
    raw: h,
    firstGenAc: ac1 === 0 ? 'AAC' : ac1 === 2 ? 'ARQC' : 'RFU',
    secondGenAcNotRequested: ((b1 >> 6) & 0x03) === 2,
    combinedDdaAc: ((b2 >> 6) & 0x01) === 1,
  };
}

// Ecos IAD ayrıştırma (Kernel 8 / Kernel 2 / Contact — 32 bayt). Tablo 10/11/15.
export function parseEcosIad(iadHex) {
  const h = clean(iadHex);
  if (h.length < 4) return null;
  const b = (i) => h.slice(i * 2, i * 2 + 2);
  const slice = (a, len) => h.slice(a * 2, (a + len) * 2);
  const kdi = b(0), cvn = b(1), cvr = slice(2, 6); // ilk 8 bayt ortak
  const ext = h.length >= 20 ? h.slice(20) : ''; // byte 11..son → Extended Input (ARQC girdisi)
  return { kdi, cvn, cvnDecoded: decodeEcosCvn(cvn), cvr, cvrDecoded: decodeEcosCvr(cvr), iadExt: ext, raw: h };
}

// ── ECOS Kernel 8 BDH (Blinded Diffie-Hellman) privacy — kaynak: gerçek terminal
// logu + Appendix B (ikisiyle de kanıtlı). z = ECDH shared secret x (odaecc.ecdhSharedX).
// Kdk = AES-CMAC(0^16, z); SKC/SKI = AES-ECB(Kdk, keyId‖CTX‖80). CTX sabit (spec).
const BDH_CTX = '010054334A325957773DA5A5A501';
export function bdhKdk(zHex) { return aesCmac('00000000000000000000000000000000', clean(zHex)); }
export function bdhSessionKeys(kdkHex) {
  const k = hexToBuf(kdkHex);
  const sk = (id) => bufToHex(aesEcbBlock(k, hexToBuf(id + BDH_CTX + '80')));
  return { skc: sk('01'), ski: sk('02') };
}
// Privacy decrypt: AES-128-CTR(SKC, IV=80‖counter(1B)‖00×14). counter: 0=blinding, 1..=kayıtlar.
export function bdhDecrypt(skcHex, counter, dataHex) {
  const iv = '80' + (counter & 0xff).toString(16).padStart(2, '0') + '00'.repeat(14);
  const d = crypto.createDecipheriv('aes-128-ctr', hexToBuf(skcHex), hexToBuf(iv));
  return bufToHex(Buffer.concat([d.update(hexToBuf(clean(dataHex))), d.final()]));
}

export const _internal = { aesEcbBlock, cmacSubkeys, bufToHex, hexToBuf, clean };
