// EMV 3DES cryptography: ICC master key derivation (Option A), session key
// derivation (EMV Common Session Key), and ARQC (Retail MAC / ISO 9797-1 Alg 3).
// Uses node-forge for DES (Node 24 / OpenSSL 3 disables legacy DES by default).
import forge from 'node-forge';

const buf = (hex) => Buffer.from((hex || '').replace(/\s/g, ''), 'hex');
const hex = (b) => b.toString('hex').toUpperCase();

// Single DES (ECB, no padding) on 8-byte buffers
function desRaw(key8, data8, decrypt) {
  const fn = decrypt ? forge.cipher.createDecipher : forge.cipher.createCipher;
  const c = fn('DES-ECB', forge.util.hexToBytes(key8.toString('hex')));
  if (decrypt) c.mode.unpad = () => true; else c.mode.pad = () => true;
  c.start();
  c.update(forge.util.createBuffer(forge.util.hexToBytes(data8.toString('hex'))));
  c.finish();
  return Buffer.from(forge.util.bytesToHex(c.output.getBytes()), 'hex');
}
const desEnc = (k, d) => desRaw(k, d, false);
const desDec = (k, d) => desRaw(k, d, true);

// Two-key 3DES (EDE) on an 8-byte block: E_K1( D_K2( E_K1(data) ) )
function tdesEnc(key16, data8) {
  const k1 = key16.slice(0, 8), k2 = key16.slice(8, 16);
  return desEnc(k1, desDec(k2, desEnc(k1, data8)));
}

function xor(a, b) { const o = Buffer.alloc(a.length); for (let i = 0; i < a.length; i++) o[i] = a[i] ^ b[i]; return o; }

// Set odd parity on each byte (EMV keys use odd parity)
function oddParity(b) {
  const o = Buffer.from(b);
  for (let i = 0; i < o.length; i++) {
    let v = o[i], bits = 0;
    for (let k = 1; k < 8; k++) if (v & (1 << k)) bits++;
    o[i] = (v & 0xFE) | (bits % 2 === 0 ? 1 : 0);
  }
  return o;
}

// ICC Master Key derivation, EMV Option A (Book 2, Annex A1.4.1)
export function deriveIccMasterKey(mkHex, pan, psn) {
  const mk = buf(mkHex);
  let digits = ((pan || '') + (psn || '00')).replace(/\D/g, '');
  digits = digits.length >= 16 ? digits.slice(-16) : digits.padStart(16, '0');
  const zl = Buffer.from(digits, 'hex');
  const zr = Buffer.from(zl.map((x) => x ^ 0xFF));
  const icc = Buffer.concat([tdesEnc(mk, zl), tdesEnc(mk, zr)]);
  return hex(oddParity(icc));
}

// Session Key derivation — EMV Common Session Key (Book 2, Annex A1.3.1)
export function deriveSessionKey(iccMkHex, atcHex) {
  const mk = buf(iccMkHex);
  const atc = Buffer.from((atcHex || '').replace(/\s/g, '').padStart(4, '0').slice(-4), 'hex');
  const f1 = Buffer.concat([atc, Buffer.from([0xF0, 0x00, 0x00, 0x00, 0x00, 0x00])]);
  const f2 = Buffer.concat([atc, Buffer.from([0x0F, 0x00, 0x00, 0x00, 0x00, 0x00])]);
  const sk = Buffer.concat([tdesEnc(mk, f1), tdesEnc(mk, f2)]);
  return hex(sk); // EMV CSK session key is not parity-adjusted (matches reference tools)
}

// Retail MAC (ISO/IEC 9797-1 MAC Algorithm 3). padMethod 2 = 0x80 00.. (Visa/MC
// CCD), padMethod 1 = zero padding only (American Express CVN 01).
export function retailMac(keyHex, dataHex, padMethod = 2, ivHex = null) {
  const key = buf(keyHex);
  const k1 = key.slice(0, 8), k2 = key.slice(8, 16);
  let d = padMethod === 1 ? buf(dataHex) : Buffer.concat([buf(dataHex), Buffer.from([0x80])]);
  while (d.length % 8 !== 0) d = Buffer.concat([d, Buffer.from([0x00])]);
  if (d.length === 0) d = Buffer.alloc(8, 0);
  // Initial chaining value: zeros by default, or a supplied ICV (EMV secure
  // messaging uses the ARQC as the ICV for the first issuer-script command MAC).
  let h = ivHex ? buf(ivHex).slice(0, 8) : Buffer.alloc(8, 0);
  for (let i = 0; i < d.length; i += 8) h = desEnc(k1, xor(d.slice(i, i + 8), h));
  return hex(desEnc(k1, desDec(k2, h)));
}

// Key Check Value: first 3 bytes of 3DES-ECB encryption of all-zero block.
export function kcv(keyHex) {
  return hex(tdesEnc(buf(keyHex), Buffer.alloc(8, 0))).slice(0, 6);
}

// 3DES-ECB encryption over one or more 8-byte blocks (enciphered PIN block).
export function tdesEcbEncrypt(keyHex, dataHex) {
  const key = buf(keyHex), d = buf(dataHex);
  let out = Buffer.alloc(0);
  for (let i = 0; i < d.length; i += 8) out = Buffer.concat([out, tdesEnc(key, d.slice(i, i + 8))]);
  return hex(out);
}

// M/Chip secure-messaging session key derivation — EMV CSK but diversified by the
// 8-byte Application Cryptogram (AC/ARQC) instead of the ATC: the branch byte
// (F0 / 0F) replaces byte index 2 of the AC, the rest of the AC is kept.
// Verified byte-exact against a FIME "Sign and Encrypt PIN Change" trace.
export function deriveSessionKeyAC(iccMkHex, acHex) {
  const mk = buf(iccMkHex);
  const ac = buf(acHex);
  if (ac.length !== 8) throw new Error('AC (ARQC) 8 bayt olmalı');
  const f1 = Buffer.from(ac); f1[2] = 0xF0;
  const f2 = Buffer.from(ac); f2[2] = 0x0F;
  return hex(Buffer.concat([tdesEnc(mk, f1), tdesEnc(mk, f2)]));
}

// Visa VIS secure-messaging session key derivation: the ICC unique key with the
// ATC XOR-folded into bytes 6-7 of each 8-byte half — left half uses the ATC,
// right half uses ATC XOR 0xFFFF. Verified byte-exact against a FIME Visa PIN
// Change trace (SMI + SMC session keys).
export function deriveSessionKeyVisa(udkHex, atcHex) {
  const s = buf(udkHex);
  if (s.length !== 16) throw new Error('UDK 16 bayt olmalı');
  const atc = Buffer.from((atcHex || '').replace(/\s/g, '').padStart(4, '0').slice(-4), 'hex');
  s[6] ^= atc[0]; s[7] ^= atc[1];
  s[14] ^= (atc[0] ^ 0xFF); s[15] ^= (atc[1] ^ 0xFF);
  return hex(s);
}

// Mastercard M/Chip session key derivation — EMV CSK but with the Unpredictable
// Number in the last 4 bytes of the diversifier (Visa/CCD uses zeros there).
export function deriveSessionKeyMChip(iccMkHex, atcHex, unHex) {
  const mk = buf(iccMkHex);
  const atc = Buffer.from((atcHex || '').replace(/\s/g, '').padStart(4, '0').slice(-4), 'hex');
  const un = Buffer.from((unHex || '').replace(/\s/g, '').padStart(8, '0').slice(-8), 'hex');
  const f1 = Buffer.concat([atc, Buffer.from([0xF0, 0x00]), un]);
  const f2 = Buffer.concat([atc, Buffer.from([0x0F, 0x00]), un]);
  return hex(Buffer.concat([tdesEnc(mk, f1), tdesEnc(mk, f2)]));
}

// Session key for an AC key at a given level (EMV CSK).
function sessionKeyFor(acKey, keyLevel, pan, psn, atc) {
  if (keyLevel === 'master') { const icc = deriveIccMasterKey(acKey, pan, psn); return { sk: deriveSessionKey(icc, atc), iccMk: icc }; }
  if (keyLevel === 'icc') return { sk: deriveSessionKey(acKey, atc), iccMk: acKey };
  return { sk: acKey, iccMk: null };
}

// ICC master key for an AC key at a given level (for M/Chip session derivation).
function iccMkFor(acKey, keyLevel, pan, psn) {
  if (keyLevel === 'master') return deriveIccMasterKey(acKey, pan, psn);
  if (keyLevel === 'icc') return acKey;
  return null;
}

// Full ARQC computation. keyLevel: 'master' | 'icc' | 'session'.
export function computeArqc({ acKey, keyLevel, pan, psn, atc, inputDataHex }) {
  const { sk, iccMk } = sessionKeyFor(acKey, keyLevel, pan, psn, atc);
  const arqc = retailMac(sk, inputDataHex);
  return { arqc, sessionKey: sk.toUpperCase(), iccMk: iccMk ? iccMk.toUpperCase() : null, inputData: inputDataHex.toUpperCase() };
}

// ARPC (Authorization Response Cryptogram), method 1 — for issuer authentication
// via EXTERNAL AUTHENTICATE. ARPC = 3DES(SKac, ARQC XOR (ARC || 0x00*6)), where
// SKac is the same AC session key used for the ARQC and ARC is the 2-byte
// Authorization Response Code. Returns the ARPC and the Issuer Authentication
// Data (ARPC || ARC) to place in the EXTERNAL AUTHENTICATE command.
export function computeArpc({ acKey, keyLevel, pan, psn, atc, arqc, arc = '3030' }) {
  const lvl = keyLevel === 'auto' ? 'master' : keyLevel;
  const { sk } = sessionKeyFor(acKey, lvl, pan, psn, atc);
  const skHex = typeof sk === 'string' ? sk : hex(sk);
  const arqcB = buf(arqc);
  const arcPad = buf((((arc || '').replace(/\s/g, '')) + '000000000000').slice(0, 16)); // 8 bytes
  const x = Buffer.from(arqcB.map((b, i) => b ^ (arcPad[i] || 0)));
  const arpc = hex(tdesEnc(buf(skHex), x));
  return { arpc, arc: (arc || '').replace(/\s/g, '').toUpperCase(), iad: arpc + (arc || '').replace(/\s/g, '').toUpperCase(), sessionKey: skHex.toUpperCase() };
}

// ARPC method 2 (EMV Book 2): leftmost 4 bytes of a Retail MAC over
// ARQC || CSU (|| proprietary auth data), keyed with the AC session key. The CSU
// (Card Status Update, 4 bytes) is the issuer response. The ARPC + CSU is the
// Issuer Authentication Data (tag 91) placed in the 2nd GENERATE AC (CDOL2).
// Verified byte-exact against a FIME Visa "Verify AC and Generate ARPC" trace.
export function computeArpcMethod2({ acKey, keyLevel, pan, psn, atc, arqc, csu = '03920000', propAuth = '' }) {
  const lvl = keyLevel === 'auto' ? 'master' : keyLevel;
  const { sk } = sessionKeyFor(acKey, lvl, pan, psn, atc);
  const skHex = typeof sk === 'string' ? sk : hex(sk);
  const c = (csu || '').replace(/\s/g, '').toUpperCase();
  const q = (arqc || '').replace(/\s/g, '').toUpperCase();
  const p = (propAuth || '').replace(/\s/g, '').toUpperCase();
  const arpc = retailMac(skHex, q + c + p, 2, null).slice(0, 8); // leftmost 4 bytes
  return { arpc, csu: c, sessionKey: skHex.toUpperCase(), issuerAuthData: arpc + c };
}

// Try Visa (EMV CSK) and Mastercard (M/Chip, UN-based) session keys across many
// ARQC data compositions to find one matching the card's ARQC.
export function verifyArqcAuto({ acKey, keyLevel, pan, psn, atc, un, base, cdol, aip, iad, cardArqc, amount, currency }) {
  const target = (cardArqc || '').toUpperCase();
  const iadB = (iad || '').match(/../g) || [];

  // CVR candidates: whole IAD, IAD with leading header dropped, 6-byte windows
  const cvrs = { fullIAD: iad || '', noIAD: '' };
  for (const k of [2, 4, 6, 8]) if (k < iadB.length) cvrs[`IAD[${k}:]`] = iadB.slice(k).join('');
  for (let off = 0; off + 6 <= iadB.length; off++) cvrs[`iad[${off}:${off + 6}]`] = iadB.slice(off, off + 6).join('');
  // Mastercard M/Chip (CVN 0x1x) cryptogram CVR = 6-byte CVR (IAD[2:8]) + counters
  // (IAD[10:]), skipping the 2-byte field at IAD[8:10] which is NOT part of the AC
  // input. Verified against FIME reference + live contactless card.
  if (iadB.length >= 10) cvrs['mchipCVR'] = iadB.slice(2, 8).join('') + iadB.slice(10).join('');
  // American Express (CVN 01) Card Verification Results = IAD bytes 3.. (after the
  // length | DKI | CVN header). Verified against a live Amex card + issuer MDK.
  if (iadB.length >= 4) cvrs['amexCVR'] = iadB.slice(3).join('');

  const prefixes = {
    'std+AIP+ATC': base + aip + atc,
    'std+ATC+AIP': base + atc + aip,
    'cdol+AIP+ATC': cdol + aip + atc,
  };
  const candidates = [];
  for (const [pn, pre] of Object.entries(prefixes))
    for (const [cn, cvr] of Object.entries(cvrs)) candidates.push({ name: `${pn} + ${cn}`, data: pre + cvr });
  // Troy D-PAS (Discover) contactless AC data: a minimal composition of
  // Amount | Transaction Currency Code | Unpredictable Number | ATC | full IAD,
  // MAC'd with the EMV CSK session key. Verified byte-exact against FIME + live card.
  if (amount && currency) candidates.push({ name: 'DPAS(amt+cur+UN+ATC+IAD)', data: amount + currency + (un || '') + (atc || '') + (iad || '') });

  const levels = keyLevel === 'auto' ? ['master', 'icc', 'session'] : [keyLevel];
  let tries = 0;
  for (const lvl of levels) {
    const iccMk = iccMkFor(acKey, lvl, pan, psn);
    // Session-key schemes: Visa/CCD (EMV CSK), Mastercard M/Chip (with UN), and
    // American Express CVN 01 (ICC Master Key used directly — no session derivation).
    const sks = [{ scheme: 'CSK', pad: 2, ...sessionKeyFor(acKey, lvl, pan, psn, atc) }];
    if (iccMk && un) sks.push({ scheme: 'MChip', pad: 2, sk: deriveSessionKeyMChip(iccMk, atc, un), iccMk });
    if (iccMk) sks.push({ scheme: 'Amex', pad: 1, sk: iccMk, iccMk });
    for (const { scheme, sk, pad, iccMk: icc } of sks) {
      for (const c of candidates) {
        tries++;
        if (retailMac(sk, c.data, pad).toUpperCase() === target) {
          return { match: true, method: `${lvl}/${scheme} | ${c.name}`, keyLevel: lvl, computed: target, cardArqc: target,
                   sessionKey: sk.toUpperCase(), iccMk: icc ? icc.toUpperCase() : null, inputData: c.data.toUpperCase() };
        }
      }
    }
  }
  // No match → informative display. For Mastercard M/Chip (typically the contactless
  // interface) the IAD carries a Cryptogram Version Number byte (IAD[1], 0x10–0x1F).
  // Show the M/Chip (UN-based) session key + computed value so the GENERATE AC / ARQC
  // operation is fully visible in the trace even though the exact CVR-from-IAD mapping
  // (issuer-specific) isn't reproduced from the public APDU response.
  const dl = keyLevel === 'auto' ? 'master' : keyLevel;
  const data = base + aip + atc + (iad || '');
  const cvn = iadB.length >= 2 ? iadB[1].toUpperCase() : '';
  const iccMkD = iccMkFor(acKey, dl, pan, psn);
  if (un && iccMkD && /^1[0-9A-F]$/.test(cvn)) {
    const sk = deriveSessionKeyMChip(iccMkD, atc, un);
    // Show the M/Chip computation over the standard CVR (IAD[2:8]+IAD[10:]) for transparency.
    const mchipCvr = iadB.length >= 10 ? iadB.slice(2, 8).join('') + iadB.slice(10).join('') : (iad || '');
    const mchipData = base + aip + atc + mchipCvr;
    return { match: false, scheme: 'MChip',
      method: `M/Chip (CVN 0x${cvn}) — bilinen kompozisyonlar eşleşmedi (${tries} kombinasyon denendi)`,
      keyLevel: dl, computed: retailMac(sk, mchipData).toUpperCase(), cardArqc: target,
      sessionKey: sk.toUpperCase(), iccMk: iccMkD.toUpperCase(), inputData: mchipData.toUpperCase() };
  }
  const { sk, iccMk } = sessionKeyFor(acKey, dl, pan, psn, atc);
  return { match: false, method: `${dl} | std+AIP+ATC+IAD (denenen ${tries} kombinasyon eşleşmedi)`,
           keyLevel: dl, computed: retailMac(sk, data).toUpperCase(), cardArqc: target,
           sessionKey: sk.toUpperCase(), iccMk: iccMk ? iccMk.toUpperCase() : null, inputData: data.toUpperCase() };
}
