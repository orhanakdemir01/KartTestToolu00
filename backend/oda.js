// EMV Offline Data Authentication (ODA): DDA, CDA (contact) and fast DDA / qVSDC
// CDA (contactless). RSA public-key recovery, Issuer/ICC public-key certificate
// chain (EMV Book 2 §6) and dynamic signature (SDAD, format 05) verification.
import crypto from 'crypto';

const clean = (h) => (h || '').replace(/\s/g, '');
const buf = (h) => Buffer.from(clean(h), 'hex');
const hex = (b) => Buffer.from(b).toString('hex').toUpperCase();

// RSA public operation: data^exp mod modulus, left-padded to the modulus length.
export function rsaPublic(dataHex, expHex, modHex) {
  const m = clean(modHex);
  const mod = BigInt('0x' + m);
  const exp = BigInt('0x' + clean(expHex));
  let base = BigInt('0x' + clean(dataHex)) % mod;
  let result = 1n, e = exp;
  while (e > 0n) { if (e & 1n) result = (result * base) % mod; base = (base * base) % mod; e >>= 1n; }
  let h = result.toString(16);
  if (h.length % 2) h = '0' + h;
  return h.padStart(m.length, '0').toUpperCase();
}

const sha1 = (hexData) => crypto.createHash('sha1').update(buf(hexData)).digest('hex').toUpperCase();

// ── Issuer Public Key Certificate recovery (cert tag 90, remainder 92, exp 9F32) ──
// capk = { modulus, exponent }
export function recoverIssuerPK({ capk, cert90, remainder92, exp9F32 }) {
  const steps = [];
  const add = (label, value, ok) => steps.push({ label, value, ok });
  if (!capk || !cert90) return { ok: false, steps: [{ label: 'Eksik veri (CAPK / sertifika)', ok: false }] };

  const rec = rsaPublic(cert90, capk.exponent, capk.modulus);
  const b = buf(rec);
  const nca = b.length;

  add('Data Header', hex(b.slice(0, 1)), b[0] === 0x6a);
  const format = b[1];
  add('Certificate Format', hex(b.slice(1, 2)), format === 0x02);
  add('Issuer Identification Number', hex(b.slice(2, 6)), true);
  add('Certificate Expiration (MMYY)', hex(b.slice(6, 8)), true);
  add('Certificate Serial Number', hex(b.slice(8, 11)), true);
  const hashInd = b[11];
  add('Hash Algorithm Indicator', hex(b.slice(11, 12)), hashInd === 0x01);
  add('Issuer PK Algorithm', hex(b.slice(12, 13)), b[12] === 0x01);
  const pkLen = b[13];
  add('Issuer PK Length', hex(b.slice(13, 14)), true);
  add('Issuer PK Exponent Length', hex(b.slice(14, 15)), true);

  const leftmostLen = nca - 36;
  const leftmost = b.slice(15, 15 + leftmostLen);
  const hashRec = hex(b.slice(nca - 21, nca - 1));
  add('Data Trailer', hex(b.slice(nca - 1)), b[nca - 1] === 0xbc);

  // Hash over: format … PK-exp-len + leftmost (incl. BB padding) + remainder + exponent
  const rem = clean(remainder92);
  const hashInput = hex(b.slice(1, nca - 21)) + rem + clean(exp9F32);
  const hashCalc = sha1(hashInput);
  add('Hash Result', hashCalc, hashCalc === hashRec);

  // Issuer modulus = leftmost(pkLen) if it fits, else leftmost + remainder
  const issuerMod = pkLen <= leftmostLen ? hex(leftmost.slice(0, pkLen)) : hex(leftmost) + rem.toUpperCase();

  const ok = steps.every((s) => s.ok);
  return { ok, steps, recovered: rec, hashRec, hashCalc,
    issuerPK: { modulus: issuerMod, exponent: clean(exp9F32).toUpperCase() } };
}

// ── ICC Public Key Certificate recovery (cert 9F46, remainder 9F48, exp 9F47) ──
// staticData = concatenated static data to be authenticated (records + AIP) for the
// certificate hash. pan used to check the embedded Application PAN.
export function recoverIccPK({ issuerPK, cert9F46, remainder9F48, exp9F47, staticData, pan }) {
  const steps = [];
  const add = (label, value, ok) => steps.push({ label, value, ok });
  if (!issuerPK || !cert9F46) return { ok: false, steps: [{ label: 'Eksik veri (Issuer PK / ICC sertifikası)', ok: false }] };

  const rec = rsaPublic(cert9F46, issuerPK.exponent, issuerPK.modulus);
  const b = buf(rec);
  const ni = b.length;

  add('Data Header', hex(b.slice(0, 1)), b[0] === 0x6a);
  add('Certificate Format', hex(b.slice(1, 2)), b[1] === 0x04);
  const certPan = hex(b.slice(2, 12)).replace(/F+$/, '');
  const panClean = clean(pan).toUpperCase();
  add('Application PAN', hex(b.slice(2, 12)), !pan || certPan.startsWith(panClean) || panClean.startsWith(certPan));
  add('Certificate Expiration (MMYY)', hex(b.slice(12, 14)), true);
  add('Certificate Serial Number', hex(b.slice(14, 17)), true);
  add('Hash Algorithm Indicator', hex(b.slice(17, 18)), b[17] === 0x01);
  add('ICC PK Algorithm', hex(b.slice(18, 19)), b[18] === 0x01);
  const pkLen = b[19];
  add('ICC PK Length', hex(b.slice(19, 20)), true);
  add('ICC PK Exponent Length', hex(b.slice(20, 21)), true);

  const leftmostLen = ni - 42;
  const leftmost = b.slice(21, 21 + leftmostLen);
  const hashRec = hex(b.slice(ni - 21, ni - 1));
  add('Data Trailer', hex(b.slice(ni - 1)), b[ni - 1] === 0xbc);

  // Hash over: format … PK-exp-len + leftmost + remainder + ICC exponent + static data
  const rem = clean(remainder9F48);
  const hashInput = hex(b.slice(1, ni - 21)) + rem + clean(exp9F47) + clean(staticData);
  const hashCalc = sha1(hashInput);
  add('Hash Result', hashCalc, hashCalc === hashRec);

  const iccMod = pkLen <= leftmostLen ? hex(leftmost.slice(0, pkLen)) : hex(leftmost) + rem.toUpperCase();

  const ok = steps.every((s) => s.ok);
  return { ok, steps, recovered: rec, hashRec, hashCalc,
    iccPK: { modulus: iccMod, exponent: clean(exp9F47).toUpperCase() } };
}

// ── Signed Dynamic Application Data (SDAD, tag 9F4B / INTERNAL AUTHENTICATE) ──
// Recovers format-05 dynamic signature, checks header/trailer and the hash over the
// dynamic data + the terminal-supplied data (DDOL data for DDA; transaction data for
// CDA/fDDA). Returns the recovered ICC Dynamic Number and (for CDA) the embedded AC.
export function verifySDAD({ iccPK, sdad, terminalData, transactionData, kind }) {
  const steps = [];
  const add = (label, value, ok, note) => steps.push({ label, value, ok, ...(note ? { note } : {}) });
  if (!iccPK || !sdad) return { ok: false, steps: [{ label: 'Eksik veri (ICC PK / SDAD)', ok: false }] };

  const rec = rsaPublic(sdad, iccPK.exponent, iccPK.modulus);
  const b = buf(rec);
  const n = b.length;

  add('Data Header', hex(b.slice(0, 1)), b[0] === 0x6a);
  // 0x05 = DDA/CDA signed data; 0x95 = Visa qVSDC fast-DDA variant (ODA-for-online TTQ).
  add('Signed Data Format', hex(b.slice(1, 2)), b[1] === 0x05 || b[1] === 0x95);
  add('Hash Algorithm Indicator', hex(b.slice(2, 3)), b[2] === 0x01);
  const ddlen = b[3]; // ICC Dynamic Data Length
  add('Signed Dynamic Application Data Length', hex(b.slice(3, 4)), ddlen >= 1 && ddlen <= n - 26);
  const dynData = b.slice(4, 4 + ddlen);
  const iccDynLen = dynData.length ? dynData[0] : 0;
  const iccDynNumber = hex(dynData.slice(1, 1 + iccDynLen));
  // CDA: after the ICC Dynamic Number the dynamic data carries CID | Application Cryptogram (8)
  // | Transaction Data Hash Code (20).
  let cid = null, ac = null, tdHash = null;
  if (kind === 'CDA' && dynData.length >= 1 + iccDynLen + 9) {
    const off = 1 + iccDynLen;
    cid = hex(dynData.slice(off, off + 1));
    ac = hex(dynData.slice(off + 1, off + 9));
    tdHash = hex(dynData.slice(off + 9, off + 29));
  }
  // Pad Pattern: the bytes between the ICC Dynamic Data and the hash must all be 0xBB.
  const pad = b.slice(4 + ddlen, n - 21);
  const padOk = pad.length > 0 && pad.every((x) => x === 0xbb);
  add('Pad Pattern', padOk ? `BB × ${pad.length}` : hex(pad).slice(0, 20) + '…', padOk);
  const hashRec = hex(b.slice(n - 21, n - 1));
  add('Data Trailer', hex(b.slice(n - 1)), b[n - 1] === 0xbc);

  // EMV (Book 2 §6.5/6.6): hash over format | hashInd | ddlen | ICC Dynamic Data | Pad
  // Pattern (BB…) | terminal DD-input. DDA → DDOL data (UN); CDA → transaction data;
  // fDDA (Visa qVSDC, VCPS) → UN | Amount, Authorised | Transaction Currency Code |
  // Card Authentication Related Data (9F69). The caller passes the assembled DD-input
  // in transactionData. Verified byte-exact against a FIME fDDA reference + live card.
  const extra = clean(kind === 'DDA' ? terminalData : transactionData);
  const hashCalc = sha1(hex(b.slice(1, n - 21)) + extra);
  const hashMatch = hashCalc === hashRec;
  const hashLabel = kind === 'fDDA' ? 'Match Signed Static Application Data Hash' : 'Hash Result';
  const hashNote = kind === 'fDDA' && !hashMatch ? 'VCPS DD-input gerekli (dinamik imza girdisi scheme-özel/gizli)' : undefined;
  add(hashLabel, hashCalc, hashMatch, hashNote);

  const structOk = steps.slice(0, -1).every((s) => s.ok); // all tests except the hash match
  const ok = steps.every((s) => s.ok);
  return { ok, structOk, hashMatch, steps, recovered: rec, hashRec, hashCalc, iccDynNumber, cid, ac, tdHash,
    dynamicData: hex(dynData) };
}
