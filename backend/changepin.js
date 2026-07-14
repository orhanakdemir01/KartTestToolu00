// EMV PIN CHANGE / UNBLOCK (Issuer Script Command 84 24) construction.
// Builds the enciphered new PIN block + secure-messaging MAC using the card's
// MAC (SMI, integrity) and ENC (SMC, confidentiality) keys.
//   mode 'change'  → new enciphered PIN (data = ENC-PIN || MAC), P2 usually 02
//   mode 'unblock' → reset PIN try counter only (data = MAC), P2 usually 00
// Session keys are derived with EMV Common Session Key (ATC diversifier).
import { deriveIccMasterKey, deriveSessionKey, deriveSessionKeyMChip, deriveSessionKeyAC, deriveSessionKeyVisa, retailMac, tdesEcbEncrypt } from './crypto3des.js';

const clean = (s) => (s || '').replace(/\s/g, '').toUpperCase();
const buf = (h) => Buffer.from((h || '').replace(/\s/g, ''), 'hex');
const hex = (b) => b.toString('hex').toUpperCase();

// ISO-9564 format 2 PIN block (offline enciphered PIN): 2 | L | digits | F pad.
export function pinBlockISO2(pin) {
  const p = (pin || '').replace(/\D/g, '');
  const b = '2' + p.length.toString(16).toUpperCase() + p;
  return (b + 'FFFFFFFFFFFFFFFF').slice(0, 16);
}

// EMV VERIFY, plaintext offline PIN (00 20 00 80): sends the ISO-2 PIN block so
// the card compares it against its stored reference PIN. No cryptography — the
// card answers 9000 (correct), 63Cx (wrong, x tries left) or 6983 (blocked).
export function buildVerifyPlaintext(pin) {
  const digits = (pin || '').replace(/\D/g, '');
  if (!/^\d{4,12}$/.test(digits)) return { error: 'PIN 4-12 rakam olmalı' };
  const pinBlock = pinBlockISO2(digits);
  return { apdu: '0020008008' + pinBlock, pinBlock };
}

// Visa PIN block: the PIN field ( 0 | L | PIN | F-pad to 8 bytes ) XOR the
// diversifier ( 0x00000000 || UDK-AC bytes 4..7 ). The last 4 bytes look random
// but are the ICC AC unique key's bytes 4-7 XOR'd in — the card validates this,
// so it is NOT free padding. Verified byte-exact against a FIME Visa PIN block
// (041234FF322C01D0 = 041234FFFFFFFFFF XOR 00000000CDD3FE2F).
export function pinBlockVisa(pin, udkAcHex) {
  const p = (pin || '').replace(/\D/g, '');
  let field = '0' + p.length.toString(16).toUpperCase() + p;    // 0 | L | PIN digits
  while (field.length < 16) field += 'F';                       // F-pad to 8 bytes
  const udk = (udkAcHex || '').replace(/\s/g, '').toUpperCase();
  const operand = ('00000000' + udk.slice(8, 16) + '0000000000000000').slice(0, 16);
  const a = buf(field), b = buf(operand);
  return hex(Buffer.from(a.map((x, i) => x ^ (b[i] || 0))));
}

// ICC master key for a key at the given level (issuer master keys are PAN-diversified).
function iccMkFor(key, keyLevel, pan, psn) {
  const k = clean(key);
  return (keyLevel === 'icc' || keyLevel === 'session') ? k : deriveIccMasterKey(k, pan, psn);
}

// M/Chip secure-messaging session key: derived from the ICC key with the AC
// (ARQC) as diversifier (session level = key used directly).
function smSessionKey(key, keyLevel, pan, psn, ac) {
  if (keyLevel === 'session') return clean(key);
  return deriveSessionKeyAC(iccMkFor(key, keyLevel, pan, psn), clean(ac));
}

// Visa secure-messaging session key: ICC key with the ATC XOR-folded in.
function smSessionKeyVisa(key, keyLevel, pan, psn, atc) {
  if (keyLevel === 'session') return clean(key);
  return deriveSessionKeyVisa(iccMkFor(key, keyLevel, pan, psn), clean(atc));
}

// Format-finder for the M/Chip secure-messaging MAC: builds a bounded set of
// PIN-UNBLOCK (84 24 00 00, MAC-only) variants that differ in the unknown
// dimensions (SM session-key derivation, MAC ICV, MAC input, pad method).
// UNBLOCK carries no enciphered PIN, so a 9000 isolates the correct MAC format
// without changing the PIN (it just resets the PIN try counter).
export function buildUnblockVariants({ macKey, keyLevel, pan, psn = '00', atc, arqc, un }) {
  const mk = clean(macKey);
  const iccMk = (keyLevel === 'icc' || keyLevel === 'session') ? mk : deriveIccMasterKey(mk, pan, psn);
  const skCsk = keyLevel === 'session' ? mk : deriveSessionKey(iccMk, clean(atc));            // EMV CSK (ATC)
  const skMchip = deriveSessionKeyMChip(iccMk, clean(atc), clean(un));                        // M/Chip (ATC + UN)
  // M/Chip cards with a non-zero UN derive the AC session key with the UN — the
  // SM session key uses the same method, so try it first.
  const sks = [['MChip(UN)', skMchip], ['CSK(ATC)', skCsk], ['ICC-MK', iccMk]];
  const icvs = [['ARQC', clean(arqc) || null], ['zero', null]]; // MAC ICV options
  const P2 = '00';
  const header = '8424' + '00' + P2;
  const variants = [];
  for (const [skName, sk] of sks) {
    for (const [icvName, icv] of icvs) {
      // MAC input options: header+Lc(08) vs header only; pad method 2 (0x80..).
      for (const [inName, macIn] of [['hdr+Lc', header + '08'], ['hdr', header]]) {
        const mac = retailMac(sk, macIn, 2, icv);
        variants.push({
          name: `SK=${skName} ICV=${icvName} in=${inName}`,
          apdu: header + '08' + mac, sk, mac,
        });
      }
    }
  }
  return variants; // 3 × 2 × 2 = 12 variants
}

// Scheme dispatcher — PIN change / unblock differs by scheme (verified against
// FIME traces): Mastercard M/Chip and Visa VIS use different session-key
// derivations, PIN block formats, enciphered-PIN sizes and MAC lengths.
export function buildPinChange({ scheme, ...rest }) {
  const s = (scheme || '').toLowerCase();
  if (s === 'visa') return { ...buildPinChangeVisa(rest), scheme: 'visa' };
  if (s === 'amex') return { ...buildPinChangeAmex(rest), scheme: 'amex' };
  // Troy D-PAS uses the same M/Chip PIN-change format (AC-diversified session
  // key, ISO-2 PIN block, 8-byte enciphered PIN + MAC) — verified against FIME.
  if (s === 'troy') return { ...buildPinChangeMchip(rest), scheme: 'troy' };
  return { ...buildPinChangeMchip(rest), scheme: 'mastercard' };
}

// ── Mastercard M/Chip ───────────────────────────────────────────────
// Session key: ICC key diversified by the AC (ARQC). Enciphered PIN: 3DES-ECB
// of the ISO-2 PIN block (8 bytes). MAC: 8-byte Retail MAC over
// header || Lc || ATC || AC || encPIN. Lc = 0x10. Verified byte-exact + live 9000.
export function buildPinChangeMchip({
  macKey, encKey, keyLevel = 'master', pan, psn = '00', atc, arqc,
  newPin, mode = 'change', p1 = '00', p2,
}) {
  if (!macKey) return { error: 'MAC anahtarı gerekli (secure messaging MAC için)' };
  if (!clean(arqc)) return { error: 'ARQC gerekli — GENERATE AC ile alınır (session key diversifier)' };
  if (!clean(atc)) return { error: 'ATC gerekli — GENERATE AC ile alınır' };
  const P1 = clean(p1) || '00';
  const P2 = clean(p2) || (mode === 'unblock' ? '00' : '02');
  const ac = clean(arqc);
  const skmac = smSessionKey(macKey, keyLevel, pan, psn, ac);
  const header = '8424' + P1 + P2;

  let encPin = '', skenc = '', pinBlock = '';
  if (mode === 'change') {
    if (!encKey) return { error: 'PIN değişimi için ENC anahtarı gerekli' };
    const digits = (newPin || '').replace(/\D/g, '');
    if (!/^\d{4,12}$/.test(digits)) return { error: 'Yeni PIN 4-12 rakam olmalı' };
    skenc = smSessionKey(encKey, keyLevel, pan, psn, ac);
    pinBlock = pinBlockISO2(digits);
    encPin = tdesEcbEncrypt(skenc, pinBlock);
  }

  const lc = ((encPin.length / 2) + 8).toString(16).padStart(2, '0').toUpperCase();
  const macInput = header + lc + clean(atc) + ac + encPin;
  const mac = retailMac(skmac, macInput, 2, null);
  const apdu = header + lc + encPin + mac;
  return { apdu, header, lc, skmac, skenc, pinBlock, encPin, mac, macInput, atc: clean(atc), arqc: ac, mode, p1: P1, p2: P2 };
}

// ── Visa VIS ────────────────────────────────────────────────────────
// Session key: ICC key with the ATC XOR-folded in (deriveSessionKeyVisa).
// Enciphered PIN: 3DES-ECB of ( 08 || Visa PIN block(8) || 80 || zeros ) → 16
// bytes. MAC: 4-byte (leftmost) Retail MAC over header || Lc || ATC || AC ||
// encPIN. Lc = 0x14. Verified byte-exact against a FIME Visa PIN Change trace.
export function buildPinChangeVisa({
  macKey, encKey, acKey, keyLevel = 'master', pan, psn = '00', atc, arqc,
  newPin, mode = 'change', p1 = '00', p2,
}) {
  if (!macKey) return { error: 'MAC anahtarı gerekli (secure messaging MAC için)' };
  if (!clean(arqc)) return { error: 'ARQC gerekli — GENERATE AC ile alınır (MAC girdisi)' };
  if (!clean(atc)) return { error: 'ATC gerekli — GENERATE AC ile alınır (session key)' };
  const P1 = clean(p1) || '00';
  const P2 = clean(p2) || (mode === 'unblock' ? '00' : '02');
  const atcC = clean(atc), ac = clean(arqc);
  const skmac = smSessionKeyVisa(macKey, keyLevel, pan, psn, atcC);
  const header = '8424' + P1 + P2;

  let encPin = '', skenc = '', pinBlock = '', plain16 = '';
  if (mode === 'change') {
    if (!encKey) return { error: 'PIN değişimi için ENC anahtarı gerekli' };
    if (!acKey) return { error: 'PIN bloğu diversifier için AC anahtarı gerekli' };
    const digits = (newPin || '').replace(/\D/g, '');
    if (!/^\d{4,12}$/.test(digits)) return { error: 'Yeni PIN 4-12 rakam olmalı' };
    skenc = smSessionKeyVisa(encKey, keyLevel, pan, psn, atcC);
    // PIN block padding is diversified by the ICC AC unique key (UDK-AC), not random.
    const udkAc = iccMkFor(acKey, keyLevel, pan, psn);
    pinBlock = pinBlockVisa(digits, udkAc);
    plain16 = '08' + pinBlock + '80' + '000000000000';    // length prefix + method-2 pad → 16 bytes
    encPin = tdesEcbEncrypt(skenc, plain16);              // 3DES-ECB (2 blocks)
  }

  const lc = ((encPin.length / 2) + 4).toString(16).padStart(2, '0').toUpperCase(); // encPIN + 4-byte MAC
  const macInput = header + lc + atcC + ac + encPin;
  const mac = retailMac(skmac, macInput, 2, null).slice(0, 8);  // leftmost 4 bytes
  const apdu = header + lc + encPin + mac;
  return { apdu, header, lc, skmac, skenc, pinBlock, plain16, encPin, mac, macInput, atc: atcC, arqc: ac, mode, p1: P1, p2: P2 };
}

// ── American Express ────────────────────────────────────────────────
// A Visa/Mastercard hybrid, verified byte-exact against a FIME Amex trace:
// session key = Visa ATC-XOR method; PIN block = Visa UDK-AC XOR; but the
// enciphered PIN is a plain 8-byte 3DES-ECB (like M/Chip, no length prefix /
// pad) and the MAC is a full 8-byte Retail MAC over header||Lc(10)||ATC||AC||
// encPIN. AC = the online ARQC (1st GENERATE AC). Issuer authentication is done
// separately via EXTERNAL AUTHENTICATE (ARPC method 1), not the CDOL2.
export function buildPinChangeAmex({
  macKey, encKey, acKey, keyLevel = 'master', pan, psn = '00', atc, arqc,
  newPin, mode = 'change', p1 = '00', p2,
}) {
  if (!macKey) return { error: 'MAC anahtarı gerekli (secure messaging MAC için)' };
  if (!clean(arqc)) return { error: 'ARQC gerekli — GENERATE AC ile alınır (MAC girdisi)' };
  if (!clean(atc)) return { error: 'ATC gerekli — GENERATE AC ile alınır (session key)' };
  const P1 = clean(p1) || '00';
  const P2 = clean(p2) || (mode === 'unblock' ? '00' : '02');
  const atcC = clean(atc), ac = clean(arqc);
  const skmac = smSessionKeyVisa(macKey, keyLevel, pan, psn, atcC);
  const header = '8424' + P1 + P2;

  let encPin = '', skenc = '', pinBlock = '';
  if (mode === 'change') {
    if (!encKey) return { error: 'PIN değişimi için ENC anahtarı gerekli' };
    if (!acKey) return { error: 'PIN bloğu diversifier için AC anahtarı gerekli' };
    const digits = (newPin || '').replace(/\D/g, '');
    if (!/^\d{4,12}$/.test(digits)) return { error: 'Yeni PIN 4-12 rakam olmalı' };
    skenc = smSessionKeyVisa(encKey, keyLevel, pan, psn, atcC);
    const udkAc = iccMkFor(acKey, keyLevel, pan, psn);
    pinBlock = pinBlockVisa(digits, udkAc);                // Visa PIN block (UDK-AC XOR)
    encPin = tdesEcbEncrypt(skenc, pinBlock);              // plain 8-byte 3DES-ECB
  }

  const lc = ((encPin.length / 2) + 8).toString(16).padStart(2, '0').toUpperCase(); // encPIN + 8-byte MAC
  const macInput = header + lc + atcC + ac + encPin;
  const mac = retailMac(skmac, macInput, 2, null);          // full 8-byte Retail MAC
  const apdu = header + lc + encPin + mac;
  return { apdu, header, lc, skmac, skenc, pinBlock, encPin, mac, macInput, atc: atcC, arqc: ac, mode, p1: P1, p2: P2 };
}
