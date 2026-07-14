// EMV / ISO 7816 parsing engine: ATR decoder, BER-TLV parser, tag & SW dictionaries.

// ── Status Word dictionary ──────────────────────────────────────────
export const SW = {
  '9000': 'Başarılı (Normal processing)',
  '6200': 'Uyarı: durum değişmedi',
  '6281': 'Dönen veri bozulmuş olabilir',
  '6282': 'Dosya sonuna ulaşıldı',
  '6283': 'Seçilen dosya geçersiz kılınmış',
  '6300': 'Uyarı: durum değişti',
  '6700': 'Yanlış uzunluk (Wrong length)',
  '6800': 'CLA fonksiyonu desteklenmiyor',
  '6881': 'Logical channel desteklenmiyor',
  '6882': 'Güvenli mesajlaşma desteklenmiyor',
  '6900': 'Komut izin verilmiyor',
  '6981': 'Dosya yapısıyla uyumsuz komut',
  '6982': 'Güvenlik durumu sağlanmadı',
  '6983': 'Kimlik doğrulama yöntemi bloklandı',
  '6984': 'Referans veri kullanılamaz',
  '6985': 'Kullanım koşulları sağlanmadı',
  '6986': 'Komut izin verilmiyor (EF yok)',
  '6987': 'Beklenen SM veri nesnesi eksik',
  '6988': 'SM veri nesneleri hatalı',
  '6A80': 'Veri alanı parametreleri yanlış',
  '6A81': 'Fonksiyon desteklenmiyor',
  '6A82': 'Dosya bulunamadı (File not found)',
  '6A83': 'Kayıt bulunamadı (Record not found)',
  '6A84': 'Dosyada yeterli alan yok',
  '6A85': 'Lc, TLV yapısıyla uyumsuz',
  '6A86': 'P1-P2 parametreleri yanlış',
  '6A87': 'Lc, P1-P2 ile uyumsuz',
  '6A88': 'Referans veri bulunamadı',
  '6B00': 'Yanlış P1-P2',
  '6D00': 'INS desteklenmiyor / geçersiz',
  '6E00': 'CLA desteklenmiyor',
  '6F00': 'Teşhis yok (No precise diagnosis)',
};

export function describeSw(sw) {
  if (!sw) return '';
  const s = sw.toUpperCase();
  if (SW[s]) return SW[s];
  if (s.startsWith('61')) return `Başarılı — ${parseInt(s.slice(2), 16)} bayt daha mevcut (GET RESPONSE)`;
  if (s.startsWith('6C')) return `Yanlış Le — doğru uzunluk: ${parseInt(s.slice(2), 16)} bayt`;
  if (s.startsWith('63C')) return `Doğrulama başarısız — ${parseInt(s.slice(3), 16)} deneme kaldı`;
  if (s.startsWith('62')) return 'Uyarı: durum değişmedi';
  if (s.startsWith('63')) return 'Uyarı: durum değişti';
  return 'Bilinmeyen status word';
}

// ── INS dictionary (ISO 7816 / EMV) ─────────────────────────────────
export const INS = {
  '04': 'DEACTIVATE FILE', '0E': 'ERASE BINARY', '20': 'VERIFY',
  '70': 'MANAGE CHANNEL', '82': 'EXTERNAL AUTHENTICATE', '84': 'GET CHALLENGE',
  '88': 'INTERNAL AUTHENTICATE', 'A4': 'SELECT', 'B0': 'READ BINARY',
  'B2': 'READ RECORD', 'C0': 'GET RESPONSE', 'CA': 'GET DATA',
  'D0': 'WRITE BINARY', 'D2': 'WRITE RECORD', 'DC': 'UPDATE RECORD',
  'DA': 'PUT DATA', 'E2': 'APPEND RECORD', 'AE': 'GENERATE AC',
};

// ── EMV / ISO BER-TLV tag dictionary ────────────────────────────────
export const TAGS = {
  '6F': 'FCI Template', '84': 'DF Name (AID)', 'A5': 'FCI Proprietary Template',
  '88': 'SFI of Directory Elementary File', '5F2D': 'Language Preference',
  '9F11': 'Issuer Code Table Index', '9F12': 'Application Preferred Name',
  '50': 'Application Label', '87': 'Application Priority Indicator',
  '9F38': 'PDOL', '5F50': 'Issuer URL', '73': 'Directory Discretionary Template',
  '61': 'Application Template', '4F': 'Application Identifier (AID)',
  '70': 'Record / READ RECORD Template', '77': 'Response Message Template Format 2',
  '80': 'Response Message Template Format 1', '57': 'Track 2 Equivalent Data',
  '5A': 'Application PAN', '5F20': 'Cardholder Name', '5F24': 'Application Expiry Date',
  '5F25': 'Application Effective Date', '5F28': 'Issuer Country Code',
  '5F30': 'Service Code', '5F34': 'PAN Sequence Number', '8C': 'CDOL1', '8D': 'CDOL2',
  '8E': 'CVM List', '8F': 'CA Public Key Index', '90': 'Issuer Public Key Certificate',
  '92': 'Issuer Public Key Remainder', '93': 'Signed Static Application Data',
  '94': 'Application File Locator (AFL)', '95': 'Terminal Verification Results',
  '9A': 'Transaction Date', '9C': 'Transaction Type', '82': 'Application Interchange Profile',
  '9F02': 'Amount, Authorised', '9F03': 'Amount, Other', '9F07': 'Application Usage Control',
  '9F08': 'Application Version Number', '9F0D': 'IAC - Default', '9F0E': 'IAC - Denial',
  '9F0F': 'IAC - Online', '9F10': 'Issuer Application Data', '9F13': 'Last Online ATC Register',
  '9F17': 'PIN Try Counter', '9F1A': 'Terminal Country Code', '9F1F': 'Track 1 Discretionary Data',
  '9F26': 'Application Cryptogram', '9F27': 'Cryptogram Information Data',
  '9F32': 'Issuer Public Key Exponent', '9F36': 'Application Transaction Counter (ATC)',
  '9F37': 'Unpredictable Number', '9F42': 'Application Currency Code',
  '9F44': 'Application Currency Exponent', '9F46': 'ICC Public Key Certificate',
  '9F47': 'ICC Public Key Exponent', '9F48': 'ICC Public Key Remainder',
  '9F4A': 'Static Data Authentication Tag List', '9F4C': 'ICC Dynamic Number',
  'BF0C': 'FCI Issuer Discretionary Data', '9F5A': 'Application Program ID',
  // ── Perso / CPV-VPA ek tag'leri ──────────────────────────────────
  '42': 'Issuer Identification Number (IIN)', '4D': 'Directory Definition File',
  '9F0B': 'Cardholder Name Extended', '5F50': 'Issuer URL',
  '9F14': 'Lower Consecutive Offline Limit', '9F23': 'Upper Consecutive Offline Limit',
  '9F45': 'Data Authentication Code', '9F49': 'DDOL', '9F4B': 'Signed Dynamic Application Data',
  '9F4D': 'Log Entry', '9F4E': 'Merchant Name and Location', '9F4F': 'Log Format',
  '9F50': 'Offline Accumulator Balance', '9F51': 'Application Currency Code',
  '9F52': 'Application Default Action (ADA)', '9F53': 'Transaction Category Code / CTC Limit',
  '9F54': 'Cumulative Total Txn Amount Limit', '9F55': 'Geographic Indicator',
  '9F56': 'Issuer Authentication Indicator', '9F57': 'Issuer Country Code',
  '9F58': 'Consecutive Transaction Counter Limit (CTCL)', '9F59': 'Consecutive Txn Int. Upper Limit',
  '9F5B': 'Issuer Script Results / DSDOL', '9F5C': 'Cumulative Total Txn Amount Upper Limit',
  '9F5D': 'Available Offline Spending Amount', '9F62': 'PCVC3 (Track1)', '9F63': 'PUNATC (Track1) / Card Auth Related',
  '9F64': 'NATC (Track1)', '9F65': 'PCVC3 (Track2)', '9F66': 'Terminal Transaction Qualifiers (TTQ)',
  '9F67': 'NATC (Track2) / MSD Offset', '9F68': 'Card Additional Processes', '9F69': 'Card Authentication Related Data',
  '9F6B': 'Track 2 Data (MSD)', '9F6C': 'Card Transaction Qualifiers (CTQ)',
  '9F6D': 'Contactless Reader Capabilities', '9F6E': 'Form Factor Indicator / Third Party Data',
  '9F71': 'DPAS Config', '9F72': 'Consecutive Txn Counter Limit (Int)', '9F73': 'Currency Conversion Factor',
  '9F74': 'VLP Issuer Authorisation Code', '9F75': 'Cumulative Total Amount Limit (Dual Cur)',
  '9F76': 'Second App Currency Code', '9F77': 'VLP Funds Limit', '9F78': 'VLP Single Txn Limit',
  '9F79': 'VLP Available Funds', '9F7D': 'Application Specific Transparent Template',
  '9F7F': 'Card Production Life Cycle (CPLC)', '9F0A': 'Application Selection Registered Proprietary Data',
  '9F6F': 'DS Slot Management Control', '9F70': 'Protected Data Envelope',
  'DF60': 'VISA Log Entry', 'DF61': 'Issuer Proprietary', 'C1': 'Application Configuration Options [DPAS]',
  'C2': 'DPAS Proprietary', 'CA': 'DPAS Proprietary', 'CD': 'DPAS Proprietary',
  // Mastercard M/Chip issuer proprietary (GET DATA)
  'C3': 'CIAC-Decline', 'C4': 'CIAC-Default', 'C5': 'CIAC-Online', '9F7E': 'Mobile Support Indicator',
  'D2': 'Common Currency Conversion Table', 'D8': 'Application Interchange Profile (Contactless)',
};

export function lookupTag(tagHex) {
  return TAGS[tagHex.toUpperCase()] || null;
}

// ── BER-TLV parser ──────────────────────────────────────────────────
// Returns { nodes: [...], ok } — ok=false if bytes don't form clean TLV.
export function parseTlv(hex) {
  const bytes = hexToBytes(hex);
  if (!bytes || bytes.length === 0) return { nodes: [], ok: false };
  try {
    let i = 0;
    const nodes = parseNodes(bytes, 0, bytes.length, (n) => (i = n));
    return { nodes, ok: true };
  } catch {
    return { nodes: [], ok: false };
  }
}

function parseNodes(bytes, start, end) {
  const nodes = [];
  let i = start;
  while (i < end) {
    // Skip padding bytes 00 / FF between objects
    if (bytes[i] === 0x00 || bytes[i] === 0xff) { i++; continue; }

    // Tag
    let tagStart = i;
    let first = bytes[i++];
    if ((first & 0x1f) === 0x1f) {
      while (i < end && (bytes[i] & 0x80)) i++;
      i++;
    }
    const tagBytes = bytes.slice(tagStart, i);
    const tag = bytesToHex(tagBytes).replace(/\s/g, '');
    const constructed = (first & 0x20) !== 0;

    // Length
    if (i >= end) throw new Error('truncated length');
    let len = bytes[i++];
    if (len & 0x80) {
      const n = len & 0x7f;
      if (n === 0 || n > 3 || i + n > end) throw new Error('bad length');
      len = 0;
      for (let k = 0; k < n; k++) len = (len << 8) | bytes[i++];
    }
    if (i + len > end) throw new Error('value exceeds buffer');

    const valBytes = bytes.slice(i, i + len);
    const node = {
      tag,
      name: lookupTag(tag),
      length: len,
      constructed,
      value: bytesToHex(valBytes),
    };
    if (constructed && len > 0) {
      node.children = parseNodes(valBytes, 0, len);
    } else {
      node.ascii = toPrintableAscii(valBytes);
      const dec = decodeTag(tag, node.value);
      if (dec && dec.length) node.decoded = dec;
    }
    nodes.push(node);
    i += len;
  }
  return nodes;
}

// ── ATR parser (ISO 7816-3) ─────────────────────────────────────────
export function parseAtr(atrHex) {
  const b = hexToBytes(atrHex);
  if (!b || b.length < 2) return null;
  const out = { raw: bytesToHex(b), fields: [], protocols: [], historical: '' };
  let i = 0;

  // TS
  const ts = b[i++];
  out.fields.push({ name: 'TS', value: hx(ts), desc: ts === 0x3b ? 'Direct convention' : ts === 0x3f ? 'Inverse convention' : 'Geçersiz' });

  // T0
  const t0 = b[i++];
  const k = t0 & 0x0f; // number of historical bytes
  out.fields.push({ name: 'T0', value: hx(t0), desc: `Y1=${(t0 >> 4).toString(2).padStart(4, '0')}, tarihçe baytı=${k}` });

  let y = t0 >> 4;
  let blockNum = 1;
  while (true) {
    if (y & 0x1) { const ta = b[i++]; out.fields.push({ name: `TA${blockNum}`, value: hx(ta), desc: taDesc(blockNum, ta) }); }
    if (y & 0x2) { const tb = b[i++]; out.fields.push({ name: `TB${blockNum}`, value: hx(tb), desc: 'Arayüz baytı' }); }
    if (y & 0x4) { const tc = b[i++]; out.fields.push({ name: `TC${blockNum}`, value: hx(tc), desc: tcDesc(blockNum, tc) }); }
    if (y & 0x8) {
      const td = b[i++];
      const proto = td & 0x0f;
      if (!out.protocols.includes(`T=${proto}`)) out.protocols.push(`T=${proto}`);
      out.fields.push({ name: `TD${blockNum}`, value: hx(td), desc: `Sonraki protokol T=${proto}` });
      y = td >> 4;
      blockNum++;
    } else break;
  }
  if (out.protocols.length === 0) out.protocols.push('T=0');

  // Historical bytes
  const hist = b.slice(i, i + k);
  i += k;
  out.historical = bytesToHex(hist);
  out.historicalAscii = toPrintableAscii(hist);

  // TCK (present if any protocol other than T=0)
  if (i < b.length) out.fields.push({ name: 'TCK', value: hx(b[i]), desc: 'Checksum' });

  return out;
}

function taDesc(n, v) {
  if (n === 1) return `Fi/Di saat hızı kodlaması (0x${v.toString(16)})`;
  return 'Arayüz baytı';
}
function tcDesc(n, v) {
  if (n === 1) return `Extra guard time = ${v}`;
  return 'Arayüz baytı';
}

// ── Card scheme detection + Luhn (works on contactless-read PAN) ─────
export function detectScheme(pan) {
  const p = (pan || '').replace(/\D/g, '');
  if (!p) return null;
  const n2 = parseInt(p.slice(0, 2)), n4 = parseInt(p.slice(0, 4)), n6 = parseInt(p.slice(0, 6));
  if (p.startsWith('9792')) return 'Troy';
  if (p[0] === '4') return 'Visa';
  if ((n2 >= 51 && n2 <= 55) || (n4 >= 2221 && n4 <= 2720)) return 'Mastercard';
  if (n2 === 34 || n2 === 37) return 'American Express';
  if (n4 >= 3528 && n4 <= 3589) return 'JCB';
  if (n4 === 6011 || n2 === 65 || (n6 >= 644000 && n6 <= 649999)) return 'Discover';
  if (n2 === 36 || n2 === 38 || (n4 >= 3000 && n4 <= 3059)) return 'Diners Club';
  if (n2 === 62) return 'UnionPay';
  return 'Bilinmeyen';
}

export function luhnCheck(pan) {
  const p = (pan || '').replace(/\D/g, '');
  if (p.length < 12) return null;
  let sum = 0, alt = false;
  for (let i = p.length - 1; i >= 0; i--) {
    let d = parseInt(p[i]);
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d; alt = !alt;
  }
  return sum % 10 === 0;
}

// Interpret a contactless UID (from PC/SC FF CA 00 00 00).
export function interpretUid(uidHex) {
  const b = hexToBytes(uidHex);
  if (!b || !b.length) return null;
  const len = b.length;
  let tech;
  if (len === 4) tech = 'Tek boyut NFCID1 (4 bayt) — Mifare Classic / Type A';
  else if (len === 7) tech = 'Çift boyut NFCID1 (7 bayt) — Mifare Ultralight / DESFire / EMV temassız';
  else if (len === 10) tech = 'Üçlü boyut NFCID1 (10 bayt)';
  else tech = `${len} baytlık tanımlayıcı`;
  const random = b[0] === 0x08 ? ' · rastgele UID (gizlilik için)' : '';
  return { uid: bytesToHex(b).replace(/\s/g, ''), length: len, tech: tech + random };
}

// ── Value decoders (bit-level meaning for known tags) ───────────────

// AIP — Application Interchange Profile (tag 82, 2 bytes)
export function decodeAip(hex) {
  const b = hexToBytes(hex);
  if (!b || b.length < 2) return [];
  const out = [];
  const b1 = b[0], b2 = b[1];
  if (b1 & 0x40) out.push('SDA destekleniyor (Statik veri doğrulama)');
  if (b1 & 0x20) out.push('DDA destekleniyor (Dinamik veri doğrulama)');
  if (b1 & 0x10) out.push('Kart sahibi doğrulaması (CVM) destekleniyor');
  if (b1 & 0x08) out.push('Terminal risk yönetimi yapılacak');
  if (b1 & 0x04) out.push('Issuer authentication destekleniyor');
  if (b1 & 0x02) out.push('On-device CVM destekleniyor (temassız)');
  if (b1 & 0x01) out.push('CDA destekleniyor (Birleşik veri doğrulama)');
  if (b2 & 0x80) out.push('EMV temassız modu destekleniyor');
  if (out.length === 0) out.push('Özel yetenek bayrağı yok');
  return out;
}

// CVM List — Cardholder Verification Method List (tag 8E)
const CVM_METHOD = {
  0x00: 'Başarısız CVM', 0x01: 'Düz metin PIN (ICC)', 0x02: 'Şifreli PIN (online)',
  0x03: 'Düz metin PIN + imza', 0x04: 'Şifreli PIN (ICC)', 0x05: 'Şifreli PIN + imza',
  0x1e: 'İmza (kağıt)', 0x1f: 'CVM yok',
};
const CVM_COND = {
  0x00: 'Her zaman', 0x01: 'Gözetimsiz nakit', 0x02: 'Nakit/manuel değilse',
  0x03: 'Terminal CVM destekliyorsa', 0x04: 'Manuel nakit', 0x05: 'Satın alma (cashback)',
  0x06: 'Uygulama para biriminde ve X altında', 0x07: 'Uygulama para biriminde ve X üstünde',
  0x08: 'Uygulama para biriminde ve Y altında', 0x09: 'Uygulama para biriminde ve Y üstünde',
};
export function decodeCvmList(hex) {
  const b = hexToBytes(hex);
  if (!b || b.length < 8) return [];
  const rules = [];
  for (let i = 8; i + 1 < b.length; i += 2) {
    const code = b[i], cond = b[i + 1];
    const method = CVM_METHOD[code & 0x3f] || `0x${(code & 0x3f).toString(16)}`;
    const next = code & 0x40 ? ' (başarısızsa sonrakini dene)' : '';
    rules.push(`${method} — koşul: ${CVM_COND[cond] || `0x${cond.toString(16)}`}${next}`);
  }
  return rules;
}

// Service Code — 3 BCD digits (tag 5F30 or from Track 2)
const SC1 = { 1: 'Uluslararası', 2: 'Uluslararası (IC kullan)', 5: 'Ulusal', 6: 'Ulusal (IC kullan)', 7: 'Özel', 9: 'Test' };
const SC2 = { 0: 'Normal yetkilendirme', 2: 'Issuer üzerinden', 4: 'Issuer üzerinden (bilateral hariç)' };
const SC3 = { 0: 'PIN gerekli, kısıtlama yok', 1: 'Kısıtlama yok', 2: 'Sadece mal/hizmet', 3: 'Sadece ATM, PIN gerekli', 4: 'Sadece nakit', 5: 'Mal/hizmet, PIN gerekli', 6: 'Kısıtlama yok, mümkünse PIN', 7: 'Mal/hizmet, mümkünse PIN' };
export function decodeServiceCode(sc) {
  const s = (sc || '').replace(/\s/g, '');
  if (s.length < 3) return null;
  const d = [parseInt(s[0]), parseInt(s[1]), parseInt(s[2])];
  return {
    code: s.slice(0, 3),
    interchange: SC1[d[0]] || '?',
    authorization: SC2[d[1]] || '?',
    services: SC3[d[2]] || '?',
  };
}

// AUC — Application Usage Control (tag 9F07, 2 bytes): where the card may be used.
export function decodeAuc(hex) {
  const b = hexToBytes(hex);
  if (!b || b.length < 1) return [];
  const b1 = b[0], b2 = b.length > 1 ? b[1] : 0;
  const out = [];
  out.push((b1 & 0x80 ? '✓' : '✗') + ' Yurt içi nakit');
  out.push((b1 & 0x40 ? '✓' : '✗') + ' Yurt dışı nakit');
  out.push((b1 & 0x20 ? '✓' : '✗') + ' Yurt içi mal');
  out.push((b1 & 0x10 ? '✓' : '✗') + ' Yurt dışı mal');
  out.push((b1 & 0x08 ? '✓' : '✗') + ' Yurt içi hizmet');
  out.push((b1 & 0x04 ? '✓' : '✗') + ' Yurt dışı hizmet');
  out.push((b1 & 0x02 ? '✓' : '✗') + ' ATM');
  out.push((b1 & 0x01 ? '✓' : '✗') + ' ATM dışı terminal');
  out.push((b2 & 0x80 ? '✓' : '✗') + ' Yurt içi cashback');
  out.push((b2 & 0x40 ? '✓' : '✗') + ' Yurt dışı cashback');
  return out;
}

// ISO 3166 numeric → country (yaygın olanlar), ISO 4217 numeric → para birimi.
const COUNTRY = {
  '0792': 'Türkiye', '0840': 'ABD', '0826': 'Birleşik Krallık', '0276': 'Almanya',
  '0250': 'Fransa', '0380': 'İtalya', '0724': 'İspanya', '0528': 'Hollanda',
  '0056': 'Belçika', '0756': 'İsviçre', '0040': 'Avusturya', '0643': 'Rusya',
  '0156': 'Çin', '0392': 'Japonya', '0036': 'Avustralya', '0124': 'Kanada',
};
const CURRENCY = {
  '0949': 'TRY (Türk Lirası)', '0840': 'USD (ABD Doları)', '0978': 'EUR (Euro)',
  '0826': 'GBP (Sterlin)', '0756': 'CHF (İsviçre Frangı)', '0392': 'JPY (Japon Yeni)',
  '0643': 'RUB (Ruble)', '0156': 'CNY (Çin Yuanı)', '0036': 'AUD', '0124': 'CAD',
};
export function countryName(hex) {
  const c = (hex || '').replace(/\s/g, '').padStart(4, '0').slice(-4);
  return COUNTRY[c] ? `${COUNTRY[c]} (${c})` : `Kod ${c}`;
}
export function currencyName(hex) {
  const c = (hex || '').replace(/\s/g, '').padStart(4, '0').slice(-4);
  return CURRENCY[c] || `Kod ${c}`;
}

// Dispatch: human-readable lines for a known tag value (used in TLV tree).
export function decodeTag(tag, valueHex) {
  switch (tag.toUpperCase()) {
    case '82': return decodeAip(valueHex);
    case '8E': return decodeCvmList(valueHex);
    case '9F07': return decodeAuc(valueHex);
    case '5F28': return [countryName(valueHex)];
    case '9F42': return [currencyName(valueHex)];
    case '5F30': { const dig = valueHex.replace(/\s/g, ''); const s = decodeServiceCode(dig.slice(-3)); return s ? [`${s.interchange} · ${s.authorization} · ${s.services}`] : null; }
    default: return null;
  }
}

// ── EMV flow helpers ────────────────────────────────────────────────

// Recursively find the first node matching a tag (hex, no spaces, upper).
export function findTag(nodes, tag) {
  if (!nodes) return null;
  const t = tag.toUpperCase();
  for (const n of nodes) {
    if (n.tag === t) return n;
    if (n.children) {
      const hit = findTag(n.children, t);
      if (hit) return hit;
    }
  }
  return null;
}

// Recursively collect ALL nodes matching a tag.
export function findAllTags(nodes, tag) {
  const out = [];
  const t = tag.toUpperCase();
  const walk = (ns) => {
    if (!ns) return;
    for (const n of ns) {
      if (n.tag === t) out.push(n);
      if (n.children) walk(n.children);
    }
  };
  walk(nodes);
  return out;
}

// Parse a DOL (Data Object List, e.g. PDOL 9F38 / CDOL) into {tag, length} pairs.
export function parseDol(hex) {
  const b = hexToBytes(hex);
  if (!b) return [];
  const out = [];
  let i = 0;
  while (i < b.length) {
    const tagStart = i;
    const first = b[i++];
    if ((first & 0x1f) === 0x1f) { while (i < b.length && (b[i] & 0x80)) i++; i++; }
    const tag = bytesToHex(b.slice(tagStart, i)).replace(/\s/g, '');
    if (i >= b.length) break;
    const length = b[i++];
    out.push({ tag, length });
  }
  return out;
}

// Build the concatenated value for a DOL, filling each entry from `defaults`
// (zero-padded/truncated to the requested length). Used to construct GPO data.
export function buildDol(entries, defaults) {
  let data = '';
  for (const e of entries) {
    const need = e.length * 2;
    let v = (defaults[e.tag.toUpperCase()] || '').replace(/\s/g, '').toUpperCase();
    v = v.length > need ? v.slice(0, need) : v.padEnd(need, '0');
    data += v;
  }
  return data;
}

// Parse an Application File Locator (tag 94) value into record-read jobs.
// Each 4-byte entry: SFI(5 bits)|.., firstRec, lastRec, #recs for offline auth.
export function parseAfl(hex) {
  const b = hexToBytes(hex);
  if (!b || b.length % 4 !== 0) return [];
  const out = [];
  for (let i = 0; i < b.length; i += 4) {
    const sfi = b[i] >> 3;
    out.push({ sfi, firstRecord: b[i + 1], lastRecord: b[i + 2], offlineRecords: b[i + 3] });
  }
  return out;
}

// Parse Track 2 Equivalent Data (tag 57): PAN 'D' YYMM ServiceCode Discretionary.
export function parseTrack2(hex) {
  const s = hex.replace(/[\s:]/g, '').toUpperCase();
  const sep = s.indexOf('D');
  if (sep < 0) return null;
  const pan = s.slice(0, sep);
  const rest = s.slice(sep + 1).replace(/F+$/, '');
  const expiry = rest.slice(0, 4);   // YYMM
  const service = rest.slice(4, 7);  // service code
  return {
    pan,
    expiry: expiry.length === 4 ? `${expiry.slice(2, 4)}/${expiry.slice(0, 2)}` : expiry, // MM/YY
    serviceCode: service,
    discretionary: rest.slice(7),
  };
}

// Format an expiry stored as YYMMDD (5F24) or YYMM into MM/YY.
export function formatExpiry(hex) {
  const s = hex.replace(/\s/g, '');
  if (s.length >= 4) return `${s.slice(2, 4)}/${s.slice(0, 2)}`;
  return s;
}

// Decode a hex-ASCII field (e.g. cardholder name 5F20) to text.
export function hexToAscii(hex) {
  const b = hexToBytes(hex);
  if (!b) return '';
  return b.map((x) => (x >= 0x20 && x <= 0x7e ? String.fromCharCode(x) : '')).join('').trim();
}

// ── Hex helpers ─────────────────────────────────────────────────────
function hexToBytes(hex) {
  if (!hex) return null;
  const clean = hex.replace(/[\s:]/g, '');
  if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) return null;
  const out = [];
  for (let j = 0; j < clean.length; j += 2) out.push(parseInt(clean.substr(j, 2), 16));
  return out;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map((x) => x.toString(16).padStart(2, '0').toUpperCase()).join(' ');
}
function hx(v) { return v.toString(16).padStart(2, '0').toUpperCase(); }
function toPrintableAscii(bytes) {
  return Array.from(bytes).map((x) => (x >= 0x20 && x <= 0x7e ? String.fromCharCode(x) : '.')).join('');
}
