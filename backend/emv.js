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

      // ── Terminal-config sözlüğünden eksik tag'ler ──
  'DF01': 'Application Selection Indicator (ASI)', 'DF13': 'TAC-Denial (terminal)',
// ── Mastercard M/Chip proprietary (Profile Advisor + sweep dolgusu) ──
  'DF3A': 'AC Session Key Counter Limit (Contact)', 'DF34': 'AC Session Key Counter Limit (Contactless)', 'DF11': 'Accumulator 1 Control (Contact)',
  'DF12': 'Accumulator 1 Control (Contactless)', 'DF28': 'Accumulator 1 CVR Dependency Data (Contact)', 'DF29': 'Accumulator 1 CVR Dependency Data (Contactless)',
  'DF14': 'Accumulator 2 Control (Contact)', 'DF15': 'Accumulator 2 Control (Contactless)', 'DF16': 'Accumulator 2 Currency Code',
  'DF17': 'Accumulator 2 Currency Conversion Table', 'DF2A': 'Accumulator 2 CVR Dependency Data (Contact)', 'DF2B': 'Accumulator 2 CVR Dependency Data (Contactless)',
  'DF18': 'Accumulator 2 Lower Limit', 'DF19': 'Accumulator 2 Upper Limit', 'DF1A': 'Counter 1 Control (Contact)',
  'DF1B': 'Counter 1 Control (Contactless)', 'DF2C': 'Counter 1 CVR Dependency Data (Contact)', 'DF2D': 'Counter 1 CVR Dependency Data (Contactless)',
  'DF1D': 'Counter 2 Control (Contact)', 'DF1E': 'Counter 2 Control (Contactless)', 'DF2E': 'Counter 2 CVR Dependency Data (Contact)',
  'DF2F': 'Counter 2 CVR Dependency Data (Contactless)', 'DF1F': 'Counter 2 Lower Limit', 'DF21': 'Counter 2 Upper Limit',
  'DF3C': 'CVR Issuer Discretionary Data (Contact)', 'DF3D': 'CVR Issuer Discretionary Data (Contactless)', 'DF30': 'Interface Enabling Switch',
  'DF3E': 'Interface Identifier (Contact)', 'DF24': 'Maximum Transaction Amount Currency Code', 'DF22': 'Maximum Transaction Amount CVM (Contact)',
  'DF23': 'Maximum Transaction Amount CVM (Contactless)', 'DF25': 'Maximum Transaction Amount NoCVM (Contact)', 'DF26': 'Maximum Transaction Amount NoCVM (Contactless)',
  'DF27': 'Number of Days Offline Limit', 'DF36': 'PIN Decipherments Error Counter Limit', 'DF3F': 'Read Record Filter (Contact)',
  'DF32': 'SMI Session Key Counter Limit (Contact)', 'DF33': 'SMI Session Key Counter Limit (Contactless)', 'C0': 'M/Chip Proprietary',
  'CC': 'M/Chip Proprietary', 'D0': 'M/Chip Proprietary', 'D4': 'M/Chip Proprietary',
  'DE': 'M/Chip Proprietary', 'DF02': 'M/Chip Proprietary', 'DF31': 'M/Chip Proprietary',
  'DF35': 'M/Chip Proprietary', 'DF37': 'M/Chip Proprietary', 'DF38': 'M/Chip Proprietary',
  'DF39': 'M/Chip Proprietary', 'DF3B': 'M/Chip Proprietary', 'DF40': 'M/Chip Proprietary',
// ── Kullanıcı Excel EMV/ISO tag sözlüğünden eklenen isimler (228 tag) ──
  '5B': 'Name of an individual', '5C': 'Tag list', '5E': 'Proprietary login data',
  '5F21': 'Track 1, identical to the data coded', '5F22': 'Track 2, identical to the data coded', '5F23': 'Track 3, identical to the data coded',
  '5F26': 'Date, Card Effective', '5F27': 'Interchange control', '5F29': 'Interchange profile',
  '5F2A': 'Transaction Currency Code', '5F2B': 'Date of birth', '5F2C': 'Cardholder nationality',
  '5F2E': 'Cardholder biometric data', '5F2F': 'PIN usage policy', '5F32': 'Transaction counter',
  '5F33': 'Date, Transaction', '5F35': 'Sex (ISO 5218)', '5F36': 'Transaction Currency Exponent',
  '5F37': 'Static internal authentication (one-step)', '5F38': 'Static internal authentication - first associated data', '5F39': 'Static internal authentication - second associated data',
  '5F3A': 'Dynamic internal authentication', '5F3B': 'Dynamic external authentication', '5F3C': 'Transaction Reference Currency Code',
  '5F3D': 'Transaction Reference Currency Exponent', '5F40': 'Cardholder portrait image', '5F41': 'Element list',
  '5F42': 'Address', '5F43': 'Cardholder handwritten signature image', '5F44': 'Application image',
  '5F45': 'Display message', '5F46': 'Timer', '5F47': 'Message reference',
  '5F48': 'Cardholder private key', '5F49': 'Cardholder public key', '5F4A': 'Public key of certification authority',
  '5F4C': 'Certificate holder authorization', '5F4D': 'Integrated circuit manufacturer identifier', '5F4E': 'Certificate content',
  '5F53': 'International Bank Account Number (IBAN)', '5F54': 'Bank Identifier Code (BIC)', '5F55': 'Issuer Country Code (alpha2 format)',
  '5F56': 'Issuer Country Code (alpha3 format)', '5F57': 'Account Type', '60A0': 'Template, Identification data',
  '628A': 'Life cycle status byte (LCS)', '628B': 'Security attribute referencing the expanded format', '628C': 'Security attribute in compact format',
  '628D': 'Identifier of an EF containing security environment templates', '62A0': 'Template, Security attribute for data objects', '62A1': 'Template, Security attribute for physical interfaces',
  '62A2': 'One or more pairs of data objects, short EF identifier (tag 88) - absolute or relative path (tag 51)', '62A5': 'Proprietary information, constructed encoding', '62AB': 'Security attribute in expanded format',
  '62AC': 'Identifier of a cryptographic mechanism', '6A': 'Template, Login', '6A80': 'Qualifier',
  '6A81': 'Telephone Number', '6A82': 'Text', '6A83': 'Delay indicators, for detecting an end of message',
  '6A84': 'Delay indicators, for detecting an absence of response', '6B': 'Template, Qualified name', '6B06': 'Qualified name',
  '6B80': 'Name', '6BA0': 'Name', '6C': 'Template, Cardholder image',
  '6D': 'Template, Application image', '6E': 'Application related data', '6FA5': 'Template, FCI A5',
  '719F18': 'Issuer Script Identifier', '7A': 'Template, Security Support (SS)', '7A80': 'Card session counter',
  '7A81': 'Session identifier', '7A82': 'File selection counter', '7A83': 'File selection counter',
  '7A84': 'File selection counter', '7A85': 'File selection counter', '7A86': 'File selection counter',
  '7A87': 'File selection counter', '7A88': 'File selection counter', '7A89': 'File selection counter',
  '7A8A': 'File selection counter', '7A8B': 'File selection counter', '7A8C': 'File selection counter',
  '7A8D': 'File selection counter', '7A8E': 'File selection counter', '7A93': 'Digital signature counter',
  '7B': 'Template, Security Environment (SE)', '7B80': 'SEID byte, mandatory', '7B8A': 'LCS byte, optional',
  '7BA4': 'Control reference template (CRT)', '7BAA': 'Control reference template (CRT)', '7BAC': 'Cryptographic mechanism identifier template, optional',
  '7BB4': 'Control reference template (CRT)', '7BB6': 'Control reference template (CRT)', '7BB8': 'Control reference template (CRT)',
  '7D': 'Template, Secure Messaging (SM)', '7D80': 'Plain value not coded in BER-TLV', '7D81': 'Plain value not coded in BER-TLV',
  '7D82': 'Cryptogram (plain value coded in BER-TLV and including secure messaging data objects)', '7D83': 'Cryptogram (plain value coded in BER-TLV and including secure messaging data objects)', '7D84': 'Cryptogram (plain value coded in BER-TLV, but not including secure messaging data objects)',
  '7D85': 'Cryptogram (plain value coded in BER-TLV, but not including secure messaging data objects)', '7D86': 'Padding-content indicator byte followed by cryptogram (plain value not coded in BER-TLV)', '7D87': 'Padding-content indicator byte followed by cryptogram (plain value not coded in BER-TLV)',
  '7D8E': 'Cryptographic checksum (at least four bytes)', '7D90': 'Hash-code', '7D91': 'Hash-code',
  '7D92': 'Certificate (not BER-TLV coded data)', '7D93': 'Certificate (not BER-TLV coded data)', '7D94': 'Security environment identifier',
  '7D95': 'Security environment identifier', '7D96': 'Number Le in the unsecured command APDU (one or two bytes)', '7D97': 'Number Le in the unsecured command APDU (one or two bytes)',
  '7D99': 'Processing status of the secured response APDU (new SW1-SW2, two bytes)', '7D9A': 'Input data element for the computation of a digital signature (the value field is signed)', '7D9B': 'Input data element for the computation of a digital signature (the value field is signed)',
  '7D9C': 'Public key', '7D9D': 'Public key', '7D9E': 'Digital signature',
  '7DA0': 'Input template for the computation of a hash-code (the template is hashed)', '7DA1': 'Input template for the computation of a hash-code (the template is hashed)', '7DA2': 'Input template for the verification of a cryptographic checksum (the template is integrated)',
  '7DA4': 'Control reference template for authentication (AT)', '7DA5': 'Control reference template for authentication (AT)', '7DA8': 'Input template for the verification of a digital signature (the template is signed)',
  '7DAA': 'Template, Control reference for hash-code (HT)', '7DAB': 'Template, Control reference for hash-code (HT)', '7DAC': 'Input template for the computation of a digital signature (the concatenated value fields are signed)',
  '7DAD': 'Input template for the computation of a digital signature (the concatenated value fields are signed)', '7DAE': 'Input template for the computation of a certificate (the concatenated value fields are certified)', '7DAF': 'Input template for the computation of a certificate (the concatenated value fields are certified)',
  '7DB0': 'Plain value coded in BER-TLV and including secure messaging data objects', '7DB1': 'Plain value coded in BER-TLV and including secure messaging data objects', '7DB2': 'Plain value coded in BER-TLV, but not including secure messaging data objects',
  '7DB3': 'Plain value coded in BER-TLV, but not including secure messaging data objects', '7DB4': 'Control reference template for cryptographic checksum (CCT)', '7DB5': 'Control reference template for cryptographic checksum (CCT)',
  '7DB6': 'Control reference template for digital signature (DST)', '7DB7': 'Control reference template for digital signature (DST)', '7DB8': 'Control reference template for confidentiality (CT)',
  '7DB9': 'Control reference template for confidentiality (CT)', '7DBA': 'Response descriptor template', '7DBB': 'Response descriptor template',
  '7DBC': 'Input template for the computation of a digital signature (the template is signed)', '7DBD': 'Input template for the computation of a digital signature (the template is signed)', '7DBE': 'Input template for the verification of a certificate (the template is certified)',
  '7E': 'Template, Nesting Interindustry data objects', '7F20': 'Display control template', '7F21': 'Cardholder certificate',
  '7F2E': 'Biometric data template', '7F49': 'Template, Cardholder public key', '7F4980': 'Algorithm reference as used in control reference data objects for secure messaging',
  '7F4981': 'RSA Modulus', '7F4982': 'RSA Public exponent', '7F4983': 'DSA Basis',
  '7F4984': 'DSA Public key', '7F4985': 'ECDSA Order', '7F4986': 'ECDSA Public key',
  '7F4C': 'Template, Certificate Holder Authorization', '7F4E': 'Certificate Body', '7F4E42': 'Certificate Authority Reference',
  '7F4E65': 'Certificate Extensions', '7F60': 'Template, Biometric information', '8A': 'Authorisation Response Code (ARC)',
  '9B': 'Transaction Status Information (TSI)', '9D': 'Directory Definition File (DDF) Name', '9F01': 'Acquirer Identifier',
  '9F04': 'Amount, Other (Binary)', '9F05': 'Application Discretionary Data', '9F06': 'Application Identifier (AID), Terminal',
  '9F09': 'Application Version Number', '9F15': 'Merchant Category Code (MCC)', '9F16': 'Merchant Identifier',
  '9F18': 'Issuer Script Identifier', '9F19': 'Token Requestor ID', '9F1B': 'Terminal Floor Limit',
  '9F1C': 'Terminal Identification', '9F1D': 'Terminal Risk Management Data', '9F1E': 'Interface Device (IFD) Serial Number',
  '9F20': 'Track 2 Discretionary Data', '9F21': 'Transaction Time', '9F22': 'Public Key Index, Certification Authority, Terminal',
  '9F24': 'Payment Account Reference (PAR)', '9F25': 'Last 4 Digits of PAN', '9F29': 'Extended Selection',
  '9F2A': 'Kernel Identifier', '9F2D': 'Integrated Circuit Card (ICC) PIN Encipherment Public Key Certificate', '9F2E': 'Integrated Circuit Card (ICC) PIN Encipherment Public Key Exponent',
  '9F2F': 'Integrated Circuit Card (ICC) PIN Encipherment Public Key Remainder', '9F33': 'Terminal Capabilities', '9F34': 'Cardholder Verification Method (CVM) Results',
  '9F35': 'Terminal Type', '9F39': 'Point-of-Service (POS) Entry Mode', '9F3A': 'Amount, Reference Currency (Binary)',
  '9F3B': 'Currency Code, Application Reference', '9F3C': 'Currency Code, Transaction Reference', '9F3D': 'Currency Exponent, Transaction Reference',
  '9F40': 'Additional Terminal Capabilities', '9F41': 'Transaction Sequence Counter', '9F43': 'Currency Exponent, Application Reference',
  '9F5E': 'Consecutive Transaction International Upper Limit (CTIUL)', '9F5F': 'DS Slot Availability', '9F60': 'CVC3 (Track1)',
  '9F61': 'CVC3 (Track2)', '9F6A': 'Unpredictable Number (Numeric)', '9F7A': 'VLP Terminal Support Indicator',
  '9F7B': 'VLP Terminal Transaction Limit', '9F7C': 'Customer Exclusive Data (CED)', 'BF50': 'Visa Fleet - CDO',
  'BF60': 'Integrated Data Storage Record Update Template', 'C6': 'PIN Try Limit', 'C7': 'CDOL 1 Related Data Length',
  'C8': 'Card risk management country code', 'C9': 'Card risk management currency code', 'CB': 'Upper cumulative offline transaction amount',
  'CE': 'Card Issuer Action Code (PayPass) - Online', 'CF': 'Card Issuer Action Code (PayPass) - Decline', 'D1': 'Currency conversion table',
  'D3': 'Additional check table', 'D5': 'Application Control', 'D6': 'Default ARPC response code',
  'D7': 'Application Control (PayPass)', 'D9': 'AFL (PayPass)', 'DA': 'Static CVC3-TRACK1',
  'DB': 'Static CVC3-TRACK2', 'DC': 'IVCVC3-TRACK1', 'DD': 'IVCVC3-TRACK2',
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
