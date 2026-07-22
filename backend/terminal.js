// Terminal-side data for building a PDOL (contactless GPO) and AID fallback list.

// Base terminal data for building PDOL/CDOL. Merged with a per-request override
// object (a terminal profile) so the same card can be tested under different
// terminal conditions (amount, currency, txn type, capabilities → offline /
// online / decline outcomes). Only known keys from the override are applied.
export function terminalDefaults(overrides = {}) {
  const d = new Date();
  const yymmdd = `${String(d.getFullYear()).slice(2)}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`;
  const base = {
    '9F66': '37000000',       // TTQ — online + contactless capable
    '9F02': '000000001000',   // Amount, Authorised = 10.00
    '9F03': '000000000000',   // Amount, Other
    '9F1A': '0792',           // Terminal Country Code (Türkiye)
    '95': '0000000000',       // TVR
    '5F2A': '0949',           // Transaction Currency Code (TRY)
    '9A': yymmdd,             // Transaction Date
    '9C': '00',               // Transaction Type (purchase)
    '9F37': '12345678',       // Unpredictable Number
    '9F35': '22',             // Terminal Type
    '9F40': '0000000000',     // Additional Terminal Capabilities
    '9F1E': '3030303030303030', // IFD Serial Number
    '9F33': 'E0F8C8',         // Terminal Capabilities
    '9F4E': '00',
    // Enhanced Contactless Reader Capabilities (Amex ExpressPay). Amex requests 9F6E in
    // its PDOL and rejects an all-zero (no-capability) value with 6985 — advertise a
    // full EMV-contactless-capable reader instead.
    '9F6E': 'D8E00000',
  };
  const out = { ...base };
  for (const [k, v] of Object.entries(overrides || {})) {
    if (k in base && typeof v === 'string' && v.replace(/\s/g, '')) out[k] = v.replace(/\s/g, '').toUpperCase();
  }
  return out;
}

// User-editable terminal data elements (for the Terminal Profili UI). hint = byte
// length; group organises the form.
export const TERMINAL_FIELDS = [
  { tag: '9F02', label: 'Amount, Authorised', group: 'İşlem', bytes: 6 },
  { tag: '9F03', label: 'Amount, Other', group: 'İşlem', bytes: 6 },
  { tag: '5F2A', label: 'Transaction Currency', group: 'İşlem', bytes: 2 },
  { tag: '9C', label: 'Transaction Type', group: 'İşlem', bytes: 1 },
  { tag: '9F1A', label: 'Terminal Country', group: 'İşlem', bytes: 2 },
  { tag: '9F37', label: 'Unpredictable Number', group: 'İşlem', bytes: 4 },
  { tag: '9F66', label: 'TTQ (temassız)', group: 'Yetenek', bytes: 4 },
  { tag: '9F33', label: 'Terminal Capabilities', group: 'Yetenek', bytes: 3 },
  { tag: '9F40', label: 'Additional Term. Capabilities', group: 'Yetenek', bytes: 5 },
  { tag: '9F35', label: 'Terminal Type', group: 'Yetenek', bytes: 1 },
  { tag: '95', label: 'TVR', group: 'Yetenek', bytes: 5 },
  { tag: '9F6E', label: 'Enh. Contactless Capabilities', group: 'Yetenek', bytes: 4 },
];

// Scenario presets — a named terminal-profile override plus the card cryptogram
// decision expected (TC=offline approve, ARQC=online, AAC=decline). Used by the
// Terminal Profili quick-picks and the scenario runner.
// expect: beklenen kart kararı (TC/ARQC/AAC) VEYA 'observe' = kart-bağımlı, sonuç
// gözlemlenir (pass/fail yok). cat: L2/L3 senaryo grubu.
export const TERMINAL_PRESETS = [
  // ── Temel sonuç: online / offline / red ──
  { id: 'default', cat: 'Temel sonuç', name: 'Varsayılan (online, 10.00)', req: 'ARQC', expect: 'ARQC', over: {} },
  { id: 'online-high', cat: 'Temel sonuç', name: 'Online talebi (5000.00)', req: 'ARQC', expect: 'ARQC', over: { '9F02': '000000500000', '9F66': '37000000' } },
  { id: 'offline-low', cat: 'Temel sonuç', name: 'Offline onay talebi (1.00)', req: 'TC', expect: 'TC', over: { '9F02': '000000000100', '9F66': '36000000', '9F33': 'E0F0C8' } },
  { id: 'offline-only', cat: 'Temel sonuç', name: 'Offline-only terminal (TC)', req: 'TC', expect: 'TC', over: { '9F66': '20000000', '9F33': '206000', '9F02': '000000000100' } },
  { id: 'decline', cat: 'Temel sonuç', name: 'Red talebi (AAC)', req: 'AAC', expect: 'AAC', over: { '9F02': '000000002000' } },
  // ── İşlem tipi (9C) ──
  { id: 'cash', cat: 'İşlem tipi', name: 'Nakit çekim (cash advance)', req: 'ARQC', expect: 'ARQC', over: { '9C': '01', '9F02': '000000010000' } },
  { id: 'cashback', cat: 'İşlem tipi', name: 'Alışveriş + nakit (cashback)', req: 'ARQC', expect: 'ARQC', over: { '9C': '09', '9F02': '000000005000', '9F03': '000000002000' } },
  { id: 'refund', cat: 'İşlem tipi', name: 'İade (refund)', req: 'ARQC', expect: 'observe', over: { '9C': '20', '9F02': '000000003000' } },
  // ── Para birimi (5F2A / 9F1A) ──
  { id: 'usd', cat: 'Para birimi', name: 'USD (yabancı, online)', req: 'ARQC', expect: 'ARQC', over: { '5F2A': '0840', '9F1A': '0840' } },
  { id: 'eur', cat: 'Para birimi', name: 'EUR (yabancı, online)', req: 'ARQC', expect: 'ARQC', over: { '5F2A': '0978', '9F1A': '0978' } },
  { id: 'gbp', cat: 'Para birimi', name: 'GBP (yabancı)', req: 'ARQC', expect: 'observe', over: { '5F2A': '0826', '9F1A': '0826' } },
  // ── Sınır / risk ──
  { id: 'zero', cat: 'Sınır / risk', name: 'Sıfır tutar', req: 'ARQC', expect: 'observe', over: { '9F02': '000000000000' } },
  { id: 'very-high', cat: 'Sınır / risk', name: 'Çok yüksek tutar (50.000)', req: 'ARQC', expect: 'ARQC', over: { '9F02': '005000000000' } },
];

// Known scheme AIDs tried directly when PPSE/PSE list no applications.
export const CANDIDATE_AIDS = [
  ['Visa', 'A0000000031010'],
  ['Visa Electron', 'A0000000032010'],
  ['V PAY', 'A0000000032020'],
  ['Mastercard', 'A0000000041010'],
  ['Mastercard US', 'A0000000042203'],
  ['Maestro', 'A0000000043060'],
  ['American Express', 'A00000002501'],
  ['Troy', 'A0000006772020'],
  ['Troy', 'A0000006772010'],
  ['Troy (alt)', 'A0000006723010'],
  ['JCB', 'A0000000651010'],
  ['UnionPay', 'A000000333010101'],
];
