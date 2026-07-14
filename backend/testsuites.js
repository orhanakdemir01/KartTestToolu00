// Built-in test suites. Each step asserts an expected Status Word (with 'X'
// wildcard nibbles) and optionally that certain TLV tags appear in the response.
// expectedSw may also start with '!' to mean "anything except this".

export const BUILTIN_SUITES = [
  {
    id: 'emv-basic',
    name: 'EMV Temel Okuma Akışı',
    description: 'Temaslı EMV kartının PPSE → AID → GPO zincirini doğrular',
    steps: [
      { name: 'SELECT PPSE', command: '00 A4 04 00 0E 32 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00', expectedSw: '9000', expectTags: ['6F', '4F'] },
      { name: 'SELECT Visa AID', command: '00 A4 04 00 07 A0 00 00 00 03 10 10 00', expectedSw: '9000', expectTags: ['6F', '50'] },
      { name: 'GET PROCESSING OPTIONS', command: '80 A8 00 00 02 83 00 00', expectedSw: '9000' },
    ],
  },
  {
    id: 'negative',
    name: 'Negatif / Hata Davranışı',
    description: 'Geçersiz komutlara kartın doğru hata kodu döndürdüğünü doğrular',
    steps: [
      { name: 'Olmayan AID seçimi', command: '00 A4 04 00 07 A0 00 00 00 99 99 99 00', expectedSw: '6AXX' },
      { name: 'Desteklenmeyen INS', command: '00 FF 00 00 00', expectedSw: '6XXX' },
      { name: 'Desteklenmeyen CLA', command: 'FF CA 00 00 00', expectedSw: '6XXX' },
    ],
  },
  {
    id: 'iso-basic',
    name: 'ISO 7816 Temel Komutlar',
    description: 'Karta özgü olmayan standart ISO komutları',
    steps: [
      { name: 'GET CHALLENGE (8 bayt)', command: '00 84 00 00 08', expectedSw: '9000' },
      { name: 'GET CHALLENGE (tekrar)', command: '00 84 00 00 08', expectedSw: '9000' },
    ],
  },
];

// Match an actual SW against an expected pattern.
// 'X' = wildcard nibble; leading '!' = negation; empty = always pass.
export function swMatch(expected, actual) {
  if (!expected) return true;
  let e = expected.toUpperCase().replace(/\s/g, '');
  const a = (actual || '').toUpperCase();
  if (e.startsWith('!')) return !swMatch(e.slice(1), a);
  if (e.length !== a.length) return false;
  for (let i = 0; i < e.length; i++) {
    if (e[i] !== 'X' && e[i] !== a[i]) return false;
  }
  return true;
}
