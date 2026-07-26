// Kripto öz-testi — aracın kendi kripto matematiğini karta ihtiyaç duymadan,
// BAĞIMSIZ referans vektörlere karşı doğrular. Bir ölçüm aletinin kalibrasyon
// sertifikası gibi: "bir kartta çalıştı" değil, "kanıtlanabilir biçimde doğru".
//
// kind='independent' → dış/yayınlanmış referans (NIST/klasik DES) veya kart
//   ground-truth (donanımın ürettiği ARQC) → GERÇEK doğruluk kanıtı.
// kind='regression'  → kendi-referans; yalnızca ileride bozulmayı yakalar.
//
// Kart-yer vektörleri EFEMER (işlem-başı) session key + terminal veri içerir;
// master anahtar veya PAN İÇERMEZ (güvenli olarak repo'da saklanabilir).
import { retailMac, kcv, tdesEcbEncrypt, computeArpc, computeArpcMethod2 } from './crypto3des.js';

const clean = (s) => (s || '').replace(/\s/g, '').toUpperCase();

const VECTORS = [
  // ── Blok şifre (3DES/DES) — yayınlanmış klasik DES bilinen-cevabı ──
  // DES(anahtar=0, blok=0) = 8CA64DE9C1B123A7 → 3DES-EDE(tüm-sıfır 16B) aynı değer.
  { name: '3DES-EDE · tüm-sıfır anahtar/blok', kind: 'independent', ref: 'NIST/klasik DES KAT',
    run: () => tdesEcbEncrypt('0'.repeat(32), '0'.repeat(16)), expect: '8CA64DE9C1B123A7' },
  { name: 'KCV · tüm-sıfır 3DES anahtar (ilk 3 bayt)', kind: 'independent', ref: 'NIST/klasik DES KAT',
    run: () => kcv('0'.repeat(32)), expect: '8CA64D' },

  // ── Retail MAC (ISO/IEC 9797-1 MAC Alg 3, pad Method 2) — kart ground-truth ──
  // Mastercard M/Chip kartının GENERATE AC'siyle ürettiği gerçek ARQC. Efemer
  // session key + terminal veri; retailMac tam ARQC'yi üretmeli.
  { name: 'Retail MAC (pad2) · Mastercard M/Chip ARQC', kind: 'independent', ref: 'kart ground-truth · Mastercard M/Chip',
    run: () => retailMac('AC8729D32A1C90E76D95A56FB0AD2957',
      '0000000010000000000000000792000000000009492607260012345678390001E9A0C243A2070C00000000000000FF00000000000000FF', 2),
    expect: '09CE06536A2E9E4D' },
  // Visa CVN 18 — EMV CSK session key + std+AIP+ATC+tam-IAD kompozisyonu (pad2).
  { name: 'Retail MAC (pad2) · Visa CVN 18 (CSK) ARQC', kind: 'independent', ref: 'kart ground-truth · Visa CVN 18',
    run: () => retailMac('B243AD24F74617C3E54A298D8139E50A',
      '00000000100000000000000007920000000000094926072600123456783900005B06011203A0A8030F04000000000000000000004E3B6B9A', 2),
    expect: '411B94ED0CA43228' },

  // ── ARPC — determinizm/regresyon çapası (aynı girdi → aynı çıktı) ──
  // Bağımsız değil (kendi-referans); kripto kodundaki ileride bozulmayı yakalar.
  { name: 'ARPC Method 1 (3DES · ARQC⊕ARC)', kind: 'regression', ref: 'kendi-referans (regresyon çapası)',
    run: () => computeArpc({ acKey: 'AC8729D32A1C90E76D95A56FB0AD2957', keyLevel: 'session', arqc: '09CE06536A2E9E4D', arc: '3030' }).arpc,
    expect: 'AFC33D616213F36C' },
  { name: 'ARPC Method 2 (Retail MAC · ARQC‖CSU)[:4]', kind: 'regression', ref: 'kendi-referans (regresyon çapası)',
    run: () => computeArpcMethod2({ acKey: 'AC8729D32A1C90E76D95A56FB0AD2957', keyLevel: 'session', arqc: '09CE06536A2E9E4D', csu: '03920000' }).arpc,
    expect: 'B74C265B' },
];

export function runSelfTest() {
  const results = VECTORS.map((v) => {
    let got = null, error = null;
    try { got = clean(v.run()); } catch (e) { error = e.message; }
    const ok = !error && got === clean(v.expect);
    return { name: v.name, kind: v.kind, ref: v.ref, expected: clean(v.expect), got, ok, error };
  });
  const passed = results.filter((r) => r.ok).length;
  const indep = results.filter((r) => r.kind === 'independent');
  return {
    total: results.length, passed, failed: results.length - passed,
    independent: { total: indep.length, passed: indep.filter((r) => r.ok).length },
    results,
  };
}
