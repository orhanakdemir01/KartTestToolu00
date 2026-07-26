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
import { retailMac, kcv, tdesEcbEncrypt, computeArpc, computeArpcMethod2, deriveIccMasterKey, deriveSessionKey } from './crypto3des.js';

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

  // ── TAM ZİNCİR — anahtar-türetme dahil, BAĞIMSIZ (paymentcardtools CVN18) ──
  // Seçilen PUBLIC test IMK'sinden master→ICC(Option A)→CSK session→ARQC/ARPC tüm
  // zinciri, bağımsız bir referans hesaplayıcıya karşı doğrulanır. Böylece
  // deriveIccMasterKey + deriveSessionKey karta ihtiyaç duymadan kanıtlanır.
  { name: 'Tam zincir IMK→ICC(A)→CSK→ARQC · CVN18', kind: 'independent', ref: 'paymentcardtools CVN18 hesaplayıcı',
    run: () => retailMac(deriveSessionKey(deriveIccMasterKey('0123456789ABCDEFFEDCBA9876543210', '4111111111111111', '00'), '005B'),
      '000000001000' + '000000000000' + '0792' + '0000000000' + '0949' + '260726' + '00' + '12345678' + '3900' + '005B' + '06011203A0A8030F0400000000000000000000', 2),
    expect: 'FFEACC117CB15D62' },
  { name: 'Tam zincir → ARPC Method 2 · CVN18', kind: 'independent', ref: 'paymentcardtools CVN18 hesaplayıcı',
    run: () => computeArpcMethod2({ acKey: deriveSessionKey(deriveIccMasterKey('0123456789ABCDEFFEDCBA9876543210', '4111111111111111', '00'), '005B'), keyLevel: 'session', arqc: 'FFEACC117CB15D62', csu: '03920000' }).arpc,
    expect: '8DD58EF4' },

  // ── ARPC üretimi ──
  // Method 2 — Visa CVN18 kartının issuer-auth ile KABUL ETTİĞİ ARPC (diferansiyel
  // PASS: doğru ARPC→TC, bozuk→AAC). Kart, ARPC'mizin doğruluğunu TC dönerek
  // kanıtladı → BAĞIMSIZ (kart-doğrulamalı).
  { name: 'ARPC Method 2 (Retail MAC · ARQC‖CSU)[:4] · KART-KABUL', kind: 'independent', ref: 'kart-KABUL · Visa CVN18 issuer-auth (diferansiyel PASS/TC)',
    run: () => computeArpcMethod2({ acKey: 'DF1238237772774A3A7CC6249A05BA01', keyLevel: 'session', arqc: 'D1AB8E8109A4D56D', csu: '03920000' }).arpc,
    expect: '50E21C41' },
  // Method 1 — 3DES(SKac, ARQC⊕ARC). M1 kabul eden kart yok (Amex/EXTERNAL AUTH);
  // regresyon çapası — temel 3DES yukarıda bağımsız kanıtlı (transitif kapsam).
  { name: 'ARPC Method 1 (3DES · ARQC⊕ARC)', kind: 'regression', ref: 'kendi-referans · 3DES bağımsız kanıtlı (transitif)',
    run: () => computeArpc({ acKey: 'AC8729D32A1C90E76D95A56FB0AD2957', keyLevel: 'session', arqc: '09CE06536A2E9E4D', arc: '3030' }).arpc,
    expect: 'AFC33D616213F36C' },
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
