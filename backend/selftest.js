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
import { aesCmac, deriveAcSessionKeyAes, ecosArqcAes } from './cryptoaes.js';
import { ecdsaVerifyP256, ecSdsaVerifyP256 } from './odaecc.js';

// Ecos Appendix B AC Input Data (Tablo 21, extended) — çözümlü örnek girdisi.
const ECOS_AC_INPUT = '00000001000000000000100008400000001080084015112400111111111B800001A080032420000000000000000000';

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

  // ── ECOS / Kernel 8 — modern kripto ilkelleri (AES + ECC), BAĞIMSIZ ──
  // AES-CMAC, AES ARQC/MAC'in çekirdeğidir; RFC 4493 dört-blok bilinen-cevabı.
  { name: 'AES-CMAC · RFC 4493 (64B)', kind: 'independent', ref: 'NIST SP800-38B / RFC 4493 KAT',
    run: () => aesCmac('2B7E151628AED2A6ABF7158809CF4F3C',
      '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'),
    expect: '51F0BEBF7E3B9D92FC49741779363CFE' },
  // ECDSA P-256, ECC ODA sertifika-zincirinin imza doğrulama çekirdeğidir.
  { name: 'ECDSA P-256 imza doğrulama · RFC 6979', kind: 'independent', ref: 'RFC 6979 A.2.5 (P-256/SHA-256 "sample")',
    run: () => String(ecdsaVerifyP256(
      '60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6',
      '7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299',
      'sample',
      'EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716',
      'F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8')),
    expect: 'true' },

  // ── ECOS AES ARQC — Mastercard'ın kendi çözümlü örnekleri (Appendix B), BAĞIMSIZ ──
  // Tam zincir MKAC→SKAC(EMV CSK AES)→AES-CMAC(AC Input). Karta/gizli anahtara gerek yok:
  // Mastercard dokümanının bilinen-cevap vektörü → GERÇEK doğruluk kanıtı.
  { name: 'Ecos AES-128 ARQC (MKAC→SKAC→CMAC)', kind: 'independent', ref: 'Mastercard Ecos v1.0 Appendix B',
    run: () => ecosArqcAes(deriveAcSessionKeyAes('2EF6E07ECBA86BCF3C3CFF7BBEBE6F38', '0001'), ECOS_AC_INPUT),
    expect: '25038F4A7BDE69E2' },
  { name: 'Ecos AES-256 ARQC (MKAC→SKAC→CMAC)', kind: 'independent', ref: 'Mastercard Ecos v1.0 Appendix B',
    run: () => ecosArqcAes(deriveAcSessionKeyAes('14D63F23982740AC65B482BAF5913092D8132BAA4143A24D3CF437232711A507', '0001'), ECOS_AC_INPUT),
    expect: '1847D8073E4D181D' },
  // Kernel 8 EDA MAC = AES-CMAC(SKi, 0000‖AC‖IAD-MAC)[:8]. SKi ECC/BDH'den gelir;
  // burada worked SKi + AC + IAD-MAC ile SKi tabanlı integrity MAC yolu kanıtlanır.
  { name: 'Ecos K8 EDA MAC (SKi · AES-CMAC)', kind: 'independent', ref: 'Mastercard Ecos v1.0 Appendix B (Kernel 8 txn)',
    run: () => aesCmac('642373F56192B09B132C7E024164D3A7', '00005C3319D5D8A4B2751D24D5CEE99FD2E1').slice(0, 16),
    expect: 'A4624217FDD8E4B1' },

  // ── ECOS ECC ODA — EC-SDSA (P-256 Schnorr) cert zinciri, Appendix B worked örnekleri ──
  // Ecos ECC sertifikaları ECDSA değil EC-SDSA kullanır. CA self-signed cert doğrulama
  // P-256 nokta aritmetiği + EC-SDSA'yı kanıtlar; Card cert Issuer PK ile → zincir.
  { name: 'EC-SDSA · Ecos CA ECC cert (P-256)', kind: 'independent', ref: 'Mastercard Ecos v1.0 Appendix B (ECC)',
    run: () => String(ecSdsaVerifyP256(
      'F60DAECD42B48FCCA547D942204D6098F1A353A5CD25CBDF2EC1ABFD0170E0FC',
      '6FD75EAAB356BE98BAA8E99A6FCE303F0C952BC02B4F566F096DD6EFF20C8FE8',
      '2000A000000004E010F60DAECD42B48FCCA547D942204D6098F1A353A5CD25CBDF2EC1ABFD0170E0FC',
      '7796E8770697859834F7E7B5E792EEB698882292E7F2B918C4BA37C9EC10CB89',
      '841639789B9221A744805DC4396365216C2219F71A0FFF078033BEAF149C0C6B')),
    expect: 'true' },
  { name: 'EC-SDSA · Ecos Card ECC cert (Issuer PK zinciri)', kind: 'independent', ref: 'Mastercard Ecos v1.0 Appendix B (ECC)',
    run: () => String(ecSdsaVerifyP256(
      'CD7400578B1164FEA954658C763C5A94FB3514FA89DB5B3B447AE8F4D5DF870A',
      '4CB6523AFD465E964F77A6DD5B67C79202E9B39892A8E9D45562D1100493D215',
      '140000202912312359987654321000010260D3FB0E45A5E64834880571152BE93E241D216D407F6F000C263B1CC87517AF43CA1837F6B4321CA70262902037EFCE790DC583828AEA628FFAAEFC08618658',
      '035824B9DD96765B97A0CC52C1B668B075ED86BE31DA1159C6F9128863B75A80',
      'BD863084A1C965C681AE72DF3B58A9CA8AEC8463DEF0A7FA35C0EE83A5269F65')),
    expect: 'true' },
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
