// Personalisation compliance / certification rule engine. Runs a battery of
// machine-checkable requirements (EMV core + scheme-specific, e.g. Mastercard
// CPV) against an extracted card image and produces a structured PASS/FAIL
// report — the requirement layer a Barnes/Collis/UL/Perceval-style tool adds on
// top of raw data acquisition. Rules are pure functions over a card image, so
// they are deterministic and auditable.
import { luhnCheck, parseTrack2, parseAfl, countryName, currencyName, parseDol } from './emv.js';

const clean = (s) => (s || '').replace(/\s/g, '').toUpperCase();

// A Data Object List (PDOL/CDOL) is valid if it parses to ≥1 {tag,length}
// entries that consume exactly the whole buffer with no leftover bytes.
function validDol(hex) {
  const h = clean(hex);
  if (!h) return { ok: false, reason: 'boş' };
  let entries;
  try { entries = parseDol(h); } catch { return { ok: false, reason: 'çözümlenemedi' }; }
  if (!entries || !entries.length) return { ok: false, reason: 'girdi yok' };
  if (entries.some((e) => !e.length || e.length < 1)) return { ok: false, reason: 'sıfır uzunluk' };
  return { ok: true, entries, tags: entries.map((e) => e.tag.toUpperCase()) };
}

// Kart PAN'ini çıkar (5A dolgu-temizli, yoksa Track2'den). STR-04 ile aynı mantık.
const cardPan = (c) => c.val('5A') ? clean(c.val('5A')).replace(/F+$/, '') : (parseTrack2(c.val('57') || '')?.pan || null);

// PAN → majör IIN aralığına göre ödeme şeması (ISO/IEC 7812 · şema IIN blokları).
// Yalnızca yaygın/kesin bloklar; belirsiz eş-markalama aralıkları null döner.
function detectPanScheme(pan) {
  if (!pan || pan.length < 4) return null;
  const n2 = parseInt(pan.slice(0, 2), 10);
  const n4 = parseInt(pan.slice(0, 4), 10);
  if (pan[0] === '4') return 'Visa';
  if ((n2 >= 51 && n2 <= 55) || (n4 >= 2221 && n4 <= 2720)) return 'Mastercard';
  if (n2 === 34 || n2 === 37) return 'Amex';
  if (pan.startsWith('9792')) return 'Troy';
  if (pan.startsWith('6011') || n2 === 65 || (n4 >= 644 && n4 <= 649)) return 'Discover';
  if (n4 >= 3528 && n4 <= 3589) return 'JCB';
  if (n2 === 62 || n2 === 81) return 'UnionPay';
  return null;
}
// Şema başına kabul edilen PAN uzunlukları (ISO/IEC 7812; Amex 15, MC 16 kesin).
const PAN_LEN = { Visa: [13, 16, 19], Mastercard: [16], Amex: [15], Discover: [16, 19], JCB: [16, 17, 18, 19], UnionPay: [16, 17, 18, 19], Troy: [16] };
// YYMMDD (EMV n6) → bugünle kıyas için YYYYMMDD dizesi (2000+YY varsayımı).
const ymd6 = (v) => '20' + v;
const todayYmd = () => { const t = new Date(); return `${t.getFullYear()}${String(t.getMonth() + 1).padStart(2, '0')}${String(t.getDate()).padStart(2, '0')}`; };
// Sertifika son kullanma (MMYY, EMV Bk2) → geçerli mi (ayın sonuna kadar). 20YY varsayımı.
const certExpValid = (mmyy) => { if (!/^[0-9]{4}$/.test(mmyy || '')) return null; const cert = '20' + mmyy.slice(2, 4) + mmyy.slice(0, 2); const t = new Date(); const today = `${t.getFullYear()}${String(t.getMonth() + 1).padStart(2, '0')}`; return { mmyy, valid: cert >= today }; };

// AIP (82) byte-1 yetenek bitleri → etiketler (EMV Bk3 Ann. C1). Şemadan bağımsız.
function decodeAip(b1) {
  const f = [];
  if (b1 & 0x40) f.push('SDA'); if (b1 & 0x20) f.push('DDA');
  if (b1 & 0x10) f.push('CV'); if (b1 & 0x08) f.push('TRM');
  if (b1 & 0x04) f.push('IssuerAuth'); if (b1 & 0x02) f.push('OnDeviceCVM');
  if (b1 & 0x01) f.push('CDA');
  return f;
}
// Cryptogram Version Number (CVN) — şema+IAD'den çıkar ve BİLİNEN algoritmasını
// etiketle. Kaynak: EMV Bk2 §8.2 + Visa VIS (paymentcardtools CVN referansları).
// Yalnızca kesin bilinen CVN'ler etiketlenir; diğerleri ham raporlanır (uydurma yok).
const CVN_KNOWN = {
  // Visa VIS IAD: byte0=Length, byte1=DKI, byte2=CVN → hex offset 4:6.
  visa: { off: 4, map: {
    '0A': 'CVN 10 · UDK-direct session key · ARPC Method 1 · pad Method 1',
    '12': 'CVN 18 · CSK session key · ARPC Method 2 · pad Method 2',
    '16': 'CVN 22 · CSK session key · ARPC Method 2 · pad Method 2',
  } },
};
function cvnInfo(scheme, iad) {
  const cfg = CVN_KNOWN[(scheme || '').toLowerCase()];
  if (!cfg || !iad || iad.length < cfg.off + 2) return null;
  const cvn = iad.slice(cfg.off, cfg.off + 2).toUpperCase();
  return { cvn, label: cfg.map[cvn] || null };
}
// AUC (9F07) kullanım bitleri → etiketler (EMV Bk3 Ann. C2). Şemadan bağımsız.
function decodeAuc(hex) {
  const b1 = parseInt(hex.slice(0, 2), 16) || 0;
  const b2 = hex.length >= 4 ? (parseInt(hex.slice(2, 4), 16) || 0) : 0;
  const f = [];
  if (b1 & 0x80) f.push('yurtiçi nakit'); if (b1 & 0x40) f.push('yurtdışı nakit');
  if (b1 & 0x20) f.push('yurtiçi mal'); if (b1 & 0x10) f.push('yurtdışı mal');
  if (b1 & 0x08) f.push('yurtiçi hizmet'); if (b1 & 0x04) f.push('yurtdışı hizmet');
  if (b1 & 0x02) f.push('ATM'); if (b1 & 0x01) f.push('ATM-dışı terminal');
  if (b2 & 0x80) f.push('yurtiçi cashback'); if (b2 & 0x40) f.push('yurtdışı cashback');
  return { flags: f, b1, b2 };
}
// TVR/IAC (5 bayt) bit → koşul etiketi (EMV Bk3 Ann. C5). IAC'ler TVR formatındadır.
const TVR_BITS = [
  [0, 0x80, 'ODA yapılmadı'], [0, 0x40, 'SDA başarısız'], [0, 0x20, 'ICC verisi eksik'],
  [0, 0x10, 'exception file'], [0, 0x08, 'DDA başarısız'], [0, 0x04, 'CDA başarısız'], [0, 0x02, 'SDA seçildi'],
  [1, 0x80, 'sürüm uyuşmazlığı'], [1, 0x40, 'süresi dolmuş'], [1, 0x20, 'henüz geçerli değil'], [1, 0x10, 'servis izinli değil'], [1, 0x08, 'yeni kart'],
  [2, 0x80, 'CVM başarısız'], [2, 0x40, 'tanınmayan CVM'], [2, 0x20, 'PIN deneme aşıldı'], [2, 0x10, 'PIN pad yok'], [2, 0x08, 'PIN girilmedi'], [2, 0x04, 'online PIN'],
  [3, 0x80, 'floor limit aşıldı'], [3, 0x40, 'alt offline limit aşıldı'], [3, 0x20, 'üst offline limit aşıldı'], [3, 0x10, 'rastgele online'], [3, 0x08, 'merchant zorladı'],
  [4, 0x80, 'default TDOL'], [4, 0x40, 'issuer auth başarısız'], [4, 0x20, 'script öncesi hata'], [4, 0x10, 'script sonrası hata'],
];
function decodeTvr(hex) {
  if (!hex || hex.length < 10) return null;
  const b = []; for (let i = 0; i < 5; i++) b.push(parseInt(hex.slice(i * 2, i * 2 + 2), 16) || 0);
  return TVR_BITS.filter(([bi, m]) => b[bi] & m).map(([, , l]) => l);
}
// CVM List (8E) çözümü (EMV Bk3 §10.5). X(4B) + Y(4B) + (CVM Code, Condition) çiftleri.
const CVM_METHOD = { 0x00: 'CVM başarısız', 0x01: 'Plaintext offline PIN', 0x02: 'Enciphered online PIN', 0x03: 'Plaintext offline PIN + imza', 0x04: 'Enciphered offline PIN', 0x05: 'Enciphered offline PIN + imza', 0x1E: 'İmza', 0x1F: 'CVM gerekmez' };
const CVM_COND = { 0x00: 'her zaman', 0x01: 'unattended nakit', 0x02: 'nakit/cashback değilse', 0x03: 'terminal CVM destekliyorsa', 0x04: 'manuel nakit', 0x05: 'cashback', 0x06: '< X', 0x07: '≥ X', 0x08: '< Y', 0x09: '≥ Y' };
function decodeCvmList(hex) {
  if (!hex || hex.length < 20) return null;
  const rules = [];
  for (let i = 16; i + 4 <= hex.length; i += 4) {
    const code = parseInt(hex.slice(i, i + 2), 16), cond = parseInt(hex.slice(i + 2, i + 4), 16);
    rules.push({ method: CVM_METHOD[code & 0x3F] || `0x${(code & 0x3F).toString(16)}`, cond: CVM_COND[cond] || `0x${cond.toString(16)}`, cont: !!(code & 0x40) });
  }
  return { X: hex.slice(0, 8), Y: hex.slice(8, 16), rules };
}
// CTQ (9F6C) byte-1 bit → anlam. Visa qVSDC; tanımlar paymentcardtools'un yetkili
// 9F6C çözücüsünden alındı (uydurma değil). Byte-2 Visa'da tanımsız/RFU.
const CTQ_B1 = [
  [0x80, 'Online PIN gerekli'], [0x40, 'İmza gerekli'],
  [0x20, 'ODA başarısızsa online (reader online-yetenekli)'],
  [0x10, 'ODA başarısızsa arayüz değiştir (contact chip)'],
  [0x08, 'uygulama süresi dolmuşsa online'],
  [0x04, '(manuel) nakit için arayüz değiştir'],
  [0x02, 'cashback için arayüz değiştir'],
  [0x01, 'temassız ATM için geçersiz'],
];
const decodeCtq = (hex) => (!hex || hex.length < 2) ? null : CTQ_B1.filter(([m]) => (parseInt(hex.slice(0, 2), 16) || 0) & m).map(([, l]) => l);
// ISO/IEC 7813 Service Code (3 hane) → semantik. Hane1=interchange, hane2=auth, hane3=servis/PIN.
const SC1 = { '1': 'uluslararası', '2': 'uluslararası · chip', '5': 'ulusal', '6': 'ulusal · chip', '7': 'özel', '9': 'test' };
const SC2 = { '0': 'normal', '2': 'online (issuer)', '4': 'online (bilateral hariç)' };
const SC3 = { '0': 'kısıtsız · PIN gerekli', '1': 'kısıtsız', '2': 'yalnızca mal/hizmet', '3': 'yalnızca ATM · PIN', '4': 'yalnızca nakit', '5': 'mal/hizmet · PIN', '6': 'kısıtsız · varsa PIN', '7': 'mal/hizmet · varsa PIN' };

// Build a lookup context over one card image (aggregating tags across all apps).
// `crypto` (optional) = { oda, genac } from the live EMV flow, so rules can also
// verify offline auth cryptographically and inspect GENERATE AC output.
function buildContext(image, iface, crypto) {
  const apps = image?.applications || [];
  const primary = apps[0] || {};
  const tags = new Map(); // tag -> [{value, sources}]
  for (const a of apps) for (const t of (a.tags || [])) {
    const list = tags.get(t.tag) || [];
    list.push({ value: clean(t.value), sources: t.sources || [] });
    tags.set(t.tag, list);
  }
  const aip = clean(primary.aip || '');
  const aipB1 = aip.length >= 2 ? parseInt(aip.slice(0, 2), 16) : 0;
  const aipB2 = aip.length >= 4 ? parseInt(aip.slice(2, 4), 16) : 0;
  const oda = crypto?.oda || null;
  const dyns = oda ? (oda.dynamics && oda.dynamics.length ? oda.dynamics : (oda.dynamic ? [oda.dynamic] : [])) : [];
  return {
    iface, scheme: primary.scheme || null, aid: primary.aid || null,
    aip, aipB1, aipB2, afl: clean(primary.afl || ''),
    records: primary.records || [], tags,
    oda, genac: crypto?.genac || null, hasCrypto: !!crypto,
    dyn: (kind) => dyns.find((d) => d.kind === kind) || null,
    has: (t) => tags.has(t.toUpperCase()),
    val: (t) => (tags.get(t.toUpperCase()) || [])[0]?.value || null,
    vals: (t) => (tags.get(t.toUpperCase()) || []).map((x) => x.value),
    src: (t) => ((tags.get(t.toUpperCase()) || [])[0]?.sources || []).join(', '),
  };
}

const PASS = (evidence) => ({ status: 'pass', evidence });
const FAIL = (evidence, detail) => ({ status: 'fail', evidence, detail });
const WARN = (evidence, detail) => ({ status: 'warn', evidence, detail });
const NA = (detail) => ({ status: 'na', detail });

// Spec izlenebilirliği: her kuralın hangi otoriter belgeye dayandığı. Kategori
// başına varsayılan; bir kural kendi `spec` alanıyla override edebilir. Amaç:
// rakip araçların kapalı-kutu kurallarının aksine her verdikt kaynağa izlenebilir.
// (Bk = EMV Book: Bk1 ICC-Terminal, Bk2 Security, Bk3 App Spec, Bk4 Terminal.)
const CAT_SPEC = {
  'Yapı': 'EMV Bk3 · Data Elements (Ann. A)',
  'AFL/Kayıt': 'EMV Bk3 · §10.2 (AFL/READ RECORD)',
  'ODA': 'EMV Bk2 · §5-7 (Offline Data Auth)',
  'CVM': 'EMV Bk3 · §10.5 (CVM List 8E)',
  'Kullanım Kontrolü (AUC)': 'EMV Bk3 · Ann. A (AUC/yerel)',
  'DOL/FCI': 'EMV Bk1 §11.3 (FCI) · Bk3 §5.4 (DOL)',
  'Veri Formatı': 'EMV Bk3 · Ann. A (veri öğesi format/uzunluk)',
  'Kart Veri Bütünlüğü': 'ISO/IEC 7812 · 7813 (PAN/IIN/tarih bütünlüğü)',
  'Bit Alanı Kodlama': 'EMV Bk3 · Ann. C1/C2 (AIP/AUC bit alanları)',
  'Tutarlılık': 'EMV Bk3 · Çapraz-alan tutarlılık',
  'Mastercard CPV': 'M/Chip Requirements · CPV',
  'Visa VIS/qVSDC': 'Visa VIS 1.6 · VCPS 2.x (qVSDC)',
  'Amex': 'Amex AEIPS 3.x',
  'Discover D-PAS': 'Discover D-PAS 1.x',
  'Troy D-PAS': 'Troy D-PAS',
  'JCB': 'JCB J/Smart',
  'UnionPay': 'UnionPay UICS · PBOC 3.0',
  'Temassız Kernel': 'EMVCo Book C-2…C-8 (Kernel)',
  'ODA Kripto': 'EMV Bk2 · §6 (RSA/SDAD)',
  'Kriptogram Sürümü (CVN)': 'EMV Bk2 · §8.2 · Visa VIS (CVN)',
  'İşlem Aksiyon Analizi': 'EMV Bk3 · §10.7 (Terminal Action Analysis)',
};

// EMVCo temassız kernel eşlemesi (şema → kernel numarası). Book C-2..C-8.
const KERNEL = {
  Visa: 'K3 (payWave / qVSDC)',
  Mastercard: 'K2 (PayPass / M-Chip)',
  Amex: 'K4 (ExpressPay)',
  JCB: 'K5 (J/Speedy)',
  Discover: 'K6 (D-PAS)',
  UnionPay: 'K7 (QuickPass)',
};
const kernelName = (scheme) => KERNEL[scheme] || null;

// A rule: { id, cat, req, sev(M/R/C), scheme?, iface?, spec?, run(ctx) -> {status,...} }
const RULES = [
  // ── Yapı / zorunlu alanlar ─────────────────────────────────────────────
  { id: 'STR-01', cat: 'Yapı', sev: 'M', req: 'Uygulama PAN mevcut (Track2 57 veya 5A)',
    run: (c) => (c.has('57') || c.has('5A')) ? PASS(c.has('57') ? 'tag 57' : 'tag 5A') : FAIL('—', 'Ne 57 ne 5A bulundu') },
  { id: 'STR-02', cat: 'Yapı', sev: 'M', req: 'Uygulama son kullanma tarihi (5F24) mevcut ve YYMMDD',
    run: (c) => { const v = c.val('5F24'); if (!v) return FAIL('—', '5F24 yok'); return /^[0-9]{6}$/.test(v) ? PASS(v) : FAIL(v, 'YYMMDD (6 hane) değil'); } },
  { id: 'STR-03', cat: 'Yapı', sev: 'C', req: 'Track2 (57) PAN ile tag 5A PAN tutarlı',
    run: (c) => { const t2 = c.val('57'), p = c.val('5A'); if (!t2 || !p) return NA('İki alan birden yok'); const tr = parseTrack2(t2); const pan5a = clean(p).replace(/F+$/, ''); return tr && tr.pan === pan5a ? PASS(tr.pan) : FAIL(`57=${tr?.pan} 5A=${pan5a}`, 'PAN uyuşmuyor'); } },
  { id: 'STR-04', cat: 'Yapı', sev: 'M', req: 'PAN Luhn kontrolünden geçer',
    run: (c) => { const p = c.val('5A') ? clean(c.val('5A')).replace(/F+$/, '') : (parseTrack2(c.val('57') || '')?.pan); if (!p) return NA('PAN yok'); return luhnCheck(p) ? PASS(p) : FAIL(p, 'Luhn hatalı'); } },
  { id: 'STR-05', cat: 'Yapı', sev: 'M', req: 'AIP (82) mevcut', run: (c) => c.aip ? PASS(c.aip) : FAIL('—') },
  { id: 'STR-06', cat: 'Yapı', sev: 'M', req: 'AFL (94) mevcut', run: (c) => c.afl ? PASS(c.afl) : (c.iface === 'contactless' && c.aip ? WARN('—', 'Temassız: GPO AIP döndürdü, AFL yok — kernel GPO-tabanlı akışı destekler') : FAIL('—')) },
  { id: 'STR-07', cat: 'Yapı', sev: 'M', req: 'CVM List (8E) mevcut', run: (c) => c.has('8E') ? PASS(c.val('8E').slice(0, 20) + '…') : (c.iface === 'contactless' ? WARN('—', 'Temassız: CVM List (8E) yok — kernel CVM (CTQ/CDCVM) kullanılır') : FAIL('—')) },
  { id: 'STR-08', cat: 'Yapı', sev: 'M', req: 'CDOL1 (8C) mevcut', iface: 'contact', run: (c) => c.has('8C') ? PASS(c.val('8C')) : FAIL('—') },
  { id: 'STR-09', cat: 'Yapı', sev: 'M', req: 'CDOL2 (8D) mevcut', iface: 'contact', run: (c) => c.has('8D') ? PASS(c.val('8D')) : FAIL('—') },
  { id: 'STR-10', cat: 'Yapı', sev: 'R', req: 'PAN Sequence Number (5F34) mevcut', run: (c) => c.has('5F34') ? PASS(c.val('5F34')) : WARN('—', 'PSN önerilir') },
  { id: 'STR-11', cat: 'Yapı', sev: 'R', req: 'Cardholder Name (5F20) mevcut', run: (c) => c.has('5F20') ? PASS(c.val('5F20')) : WARN('—') },
  { id: 'STR-12', cat: 'Yapı', sev: 'R', spec: 'EMV Bk1 · tag 87 (API)', req: 'Application Priority Indicator (87) mevcut',
    run: (c) => c.has('87') ? PASS(c.val('87')) : WARN('—', 'API önerilir') },
  { id: 'STR-13', cat: 'Yapı', sev: 'R', spec: 'EMV Bk1 · tag 50/9F12', req: 'Application Label (50) veya Preferred Name (9F12) mevcut',
    run: (c) => (c.has('50') || c.has('9F12')) ? PASS(c.has('50') ? `50=${c.val('50')}` : `9F12=${c.val('9F12')}`) : WARN('—', 'Uygulama adı önerilir') },

  // ── AFL / kayıt bütünlüğü ─────────────────────────────────────────────
  { id: 'AFL-01', cat: 'AFL/Kayıt', sev: 'M', req: 'AFL geçerli formatta (4-baytın katı)',
    run: (c) => { if (!c.afl) return c.iface === 'contactless' ? NA('Temassız: AFL yok (GPO-tabanlı akış)') : FAIL('—'); return c.afl.length % 8 === 0 ? PASS(`${c.afl.length / 8} girdi`) : FAIL(c.afl, '4 baytın katı değil'); } },
  { id: 'AFL-02', cat: 'AFL/Kayıt', sev: 'M', req: "AFL'nin işaret ettiği tüm kayıtlar okundu",
    run: (c) => { if (!c.afl) return NA('AFL yok'); const entries = parseAfl(c.afl); let need = 0; for (const e of entries) need += (e.lastRecord - e.firstRecord + 1); const got = c.records.length; return got >= need ? PASS(`${got}/${need} kayıt`) : FAIL(`${got}/${need}`, 'Eksik kayıt'); } },
  { id: 'AFL-03', cat: 'AFL/Kayıt', sev: 'M', req: 'AFL girdileri geçerli (SFI 1-30, 1 ≤ ilk ≤ son kayıt)',
    run: (c) => { if (!c.afl) return NA('AFL yok'); const es = parseAfl(c.afl); if (!es.length) return FAIL(c.afl, 'AFL çözümlenemedi'); const bad = es.filter((e) => e.sfi < 1 || e.sfi > 30 || e.firstRecord < 1 || e.firstRecord > e.lastRecord); return bad.length ? FAIL(bad.map((e) => `SFI${e.sfi} ${e.firstRecord}-${e.lastRecord}`).join(', '), 'Geçersiz SFI/kayıt aralığı') : PASS(`${es.length} girdi · SFI ${[...new Set(es.map((e) => e.sfi))].join(',')}`); } },

  // ── Offline Data Authentication tutarlılığı (AIP ↔ sertifika tag'leri) ──
  { id: 'ODA-01', cat: 'ODA', sev: 'M', req: 'AIP en az bir ODA yöntemi bildiriyor (SDA/DDA/CDA)',
    run: (c) => { const any = (c.aipB1 & 0x40) || (c.aipB1 & 0x20) || (c.aipB1 & 0x01); return any ? PASS(`SDA:${!!(c.aipB1 & 0x40)} DDA:${!!(c.aipB1 & 0x20)} CDA:${!!(c.aipB1 & 0x01)}`) : WARN(c.aip, 'Hiç ODA yöntemi yok'); } },
  { id: 'ODA-02', cat: 'ODA', sev: 'M', req: 'DDA/CDA destekleniyorsa CA PK Index (8F) mevcut',
    run: (c) => { const need = (c.aipB1 & 0x20) || (c.aipB1 & 0x01); if (!need) return NA('DDA/CDA yok'); return c.has('8F') ? PASS(`8F=${c.val('8F')}`) : FAIL('—', 'DDA/CDA var ama 8F yok'); } },
  { id: 'ODA-03', cat: 'ODA', sev: 'M', req: 'DDA/CDA/SDA destekleniyorsa Issuer PK Cert (90) mevcut',
    run: (c) => { const need = (c.aipB1 & 0x60) || (c.aipB1 & 0x01); if (!need) return NA('ODA yok'); return c.has('90') ? PASS('tag 90') : FAIL('—', 'Issuer PK Cert yok'); } },
  { id: 'ODA-04', cat: 'ODA', sev: 'M', req: 'DDA/CDA destekleniyorsa ICC PK Cert (9F46) + Exp (9F47) mevcut',
    run: (c) => { const need = (c.aipB1 & 0x20) || (c.aipB1 & 0x01); if (!need) return NA('DDA/CDA yok'); const ok = c.has('9F46') && c.has('9F47'); return ok ? PASS('9F46 + 9F47') : FAIL(`9F46:${c.has('9F46')} 9F47:${c.has('9F47')}`, 'ICC PK sertifika alanları eksik'); } },
  { id: 'ODA-05', cat: 'ODA', sev: 'M', req: 'Issuer PK Exponent (9F32) mevcut (ODA varsa)',
    run: (c) => { const need = (c.aipB1 & 0x60) || (c.aipB1 & 0x01); if (!need) return NA('ODA yok'); return c.has('9F32') ? PASS(`9F32=${c.val('9F32')}`) : FAIL('—'); } },
  { id: 'ODA-06', cat: 'ODA', sev: 'C', req: 'SDA destekleniyorsa Signed Static App Data (93) mevcut',
    run: (c) => { if (!(c.aipB1 & 0x40)) return NA('SDA yok'); return c.has('93') ? PASS('tag 93') : WARN('—', 'SDA bildirildi ama 93 yok'); } },
  { id: 'ODA-07', cat: 'ODA', sev: 'C', spec: 'EMV Bk3 · tag 9F4A (SDA Tag List)', req: 'SDA destekleniyorsa SDA Tag List (9F4A) mevcut',
    run: (c) => { if (!(c.aipB1 & 0x40)) return NA('SDA yok'); return c.has('9F4A') ? PASS(c.val('9F4A')) : WARN('—', 'SDA var ama 9F4A yok'); } },
  // Sertifika-zinciri YAPI doğrulaması (uzunluk/remainder ilişkileri, EMV Bk2 §6).
  // NCA=len(90), NI=len(9F46) statik; NIC recovered ICC cert'ten. Overhead: Issuer 36, ICC 42 bayt.
  { id: 'ODA-08', cat: 'ODA', sev: 'M', spec: 'EMV Bk2 · §6.3 (NI ≤ NCA)', req: 'Issuer PK modülüs uzunluğu (9F46) ≤ CA PK modülüs uzunluğu (90)',
    run: (c) => { const c90 = c.val('90'), c46 = c.val('9F46'); if (!c90 || !c46) return NA('90/9F46 yok'); const nca = c90.length / 2, ni = c46.length / 2; return ni <= nca ? PASS(`NI=${ni} ≤ NCA=${nca} bayt`) : FAIL(`NI=${ni} NCA=${nca}`, 'Issuer anahtarı CA anahtarından büyük — EMV ihlali'); } },
  { id: 'ODA-09', cat: 'ODA', sev: 'C', spec: 'EMV Bk2 · §6.3 (Issuer PK Remainder 92)', req: 'Issuer PK Remainder (92) yalnızca NI > NCA−36 iken ve doğru uzunlukta',
    run: (c) => { const c90 = c.val('90'), c46 = c.val('9F46'); if (!c90 || !c46) return NA('90/9F46 yok'); const nca = c90.length / 2, ni = c46.length / 2; const carried = nca - 36; const need = ni > carried; const rem = c.val('92'); const remLen = rem ? rem.length / 2 : 0; if (need) { const want = ni - carried; return (rem && remLen === want) ? PASS(`92 var · ${remLen}B (=${want})`) : FAIL(`92:${rem ? remLen + 'B' : 'yok'} beklenen ${want}B`, 'Issuer PK Remainder eksik/yanlış uzunlukta'); } return rem ? WARN(`92 var (${remLen}B)`, 'NI ≤ NCA−36 iken Remainder gereksiz') : PASS('92 gerekmiyor (NI sığıyor)'); } },
  { id: 'ODA-10', cat: 'ODA', sev: 'C', spec: 'EMV Bk2 · §6.4 (ICC PK Remainder 9F48)', req: 'ICC PK Remainder (9F48) yalnızca NIC > NI−42 iken ve doğru uzunlukta',
    run: (c) => { if (!c.hasCrypto) return NA('Kripto akışı yok'); const rec = c.oda?.iccPK?.recovered; const c46 = c.val('9F46'); if (!rec || rec.length < 40 || rec.slice(0, 2).toUpperCase() !== '6A' || !c46) return NA('ICC PK recovered/9F46 yok'); const ni = c46.length / 2; const nic = parseInt(rec.slice(38, 40), 16); const carried = ni - 42; const need = nic > carried; const rem = c.val('9F48'); const remLen = rem ? rem.length / 2 : 0; if (need) { const want = nic - carried; return (rem && remLen === want) ? PASS(`9F48 var · ${remLen}B (=${want})`) : FAIL(`9F48:${rem ? remLen + 'B' : 'yok'} beklenen ${want}B`, 'ICC PK Remainder eksik/yanlış uzunlukta'); } return rem ? WARN(`9F48 var (${remLen}B)`, 'NIC ≤ NI−42 iken Remainder gereksiz') : PASS(`9F48 gerekmiyor (NIC=${nic} sığıyor)`); } },
  { id: 'ODA-11', cat: 'ODA', sev: 'R', spec: 'EMV Bk2 · Ann. B (RSA anahtar boyu)', req: 'CA/Issuer modülüs uzunlukları EMV RSA aralığında (1024–1984 bit)',
    run: (c) => { const c90 = c.val('90'); if (!c90) return NA('90 yok'); const bits = c90.length / 2 * 8; const c46 = c.val('9F46'); const niInfo = c46 ? ` · NI=${c46.length / 2 * 8}bit` : ''; return (bits >= 1024 && bits <= 1984) ? PASS(`NCA=${bits}bit${niInfo}`) : WARN(`${bits}bit`, 'CA modülüs EMV aralığı (1024–1984) dışında'); } },

  // ── CVM ───────────────────────────────────────────────────────────────
  { id: 'CVM-01', cat: 'CVM', sev: 'M', req: 'CVM List (8E) format: ≥10 bayt ve (uzunluk-8) çift',
    run: (c) => { const v = c.val('8E'); if (!v) return NA('8E yok'); const n = v.length / 2; return (n >= 10 && (n - 8) % 2 === 0) ? PASS(`${n} bayt, ${(n - 8) / 2} kural`) : FAIL(`${n} bayt`, 'Format hatalı'); } },
  { id: 'CVM-02', cat: 'CVM', sev: 'R', req: 'CVM için X/Y ikincil tutar alanları (8E ilk 8 bayt)',
    run: (c) => { const v = c.val('8E'); if (!v) return NA('8E yok'); return v.length >= 16 ? PASS(`X=${v.slice(0, 8)} Y=${v.slice(8, 16)}`) : FAIL(v, 'X/Y eksik'); } },
  { id: 'CVM-03', cat: 'CVM', sev: 'R', req: 'CVM List (8E) kuralları tanınan CVM kodu içerir (method düşük 6 bit)',
    run: (c) => { const v = c.val('8E'); if (!v) return NA('8E yok'); const rules = v.slice(16); if (rules.length < 4) return WARN('—', 'CVM kuralı yok'); const known = new Set([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x1E, 0x1F]); const codes = []; for (let i = 0; i + 4 <= rules.length; i += 4) codes.push(parseInt(rules.slice(i, i + 2), 16) & 0x3F); const bad = codes.filter((m) => !known.has(m)); return bad.length ? WARN(`bilinmeyen: ${bad.map((m) => '0x' + m.toString(16)).join(',')}`, 'Tanınmayan CVM method kodu (RFU)') : PASS(`${codes.length} kural · ${[...new Set(codes)].map((m) => '0x' + m.toString(16).padStart(2, '0')).join(' ')}`); } },
  { id: 'CVM-04', cat: 'CVM', sev: 'R', spec: 'EMV Bk3 · §10.5 (CVM koşul kodları)', req: 'CVM kural koşul kodları geçerli aralıkta (0x00–0x09; ≥0x80 şema-özel)',
    run: (c) => { const v = c.val('8E'); if (!v) return NA('8E yok'); const rules = v.slice(16); if (rules.length < 4) return NA('CVM kuralı yok'); const conds = []; for (let i = 0; i + 4 <= rules.length; i += 4) conds.push(parseInt(rules.slice(i + 2, i + 4), 16)); const rfu = conds.filter((x) => x > 0x09 && x < 0x80); return rfu.length ? WARN(`RFU: ${rfu.map((x) => '0x' + x.toString(16)).join(',')}`, 'Tanımsız (RFU) CVM koşul kodu') : PASS(`${conds.length} koşul · ${[...new Set(conds)].map((x) => '0x' + x.toString(16).padStart(2, '0')).join(' ')}`); } },
  { id: 'CVM-05', cat: 'CVM', sev: 'C', spec: 'EMV Bk2 · §7.1 (Enciphered Offline PIN)', req: 'Şifreli offline PIN CVM (0x04/0x05) ⇒ ICC PIN Şifreleme PK (9F2D) veya ICC PK (9F46) mevcut',
    run: (c) => { const v = c.val('8E'); if (!v) return NA('8E yok'); const rules = v.slice(16); const methods = []; for (let i = 0; i + 4 <= rules.length; i += 4) methods.push(parseInt(rules.slice(i, i + 2), 16) & 0x3F); const encPin = methods.some((m) => m === 0x04 || m === 0x05); if (!encPin) return NA('Şifreli offline PIN CVM yok'); const ok = c.has('9F2D') || c.has('9F46'); return ok ? PASS(c.has('9F2D') ? 'ICC PIN Enc PK (9F2D)' : 'ICC PK (9F46) ile') : FAIL('—', 'Şifreli offline PIN var ama ne 9F2D ne 9F46 mevcut'); } },
  { id: 'CVM-06', cat: 'CVM', sev: 'R', spec: 'EMV Bk3 · §10.5 (CVM List çözümü)', req: 'CVM List (8E) kuralları insan-okunur çözümlenir',
    run: (c) => { const v = c.val('8E'); if (!v) return NA('8E yok'); const d = decodeCvmList(v); if (!d || !d.rules.length) return WARN(v, 'CVM kuralı çözülemedi'); return PASS(d.rules.map((r) => `${r.method} [${r.cond}]${r.cont ? ' →devam' : ''}`).join(' · ')); } },

  // ── Kullanım kontrolü / yerel veri ─────────────────────────────────────
  { id: 'USE-01', cat: 'Kullanım Kontrolü (AUC)', sev: 'R', req: 'Application Usage Control (9F07) mevcut',
    run: (c) => c.has('9F07') ? PASS(c.val('9F07')) : WARN('—', 'AUC önerilir') },
  { id: 'USE-02', cat: 'Kullanım Kontrolü (AUC)', sev: 'C', req: 'Issuer Country Code (5F28) geçerli ISO 3166 numerik',
    run: (c) => { const v = c.val('5F28'); if (!v) return NA('5F28 yok'); return countryName(v) ? PASS(`${v} (${countryName(v)})`) : FAIL(v, 'Geçersiz ülke kodu'); } },
  { id: 'USE-03', cat: 'Kullanım Kontrolü (AUC)', sev: 'C', req: 'Application Currency Code (9F42) geçerli ISO 4217',
    run: (c) => { const v = c.val('9F42'); if (!v) return NA('9F42 yok'); return currencyName(v) ? PASS(`${v} (${currencyName(v)})`) : FAIL(v, 'Geçersiz para birimi'); } },
  { id: 'USE-04', cat: 'Kullanım Kontrolü (AUC)', sev: 'R', req: 'Language Preference (5F2D) mevcut',
    run: (c) => c.has('5F2D') ? PASS(c.val('5F2D')) : WARN('—') },
  { id: 'USE-05', cat: 'Kullanım Kontrolü (AUC)', sev: 'R', spec: 'EMV Bk3 · Ann. A tag 5F25', req: 'Application Effective Date (5F25) varsa geçerli YYMMDD',
    run: (c) => { const v = c.val('5F25'); if (!v) return WARN('—', '5F25 önerilir'); return /^[0-9]{6}$/.test(v) ? PASS(v) : FAIL(v, 'YYMMDD değil'); } },

  // ── DOL / FCI yapısı ───────────────────────────────────────────────────
  { id: 'FCI-01', cat: 'DOL/FCI', sev: 'M', req: 'DF Name (84) seçilen AID ile eşleşir',
    run: (c) => { const dn = c.val('84'); if (!dn) return NA('84 yok'); if (!c.aid) return NA('AID yok'); return (c.aid === dn || c.aid.startsWith(dn) || dn.startsWith(c.aid)) ? PASS(dn) : FAIL(`84=${dn} AID=${c.aid}`, 'DF Name ≠ AID'); } },
  { id: 'DOL-01', cat: 'DOL/FCI', sev: 'M', iface: 'contact', req: 'CDOL1 (8C) geçerli DOL ve Amount (9F02) + UN (9F37) içerir',
    run: (c) => { const v = c.val('8C'); if (!v) return NA('8C yok'); const d = validDol(v); if (!d.ok) return FAIL(v.slice(0, 20), 'Geçersiz DOL: ' + d.reason); const miss = ['9F02', '9F37'].filter((t) => !d.tags.includes(t)); return miss.length ? FAIL(`eksik: ${miss.join(',')}`, 'Zorunlu CDOL1 tag eksik') : PASS(`${d.entries.length} tag`); } },
  { id: 'DOL-02', cat: 'DOL/FCI', sev: 'M', iface: 'contact', req: 'CDOL2 (8D) geçerli DOL formatında',
    run: (c) => { const v = c.val('8D'); if (!v) return NA('8D yok'); const d = validDol(v); return d.ok ? PASS(`${d.entries.length} tag`) : FAIL(v.slice(0, 20), 'Geçersiz DOL: ' + d.reason); } },
  { id: 'DOL-03', cat: 'DOL/FCI', sev: 'C', req: 'PDOL (9F38) varsa geçerli DOL formatında',
    run: (c) => { const v = c.val('9F38'); if (!v) return NA('9F38 yok'); const d = validDol(v); return d.ok ? PASS(`${d.entries.length} tag`) : FAIL(v.slice(0, 20), 'Geçersiz DOL: ' + d.reason); } },
  { id: 'IAD-01', cat: 'DOL/FCI', sev: 'R', req: 'Issuer Application Data (9F10) makul uzunlukta (≥ 7 bayt)',
    run: (c) => { const v = c.val('9F10') || c.genac?.iad; if (!v) return NA('9F10 yok'); const n = v.length / 2; return n >= 7 ? PASS(`${n} bayt`) : WARN(`${n} bayt`, 'IAD kısa görünüyor'); } },
  { id: 'DOL-04', cat: 'DOL/FCI', sev: 'C', spec: 'EMV Bk3 · tag 9F49 (DDOL)', req: 'DDOL (9F49) varsa geçerli DOL ve UN (9F37) içerir',
    run: (c) => { const v = c.val('9F49'); if (!v) return (c.aipB1 & 0x20) ? PASS('DDOL yok — varsayılan (9F37) kullanılır') : NA('9F49 yok'); const d = validDol(v); if (!d.ok) return FAIL(v.slice(0, 20), 'Geçersiz DOL: ' + d.reason); return d.tags.includes('9F37') ? PASS(`${d.entries.length} tag · 9F37 (UN) içeriyor`) : WARN(`${d.entries.length} tag`, 'DDOL 9F37 (UN) içermiyor — DDA replay riski'); } },
  { id: 'DOL-05', cat: 'DOL/FCI', sev: 'C', spec: 'EMV Bk3 · tag 97 (TDOL)', req: 'TDOL (97) varsa geçerli DOL formatında',
    run: (c) => { const v = c.val('97'); if (!v) return NA('97 yok'); const d = validDol(v); return d.ok ? PASS(`${d.entries.length} tag`) : FAIL(v.slice(0, 20), 'Geçersiz DOL: ' + d.reason); } },
  { id: 'FCI-02', cat: 'DOL/FCI', sev: 'C', spec: 'EMV Bk1 · 9F12 ↔ 9F11', req: 'Application Preferred Name (9F12) varsa Issuer Code Table Index (9F11) mevcut',
    run: (c) => { if (!c.has('9F12')) return NA('9F12 yok'); return c.has('9F11') ? PASS(`9F11=${c.val('9F11')} (kod tablosu)`) : WARN('—', 'Preferred Name var ama Issuer Code Table Index (9F11) yok — gösterim kod tablosu belirsiz'); } },
  { id: 'DOL-06', cat: 'DOL/FCI', sev: 'C', iface: 'contact', spec: 'EMV Bk3 · CDOL1 kripto alanları', req: 'CDOL1 (8C) standart ARQC veri alanlarını içerir (9F02·9F1A·95·5F2A·9A·9C·9F37)',
    run: (c) => { const v = c.val('8C'); if (!v) return NA('8C yok'); const d = validDol(v); if (!d.ok) return FAIL(v.slice(0, 20), 'Geçersiz DOL: ' + d.reason); const need = ['9F02', '9F1A', '95', '5F2A', '9A', '9C', '9F37']; const miss = need.filter((t) => !d.tags.includes(t)); return miss.length ? WARN(`eksik: ${miss.join(',')}`, 'CDOL1 bazı standart ARQC alanlarını istemiyor — terminal varsayılanı devreye girer') : PASS('tüm standart ARQC alanları mevcut'); } },

  // ── Veri öğesi format / uzunluk (EMV Ann. A — kesin uzunluk & kodlama) ──
  { id: 'FMT-01', cat: 'Veri Formatı', sev: 'M', req: 'Application Version Number (9F08) tam 2 bayt',
    run: (c) => { const v = c.val('9F08'); if (!v) return NA('9F08 yok'); return v.length === 4 ? PASS(v) : FAIL(v, `${v.length / 2} bayt (2 olmalı)`); } },
  { id: 'FMT-02', cat: 'Veri Formatı', sev: 'C', req: 'Application Usage Control (9F07) varsa tam 2 bayt',
    run: (c) => { const v = c.val('9F07'); if (!v) return NA('9F07 yok'); return v.length === 4 ? PASS(v) : FAIL(v, `${v.length / 2} bayt (2 olmalı)`); } },
  { id: 'FMT-03', cat: 'Veri Formatı', sev: 'C', req: 'Application Currency Exponent (9F44) varsa 1 bayt ve ≤ 4',
    run: (c) => { const v = c.val('9F44'); if (!v) return NA('9F44 yok'); if (v.length !== 2) return FAIL(v, '1 bayt olmalı'); const n = parseInt(v, 16); return n <= 4 ? PASS(`üs=${n}`) : WARN(`üs=${n}`, 'Olağandışı para birimi üssü (>4)'); } },
  { id: 'FMT-04', cat: 'Veri Formatı', sev: 'C', spec: 'EMV Bk3 · §10.3 (SDA Tag List yalnızca 82)', req: 'SDA Tag List (9F4A) yalnızca AIP tag’ini (82) içerir',
    run: (c) => { const v = c.val('9F4A'); if (!v) return NA('9F4A yok'); return v.toUpperCase() === '82' ? PASS('82 (AIP)') : FAIL(v, 'EMV: SDA Tag List yalnızca 82 içerebilir'); } },
  { id: 'FMT-05', cat: 'Veri Formatı', sev: 'R', req: 'PAN Sequence Number (5F34) varsa 1 bayt',
    run: (c) => { const v = c.val('5F34'); if (!v) return NA('5F34 yok'); return v.length === 2 ? PASS(v) : WARN(v, '1 bayt beklenir'); } },
  { id: 'FMT-06', cat: 'Veri Formatı', sev: 'C', spec: 'ISO/IEC 7813 · 5F30 ↔ 57 (Service Code)', req: 'Service Code (5F30) varsa 2 bayt ve Track2 hizmet koduyla tutarlı',
    run: (c) => { const v = c.val('5F30'); if (!v) return NA('5F30 yok'); if (v.length !== 4) return FAIL(v, '2 bayt beklenir (n3)'); const t2 = c.val('57'); const t2sc = t2 ? parseTrack2(t2)?.serviceCode : null; const norm = (s) => s == null ? null : parseInt(String(s).replace(/[^0-9]/g, ''), 10).toString().padStart(3, '0'); const a = norm(v), b = norm(t2sc); if (!b) return PASS(`SC=${a}`); return a === b ? PASS(`SC=${a} ↔ Track2 ✓`) : FAIL(`5F30=${a} 57=${b}`, 'Service Code uyuşmuyor'); } },
  { id: 'FMT-07', cat: 'Veri Formatı', sev: 'M', req: 'Application Interchange Profile (82) tam 2 bayt',
    run: (c) => { if (!c.aip) return NA('82 yok'); return c.aip.length === 4 ? PASS(c.aip) : FAIL(c.aip, `${c.aip.length / 2} bayt (2 olmalı)`); } },

  // ── Çapraz-alan tutarlılık (sadece "var mı" değil, alanlar birbiriyle uyumlu mu) ──
  { id: 'CON-01', cat: 'Tutarlılık', sev: 'M', req: 'AIP "CV desteklenir" (byte1 bit5) ↔ CVM List (8E) mevcut',
    run: (c) => { if (!c.aip) return NA('AIP yok'); if (!(c.aipB1 & 0x10)) return NA('AIP CV bildirmez'); return c.has('8E') ? PASS('AIP CV ↔ 8E ✓') : FAIL('—', 'AIP CV destekliyor ama CVM List (8E) yok'); } },
  { id: 'CON-02', cat: 'Tutarlılık', sev: 'R', spec: 'ISO/IEC 7813 · Service Code', req: 'Track2 (57) hizmet kodu 1. hanesi chip kartı gösterir (2 veya 6)',
    run: (c) => { const t2 = c.val('57'); if (!t2) return NA('Track2 yok'); const sc = parseTrack2(t2)?.serviceCode; if (!sc) return NA('Hizmet kodu yok'); return (sc[0] === '2' || sc[0] === '6') ? PASS(`SC=${sc} (IC kart)`) : WARN(`SC=${sc}`, '1. hane 2/6 değil — chip göstermiyor'); } },
  { id: 'CON-03', cat: 'Tutarlılık', sev: 'C', spec: 'EMV Bk3 · 57 ↔ 5F24', req: 'Track2 (57) son kullanma ile tag 5F24 (YYMM) tutarlı',
    run: (c) => { const t2 = c.val('57'), exp = c.val('5F24'); if (!t2 || !exp) return NA('İki alan birden yok'); const sep = t2.indexOf('D'); if (sep < 0) return NA('Track2 format'); const t2yymm = t2.slice(sep + 1).slice(0, 4); const e = exp.slice(0, 4); return t2yymm === e ? PASS(`YYMM=${e} ✓`) : FAIL(`57=${t2yymm} 5F24=${e}`, 'Son kullanma uyuşmuyor'); } },
  { id: 'CON-04', cat: 'Tutarlılık', sev: 'C', spec: 'EMV Bk3 · 5F24 ≥ 5F25', req: 'Son kullanma (5F24) ≥ geçerlilik başlangıcı (5F25)',
    run: (c) => { const exp = c.val('5F24'), eff = c.val('5F25'); if (!exp || !eff) return NA('İki tarih birden yok'); if (!/^[0-9]{6}$/.test(exp) || !/^[0-9]{6}$/.test(eff)) return NA('YYMMDD değil'); return exp >= eff ? PASS(`${eff} → ${exp}`) : FAIL(`5F25=${eff} 5F24=${exp}`, 'Son kullanma, başlangıçtan önce'); } },
  // AIP (82) yetenek bitleri ↔ ilgili veri öğeleri tutarlılığı (EMV Bk3 Ann. C1).
  { id: 'CON-05', cat: 'Tutarlılık', sev: 'C', iface: 'contact', spec: 'EMV Bk3 · Issuer Authentication (tag 91)', req: 'AIP Issuer Authentication (byte1 bit3) ⇒ CDOL2 (8D) Issuer Auth Data (91) ister',
    run: (c) => { if (!c.aip) return NA('AIP yok'); if (!(c.aipB1 & 0x04)) return NA('AIP issuer auth bildirmez'); const v = c.val('8D'); if (!v) return WARN('—', 'Issuer auth var ama CDOL2 (8D) yok'); const d = validDol(v); return (d.ok && d.tags.includes('91')) ? PASS('CDOL2, 91 (Issuer Auth Data) içeriyor') : WARN('CDOL2 91 içermiyor', 'Issuer auth EXTERNAL AUTHENTICATE yoluyla yapılıyor olabilir — doğrula'); } },
  { id: 'CON-06', cat: 'Tutarlılık', sev: 'R', spec: 'EMV Bk3 · Terminal Risk Management (9F14/9F23)', req: 'AIP Terminal Risk Management (byte1 bit4) ⇒ velocity limitleri (9F14/9F23) mevcut',
    run: (c) => { if (!c.aip) return NA('AIP yok'); if (!(c.aipB1 & 0x08)) return NA('AIP TRM bildirmez'); const lo = c.has('9F14'), hi = c.has('9F23'); return (lo && hi) ? PASS('9F14 (Lower) + 9F23 (Upper) Consecutive Offline Limit') : WARN(`9F14:${lo} 9F23:${hi}`, 'TRM var ama velocity-checking limitleri eksik (floor/random yine çalışır)'); } },
  { id: 'CON-07', cat: 'Tutarlılık', sev: 'R', spec: 'EMV Bk3 · Ann. C1 (AIP)', req: 'AIP byte1 RFU biti (0x80) EMV çekirdeğinde sıfır',
    run: (c) => { if (!c.aip) return NA('AIP yok'); return (c.aipB1 & 0x80) ? WARN(c.aip, 'AIP byte1 b8 (0x80) EMV çekirdeğinde RFU — sıfır beklenir (şema-özel olabilir)') : PASS('RFU bit (0x80) sıfır'); } },
  { id: 'CON-08', cat: 'Tutarlılık', sev: 'R', spec: 'ISO/IEC 7813 · Service Code', req: 'Track2 (57) hizmet kodu semantiği çözümlenir',
    run: (c) => { const t2 = c.val('57'); if (!t2) return NA('Track2 yok'); const sc = parseTrack2(t2)?.serviceCode; if (!sc || sc.length < 3) return NA('Hizmet kodu yok'); return PASS(`SC=${sc}: ${SC1[sc[0]] || '?'} · ${SC2[sc[1]] || '?'} · ${SC3[sc[2]] || '?'}`); } },
  { id: 'CON-09', cat: 'Tutarlılık', sev: 'C', spec: 'EMV Bk3 · 9F42 ↔ 9F44', req: 'Application Currency Code (9F42) varsa Currency Exponent (9F44) da mevcut',
    run: (c) => { if (!c.has('9F42')) return NA('9F42 yok'); return c.has('9F44') ? PASS(`9F42=${c.val('9F42')} · 9F44=${c.val('9F44')}`) : WARN('9F44 yok', 'Para birimi var ama üssü (9F44) yok — tutar ondalık konumu belirsiz'); } },

  // ── Kart veri bütünlüğü (PAN IIN ↔ şema · uzunluk · tarih geçerliliği) ──
  { id: 'CVD-01', cat: 'Kart Veri Bütünlüğü', sev: 'C', spec: 'ISO/IEC 7812 · IIN ↔ şema', req: 'PAN IIN öneki seçilen AID şemasıyla tutarlı',
    run: (c) => { const pan = cardPan(c); if (!pan) return NA('PAN yok'); if (!c.scheme) return NA('Şema bilinmiyor'); const det = detectPanScheme(pan); if (!det) return WARN(`IIN ${pan.slice(0, 6)}`, 'PAN IIN majör aralıklara uymuyor'); return det === c.scheme ? PASS(`IIN ${pan.slice(0, 6)} → ${det}`) : WARN(`PAN→${det} · AID→${c.scheme}`, 'PAN IIN farklı şema gösteriyor (eş-marka olabilir — doğrula)'); } },
  { id: 'CVD-02', cat: 'Kart Veri Bütünlüğü', sev: 'C', spec: 'ISO/IEC 7812 · PAN uzunluğu', req: 'PAN uzunluğu şema için geçerli aralıkta',
    run: (c) => { const pan = cardPan(c); if (!pan) return NA('PAN yok'); const allow = PAN_LEN[c.scheme]; if (!allow) return NA('Şema uzunluk tablosu yok'); return allow.includes(pan.length) ? PASS(`${pan.length} hane`) : WARN(`${pan.length} hane`, `${c.scheme} için beklenen: ${allow.join('/')}`); } },
  { id: 'CVD-03', cat: 'Kart Veri Bütünlüğü', sev: 'R', spec: 'EMV Bk3 · tag 5F24', req: 'Application Expiration Date (5F24) geçmemiş',
    run: (c) => { const v = c.val('5F24'); if (!v || !/^[0-9]{6}$/.test(v)) return NA('5F24 yok/format'); return ymd6(v) >= todayYmd() ? PASS(`${v} geçerli`) : WARN(`${v} (dolmuş)`, 'Kartın süresi dolmuş — test kartında beklenebilir'); } },
  { id: 'CVD-04', cat: 'Kart Veri Bütünlüğü', sev: 'C', spec: 'EMV Bk3 · tag 5F25', req: 'Application Effective Date (5F25) gelecekte değil',
    run: (c) => { const v = c.val('5F25'); if (!v || !/^[0-9]{6}$/.test(v)) return NA('5F25 yok/format'); return ymd6(v) <= todayYmd() ? PASS(`${v} aktif`) : WARN(`${v} (gelecek)`, 'Geçerlilik başlangıcı gelecekte — kart henüz aktif değil'); } },

  // ── Bit-alanı kodlama: standart EMV bit alanlarını çöz + doğrula (şemadan bağımsız).
  // CVR (IAD içi) BİLİNÇLİ olarak dışarıda: bit anlamları şema/issuer-özel, otoriter değil.
  { id: 'BIT-01', cat: 'Bit Alanı Kodlama', sev: 'R', spec: 'EMV Bk3 · Ann. C1 (AIP)', req: 'AIP (82) yetenek bitleri çözümlenir',
    run: (c) => { if (!c.aip) return NA('AIP yok'); const f = decodeAip(c.aipB1); return f.length ? PASS(f.join(' · ')) : WARN(c.aip, 'AIP hiç yetenek bildirmiyor'); } },
  { id: 'BIT-02', cat: 'Bit Alanı Kodlama', sev: 'R', spec: 'EMV Bk3 · Ann. C2 (AUC 9F07)', req: 'Application Usage Control (9F07) kullanım bitleri çözümlenir',
    run: (c) => { const v = c.val('9F07'); if (!v || v.length < 2) return NA('9F07 yok'); const d = decodeAuc(v); return d.flags.length ? PASS(d.flags.join(' · ')) : WARN(v, 'Hiç kullanım bildirilmemiş'); } },
  { id: 'BIT-03', cat: 'Bit Alanı Kodlama', sev: 'C', spec: 'EMV Bk3 · Ann. C2 (AUC RFU)', req: 'AUC (9F07) byte2 RFU bitleri (b1–b6) sıfır',
    run: (c) => { const v = c.val('9F07'); if (!v || v.length < 4) return NA('9F07 (2 bayt) yok'); const b2 = parseInt(v.slice(2, 4), 16); return (b2 & 0x3F) ? WARN('byte2=' + v.slice(2, 4), 'AUC byte2 RFU bitleri sıfır değil') : PASS('RFU sıfır'); } },
  { id: 'BIT-04', cat: 'Bit Alanı Kodlama', sev: 'C', spec: 'EMV Bk3 · Ann. C2 (AUC)', req: 'AUC (9F07) en az bir kullanım bağlamı bildiriyor',
    run: (c) => { const v = c.val('9F07'); if (!v || v.length < 2) return NA('9F07 yok'); const d = decodeAuc(v); return d.flags.length ? PASS(`${d.flags.length} kullanım bağlamı`) : WARN(v, 'AUC tümü sıfır — kart hiçbir bağlamda geçerli değil (perso hatası?)'); } },
  { id: 'BIT-05', cat: 'Bit Alanı Kodlama', sev: 'R', spec: 'EMV Bk3 · Ann. C2 (AUC cashback)', req: 'AUC cashback açıksa mal/hizmet kullanımı da açık',
    run: (c) => { const v = c.val('9F07'); if (!v || v.length < 4) return NA('9F07 (2 bayt) yok'); const b1 = parseInt(v.slice(0, 2), 16), b2 = parseInt(v.slice(2, 4), 16); if (!(b2 & 0xC0)) return NA('Cashback bildirilmemiş'); return (b1 & 0x3C) ? PASS('cashback ↔ mal/hizmet ✓') : WARN(v, 'Cashback açık ama mal/hizmet kullanımı kapalı'); } },
  { id: 'BIT-06', cat: 'Bit Alanı Kodlama', sev: 'R', spec: 'EMV Bk3 · Ann. C5 (IAC/TVR)', req: 'IAC-Denial (9F0F) — offline red koşulları çözümlenir',
    run: (c) => { const v = c.val('9F0F'); if (!v) return NA('9F0F yok'); if (v.length !== 10) return WARN(v, 'IAC 5 bayt olmalı'); const f = decodeTvr(v); return f.length ? PASS('Offline RED: ' + f.join(' · ')) : PASS('hiçbir koşulda offline red (00…)'); } },
  { id: 'BIT-07', cat: 'Bit Alanı Kodlama', sev: 'R', spec: 'EMV Bk3 · Ann. C5 (IAC/TVR)', req: 'IAC-Online (9F0E) — online zorlama koşulları çözümlenir',
    run: (c) => { const v = c.val('9F0E'); if (!v) return NA('9F0E yok'); if (v.length !== 10) return WARN(v, 'IAC 5 bayt olmalı'); const f = decodeTvr(v); return f.length ? PASS('ONLINE zorla: ' + f.join(' · ')) : PASS('hiçbir koşulda online zorlama (00…)'); } },
  { id: 'BIT-08', cat: 'Bit Alanı Kodlama', sev: 'R', spec: 'EMV Bk3 · Ann. C5 (IAC/TVR)', req: 'IAC-Default (9F0D) — online olunamazsa red koşulları çözümlenir',
    run: (c) => { const v = c.val('9F0D'); if (!v) return NA('9F0D yok'); if (v.length !== 10) return WARN(v, 'IAC 5 bayt olmalı'); const f = decodeTvr(v); return f.length ? PASS('Online yoksa RED: ' + f.join(' · ')) : PASS('offline onay (00…)'); } },

  // ── Mastercard CPV (şema-özel) ─────────────────────────────────────────
  { id: 'MC-01', cat: 'Mastercard CPV', sev: 'M', scheme: 'Mastercard', req: 'Application Version Number (9F08) mevcut',
    run: (c) => c.has('9F08') ? PASS(c.val('9F08')) : FAIL('—') },
  { id: 'MC-02', cat: 'Mastercard CPV', sev: 'M', scheme: 'Mastercard', req: 'M/Chip CIAC: Decline (C3), Default (C4), Online (C5) mevcut',
    run: (c) => { const m = ['C3', 'C4', 'C5'].filter((t) => c.has(t)); return m.length === 3 ? PASS(m.map((t) => `${t}=${c.val(t)}`).join(' ')) : FAIL(`var: ${m.join(',') || 'yok'}`, 'Eksik CIAC'); } },
  { id: 'MC-03', cat: 'Mastercard CPV', sev: 'M', scheme: 'Mastercard', req: 'Issuer Application Data (9F10) mevcut',
    run: (c) => { const v = c.val('9F10') || c.genac?.iad; if (v) return PASS(v + (c.has('9F10') ? '' : ' (GENERATE AC)')); return c.hasCrypto ? FAIL('—', 'Ne kayıtta ne GENERATE AC yanıtında') : WARN('—', 'Kayıtta yok — kripto akışı çalışmadı'); } },
  { id: 'MC-04', cat: 'Mastercard CPV', sev: 'R', scheme: 'Mastercard', req: 'Application Control / IAC alanları (8D-CDOL2 & IAC 9F0D/0E/0F) mevcut',
    run: (c) => { const iac = ['9F0D', '9F0E', '9F0F'].filter((t) => c.has(t)); return iac.length === 3 ? PASS('IAC Default/Denial/Online') : WARN(`IAC var: ${iac.join(',') || 'yok'}`, 'Tüm IAC alanları önerilir'); } },
  { id: 'MC-05', cat: 'Mastercard CPV', sev: 'R', scheme: 'Mastercard', req: 'M/Chip: Track1 Discretionary (9F1F) veya CVC3 (temassız) veri alanları',
    run: (c) => { const cl = c.iface === 'contactless'; if (cl) { const has = c.has('9F60') || c.has('9F61') || c.has('9F62') || c.has('9F63'); return has ? PASS('CVC3/Track verileri') : WARN('—', 'PayPass temassız veri alanları görülmedi'); } return c.has('9F1F') ? PASS(c.val('9F1F').slice(0, 20) + '…') : WARN('—', 'Track1 Discretionary önerilir'); } },

  // ── Visa VIS / qVSDC (şema-özel) ───────────────────────────────────────
  { id: 'VZ-01', cat: 'Visa VIS/qVSDC', sev: 'M', scheme: 'Visa', req: 'Application Version Number (9F08) mevcut',
    run: (c) => c.has('9F08') ? PASS(c.val('9F08')) : (c.iface === 'contactless' ? WARN('—', 'Temassız: 9F08 yok — sürüm IAD/kernel akışında taşınabilir') : FAIL('—')) },
  { id: 'VZ-02', cat: 'Visa VIS/qVSDC', sev: 'M', scheme: 'Visa', req: 'Issuer Application Data (9F10, VIS formatı) mevcut',
    run: (c) => { const v = c.val('9F10') || c.genac?.iad; return v ? PASS(v + (c.has('9F10') ? '' : ' (GENERATE AC)')) : (c.hasCrypto ? FAIL('—', 'IAD yok') : WARN('—', 'Kripto akışı çalışmadı')); } },
  { id: 'VZ-03', cat: 'Visa VIS/qVSDC', sev: 'R', scheme: 'Visa', req: 'IAC alanları (9F0D/0E/0F) mevcut',
    run: (c) => { const iac = ['9F0D', '9F0E', '9F0F'].filter((t) => c.has(t)); return iac.length === 3 ? PASS('IAC Default/Denial/Online') : WARN(`var: ${iac.join(',') || 'yok'}`); } },
  { id: 'VZ-04', cat: 'Visa VIS/qVSDC', sev: 'C', scheme: 'Visa', req: 'Temassız: Card Transaction Qualifiers (9F6C) veya Form Factor (9F6E)',
    run: (c) => { if (c.iface !== 'contactless') return NA('Sadece temassız'); return (c.has('9F6C') || c.has('9F6E')) ? PASS(c.has('9F6C') ? `CTQ ${c.val('9F6C')}` : `FFI ${c.val('9F6E')}`) : WARN('—', 'qVSDC temassız alanları görülmedi'); } },
  { id: 'VZ-05', cat: 'Visa VIS/qVSDC', sev: 'M', scheme: 'Visa', req: 'IAD (9F10) VIS formatı — Cryptogram Version (CVN) + DKI çıkarılabiliyor',
    run: (c) => { const v = c.val('9F10') || c.genac?.iad; if (!v) return c.hasCrypto ? FAIL('—', 'IAD yok') : NA('IAD yok'); if (v.length < 6) return FAIL(v, 'IAD çok kısa (VIS ≥ 3 bayt)'); return PASS(`CVN=${v.slice(4, 6)} · DKI=${v.slice(2, 4)}`); } },
  { id: 'VZ-06', cat: 'Visa VIS/qVSDC', sev: 'C', scheme: 'Visa', iface: 'contactless', spec: 'VCPS 2.x (qVSDC) · PDOL/TTQ',
    req: 'qVSDC: PDOL (9F38) Terminal Transaction Qualifiers (9F66) ister',
    run: (c) => { const v = c.val('9F38'); if (!v) return WARN('—', 'PDOL yok — qVSDC PDOL bekler'); const d = validDol(v); if (!d.ok) return FAIL(v.slice(0, 20), 'Geçersiz PDOL'); return d.tags.includes('9F66') ? PASS('PDOL 9F66 (TTQ) içeriyor') : WARN(`${d.entries.length} tag`, 'PDOL 9F66 (TTQ) istemiyor — qVSDC için beklenir'); } },
  { id: 'VZ-07', cat: 'Visa VIS/qVSDC', sev: 'C', scheme: 'Visa', spec: 'Visa VIS · Cryptogram Version Number (CVN)',
    req: 'IAD (9F10) CVN yaygın Visa değerlerinden biri (10=0x0A / 18=0x12 / 22=0x16)',
    run: (c) => { const v = c.val('9F10') || c.genac?.iad; if (!v || v.length < 6) return NA('IAD yok/kısa'); const cvn = parseInt(v.slice(4, 6), 16); const known = { 0x0A: 'CVN 10', 0x12: 'CVN 18', 0x16: 'CVN 22' }; return known[cvn] ? PASS(`${known[cvn]} (0x${cvn.toString(16).padStart(2, '0')})`) : WARN(`0x${cvn.toString(16).padStart(2, '0')}`, 'Yaygın Visa CVN (10/18/22) değil — issuer spec ile doğrula'); } },

  // ── Amex (AEIPS, şema-özel) ────────────────────────────────────────────
  { id: 'AX-01', cat: 'Amex', sev: 'M', scheme: 'Amex', req: 'Application Version Number (9F08) mevcut',
    run: (c) => c.has('9F08') ? PASS(c.val('9F08')) : FAIL('—') },
  { id: 'AX-02', cat: 'Amex', sev: 'M', scheme: 'Amex', req: 'Issuer Application Data (9F10) mevcut',
    run: (c) => { const v = c.val('9F10') || c.genac?.iad; return v ? PASS(v) : (c.hasCrypto ? FAIL('—', 'IAD yok') : WARN('—')); } },
  { id: 'AX-03', cat: 'Amex', sev: 'R', scheme: 'Amex', req: 'IAC Default/Denial/Online (9F0D/0E/0F) mevcut',
    run: (c) => { const iac = ['9F0D', '9F0E', '9F0F'].filter((t) => c.has(t)); return iac.length === 3 ? PASS('IAC tam') : WARN(`var: ${iac.join(',') || 'yok'}`); } },
  { id: 'AX-04', cat: 'Amex', sev: 'M', scheme: 'Amex', req: 'IAD (9F10) AEIPS formatı — makul uzunluk + CVN çıkarımı',
    run: (c) => { const v = c.val('9F10') || c.genac?.iad; if (!v) return c.hasCrypto ? FAIL('—', 'IAD yok') : NA('IAD yok'); if (v.length < 8) return FAIL(v, 'IAD çok kısa (AEIPS ≥ 4 bayt)'); return PASS(`CVN=${v.slice(2, 4)} · ${v.length / 2} bayt`); } },

  // ── Discover (D-PAS, şema-özel) ────────────────────────────────────────
  { id: 'DIS-01', cat: 'Discover D-PAS', sev: 'M', scheme: 'Discover', req: 'Application Version Number (9F08) mevcut',
    run: (c) => c.has('9F08') ? PASS(c.val('9F08')) : FAIL('—') },
  { id: 'DIS-02', cat: 'Discover D-PAS', sev: 'M', scheme: 'Discover', req: 'Issuer Application Data (9F10) mevcut',
    run: (c) => { const v = c.val('9F10') || c.genac?.iad; return v ? PASS(v + (c.has('9F10') ? '' : ' (GENERATE AC)')) : (c.hasCrypto ? FAIL('—', 'IAD yok') : WARN('—', 'Kripto akışı çalışmadı')); } },
  { id: 'DIS-03', cat: 'Discover D-PAS', sev: 'R', scheme: 'Discover', req: 'IAC Default/Denial/Online (9F0D/0E/0F) mevcut',
    run: (c) => { const iac = ['9F0D', '9F0E', '9F0F'].filter((t) => c.has(t)); return iac.length === 3 ? PASS('IAC tam') : WARN(`var: ${iac.join(',') || 'yok'}`); } },
  { id: 'DIS-04', cat: 'Discover D-PAS', sev: 'R', scheme: 'Discover', req: 'Application Usage Control (9F07) mevcut',
    run: (c) => c.has('9F07') ? PASS(c.val('9F07')) : WARN('—', 'AUC önerilir') },
  { id: 'DIS-05', cat: 'Discover D-PAS', sev: 'C', scheme: 'Discover', iface: 'contactless', spec: 'D-PAS Contactless',
    req: 'Temassız: PDOL (9F38) mevcut (D-PAS GPO)',
    run: (c) => { const v = c.val('9F38'); if (!v) return WARN('—', 'PDOL yok — temassız GPO PDOL bekler'); const d = validDol(v); return d.ok ? PASS(`${d.entries.length} tag`) : FAIL(v.slice(0, 20), 'Geçersiz PDOL'); } },

  // ── Troy (D-PAS, şema-özel) ────────────────────────────────────────────
  { id: 'TR-01', cat: 'Troy D-PAS', sev: 'M', scheme: 'Troy', req: 'Application Version Number (9F08) mevcut',
    run: (c) => c.has('9F08') ? PASS(c.val('9F08')) : WARN('—', 'D-PAS sürümü önerilir') },
  { id: 'TR-02', cat: 'Troy D-PAS', sev: 'R', scheme: 'Troy', req: 'IAC alanları (9F0D/0E/0F) mevcut',
    run: (c) => { const iac = ['9F0D', '9F0E', '9F0F'].filter((t) => c.has(t)); return iac.length === 3 ? PASS('IAC tam') : WARN(`var: ${iac.join(',') || 'yok'}`); } },

  // ── JCB (J/Smart, şema-özel) ───────────────────────────────────────────
  { id: 'JCB-01', cat: 'JCB', sev: 'M', scheme: 'JCB', req: 'Application Version Number (9F08) mevcut',
    run: (c) => c.has('9F08') ? PASS(c.val('9F08')) : FAIL('—') },
  { id: 'JCB-02', cat: 'JCB', sev: 'M', scheme: 'JCB', req: 'Issuer Application Data (9F10) mevcut',
    run: (c) => { const v = c.val('9F10') || c.genac?.iad; return v ? PASS(v + (c.has('9F10') ? '' : ' (GENERATE AC)')) : (c.hasCrypto ? FAIL('—', 'IAD yok') : WARN('—', 'Kripto akışı çalışmadı')); } },
  { id: 'JCB-03', cat: 'JCB', sev: 'R', scheme: 'JCB', req: 'IAC Default/Denial/Online (9F0D/0E/0F) mevcut',
    run: (c) => { const iac = ['9F0D', '9F0E', '9F0F'].filter((t) => c.has(t)); return iac.length === 3 ? PASS('IAC tam') : WARN(`var: ${iac.join(',') || 'yok'}`); } },

  // ── UnionPay (UICS / PBOC 3.0, şema-özel) ──────────────────────────────
  { id: 'UP-01', cat: 'UnionPay', sev: 'M', scheme: 'UnionPay', req: 'Application Version Number (9F08) mevcut',
    run: (c) => c.has('9F08') ? PASS(c.val('9F08')) : FAIL('—') },
  { id: 'UP-02', cat: 'UnionPay', sev: 'M', scheme: 'UnionPay', req: 'Issuer Application Data (9F10) mevcut',
    run: (c) => { const v = c.val('9F10') || c.genac?.iad; return v ? PASS(v + (c.has('9F10') ? '' : ' (GENERATE AC)')) : (c.hasCrypto ? FAIL('—', 'IAD yok') : WARN('—', 'Kripto akışı çalışmadı')); } },
  { id: 'UP-03', cat: 'UnionPay', sev: 'R', scheme: 'UnionPay', req: 'IAC Default/Denial/Online (9F0D/0E/0F) mevcut',
    run: (c) => { const iac = ['9F0D', '9F0E', '9F0F'].filter((t) => c.has(t)); return iac.length === 3 ? PASS('IAC tam') : WARN(`var: ${iac.join(',') || 'yok'}`); } },
  { id: 'UP-04', cat: 'UnionPay', sev: 'C', scheme: 'UnionPay', req: 'Application Usage Control (9F07) mevcut',
    run: (c) => c.has('9F07') ? PASS(c.val('9F07')) : WARN('—', 'AUC önerilir') },

  // ── Temassız kernel (EMVCo Book C-2 Kernel 2 / C-3 Kernel 3) — sadece temassız ──
  { id: 'KNL-01', cat: 'Temassız Kernel', sev: 'C', iface: 'contactless', req: 'Temassız kernel kimliği (şema → EMVCo kernel)',
    run: (c) => { const k = kernelName(c.scheme); return k ? PASS(k) : WARN(c.scheme || '—', 'Kernel eşlemesi bilinmiyor'); } },
  { id: 'KNL-02', cat: 'Temassız Kernel', sev: 'C', iface: 'contactless', scheme: 'Visa', spec: 'EMVCo Book C-3 (Kernel 3)', req: 'Kernel 3 qVSDC — Card Transaction Qualifiers (9F6C) mevcut',
    run: (c) => c.has('9F6C') ? PASS(`CTQ ${c.val('9F6C')}`) : WARN('—', 'qVSDC CTQ (9F6C) görülmedi') },
  { id: 'KNL-03', cat: 'Temassız Kernel', sev: 'C', iface: 'contactless', scheme: 'Mastercard', spec: 'EMVCo Book C-2 (Kernel 2)', req: 'Kernel 2 — offline auth için CDA (AIP bit1) destekleniyor',
    run: (c) => (c.aipB1 & 0x01) ? PASS('CDA destekleniyor') : WARN(c.aip, 'K2 temassız offline auth için CDA beklenir') },
  { id: 'KNL-04', cat: 'Temassız Kernel', sev: 'M', iface: 'contactless', spec: 'EMV Bk2 · temassız ODA', req: 'Temassız dinamik offline auth: AIP DDA (bit6) veya CDA (bit1) bildiriyor',
    run: (c) => { if (!c.aip) return NA('AIP yok'); return ((c.aipB1 & 0x20) || (c.aipB1 & 0x01)) ? PASS(`DDA:${!!(c.aipB1 & 0x20)} CDA:${!!(c.aipB1 & 0x01)}`) : WARN(c.aip, 'Temassız dinamik ODA (fDDA/CDA) bildirilmedi'); } },
  { id: 'KNL-05', cat: 'Temassız Kernel', sev: 'R', iface: 'contactless', spec: 'Visa qVSDC · 9F6C (CTQ)', req: 'Card Transaction Qualifiers (9F6C) çözümlenir',
    run: (c) => { const v = c.val('9F6C'); if (!v) return NA('9F6C (CTQ) yok'); const f = decodeCtq(v); return PASS(`${v}: ${f && f.length ? f.join(' · ') : 'hiç koşul set değil'}`); } },

  // ── Offline Data Authentication — KRİPTOGRAFİK doğrulama (canlı akış) ──
  // Tag varlığı değil, sertifika zinciri/imzanın matematiksel geçerliliği.
  { id: 'CRY-01', cat: 'ODA Kripto', sev: 'M', req: 'CA Public Key (CAPK) bulundu (RID + index 8F)',
    run: (c) => { if (!c.hasCrypto) return NA('Kripto akışı yok'); const o = c.oda; if (!o) return NA('ODA verisi yok'); return o.capkFound ? PASS(`RID ${o.rid} idx ${o.capkIndex}`) : FAIL(`RID ${o.rid} idx ${o.capkIndex}`, 'CAPK deposunda yok — CA Anahtarları sekmesinden ekleyin'); } },
  { id: 'CRY-02', cat: 'ODA Kripto', sev: 'M', req: 'Issuer Public Key sertifikası (90) kriptografik doğrulandı',
    run: (c) => { if (!c.hasCrypto || !c.oda?.capkFound) return NA('CAPK yok'); return c.oda.issuerPK?.ok ? PASS('Issuer PK recovered') : FAIL('—', 'Issuer PK sertifikası doğrulanamadı'); } },
  { id: 'CRY-03', cat: 'ODA Kripto', sev: 'M', req: 'ICC Public Key sertifikası (9F46) kriptografik doğrulandı',
    run: (c) => { if (!c.hasCrypto || !c.oda?.capkFound) return NA('CAPK yok'); if (!c.oda.issuerPK?.ok) return NA('Issuer PK yok'); return c.oda.iccPK?.ok ? PASS('ICC PK recovered') : FAIL('—', 'ICC PK sertifikası doğrulanamadı'); } },
  { id: 'CRY-04', cat: 'ODA Kripto', sev: 'M', req: 'CDA destekleniyorsa (AIP bit1) CDA dinamik imza doğrulandı',
    run: (c) => { if (!(c.aipB1 & 0x01)) return NA('CDA desteklenmiyor'); if (!c.hasCrypto || !c.oda?.capkFound) return NA('CAPK yok'); const d = c.dyn('CDA'); if (!d) return WARN('—', 'CDA SDAD üretilmedi (bu işlem tipinde)'); const ok = d.hashMatch != null ? d.hashMatch : d.ok; return ok ? PASS('SDAD hash ✓') : (d.structOk ? WARN('yapısal ✓', 'Hash eşleşmedi') : FAIL('—', 'CDA imza doğrulanamadı')); } },
  { id: 'CRY-05', cat: 'ODA Kripto', sev: 'M', req: 'DDA destekleniyorsa (AIP bit6) DDA dinamik imza doğrulandı',
    run: (c) => { if (!(c.aipB1 & 0x20)) return NA('DDA desteklenmiyor'); if (!c.hasCrypto || !c.oda?.capkFound) return NA('CAPK yok'); const d = c.dyn('DDA'); if (!d) return c.dyn('fDDA') ? NA('Temassız: DDA, fDDA olarak yapıldı → CRY-12') : WARN('—', 'DDA imza üretilmedi (INTERNAL AUTH yok/qVSDC)'); const ok = d.hashMatch != null ? d.hashMatch : d.ok; return ok ? PASS('SDAD hash ✓') : (d.structOk ? WARN('yapısal ✓', 'Hash eşleşmedi') : FAIL('—', 'DDA imza doğrulanamadı')); } },
  { id: 'CRY-06', cat: 'ODA Kripto', sev: 'R', req: 'Application Cryptogram (ARQC/TC) üretildi (GENERATE AC)',
    run: (c) => { if (!c.hasCrypto) return NA('Kripto akışı yok'); const g = c.genac; if (!g || !g.arqc) return WARN('—', 'AC üretilmedi'); return PASS(`CID ${g.cid || '?'} · AC ${g.arqc}`); } },
  { id: 'CRY-07', cat: 'ODA Kripto', sev: 'R', req: 'ARQC işlem anahtarıyla doğrulandı',
    // Önerilen (R) kural: eşleşmezlik FAIL değil WARN — yanlış/eksik yapılandırılmış
    // işlem anahtarı da eşleşmezlik verir, bu bir kart kusuru olmayabilir.
    run: (c) => { if (!c.hasCrypto || !c.genac?.arqc) return NA('AC yok'); const v = c.genac.verify; if (!v) return NA('Doğrulama yok'); if (v.noKey) return WARN('—', 'Bu PAN için oturum anahtarı yok — Oturum Anahtarları sekmesi'); return v.match ? PASS(`anahtar ${v.keyLabel || ''}`) : WARN('—', 'ARQC eşleşmedi — anahtar yanlış/eksik olabilir'); } },
  // Sertifika son-kullanma (recovered cert'ten): Issuer PK cert MMYY @ bayt 6-7, ICC PK
  // cert MMYY @ bayt 12-13 (EMV Bk2 §6.3/6.4). Süresi dolmuşsa canlı terminalde ODA FAIL.
  { id: 'CRY-08', cat: 'ODA Kripto', sev: 'R', spec: 'EMV Bk2 · §6.3 (Issuer cert son kullanma)', req: 'Issuer PK Sertifikası (90) süresi geçmemiş',
    run: (c) => { const rec = c.oda?.issuerPK?.recovered; if (!c.hasCrypto || !rec || rec.length < 16 || rec.slice(0, 2).toUpperCase() !== '6A') return NA('Recovered Issuer cert yok'); const e = certExpValid(rec.slice(12, 16)); if (!e) return NA('Tarih çözülemedi'); return e.valid ? PASS(`son ${e.mmyy} (MMYY)`) : WARN(`son ${e.mmyy}`, 'Issuer PK sertifikası süresi dolmuş — canlı terminalde ODA reddedilir'); } },
  { id: 'CRY-09', cat: 'ODA Kripto', sev: 'R', spec: 'EMV Bk2 · §6.4 (ICC cert son kullanma)', req: 'ICC PK Sertifikası (9F46) süresi geçmemiş',
    run: (c) => { const rec = c.oda?.iccPK?.recovered; if (!c.hasCrypto || !rec || rec.length < 28 || rec.slice(0, 2).toUpperCase() !== '6A') return NA('Recovered ICC cert yok'); const e = certExpValid(rec.slice(24, 28)); if (!e) return NA('Tarih çözülemedi'); return e.valid ? PASS(`son ${e.mmyy} (MMYY)`) : WARN(`son ${e.mmyy}`, 'ICC PK sertifikası süresi dolmuş — canlı terminalde ODA reddedilir'); } },
  { id: 'CRY-10', cat: 'ODA Kripto', sev: 'R', spec: 'EMV Bk2 · §6.3 (algo göstergeleri)', req: 'Issuer PK cert Hash (SHA-1=01) + PK (RSA=01) algoritma göstergeleri geçerli',
    run: (c) => { const rec = c.oda?.issuerPK?.recovered; if (!c.hasCrypto || !rec || rec.length < 26 || rec.slice(0, 2).toUpperCase() !== '6A') return NA('Recovered Issuer cert yok'); const hash = rec.slice(22, 24), pk = rec.slice(24, 26); return (hash === '01' && pk === '01') ? PASS('Hash=SHA-1(01) · PK=RSA(01)') : WARN(`Hash=${hash} PK=${pk}`, 'Beklenen 01/01 dışında algoritma göstergesi'); } },
  { id: 'CRY-11', cat: 'ODA Kripto', sev: 'R', spec: 'EMV Bk2 · §6.4 (algo göstergeleri)', req: 'ICC PK cert Hash (SHA-1=01) + PK (RSA=01) algoritma göstergeleri geçerli',
    run: (c) => { const rec = c.oda?.iccPK?.recovered; if (!c.hasCrypto || !rec || rec.length < 38 || rec.slice(0, 2).toUpperCase() !== '6A') return NA('Recovered ICC cert yok'); const hash = rec.slice(34, 36), pk = rec.slice(36, 38); return (hash === '01' && pk === '01') ? PASS('Hash=SHA-1(01) · PK=RSA(01)') : WARN(`Hash=${hash} PK=${pk}`, 'Beklenen 01/01 dışında algoritma göstergesi'); } },
  { id: 'CRY-12', cat: 'ODA Kripto', sev: 'M', iface: 'contactless', spec: 'EMV Bk2 · §6 · VCPS (fDDA)', req: 'fDDA (temassız fast DDA) dinamik imza kriptografik doğrulandı',
    run: (c) => { if (!c.hasCrypto || !c.oda?.capkFound) return NA('CAPK yok'); const d = c.dyn('fDDA'); if (!d) return NA('fDDA imza üretilmedi (bu kart/akış)'); const ok = d.hashMatch != null ? d.hashMatch : d.ok; return ok ? PASS('SDAD hash ✓ (fDDA)') : (d.structOk ? WARN('yapısal ✓', 'fDDA hash eşleşmedi — terminal DD-input (VCPS) gerekebilir') : FAIL('—', 'fDDA imza doğrulanamadı')); } },

  // ── Kriptogram Sürümü (CVN) tanımlama — IAD'den CVN + bilinen algoritma ──
  { id: 'CVN-01', cat: 'Kriptogram Sürümü (CVN)', sev: 'R', spec: 'EMV Bk2 · §8.2 (CVN)', req: 'Cryptogram Version Number (CVN) tanımlanır + bilinen algoritma',
    run: (c) => { const iad = c.val('9F10') || c.genac?.iad; if (!iad) return NA('IAD (9F10) yok'); const info = cvnInfo(c.scheme, iad); if (!info) return NA(`${c.scheme || '?'} için CVN eşlemi yok (ham IAD: ${iad.slice(0, 8)}…)`); return info.label ? PASS(`0x${info.cvn} — ${info.label}`) : WARN(`0x${info.cvn}`, 'Tanınan CVN listesinde değil — issuer spec ile doğrula'); } },
  { id: 'CVN-02', cat: 'Kriptogram Sürümü (CVN)', sev: 'C', spec: 'EMV Bk2 · §8.2 (CVN ↔ ARQC)', req: 'Bildirilen CVN, doğrulanan ARQC kompozisyonuyla tutarlı',
    run: (c) => { const iad = c.val('9F10') || c.genac?.iad; if (!iad || !c.hasCrypto) return NA('IAD/kripto yok'); const info = cvnInfo(c.scheme, iad); const m = c.genac?.verify?.method; if (!info || !info.label || !m || !c.genac?.verify?.match) return NA('CVN etiketi veya doğrulanmış ARQC yok'); const csk = /CSK/i.test(m); const wantCsk = /CSK/i.test(info.label); return csk === wantCsk ? PASS(`CVN ↔ ${csk ? 'CSK' : 'UDK'} ✓`) : WARN(`CVN=${info.cvn} ama ARQC ${m}`, 'Bildirilen CVN ile eşleşen ARQC kompozisyonu farklı'); } },

  // ── Terminal Action Analysis: kartın IAC'leriyle temsili koşullar → offline karar ──
  // Online-yetenekli terminal modeli: TVR&IAC-Denial→AAC · TVR&IAC-Online→ARQC · yoksa TC.
  // (TAC'ler terminal profiline bağlı; burada yalnızca kart IAC'lerinin davranışı gösterilir.)
  { id: 'TAA-01', cat: 'İşlem Aksiyon Analizi', sev: 'R', spec: 'EMV Bk3 · §10.7 (Action Analysis)', req: 'Kartın IAC risk-davranış profili (temsili koşullar → TC/ARQC/AAC)',
    run: (c) => { const p5 = (h) => (h && h.length >= 10) ? [0, 1, 2, 3, 4].map((i) => parseInt(h.slice(i * 2, i * 2 + 2), 16) || 0) : null; const D = p5(c.val('9F0F')), O = p5(c.val('9F0E')); if (!D && !O) return NA('IAC (9F0E/9F0F) yok'); const dD = D || [0, 0, 0, 0, 0], dO = O || [0, 0, 0, 0, 0]; const SCEN = { 'ODA-fail': [0x4C, 0, 0, 0, 0], 'süre-dolmuş': [0, 0x40, 0, 0, 0], 'CVM-fail': [0, 0, 0x80, 0, 0], 'floor-aşıldı': [0, 0, 0, 0x80, 0], 'offline-limit': [0, 0, 0, 0x60, 0], 'rastgele-online': [0, 0, 0, 0x10, 0] }; const and = (a, b) => a.some((x, i) => x & (b[i] || 0)); const act = (t) => and(t, dD) ? 'AAC' : (and(t, dO) ? 'ARQC' : 'TC'); return PASS(Object.entries(SCEN).map(([k, t]) => `${k}→${act(t)}`).join(' · ')); } },
];

// Run all applicable rules against a card image for one interface.
// `crypto` (optional) = { oda, genac } from the live EMV flow.
export function runCompliance(image, iface, crypto) {
  const ctx = buildContext(image, iface, crypto);
  const results = [];
  for (const rule of RULES) {
    if (rule.scheme && ctx.scheme !== rule.scheme) continue;     // farklı şema — atla
    if (rule.iface && iface && rule.iface !== iface) continue;   // farklı arayüz — atla
    let r;
    try { r = rule.run(ctx); } catch (e) { r = FAIL('—', 'Kural hatası: ' + e.message); }
    results.push({ id: rule.id, cat: rule.cat, req: rule.req, sev: rule.sev, spec: rule.spec || CAT_SPEC[rule.cat] || null, ...r, evidence: r.evidence ?? null, detail: r.detail ?? null });
  }
  // Group by category (stable order of first appearance).
  const cats = [];
  const byCat = new Map();
  for (const r of results) {
    if (!byCat.has(r.cat)) { byCat.set(r.cat, { name: r.cat, rules: [] }); cats.push(byCat.get(r.cat)); }
    byCat.get(r.cat).rules.push(r);
  }
  const count = (s) => results.filter((r) => r.status === s).length;
  // A mandatory FAIL blocks certification; recommended issues are warnings only.
  const mandatoryFails = results.filter((r) => r.status === 'fail' && r.sev !== 'R').length;
  const summary = {
    pass: count('pass'), fail: count('fail'), warn: count('warn'), na: count('na'),
    total: results.length, mandatoryFails,
    verdict: mandatoryFails === 0 ? (count('fail') === 0 ? 'PASS' : 'PASS_WITH_WARN') : 'FAIL',
  };
  return { iface, scheme: ctx.scheme, aid: ctx.aid, aip: ctx.aip, kernel: iface === 'contactless' ? kernelName(ctx.scheme) : null, categories: cats, summary };
}

// Kural motorunun kapsam özeti (Genel Bakış panosu / kabiliyet manifesti için).
export function ruleManifest() {
  const bySev = { M: 0, R: 0, C: 0 };
  for (const r of RULES) if (bySev[r.sev] != null) bySev[r.sev]++;
  return {
    count: RULES.length,
    categories: [...new Set(RULES.map((r) => r.cat))],
    schemes: [...new Set(RULES.filter((r) => r.scheme).map((r) => r.scheme))],
    kernels: KERNEL,
    sev: bySev,
  };
}

// Kapsam haritası — aracın EMV sertifikasyon katmanlarına göre neyi test ettiği ve
// neyi ETMEDİĞİ (DÜRÜST scope). 'full' tam kapsanır · 'partial' kısmen · 'out' kapsam
// dışı. Amaç: rakip kapalı-kutu araçların aksine tam şeffaf kapsam beyanı.
const COVERAGE = [
  { area: 'L1 · Fiziksel / Elektriksel', scope: 'partial', tool: 'ATR + protokol (T=0/T=1) + temaslı/temassız tespiti', out: 'Dalga formu, zamanlama, RF alan/güç ölçümü (özel donanım gerekir)' },
  { area: 'L1.5 · APDU / İletişim', scope: 'full', tool: 'Tam APDU zinciri, TLV çözümleme, SW yorumlama, ham konsol', out: '—' },
  { area: 'L2 · Uygulama Seçimi', scope: 'full', tool: 'PPSE/PSE/AID seçimi, FCI + DF Name doğrulama', out: '—' },
  { area: 'L2 · İşlem Akışı', scope: 'full', tool: 'GPO, AIP/AFL, READ RECORD, CDOL/DOL, GENERATE AC', out: '—' },
  { area: 'L2 · Offline Veri Doğrulama (ODA)', scope: 'full', tool: 'SDA/DDA/CDA tag + sertifika zinciri (recover · uzunluk · son-kullanma · algo) + dinamik imza kripto', out: 'SDA statik-imza kripto (SDA destekli kart yoksa)' },
  { area: 'L2 · Kart Doğrulama (CVM)', scope: 'full', tool: 'CVM List format + insan-okunur çözüm + offline PIN kripto tutarlılığı', out: 'Canlı PIN-pad etkileşimi' },
  { area: 'L2 · Kriptogram (ARQC)', scope: 'full', tool: 'Çok-şemalı ARQC doğrulama (CSK · M/Chip · CVN10-UDK) + session-key türetme', out: '—' },
  { area: 'L2 · Issuer Auth (ARPC)', scope: 'full', tool: 'ARPC üretimi + diferansiyel karta-doğrulatma (doğru→TC ∧ bozuk→AAC negatif test)', out: '—' },
  { area: 'L2 · Risk / Aksiyon Analizi', scope: 'full', tool: 'IAC decode + Terminal Action Analysis (koşul → TC/ARQC/AAC)', out: 'Terminal TAC yapılandırması (profil-bağımlı)' },
  { area: 'L2 · Kernel Uygunluk', scope: 'partial', tool: 'EMVCo Kernel (C-2…C-8) farkındalığı + temassız kural matrisi', out: 'EMVCo Type Approval kernel test paketi (lisanslı)' },
  { area: 'L3 · Uçtan-uca / Şema', scope: 'partial', tool: 'Issuer auth + L2/L3 senaryo runner (TC/ARQC/AAC)', out: 'Lisanslı şema test paketleri (VTS · MTIP · ADVT)' },
  { area: 'Perso / Veri Bütünlüğü', scope: 'full', tool: 'PAN/IIN↔şema · tarih · AIP/AUC/format · CVN tanımlama · spec-izlenebilir kural motoru', out: '—' },
  { area: 'Akreditasyon', scope: 'out', tool: 'Açık, spec-izlenebilir kural motoru (denetlenebilir)', out: 'Aracın EMVCo/şema qualification\'ı — bu bir analiz/QA aracıdır, resmi sertifika ÜRETMEZ' },
];
export function coverageMap() {
  const by = { full: 0, partial: 0, out: 0 };
  for (const a of COVERAGE) by[a.scope]++;
  return { areas: COVERAGE, summary: by };
}
