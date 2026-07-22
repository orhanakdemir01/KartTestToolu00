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
  'Kullanım/Yerel': 'EMV Bk3 · Ann. A (AUC/yerel)',
  'DOL/FCI': 'EMV Bk1 §11.3 (FCI) · Bk3 §5.4 (DOL)',
  'Mastercard CPV': 'M/Chip Requirements · CPV',
  'Visa VIS/qVSDC': 'Visa VIS 1.6 · VCPS 2.x (qVSDC)',
  'Amex': 'Amex AEIPS 3.x',
  'Discover D-PAS': 'Discover D-PAS 1.x',
  'Troy D-PAS': 'Troy D-PAS',
  'ODA Kripto': 'EMV Bk2 · §6 (RSA/SDAD)',
};

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
  { id: 'STR-06', cat: 'Yapı', sev: 'M', req: 'AFL (94) mevcut', run: (c) => c.afl ? PASS(c.afl) : FAIL('—') },
  { id: 'STR-07', cat: 'Yapı', sev: 'M', req: 'CVM List (8E) mevcut', run: (c) => c.has('8E') ? PASS(c.val('8E').slice(0, 20) + '…') : FAIL('—') },
  { id: 'STR-08', cat: 'Yapı', sev: 'M', req: 'CDOL1 (8C) mevcut', iface: 'contact', run: (c) => c.has('8C') ? PASS(c.val('8C')) : FAIL('—') },
  { id: 'STR-09', cat: 'Yapı', sev: 'M', req: 'CDOL2 (8D) mevcut', iface: 'contact', run: (c) => c.has('8D') ? PASS(c.val('8D')) : FAIL('—') },
  { id: 'STR-10', cat: 'Yapı', sev: 'R', req: 'PAN Sequence Number (5F34) mevcut', run: (c) => c.has('5F34') ? PASS(c.val('5F34')) : WARN('—', 'PSN önerilir') },
  { id: 'STR-11', cat: 'Yapı', sev: 'R', req: 'Cardholder Name (5F20) mevcut', run: (c) => c.has('5F20') ? PASS(c.val('5F20')) : WARN('—') },

  // ── AFL / kayıt bütünlüğü ─────────────────────────────────────────────
  { id: 'AFL-01', cat: 'AFL/Kayıt', sev: 'M', req: 'AFL geçerli formatta (4-baytın katı)',
    run: (c) => { if (!c.afl) return FAIL('—'); return c.afl.length % 8 === 0 ? PASS(`${c.afl.length / 8} girdi`) : FAIL(c.afl, '4 baytın katı değil'); } },
  { id: 'AFL-02', cat: 'AFL/Kayıt', sev: 'M', req: "AFL'nin işaret ettiği tüm kayıtlar okundu",
    run: (c) => { if (!c.afl) return NA('AFL yok'); const entries = parseAfl(c.afl); let need = 0; for (const e of entries) need += (e.lastRecord - e.firstRecord + 1); const got = c.records.length; return got >= need ? PASS(`${got}/${need} kayıt`) : FAIL(`${got}/${need}`, 'Eksik kayıt'); } },

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

  // ── CVM ───────────────────────────────────────────────────────────────
  { id: 'CVM-01', cat: 'CVM', sev: 'M', req: 'CVM List (8E) format: ≥10 bayt ve (uzunluk-8) çift',
    run: (c) => { const v = c.val('8E'); if (!v) return NA('8E yok'); const n = v.length / 2; return (n >= 10 && (n - 8) % 2 === 0) ? PASS(`${n} bayt, ${(n - 8) / 2} kural`) : FAIL(`${n} bayt`, 'Format hatalı'); } },
  { id: 'CVM-02', cat: 'CVM', sev: 'R', req: 'CVM için X/Y ikincil tutar alanları (8E ilk 8 bayt)',
    run: (c) => { const v = c.val('8E'); if (!v) return NA('8E yok'); return v.length >= 16 ? PASS(`X=${v.slice(0, 8)} Y=${v.slice(8, 16)}`) : FAIL(v, 'X/Y eksik'); } },

  // ── Kullanım kontrolü / yerel veri ─────────────────────────────────────
  { id: 'USE-01', cat: 'Kullanım/Yerel', sev: 'R', req: 'Application Usage Control (9F07) mevcut',
    run: (c) => c.has('9F07') ? PASS(c.val('9F07')) : WARN('—', 'AUC önerilir') },
  { id: 'USE-02', cat: 'Kullanım/Yerel', sev: 'C', req: 'Issuer Country Code (5F28) geçerli ISO 3166 numerik',
    run: (c) => { const v = c.val('5F28'); if (!v) return NA('5F28 yok'); return countryName(v) ? PASS(`${v} (${countryName(v)})`) : FAIL(v, 'Geçersiz ülke kodu'); } },
  { id: 'USE-03', cat: 'Kullanım/Yerel', sev: 'C', req: 'Application Currency Code (9F42) geçerli ISO 4217',
    run: (c) => { const v = c.val('9F42'); if (!v) return NA('9F42 yok'); return currencyName(v) ? PASS(`${v} (${currencyName(v)})`) : FAIL(v, 'Geçersiz para birimi'); } },
  { id: 'USE-04', cat: 'Kullanım/Yerel', sev: 'R', req: 'Language Preference (5F2D) mevcut',
    run: (c) => c.has('5F2D') ? PASS(c.val('5F2D')) : WARN('—') },

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
    run: (c) => c.has('9F08') ? PASS(c.val('9F08')) : FAIL('—') },
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

  // ── Amex (AEIPS, şema-özel) ────────────────────────────────────────────
  { id: 'AX-01', cat: 'Amex', sev: 'M', scheme: 'Amex', req: 'Application Version Number (9F08) mevcut',
    run: (c) => c.has('9F08') ? PASS(c.val('9F08')) : FAIL('—') },
  { id: 'AX-02', cat: 'Amex', sev: 'M', scheme: 'Amex', req: 'Issuer Application Data (9F10) mevcut',
    run: (c) => { const v = c.val('9F10') || c.genac?.iad; return v ? PASS(v) : (c.hasCrypto ? FAIL('—', 'IAD yok') : WARN('—')); } },
  { id: 'AX-03', cat: 'Amex', sev: 'R', scheme: 'Amex', req: 'IAC Default/Denial/Online (9F0D/0E/0F) mevcut',
    run: (c) => { const iac = ['9F0D', '9F0E', '9F0F'].filter((t) => c.has(t)); return iac.length === 3 ? PASS('IAC tam') : WARN(`var: ${iac.join(',') || 'yok'}`); } },
  { id: 'AX-04', cat: 'Amex', sev: 'M', scheme: 'Amex', req: 'IAD (9F10) AEIPS formatı — makul uzunluk + CVN çıkarımı',
    run: (c) => { const v = c.val('9F10') || c.genac?.iad; if (!v) return c.hasCrypto ? FAIL('—', 'IAD yok') : NA('IAD yok'); if (v.length < 8) return FAIL(v, 'IAD çok kısa (AEIPS ≥ 4 bayt)'); return PASS(`CVN=${v.slice(2, 4)} · ${v.length / 2} bayt`); } },
  { id: 'AX-05', cat: 'Amex', sev: 'R', scheme: 'Amex', req: 'Application Effective Date (5F25) varsa geçerli YYMMDD',
    run: (c) => { const v = c.val('5F25'); if (!v) return WARN('—', '5F25 önerilir'); return /^[0-9]{6}$/.test(v) ? PASS(v) : FAIL(v, 'YYMMDD değil'); } },

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
    run: (c) => { if (!(c.aipB1 & 0x20)) return NA('DDA desteklenmiyor'); if (!c.hasCrypto || !c.oda?.capkFound) return NA('CAPK yok'); const d = c.dyn('DDA'); if (!d) return WARN('—', 'DDA imza üretilmedi (INTERNAL AUTH yok/qVSDC)'); const ok = d.hashMatch != null ? d.hashMatch : d.ok; return ok ? PASS('SDAD hash ✓') : (d.structOk ? WARN('yapısal ✓', 'Hash eşleşmedi') : FAIL('—', 'DDA imza doğrulanamadı')); } },
  { id: 'CRY-06', cat: 'ODA Kripto', sev: 'R', req: 'Application Cryptogram (ARQC/TC) üretildi (GENERATE AC)',
    run: (c) => { if (!c.hasCrypto) return NA('Kripto akışı yok'); const g = c.genac; if (!g || !g.arqc) return WARN('—', 'AC üretilmedi'); return PASS(`CID ${g.cid || '?'} · AC ${g.arqc}`); } },
  { id: 'CRY-07', cat: 'ODA Kripto', sev: 'R', req: 'ARQC işlem anahtarıyla doğrulandı',
    // Önerilen (R) kural: eşleşmezlik FAIL değil WARN — yanlış/eksik yapılandırılmış
    // işlem anahtarı da eşleşmezlik verir, bu bir kart kusuru olmayabilir.
    run: (c) => { if (!c.hasCrypto || !c.genac?.arqc) return NA('AC yok'); const v = c.genac.verify; if (!v) return NA('Doğrulama yok'); if (v.noKey) return WARN('—', 'Bu PAN için işlem anahtarı yok — İşlem Anahtarları sekmesi'); return v.match ? PASS(`anahtar ${v.keyLabel || ''}`) : WARN('—', 'ARQC eşleşmedi — anahtar yanlış/eksik olabilir'); } },
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
  return { iface, scheme: ctx.scheme, aid: ctx.aid, aip: ctx.aip, categories: cats, summary };
}
