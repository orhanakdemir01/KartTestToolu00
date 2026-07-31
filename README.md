# KartTest — EMV Kart Analiz & Ön-Sertifikasyon Aracı

Temaslı ve temassız EMV kartları için PC/SC tabanlı, **spec-izlenebilir** bir analiz / QA / ön-sertifikasyon aracı. Perso okuma, offline data authentication (ODA), kriptogram (ARQC/ARPC) doğrulama ve kural-bazlı uyumluluk denetimini tek araçta toplar; her verdikt otoriter bir EMV/ISO kaynağına izlenebilir.

> **Kapsam — dürüst beyan.** Bu bir **analiz / QA / laboratuvar-öncesi** araçtır. FIME · UL (Collis) · Galitt (Perceval) · Barnes gibi **resmi sertifika ÜRETMEZ**: bunlar EMVCo/şema akreditasyonu, lisanslı L2/L3 test paketleri ve L1 elektriksel donanım gerektirir. KartTest, açık spec'lere (EMV Book 1–4, ISO 7816/7813/7812/4217/3166) dayanarak kartı **resmi laboratuvara göndermeden önce** hataları yakalar — geçen bir kart, resmi labda geçme olasılığı yüksek olan karttır. Araç içindeki **Kapsam Haritası** neyin test edilip edilmediğini açıkça gösterir.

## Öne çıkan yetenekler

- **Kart & EMV okuma** — PPSE/PSE → SELECT AID → GPO → READ RECORD zinciri, ATR/TLV çözümleme, şema-renkli kart görseli
- **Kart Image** — tüm personalize EMV tag'lerini çıkarma (AFL-odaklı + GET DATA sweep + CPLC), **altın-referans regresyon** (onaylı profile karşı alan-alan diff)
- **Offline Doğrulama (ODA)** — SDA/DDA/CDA/fDDA sertifika zinciri (CAPK → Issuer PK → ICC PK), uzunluk/son-kullanma/algoritma doğrulama, dinamik imza kripto
- **Uyumluluk** — **125+ kural / 21 kategori**, EMV çekirdek + şema-özel (Mastercard CPV, Visa VIS/qVSDC, Amex, Discover/Troy D-PAS, JCB, UnionPay), kriptografik ODA/ARQC entegrasyonu, temaslı↔temassız matris, CVN tanımlama, bit-alanı çözümleme (AIP/AUC/IAC/CVM), Terminal Action Analysis
- **Issuer Authentication (ARPC)** — ARPC üretimi + **diferansiyel karta-doğrulatma** (doğru ARPC → TC ∧ bozuk ARPC → AAC ⇒ kart issuer-auth'u kriptografik doğruluyor); şema-farkında session key, ARQC-doğrulamalı
- **Kripto Öz-testi (kalibrasyon)** — aracın kendi kriptosunu (3DES · Retail MAC · ARQC/ARPC · anahtar türetme) karta ihtiyaç duymadan **bağımsız referans vektörlere** karşı doğrular (NIST DES + kart ground-truth + bağımsız hesaplayıcı)
- **Birleşik Denetim Raporu** — uyumluluk + ODA + ARPC + kapsam haritası + öz-test kalibrasyonu, tek otoriter, izlenebilir, imzalanabilir belge
- **Terminal / Senaryo** — yapılandırılabilir terminal profili + TC/ARQC/AAC senaryo koşucusu
- **PDF Profil** — Mastercard Profile Advisor PDF'ini parse edip kartla karşılaştırma
- **Oturum Anahtarları & PIN** — CAPK ve 3DES oturum anahtarı yönetimi, PIN değiştir/doğrula (Mastercard/Visa/Amex/Troy)
- **APDU Konsolu** — ham APDU + hızlı komutlar + APDU oluşturucu + TLV çözümleme

Modül-modül kullanım için: **[Operatör Kılavuzu](docs/OPERATOR.md)**.

## Mimari

- **backend/** — Node.js + Express, PC/SC (`@pokusew/pcsclite`), saf JS EMV/kripto (RSA ODA, 3DES ARQC/ARPC, `node-forge`), PDF parse (`pdfjs-dist`)
- **frontend/** — React + Vite (tek sayfa, iki seviyeli sekme navigasyonu)
- **packaging/** — standalone Windows `.exe` ve tek dosya `Setup.exe` build script'leri

## Çalıştırma (geliştirme)

```bash
cd backend && npm install && node server.js      # http://localhost:3001
cd frontend && npm install && npm run dev         # http://localhost:5173
```

## Windows dağıtımı

```powershell
powershell -ExecutionPolicy Bypass -File packaging\build-exe.ps1     # dist-win\KartTest\ (taşınabilir klasör)
powershell -ExecutionPolicy Bypass -File packaging\build-setup.ps1   # dist-win\KartTest-Setup.exe (tek dosya kurulum)
```

`KartTest.exe` backend'i başlatır ve tarayıcıda arayüzü açar; native `pcsclite.node` sistem `node.exe`'siyle paketlenir (ek derleme gerekmez). Standalone `.exe` **offline** çalışır. Sürümler ayrı bir public releases repo'suna GitHub Actions ile yayınlanır (bir `v*` tag push edilince).

## Gereksinimler

- Windows + PC/SC uyumlu kart okuyucu (geliştirmede SDI011 combo temaslı/temassız)
- Node.js 20+

## Güvenlik notu

`backend/capk.json` **public CA anahtarlarını** tutar (gizli değil). Oturum anahtarı deposu yalnızca **test/dummy** anahtarları içerir. Gerçek issuer anahtarlarını depoya koymayın.
