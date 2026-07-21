# KartTest — Smart Card / EMV Test Tool

Temaslı ve temassız EMV kartları için PC/SC tabanlı bir test/analiz aracı. FIME / UL(Collis) / Barnes / Perceval tarzı sertifikasyon akışlarının çekirdeğini hedefler: perso okuma, offline data authentication, kriptogram doğrulama ve kural-bazlı uyumluluk denetimi.

## Özellikler

- **Kart & EMV okuma** — PPSE/PSE → SELECT AID → GPO → READ RECORD zinciri, ATR çözümleme, TLV ağacı
- **Kart Image** — kartın tüm personalize EMV tag'lerini çıkarma (AFL-odaklı okuma + GET DATA sweep + CPLC), CPV/VPA perso doğrulama
- **Offline Sertifika** — DDA / CDA / fDDA sertifika zinciri (CAPK → Issuer PK → ICC PK) ve dinamik imza doğrulama
- **Uyumluluk** — EMV çekirdek + Mastercard CPV kural motoru; kriptografik ODA/ARQC entegrasyonu; temaslı↔temassız matris; HTML sertifikasyon raporu
- **Terminal / Senaryo** — yapılandırılabilir terminal profili + TC/ARQC/AAC senaryo koşucusu
- **PDF Profil** — Mastercard Profile Advisor raporu PDF'ini parse edip kartla (temaslı/temassız) karşılaştırma
- **Anahtarlar & PIN** — CAPK ve işlem anahtarı yönetimi, PIN değiştir/doğrula (Mastercard/Visa/Amex/Troy)
- **APDU Konsolu** — ham APDU gönderme + hızlı komutlar + APDU oluşturucu

## Mimari

- **backend/** — Node.js + Express, PC/SC (`@pokusew/pcsclite`), saf JS EMV/kripto (RSA ODA, 3DES ARQC), PDF parse (`pdfjs-dist`)
- **frontend/** — React + Vite (tek sayfa, iki seviyeli sekme navigasyonu)
- **packaging/** — standalone Windows `.exe` ve tek dosya `Setup.exe` build script'leri

## Çalıştırma (geliştirme)

```bash
cd backend && npm install && node server.js      # http://localhost:3001
cd frontend && npm install && npm run dev         # http://localhost:5173
```

## Uzaktan Erişim (LAN)

Backend, aynı ağdaki başka bir cihazdan da kontrol edilebilir: arayüzdeki
**🌐 Uzaktan Erişim** rozetine tıklayınca (kart okuyucuyu barındıran
makinede) LAN adresi ve tek seferlik erişim token'ı görüntülenir. Uzaktaki
cihazda o adrese tarayıcıyla gidip aynı rozetten token'ı girmek yeterlidir.

Yerel makineden (localhost) gelen istekler her zaman doğrudan çalışır; ağdan
gelen her istek (kart okuma, APDU gönderme, PIN değiştirme dahil) token
doğrulaması gerektirir — token her başlatmada yeniden üretilir, sabitlemek
isterseniz `KARTTEST_REMOTE_TOKEN` ortam değişkenini kullanabilirsiniz.

## Windows dağıtımı

```powershell
powershell -ExecutionPolicy Bypass -File packaging\build-exe.ps1     # dist-win\KartTest\ (taşınabilir klasör)
powershell -ExecutionPolicy Bypass -File packaging\build-setup.ps1   # dist-win\KartTest-Setup.exe (tek dosya kurulum)
```

`KartTest.exe` backend'i başlatır ve tarayıcıda arayüzü açar. Native `pcsclite.node` sistem `node.exe`'siyle birlikte paketlenir (ABI eşleşmesi için ek derleme gerekmez).

## Gereksinimler

- Windows + PC/SC uyumlu kart okuyucu (geliştirmede SDI011 combo temaslı/temassız)
- Node.js 20+
