# KartTest — Operatör Kılavuzu

Bu kılavuz, bir kartı KartTest ile değerlendirirken izlenecek akışı, her modülün ne işe yaradığını, verdiktlerin anlamını ve sık karşılaşılan durumları açıklar.

---

## 1. Hızlı başlangıç

1. Okuyucuyu bağla, kartı tak (temaslı yuva veya temassız alan).
2. Üst çubukta okuyucu ve kart durumunu doğrula (● Kart Bağlı).
3. Aşağıdaki **tipik akışı** izle.

### Tipik değerlendirme akışı (bir kart)

| Adım | Sekme | Ne yapar |
|---|---|---|
| 1 | **Kart & EMV** | Kartı oku: PPSE → SELECT AID → GPO → READ RECORD → GENERATE AC. Kart görseli + kriptogram. |
| 2 | **Uyumluluk** | 125+ kuralı çalıştır (temaslı ve temassız ayrı). Verdikt + spec izlenebilirliği. |
| 3 | **Offline Doğrulama (ODA)** | Sertifika zinciri + DDA/CDA/fDDA dinamik imza. |
| 4 | **Oturum Anahtarları → Issuer Auth (ARPC)** | Anahtar varsa issuer authentication'ı diferansiyel test et. |
| 5 | **Kart Image → Altın Referans** | Onaylı profile karşı alan-alan diff (perso QA). |
| 6 | **Rapor** | Tek birleşik denetim belgesi üret (yazdır/indir). |

---

## 2. Modüller

### Genel Bakış
Aracın kabiliyet manifesti: şema/kernel/kural/CAPK sayıları, **Kapsam Haritası** (neyin test edilip edilmediği) ve **Kripto Öz-testi** butonu. Öz-testi çalıştır → `N/N geçti · M/M bağımsız` görmelisin (aracın kalibrasyonu).

### Kart & EMV
Tam EMV okuma zincirini çalıştırır. **▶ EMV Akışını Çalıştır** → kart görseli perso verisinden dolar (PAN, isim, son kullanma, şema). Altında AID/AIP/AFL/Service Code, GENERATE AC (kriptogram) ve CAPK bulundu bilgisi. Ham APDU adımları alt Trace dock'unda.

### Kart Image
Karttaki **tüm** personalize tag'leri çıkarır (AFL + tüm SFI brute-force + GET DATA sweep + CPLC). Modlar:
- **Kart Image** — tag dökümü + kart görseli
- **Dual-Interface** — temaslı ↔ temassız karşılaştırma
- **Kart ↔ Kart** — iki kartı diff'le
- **Altın Referans** — onaylı bir kartı referans kaydet, sonraki kartları alan-alan diff'le (perso sürüklenmesi yakalama). "Sadece A" = referansta var kartta yok (olası perso hatası).
- **Profil Karşılaştır** — beklenen profil metnine karşı diff

### Offline Doğrulama (ODA)
CAPK → Issuer PK → ICC PK sertifika zincirini kriptografik çözer ve dinamik imzayı (DDA/CDA/fDDA) doğrular. Her iki arayüzü ayrı test et. Temassız fast-DDA (fDDA) burada doğrulanır.

### Uyumluluk
Kart imajını + canlı kriptoyu 125+ kurala karşı denetler. Her kural: `ID · önem (M/R/C) · gereksinim · durum · kanıt · spec kaynağı`. Verdikt = en kötü sonuç; **zorunlu (M/C) FAIL** sertifikasyonu bloklar, öneri (R) yalnızca uyarıdır. Temaslı ve temassız sonuçlar bir matriste karşılaştırılabilir.

### Issuer Authentication (ARPC) — Oturum Anahtarları sekmesi
Kartın ARQC'sinden ARPC üretir ve **diferansiyel test** ile karta doğrulatır:
- **doğru ARPC → TC (kabul)** ∧ **bozuk ARPC → AAC (red)** ⇒ **PASS** (kart issuer-auth'u kriptografik doğruluyor)
Kullanım: anahtar seti seç → yöntem (auto) → **ARPC Üret & Karta Doğrulat**. Karta giden ham APDU (2. GENERATE AC / EXTERNAL AUTHENTICATE, tag 91) Trace'te görünür.

### Terminal / Senaryo · PDF Profil · CA Anahtarları · Oturum Anahtarları · PIN
- **Terminal / Senaryo** — terminal profili + TC/ARQC/AAC senaryoları.
- **PDF Profil** — Mastercard Profile Advisor PDF ↔ kart karşılaştırma.
- **CA Anahtarları** — CAPK deposu (RID + index).
- **Oturum Anahtarları** — 3DES AC/MAC/ENC anahtarları + ARPC paneli.
- **PIN** — offline PIN değiştir (84 24) / doğrula (00 20).

### Rapor · Oturum · Geçmiş · Parti
- **Rapor** — birleşik denetim belgesi (DUT → kapsam → uyumluluk → ODA → ARPC → öz-test → imza).
- **Oturum** — testi kaydet/yükle.
- **Geçmiş** — kart-bazlı regresyon trendi (PASS↔FAIL geçişleri).
- **Parti** — çoklu-kart QA.

---

## 3. Verdikt anlamları

| Verdikt | Anlam |
|---|---|
| **PASS** | Doğrulandı. |
| **WARN** | Öneri düzeyinde sorun veya belirsizlik; sertifikasyonu bloklamaz. |
| **FAIL** | Zorunlu gereksinim karşılanmadı (mandatory ise bloklar). |
| **NA** | Uygulanamaz — bu kart/akış bu kontrolü kapsamıyor (kusur DEĞİL). |

**Önemli örnek — ARPC NA:** Kart doğru ve bozuk ARPC'ye **aynı** yanıtı verirse (ör. ikisi de AAC) ve ARQC doğrulanmışsa, kart offline TC vermiyor (online-zorunlu yapılandırma) demektir. Bu **NA**'dır — kripto sorunu yok, kart kusuru yok, test bu karta uygulanamıyor.

---

## 4. Kapsam ve sınırlar (dürüst)

Araç **açık spec'lere** dayanır ve **resmi sertifika üretmez**. Kapsam Haritası (Genel Bakış) tam listeyi verir. Özet:

- **Kapsanır:** APDU/iletişim, uygulama seçimi, işlem akışı, ODA (SDA/DDA/CDA/fDDA), CVM, ARQC/ARPC, risk/aksiyon analizi, perso/veri bütünlüğü.
- **Kısmen:** L1 (yalnızca ATR/protokol; elektriksel/RF yok), kernel uygunluk (Type Approval değil), L3 (senaryo var, lisanslı şema test paketleri yok).
- **Kapsam dışı:** Aracın EMVCo/şema akreditasyonu, L1 donanım testleri, lisanslı L2/L3 test suite'leri.

Kartın tam **resmi** sertifikasyonu için akredite bir laboratuvar (FIME/UL/Galitt/Barnes) gerekir. KartTest o koşuya hazırlık ve QA katmanıdır.

---

## 5. Kripto güveni (kalibrasyon)

Her ARQC/ARPC/ODA verdikti, altındaki kriptonun doğruluğuna dayanır. **Genel Bakış → Kripto Öz-testi** aracın kendi 3DES / Retail MAC / anahtar-türetme / ARQC / ARPC matematiğini **bağımsız referanslara** karşı doğrular (NIST/klasik DES vektörü + gerçek kart ground-truth + bağımsız hesaplayıcı). Değerlendirmeden önce `bağımsız` testlerin hepsinin geçtiğini gör — bir ölçüm aletinin kalibrasyon sertifikası gibi.

---

## 6. Sorun giderme

| Belirti | Çözüm |
|---|---|
| Okuyucu 0'a düştü / kart askıda (0x8010006x) | Backend'i yeniden başlat (SDI011 combo bilinen durum). |
| ARQC "eşleşmedi / anahtar yok" | Kartın PAN'ına ait doğru issuer anahtarı **Oturum Anahtarları**'nda yüklü değil. |
| ARPC **NA** (belirsiz değil) | Kart offline TC vermiyor (online-zorunlu) — kusur değil, test kapsam dışı. Bkz. §3. |
| Temassız ODA kısmi / ICC PK yok | AFL'siz qVSDC kart — Issuer PK kurtarılır ama ICC PK hash'i için SDA verisi tanımsız. Tam ODA temaslı arayüzdedir. |
| CA anahtarı 0 (şema) | O şema için CAPK yok — **CA Anahtarları**'ndan ekle. |

---

*Bu kılavuz araçla birlikte sürümlenir. Kapsam beyanı ve kural motoru sürümle güncellenir.*
