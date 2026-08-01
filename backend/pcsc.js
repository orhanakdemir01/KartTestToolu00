import pcsclite from '@pokusew/pcsclite';

/**
 * PC/SC reader manager.
 * Tracks connected readers, the card present in each, and provides APDU transmit.
 * Emits no events outward — the REST layer just reads current state and calls transmit().
 */
class PcscManager {
  constructor() {
    this.available = false;       // true once the pcsclite layer is up
    this.lastError = null;
    this.readers = new Map();     // name -> { reader, present, atr, protocol, connected }
    // ── Oto-kurtarma durumu ──
    this._hadReaders = false;     // hiç okuyucu görüldü mü (boş makineyi kurtarmaya kalkma)
    this._zeroSince = null;       // okuyucu sayısı ne zamandır 0 (sessiz düşme tespiti)
    this._silentTries = 0;        // ardışık başarısız sessiz-kurtarma → backoff
    this.recovering = false;      // şu an context yeniden mi kuruluyor
    this.recoveryCount = 0;       // toplam kurtarma sayısı (izleme)
    this.lastRecoveryAt = null;
    this._init();
    this._startWatchdog();        // sessiz "0 okuyucu" düşmesini yakala (SDI011 combo)
  }

  _init() {
    try {
      this.pcsc = pcsclite();
      this.available = true;
    } catch (err) {
      this.available = false;
      this.lastError = err.message;
      this._scheduleReconnect(); // service down → retry until it comes back
      return;
    }

    this.pcsc.on('error', (err) => {
      // Fires when SCardSvr stops (e.g. reader unplugged). The context is now
      // stale and won't see a re-plugged reader, so re-establish it.
      this.lastError = err.message;
      this._scheduleReconnect();
    });

    this.pcsc.on('reader', (reader) => {
      console.log(`[pcsc] okuyucu algılandı: ${reader.name}`);
      // Okuyucu (yeniden) göründü → kurtarma durumunu temizle.
      this._hadReaders = true;
      this._zeroSince = null;
      this._silentTries = 0;
      this.recovering = false;
      const entry = { reader, present: false, atr: null, protocol: null, connected: false };
      this.readers.set(reader.name, entry);

      reader.on('error', (err) => {
        this.lastError = `${reader.name}: ${err.message}`;
      });

      reader.on('status', (status) => {
        const changes = reader.state ^ status.state;
        if (!changes) return;

        // Card removed
        if ((changes & reader.SCARD_STATE_EMPTY) && (status.state & reader.SCARD_STATE_EMPTY)) {
          if (entry.connected) {
            reader.disconnect(reader.SCARD_LEAVE_CARD, () => {});
          }
          entry.present = false;
          entry.atr = null;
          entry.protocol = null;
          entry.connected = false;
        }

        // Card inserted
        if ((changes & reader.SCARD_STATE_PRESENT) && (status.state & reader.SCARD_STATE_PRESENT)) {
          entry.present = true;
          entry.atr = status.atr && status.atr.length ? status.atr : null;
          reader.connect(
            { share_mode: reader.SCARD_SHARE_SHARED },
            (err, protocol) => {
              if (err) {
                this.lastError = `connect ${reader.name}: ${err.message}`;
                entry.connected = false;
                return;
              }
              entry.protocol = protocol;
              entry.connected = true;
            }
          );
        }
      });

      reader.on('end', () => {
        this.readers.delete(reader.name);
      });
    });
  }

  // Re-establish the PC/SC context (debounced) so an unplugged→replugged reader
  // is detected without restarting the backend.
  _scheduleReconnect(delay = 4000) {
    if (this._reconnectTimer) return;
    console.log(`[pcsc] hata algılandı (${this.lastError}) — ${delay}ms sonra yeniden bağlanılacak`);
    this._reconnectTimer = setTimeout(() => { this._reconnectTimer = null; this._reconnect(); }, delay);
  }

  _reconnect() {
    console.log('[pcsc] PC/SC context yeniden kuruluyor…');
    const old = this.pcsc;
    this.pcsc = null;
    this.readers.clear();
    try {
      if (old) {
        if (typeof old.removeAllListeners === 'function') old.removeAllListeners();
        // close() bir SCardCancel tetikler → context 'error' (0x80100002
        // SCARD_E_CANCELLED) yayar. Dinleyicisiz 'error' Node'u çökertir; bu
        // yüzden kapatmadan hemen önce yutucu bir handler ekle.
        if (typeof old.on === 'function') old.on('error', () => {});
        if (typeof old.close === 'function') old.close();
      }
    } catch { /* ignore close errors */ }
    this._init(); // new context picks up current readers; if still down, error reschedules
  }

  // Sağlık watchdog'u — bazı okuyucular (ör. SDI011 combo) PC/SC katmanından
  // SESSİZCE düşer: 'error' eventi ateşlenmez, okuyucu sayısı 0'a iner ve context
  // kendini toparlamaz (backend restart gerekirdi). Bu döngü o durumu yakalar:
  // daha önce okuyucu görülmüşken sayı bir süredir 0 ise context'i proaktif kurar.
  _startWatchdog(intervalMs = 5000, baseGraceMs = 6000) {
    if (this._watchdog) return;
    this._watchdog = setInterval(() => this._healthTick(baseGraceMs), intervalMs);
    if (this._watchdog.unref) this._watchdog.unref(); // süreç kapanışını engelleme
  }

  _healthTick(baseGraceMs) {
    if (!this.available || this._reconnectTimer) return; // servis düştüyse init/error kurtarıyor
    const count = this.readers.size;
    if (count > 0) { this._zeroSince = null; this._silentTries = 0; this.recovering = false; return; }
    if (!this._hadReaders) return;              // hiç okuyucu görülmedi (boş makine) → dokunma
    const now = Date.now();
    if (!this._zeroSince) { this._zeroSince = now; return; } // bir tur bekle — geçici olabilir
    // Ardışık başarısız kurtarmada geri çekil (6s→12s→24s… max 60s) ki okuyucu
    // gerçekten çıkarıldıysa log'u ve context'i sürekli kurcalamayalım.
    const grace = Math.min(baseGraceMs * 2 ** this._silentTries, 60000);
    if (now - this._zeroSince < grace) return;
    console.log(`[pcsc] okuyucu 0'a düştü (sessiz) — context proaktif yeniden kuruluyor (deneme ${this._silentTries + 1})`);
    this._zeroSince = null;
    this._silentTries++;
    this.recovering = true;
    this.recoveryCount++;
    this.lastRecoveryAt = now;
    this._reconnect();
  }

  // Operatör tetiklemeli anında kurtarma (backend restart yerine "Okuyucu Kurtar"
  // butonu). Bekleyen gecikmeleri atlar, context'i hemen yeniden kurar.
  forceRecover() {
    if (this._reconnectTimer) { clearTimeout(this._reconnectTimer); this._reconnectTimer = null; }
    this._zeroSince = null;
    this._silentTries = 0; // operatör bilerek istedi → hemen dene, backoff'u sıfırla
    this.recovering = true;
    this.recoveryCount++;
    this.lastRecoveryAt = Date.now();
    console.log('[pcsc] elle kurtarma tetiklendi — context yeniden kuruluyor');
    this._reconnect();
    return this.getHealth();
  }

  // PC/SC sağlık özeti — frontend'in kurtarma göstergesi + "Kurtar" butonu için.
  getHealth() {
    return {
      available: this.available,
      readerCount: this.readers.size,
      hadReaders: this._hadReaders,
      recovering: this.recovering,
      recoveryCount: this.recoveryCount,
      lastRecoveryAt: this.lastRecoveryAt,
      lastError: this.lastError,
    };
  }

  /** List reader names currently known to the PC/SC layer. */
  listReaders() {
    return Array.from(this.readers.keys());
  }

  /** Per-reader status (name, card present, ATR, protocol). */
  getReaderStatus() {
    return Array.from(this.readers.entries()).map(([name, e]) => ({
      reader: name,
      present: e.present,
      atr: e.present && e.atr ? hex(e.atr) : null,
      protocol: e.protocol === 1 ? 'T=0' : e.protocol === 2 ? 'T=1' : null,
      connected: e.connected,
      contactless: /contactless/i.test(name),
    }));
  }

  /**
   * Return info about a card. If preferName is given and that reader has a
   * card, use it; otherwise fall back to the first reader with a card present.
   */
  getActiveCard(preferName) {
    const pick = (name, e) => ({
      reader: name,
      atr: e.atr ? hex(e.atr) : null,
      protocol: e.protocol === 1 ? 'T=0' : e.protocol === 2 ? 'T=1' : 'unknown',
      connected: e.connected,
      contactless: /contactless/i.test(name),
    });
    // Belirli bir okuyucu istendiyse KATI davran: kart o okuyucuda yoksa null
    // dön — farklı bir arayüze (ör. temaslı istenip temassıza) sessizce DÜŞME.
    // Sertifikasyonda hangi arayüzün test edildiği kritiktir; fallback yanlış
    // arayüzü doğru sanıp "GEÇTİ" raporlamaya yol açar.
    if (preferName) {
      const e = this.readers.get(preferName);
      return e && e.present ? pick(preferName, e) : null;
    }
    for (const [name, e] of this.readers) {
      if (e.present) return pick(name, e);
    }
    return null;
  }

  // Tek APDU gönderimi (düşük seviye).
  _rawTransmit(target, apduBuffer) {
    return new Promise((resolve, reject) => {
      target.reader.transmit(apduBuffer, 512, target.protocol, (err, data) => {
        if (err) return reject(err);
        const full = hex(data);
        const sw = data.length >= 2 ? hex(data.slice(-2)).replace(/\s/g, '') : '';
        resolve({ response: full, sw });
      });
    });
  }

  // Karta yeniden bağlan (SCardReconnect, kartı resetleyerek). Bağlantı bayatladıysa
  // (kart sıfırlandı) toparlar; yeni protokolü entry'e yazar.
  _reconnectCard(target) {
    return new Promise((resolve, reject) => {
      const r = target.reader;
      r.reconnect(
        { share_mode: r.SCARD_SHARE_SHARED, initialization: r.SCARD_RESET_CARD },
        (err, protocol) => {
          if (err) return reject(err);
          target.protocol = protocol;
          target.connected = true;
          resolve();
        }
      );
    });
  }

  /**
   * Transmit an APDU (Buffer) to the first connected card.
   * Kart-reset (0x80100068 SCARD_W_RESET_CARD / 0x80100069 SCARD_W_REMOVED_CARD)
   * hatasında bir kez yeniden bağlanıp tekrar dener — bir işlemden (transaction)
   * sonra bayatlayan bağlantı için backend restart gerektirmeden kendini toparlar.
   * Returns a Promise resolving to { response, sw } as hex strings.
   */
  async transmit(apduBuffer, preferName) {
    let target = null;
    if (preferName) {
      // KATI: istenen okuyucuda bağlı kart yoksa BAŞKA okuyucuya düşme.
      const e = this.readers.get(preferName);
      if (e && e.present && e.connected) target = e;
    } else {
      for (const [, e] of this.readers) {
        if (e.present && e.connected) { target = e; break; }
      }
    }
    if (!target) {
      throw new Error(preferName
        ? `İstenen okuyucuda bağlı kart yok: ${preferName}`
        : 'No connected card available');
    }

    try {
      return await this._rawTransmit(target, apduBuffer);
    } catch (err) {
      const reset = /0x8010006[89]\b/i.test(String(err?.message || ''));
      if (!reset) throw err;
      // Kart oturumu geçersiz — yeniden bağlan ve bir kez daha dene.
      await this._reconnectCard(target);
      return await this._rawTransmit(target, apduBuffer);
    }
  }
}

function hex(buf) {
  return Array.from(buf)
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join(' ');
}

export default new PcscManager();
