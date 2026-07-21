// Oturum deposu — bir test oturumunun tüm sonuçlarını + metadata'sını tek bir
// .ktsession.json dosyası olarak backend/sessions/ altına yazar/okur. Sertifikasyon
// iş akışı için: test et → kaydet → ara ver → yükle → devam et / karşılaştır.
// Not: burada yalnızca EKRANDA GÖRÜNEN sonuç verisi tutulur; hiçbir gizli anahtar
// (AC/MAC/ENC master) saklanmaz — onlar sessionkeys.js'te kalır, yalnızca seçili
// anahtar setinin indeksi kaydedilir.
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'sessions');
const EXT = '.ktsession.json';

function ensureDir() {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

// Dosya adını güvenli hale getir (path traversal ve geçersiz karakterlere karşı).
const safeName = (name) => String(name || '')
  .replace(/[^a-zA-Z0-9 _.-]/g, '_')
  .replace(/\s+/g, ' ')
  .trim()
  .slice(0, 80) || 'oturum';

const toFile = (name) => {
  const base = safeName(name.replace(new RegExp(EXT.replace('.', '\\.') + '$'), ''));
  return base + EXT;
};

export function listSessions() {
  ensureDir();
  return fs.readdirSync(dir)
    .filter((f) => f.endsWith(EXT))
    .map((f) => {
      const st = fs.statSync(path.join(dir, f));
      let savedAt = st.mtime.toISOString();
      let scheme = null, pan = null;
      try {
        const j = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
        savedAt = j.savedAt || savedAt;
        scheme = j.state?.emv?.cardData?.scheme || j.state?.card?.scheme || null;
        pan = j.state?.emv?.cardData?.panFormatted || null;
      } catch { /* bozuk dosya — yine de listede göster */ }
      return { name: f.slice(0, -EXT.length), file: f, savedAt, size: st.size, scheme, pan };
    })
    .sort((a, b) => String(b.savedAt).localeCompare(String(a.savedAt)));
}

export function saveSession(name, snapshot) {
  ensureDir();
  const file = toFile(name);
  fs.writeFileSync(path.join(dir, file), JSON.stringify(snapshot, null, 1));
  return { file, name: file.slice(0, -EXT.length) };
}

export function loadSession(file) {
  ensureDir();
  const real = path.join(dir, toFile(file));
  if (!fs.existsSync(real)) return null;
  return JSON.parse(fs.readFileSync(real, 'utf8'));
}

export function deleteSession(file) {
  ensureDir();
  const real = path.join(dir, toFile(file));
  if (fs.existsSync(real)) { fs.unlinkSync(real); return true; }
  return false;
}
