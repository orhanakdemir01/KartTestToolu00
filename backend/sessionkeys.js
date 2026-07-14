// Store for per-card 3DES keys (AC / MAC / ENC) used in cryptogram processing.
import { readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { kcv } from './crypto3des.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const FILE = join(HERE, 'sessionkeys.json');

let keys = [];
try { keys = JSON.parse(readFileSync(FILE, 'utf-8')); } catch { keys = []; }

const clean = (s) => (s || '').replace(/\s/g, '').toUpperCase();
const isHex = (s, bytes) => /^[0-9A-F]*$/.test(s) && (!bytes || s.length === bytes * 2);

export function listKeys() { return keys; }

// Match a key set for a PAN (exact PAN match, else a default entry with no PAN).
export function findForPan(pan) {
  const p = clean(pan);
  return keys.find((k) => k.pan && clean(k.pan) === p)
      || keys.find((k) => !k.pan)
      || null;
}

// Find an exact key set by label (+ optional PAN) — used when the user picks one.
export function findExact(label, pan) {
  return keys.find((k) => k.label === label && clean(k.pan) === clean(pan || '')) || null;
}

// Validate + normalise a key-set input, computing KCVs. Returns { key } or { error }.
function buildKeySet(input) {
  const k = {
    label: (input.label || '').trim() || 'Anahtar seti',
    pan: clean(input.pan),
    psn: clean(input.psn) || '00',
    keyLevel: ['master', 'icc', 'session', 'auto'].includes(input.keyLevel) ? input.keyLevel : 'master',
    cvn: (input.cvn || 'mastercard'),
    acKey: clean(input.acKey),
    macKey: clean(input.macKey),
    encKey: clean(input.encKey),
  };
  if (!isHex(k.acKey, 16)) return { error: 'AC anahtarı 16 bayt (32 hex) olmalı', acKcv: '', macKcv: '', encKcv: '' };
  if (k.macKey && !isHex(k.macKey, 16)) return { error: 'MAC anahtarı 16 bayt (32 hex) olmalı' };
  if (k.encKey && !isHex(k.encKey, 16)) return { error: 'ENC anahtarı 16 bayt (32 hex) olmalı' };
  k.acKcv = kcv(k.acKey);
  k.macKcv = k.macKey ? kcv(k.macKey) : '';
  k.encKcv = k.encKey ? kcv(k.encKey) : '';
  const exp = (s) => clean(s);
  const mism = [];
  if (input.acKcv && exp(input.acKcv) !== k.acKcv) mism.push(`AC KCV ${k.acKcv}≠${exp(input.acKcv)}`);
  if (input.macKcv && k.macKcv && exp(input.macKcv) !== k.macKcv) mism.push(`MAC KCV ${k.macKcv}≠${exp(input.macKcv)}`);
  if (input.encKcv && k.encKcv && exp(input.encKcv) !== k.encKcv) mism.push(`ENC KCV ${k.encKcv}≠${exp(input.encKcv)}`);
  if (mism.length) return { error: 'KCV uyuşmuyor: ' + mism.join(', '), acKcv: k.acKcv, macKcv: k.macKcv, encKcv: k.encKcv };
  return { key: k };
}

const maskedView = (k) => ({ ...k, acKey: mask(k.acKey), macKey: mask(k.macKey), encKey: mask(k.encKey) });

export function addKeySet(input) {
  const { key: k, error, acKcv, macKcv, encKcv } = buildKeySet(input);
  if (error) return { added: false, reason: error, acKcv, macKcv, encKcv };
  keys = keys.filter((x) => !(x.label === k.label && clean(x.pan) === k.pan)); // replace same label+pan
  keys.push(k);
  try { writeFileSync(FILE, JSON.stringify(keys, null, 1)); } catch (e) { return { added: false, reason: 'Diske yazılamadı: ' + e.message }; }
  return { added: true, acKcv: k.acKcv, macKcv: k.macKcv, encKcv: k.encKcv, key: maskedView(k) };
}

// Update an existing key set found by original label+pan. Persists.
export function updateKeySet(input) {
  const origLabel = input.origLabel ?? input.label;
  const origPan = clean(input.origPan ?? input.pan);
  const at = keys.findIndex((x) => x.label === origLabel && clean(x.pan) === origPan);
  if (at < 0) return { updated: false, reason: 'Düzenlenecek anahtar bulunamadı' };
  const { key: k, error, acKcv, macKcv, encKcv } = buildKeySet(input);
  if (error) return { updated: false, reason: error, acKcv, macKcv, encKcv };
  const clash = keys.findIndex((x) => x.label === k.label && clean(x.pan) === k.pan);
  if (clash >= 0 && clash !== at) return { updated: false, reason: 'Bu etiket + PAN zaten başka bir kayıtta var' };
  const prev = keys[at];
  keys[at] = k;
  try { writeFileSync(FILE, JSON.stringify(keys, null, 1)); } catch (e) { keys[at] = prev; return { updated: false, reason: 'Diske yazılamadı: ' + e.message }; }
  return { updated: true, acKcv: k.acKcv, macKcv: k.macKcv, encKcv: k.encKcv, key: maskedView(k) };
}

// Full (unmasked) key set for the edit form — this is a local test tool.
export function getKeySet(label, pan) {
  return keys.find((k) => k.label === label && clean(k.pan) === clean(pan || '')) || null;
}

export function deleteKeySet(label, pan) {
  const before = keys.length;
  keys = keys.filter((x) => !(x.label === label && clean(x.pan) === clean(pan)));
  try { writeFileSync(FILE, JSON.stringify(keys, null, 1)); } catch (e) { return { deleted: false, reason: e.message }; }
  return { deleted: keys.length < before };
}

// Mask a key for display (show first/last 4 hex)
export function mask(h) {
  if (!h) return '';
  return h.length <= 8 ? h : `${h.slice(0, 4)}…${h.slice(-4)}`;
}

// Public view (keys masked)
export function listKeysMasked() {
  return keys.map((k) => ({ ...k, acKey: mask(k.acKey), macKey: mask(k.macKey), encKey: mask(k.encKey) }));
}
