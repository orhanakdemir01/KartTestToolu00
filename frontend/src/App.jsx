import { useState, useEffect, useRef } from 'react';
import './App.css';
import { buildReportHtml, traceCsv, tlvTreeHtml, TLV_CSS } from './lib/report.js';
import { CardTab } from './components/tabs/CardTab.jsx';
import { ApduTab } from './components/tabs/ApduTab.jsx';
import { TestTab } from './components/tabs/TestTab.jsx';
import { CapkTab } from './components/tabs/CapkTab.jsx';
import { KeysTab } from './components/tabs/KeysTab.jsx';
import { PinTab } from './components/tabs/PinTab.jsx';
import { CardImageTab } from './components/tabs/CardImageTab.jsx';
import { OdaTab } from './components/tabs/OdaTab.jsx';
import { ComplianceTab } from './components/tabs/ComplianceTab.jsx';
import { TerminalTab } from './components/tabs/TerminalTab.jsx';
import { ProfilePdfTab } from './components/tabs/ProfilePdfTab.jsx';
import { ReportTab } from './components/tabs/ReportTab.jsx';
import { TraceDock } from './components/TraceDock.jsx';

const API = 'http://localhost:3001/api';

// SW1SW2 values that are expected "misses" during a GET DATA / read sweep — the
// card simply doesn't hold that object. Muted in the trace instead of warned.
const BENIGN_SW = new Set(['6A88', '6D00', '6A81', '6E00', '6985', '6A82', '6A83', '6700']);

const QUICK = [
  { group: 'Uygulama Seçimi', items: [
    { label: 'SELECT PPSE', cmd: '00 A4 04 00 0E 32 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00' },
    { label: 'SELECT PSE', cmd: '00 A4 04 00 0E 31 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00' },
    { label: 'Visa', cmd: '00 A4 04 00 07 A0 00 00 00 03 10 10 00' },
    { label: 'Mastercard', cmd: '00 A4 04 00 07 A0 00 00 00 04 10 10 00' },
    { label: 'Amex', cmd: '00 A4 04 00 06 A0 00 00 00 25 01 00' },
    { label: 'Troy', cmd: '00 A4 04 00 07 A0 00 00 06 72 30 10 00' },
  ] },
  { group: 'İşlem / Okuma', items: [
    { label: 'GPO (boş PDOL)', cmd: '80 A8 00 00 02 83 00 00' },
    { label: 'READ SFI1 #1', cmd: '00 B2 01 0C 00' },
    { label: 'READ SFI2 #1', cmd: '00 B2 01 14 00' },
    { label: 'READ SFI3 #1', cmd: '00 B2 01 1C 00' },
    { label: 'READ SFI4 #1', cmd: '00 B2 01 24 00' },
  ] },
  { group: 'GET DATA', items: [
    { label: 'ATC (9F36)', cmd: '80 CA 9F 36 00' },
    { label: 'PIN Deneme (9F17)', cmd: '80 CA 9F 17 00' },
    { label: 'Son Online ATC (9F13)', cmd: '80 CA 9F 13 00' },
    { label: 'Log Format (9F4F)', cmd: '80 CA 9F 4F 00' },
    { label: 'App Config C1 (DPAS)', cmd: '80 CA 00 C1 00' },
  ] },
  { group: 'Kimlik Doğrulama', items: [
    { label: 'GET CHALLENGE', cmd: '00 84 00 00 08' },
    { label: 'INTERNAL AUTH (UN)', cmd: '00 88 00 00 04 12 34 56 78 00' },
    { label: 'VERIFY PIN 1234', cmd: '00 20 00 80 08 24 12 34 FF FF FF FF FF', fill: true },
  ] },
  // PUT DATA (INS DA): P1-P2 = yazılacak veri nesnesinin tag'ı. Çoğu kartta
  // issuer script olduğu için secure messaging (84 DA + MAC) gerekir; şablonlar
  // sadece kutuya doldurur — kullanıcı gözden geçirip gönderir.
  { group: 'Yazma · PUT DATA (80 DA)', items: [
    { label: 'PUT DATA şablon', cmd: '80 DA 00 00 00', fill: true },
    { label: 'PUT · PTC 9F17=3', cmd: '80 DA 9F 17 01 03', fill: true },
    { label: 'PUT · ATC 9F36', cmd: '80 DA 9F 36 02 00 01', fill: true },
    { label: 'PUT · Son Online ATC 9F13', cmd: '80 DA 9F 13 02 00 00', fill: true },
  ] },
];

// Tabs grouped into logical categories → two-level navigation (group row + sub-tabs).
const TAB_GROUPS = [
  { id: 'read', label: 'Okuma & Analiz', icon: '📖', tabs: [
    { id: 'card', label: 'Kart & EMV' },
    { id: 'image', label: 'Kart Image' },
    { id: 'apdu', label: 'APDU Konsolu' },
  ] },
  { id: 'cert', label: 'Sertifikasyon', icon: '🛡️', tabs: [
    { id: 'compliance', label: 'Uyumluluk' },
    { id: 'profilepdf', label: 'PDF Profil' },
    { id: 'oda', label: 'Offline Sertifika' },
    { id: 'terminal', label: 'Terminal / Senaryo' },
    { id: 'test', label: 'Test' },
  ] },
  { id: 'keymgmt', label: 'Anahtarlar & PIN', icon: '🔑', tabs: [
    { id: 'capk', label: 'CA Anahtarları' },
    { id: 'keys', label: 'İşlem Anahtarları' },
    { id: 'pin', label: 'PIN Değiştir' },
  ] },
  { id: 'output', label: 'Rapor', icon: '📄', tabs: [
    { id: 'report', label: 'Rapor' },
  ] },
];

function App() {
  const [mode, setMode] = useState(null);
  const [readers, setReaders] = useState([]);
  const [readerStatus, setReaderStatus] = useState([]);
  const [selectedReader, setSelectedReader] = useState(null); // null = otomatik
  const [card, setCard] = useState(null);
  const [cardPresent, setCardPresent] = useState(false);
  const [raw, setRaw] = useState('00 84 00 00 08');
  const [builder, setBuilder] = useState({ cla: '00', ins: 'A4', p1: '04', p2: '00', data: '', le: '' });
  const [resp, setResp] = useState(null);
  const [emv, setEmv] = useState(null);
  const [emvBusy, setEmvBusy] = useState(false);
  const [suites, setSuites] = useState([]);
  const [suiteJson, setSuiteJson] = useState('');
  const [testResult, setTestResult] = useState(null);
  const [testBusy, setTestBusy] = useState(false);
  const [trace, setTrace] = useState([]);
  const [activeTab, setActiveTab] = useState('card');
  const [groupLast, setGroupLast] = useState({}); // remember last sub-tab per group
  const [traceOpen, setTraceOpen] = useState(true);
  const [uid, setUid] = useState(null);
  const [uidBusy, setUidBusy] = useState(false);
  const [capks, setCapks] = useState([]);
  const [capkSchemes, setCapkSchemes] = useState({});
  const [capkFilter, setCapkFilter] = useState('all');
  const [addForm, setAddForm] = useState({ scheme: '', rid: '', index: '', exponent: '03', modulus: '', hash: '' });
  const [addResult, setAddResult] = useState(null);
  const [capkEdit, setCapkEdit] = useState(null); // { origRid, origIndex } while editing, else null
  const [sessionKeys, setSessionKeys] = useState([]);
  const [keyForm, setKeyForm] = useState({ label: '', pan: '', psn: '00', keyLevel: 'master', cvn: 'mastercard', acKey: '', macKey: '', encKey: '' });
  const [keyAddResult, setKeyAddResult] = useState(null);
  const [keyEdit, setKeyEdit] = useState(null); // { origLabel, origPan } while editing, else null
  const [selectedKeyIdx, setSelectedKeyIdx] = useState(-1);
  const [pinForm, setPinForm] = useState({ keyLabel: '', keyPan: '', newPin: '', mode: 'change', aid: '', pan: '', atc: '', p1: '', p2: '' });
  const [pinBusy, setPinBusy] = useState(false);
  const [pinResult, setPinResult] = useState(null);
  const [verifyForm, setVerifyForm] = useState({ pin: '' });
  const [verifyBusy, setVerifyBusy] = useState(false);
  const [verifyResult, setVerifyResult] = useState(null);
  const [cardImage, setCardImage] = useState(null);
  const [imageBusy, setImageBusy] = useState(false);
  const [imageA, setImageA] = useState(null);
  const [imageB, setImageB] = useState(null);
  const [captureBusy, setCaptureBusy] = useState('');
  const [imageContact, setImageContact] = useState(null);
  const [imageContactless, setImageContactless] = useState(null);
  const [dualPhase, setDualPhase] = useState('');
  const dualCancel = useRef(false);
  const [imageAcl, setImageAcl] = useState(null); // Kart A contactless (Kart↔Kart dual)
  const [imageBcl, setImageBcl] = useState(null); // Kart B contactless
  const [cardDualPhase, setCardDualPhase] = useState('');
  const [cardDualSlot, setCardDualSlot] = useState('');
  const cardDualCancel = useRef(false);
  const [odaContact, setOdaContact] = useState(null);       // Offline Sertifika — contact result
  const [odaContactless, setOdaContactless] = useState(null); // contactless result
  const [odaBusy, setOdaBusy] = useState('');
  const [compContact, setCompContact] = useState(null);       // Uyumluluk — contact result
  const [compContactless, setCompContactless] = useState(null); // contactless result
  const [compBusy, setCompBusy] = useState('');
  const [profilePdf, setProfilePdf] = useState(null);         // parsed Profile Advisor PDF
  const [pdfBusy, setPdfBusy] = useState('');                 // 'parse'|'contact'|'contactless'
  const [pdfCmpContact, setPdfCmpContact] = useState(null);
  const [pdfCmpContactless, setPdfCmpContactless] = useState(null);
  const [terminalProfile, setTerminalProfile] = useState({}); // terminal data overrides
  const [terminalMeta, setTerminalMeta] = useState(null);     // fields/defaults/presets
  const [scenarioResult, setScenarioResult] = useState(null);
  const [scenarioBusy, setScenarioBusy] = useState(false);
  const [conn, setConn] = useState('idle');
  const traceRef = useRef(null);

  const now = () => new Date().toLocaleTimeString('tr-TR');
  const readerQS = () => (selectedReader ? `?reader=${encodeURIComponent(selectedReader)}` : '');
  const withReader = (obj) => (selectedReader ? { ...obj, reader: selectedReader } : obj);
  const addTrace = (entry) => setTrace((p) => [...p, { ...entry, time: now() }]);

  // ── Two-level tab navigation ──
  const activeGroup = TAB_GROUPS.find((g) => g.tabs.some((t) => t.id === activeTab)) || TAB_GROUPS[0];
  const selectTab = (id) => {
    setActiveTab(id);
    const g = TAB_GROUPS.find((x) => x.tabs.some((t) => t.id === id));
    if (g) setGroupLast((p) => ({ ...p, [g.id]: id }));
  };
  const selectGroup = (g) => selectTab(groupLast[g.id] || g.tabs[0].id);

  // ── Polling: readers (mode) + card presence ──
  const pollReaders = async () => {
    try {
      const r = await fetch(`${API}/readers`);
      const d = await r.json();
      setReaders(d.readers);
      setReaderStatus(d.status || []);
      setMode(d.mode);
      setConn('ok');
    } catch {
      setConn('error');
    }
  };

  const pollCard = async (manual = false) => {
    try {
      const r = await fetch(`${API}/card${readerQS()}`);
      if (r.status === 404) {
        if (cardPresent) addTrace({ kind: 'event', msg: 'Kart çıkarıldı' });
        setCardPresent(false);
        setCard(null);
        return;
      }
      const d = await r.json();
      if (!cardPresent || manual) addTrace({ kind: 'event', msg: `Kart algılandı — ATR: ${d.atr}` });
      setCardPresent(true);
      setCard(d);
    } catch {
      setCardPresent(false);
    }
  };

  useEffect(() => {
    pollReaders();
    pollCard();
    const id = setInterval(() => { pollReaders(); pollCard(); }, 2000);
    return () => clearInterval(id);
    // eslint-disable-next-line
  }, [cardPresent, selectedReader]);

  useEffect(() => {
    if (traceRef.current) traceRef.current.scrollTop = traceRef.current.scrollHeight;
  }, [trace]);

  useEffect(() => {
    fetch(`${API}/test/suites`).then((r) => r.json()).then((d) => {
      setSuites(d.suites || []);
      if (d.suites?.[0]) setSuiteJson(JSON.stringify(d.suites[0], null, 2));
    }).catch(() => {});
  }, []);

  const loadCapks = async () => {
    try {
      const r = await fetch(`${API}/capk`);
      const d = await r.json();
      setCapks(d.keys || []);
      setCapkSchemes(d.schemes || {});
    } catch { /* ignore */ }
  };
  useEffect(() => { loadCapks(); }, []);

  const loadSessionKeys = async () => {
    try { const r = await fetch(`${API}/keys`); const d = await r.json(); setSessionKeys(d.keys || []); } catch { /* */ }
  };
  useEffect(() => { loadSessionKeys(); }, []);

  // ── Send APDU ──
  const send = async (cmdArg) => {
    const cmd = (cmdArg ?? raw).trim();
    if (!cmd) return;
    try {
      const r = await fetch(`${API}/apdu`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(withReader({ command: cmd })),
      });
      const d = await r.json();
      if (d.error) {
        addTrace({ kind: 'error', msg: `→ ${cmd}  ✗ ${d.error}` });
        setResp({ error: d.error });
        return;
      }
      setResp(d);
      addTrace({
        kind: d.sw === '9000' ? 'ok' : 'warn',
        apdu: { name: 'APDU', command: d.command, response: d.response, sw: d.sw, swText: d.swText, tlv: d.tlv, durationMs: d.durationMs, ok: d.sw === '9000' },
      });
    } catch {
      addTrace({ kind: 'error', msg: 'Backend bağlantısı başarısız' });
    }
  };

  // ── Contactless UID read ──
  const readUid = async () => {
    setUidBusy(true);
    addTrace({ kind: 'send', msg: 'FF CA 00 00 00 (GET UID)' });
    try {
      const r = await fetch(`${API}/uid`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(withReader({})) });
      const d = await r.json();
      setUid(d);
      if (d.error) addTrace({ kind: 'error', msg: d.error });
      else if (d.supported) addTrace({ kind: 'ok', msg: `UID: ${d.uid} (${d.length} bayt, ${d.durationMs}ms)` });
      else addTrace({ kind: 'warn', msg: `UID alınamadı: ${d.sw} — ${d.note}` });
    } catch {
      addTrace({ kind: 'error', msg: 'UID okunamadı (backend?)' });
    } finally {
      setUidBusy(false);
    }
  };

  // ── EMV full read flow ──
  const runEmv = async () => {
    setEmvBusy(true);
    setEmv(null);
    addTrace({ kind: 'event', msg: '═══ EMV okuma akışı başlatıldı ═══' });
    try {
      const ks = selectedKeyIdx >= 0 ? sessionKeys[selectedKeyIdx] : null;
      const r = await fetch(`${API}/emv/read`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(withReader({ terminal: terminalProfile, ...(ks ? { keyLabel: ks.label, keyPan: ks.pan } : {}) })),
      });
      const d = await r.json();
      setEmv(d);
      (d.steps || []).forEach((s) =>
        addTrace({ kind: s.ok ? 'ok' : (s.benign ? 'expected' : 'warn'), apdu: { name: s.name, command: s.command, response: s.response, sw: s.sw, swText: s.swText, tlv: s.tlv, durationMs: s.durationMs, ok: s.ok, benign: s.benign } }));
      if (d.genac && d.genac.arqc && d.genac.source) {
        addTrace({ kind: 'event', msg: `Kriptogram kaynağı: ${d.genac.source} · CID ${d.genac.cid} · ARQC ${d.genac.arqc}` });
      }
      if (d.genac && d.genac.verify) {
        const v = d.genac.verify;
        if (v.match != null) {
          addTrace({ kind: v.match ? 'ok' : 'error', verify: { ...v, cid: d.genac.cid, atc: d.genac.atc, arqc: d.genac.arqc, iad: d.genac.iad } });
        } else if (v.noKey) {
          addTrace({ kind: 'event', msg: 'ARQC: bu PAN için işlem anahtarı yok — doğrulanamadı' });
        } else if (v.error) {
          addTrace({ kind: 'error', msg: `ARQC hesaplama hatası: ${v.error}` });
        }
      } else if (d.genac && d.genac.error) {
        addTrace({ kind: 'warn', msg: `GENERATE AC: ${d.genac.error}` });
      }
      if (d.oda && d.oda.capkFound) {
        const dyn = d.oda.dynamic;
        const issOk = d.oda.issuerPK && d.oda.issuerPK.ok;
        const iccOk = d.oda.iccPK && d.oda.iccPK.ok;
        // fDDA whose structure verifies but whose VCPS DD-input hash can't be reproduced
        // is a "partial" (◐), not a failure — the cert chain + signature structure are valid.
        const dynNA = dyn && dyn.notApplicable;
        const dynPartial = dyn && !dyn.ok && dyn.structOk && dyn.kind === 'fDDA';
        const dynSym = !dyn ? '' : dynNA ? '—' : dyn.ok ? '✓' : dynPartial ? '◐' : '✗';
        addTrace({ kind: (issOk && iccOk && (!dyn || dyn.ok || dynPartial || dynNA)) ? 'ok' : 'error',
          msg: `ODA: Issuer PK ${issOk ? '✓' : '✗'} · ICC PK ${iccOk ? '✓' : '✗'}${dyn ? (dynNA ? ' · dinamik imza yok (—)' : ` · ${dyn.kind} ${dynSym}`) : ''}` });
      } else if (d.oda && !d.oda.capkFound) {
        addTrace({ kind: 'warn', msg: `ODA: CAPK bulunamadı (RID ${d.oda.rid} idx ${d.oda.capkIndex})` });
      }
      if (d.error) addTrace({ kind: 'error', msg: d.error });
      else if (d.cardData?.pan) addTrace({ kind: 'event', msg: `✔ PAN ${d.cardData.panFormatted} · ${d.cardData.cardholderName || ''}` });
    } catch {
      addTrace({ kind: 'error', msg: 'EMV akışı başarısız (backend?)' });
    } finally {
      setEmvBusy(false);
    }
  };

  const loadSuite = (s) => { setSuiteJson(JSON.stringify(s, null, 2)); setTestResult(null); };

  const emptyKeyForm = { label: '', pan: '', psn: '00', keyLevel: 'master', cvn: 'mastercard', acKey: '', macKey: '', encKey: '' };

  const addSessionKey = async () => {
    setKeyAddResult(null);
    try {
      const r = await fetch(`${API}/keys/add`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(keyForm) });
      const d = await r.json();
      setKeyAddResult(d);
      if (d.added) { addTrace({ kind: 'ok', msg: `İşlem anahtarı eklendi: ${keyForm.label}` }); setKeyForm(emptyKeyForm); loadSessionKeys(); }
    } catch { setKeyAddResult({ added: false, reason: 'Backend bağlantısı başarısız' }); }
  };

  // Load the full (unmasked) key set into the form for editing.
  const startEditKey = async (k) => {
    setKeyAddResult(null);
    try {
      const r = await fetch(`${API}/keys/get`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ label: k.label, pan: k.pan }) });
      if (!r.ok) { addTrace({ kind: 'error', msg: 'Anahtar okunamadı' }); return; }
      const f = await r.json();
      setKeyEdit({ origLabel: f.label, origPan: f.pan });
      setKeyForm({ label: f.label, pan: f.pan, psn: f.psn || '00', keyLevel: f.keyLevel || 'auto', cvn: f.cvn || 'mastercard', acKey: f.acKey || '', macKey: f.macKey || '', encKey: f.encKey || '' });
    } catch { addTrace({ kind: 'error', msg: 'Anahtar okunamadı (backend?)' }); }
  };
  const cancelEditKey = () => { setKeyEdit(null); setKeyForm(emptyKeyForm); setKeyAddResult(null); };

  const updateSessionKey = async () => {
    setKeyAddResult(null);
    try {
      const r = await fetch(`${API}/keys/update`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...keyForm, origLabel: keyEdit.origLabel, origPan: keyEdit.origPan }),
      });
      const d = await r.json();
      setKeyAddResult(d.updated ? { added: true, ...d } : d);
      if (d.updated) { addTrace({ kind: 'ok', msg: `İşlem anahtarı güncellendi: ${keyForm.label}` }); setKeyEdit(null); setKeyForm(emptyKeyForm); loadSessionKeys(); }
    } catch { setKeyAddResult({ added: false, reason: 'Backend bağlantısı başarısız' }); }
  };

  const deleteSessionKey = async (label, pan) => {
    try { await fetch(`${API}/keys/delete`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ label, pan }) }); loadSessionKeys(); } catch { /* */ }
  };

  // Send an EMV PIN CHANGE/UNBLOCK (84 24) issuer script to the card.
  const changePin = async () => {
    setPinBusy(true); setPinResult(null);
    if (!pinForm.keyLabel) { setPinResult({ error: 'Anahtar seti seçin' }); setPinBusy(false); return; }
    const opName = pinForm.mode === 'unblock' ? 'blokaj kaldırma' : 'değişimi';
    addTrace({ kind: 'event', msg: `═══ PIN ${opName} başlatıldı ═══` });
    try {
      const r = await fetch(`${API}/pin/change`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(withReader({ ...pinForm })),
      });
      const d = await r.json();
      setPinResult(d);
      // Her kart komutunu (APDU + yanıt) trace'e ekle — keşif adımları + 84 24
      (d.steps || []).forEach((s) => addTrace({
        kind: s.sw === '9000' ? 'ok' : 'warn',
        apdu: { name: s.name, command: s.command, response: s.response, sw: s.sw, swText: s.swText, tlv: s.tlv, ok: s.sw === '9000' },
      }));
      if (d.error) addTrace({ kind: 'error', msg: `PIN ${opName}: ${d.error}` });
      else addTrace({
        kind: d.ok ? 'ok' : 'error',
        msg: `PIN ${opName}: SW ${d.sw || '—'} ${d.ok ? '✓ başarılı' : (d.swText || 'başarısız')}`,
      });
    } catch { setPinResult({ error: 'Backend bağlantısı başarısız' }); }
    setPinBusy(false);
  };

  // Verify the card's offline PIN in plaintext (EMV VERIFY 00 20 00 80).
  const verifyPin = async () => {
    setVerifyBusy(true); setVerifyResult(null);
    if (!/^\d{4,12}$/.test(verifyForm.pin)) { setVerifyResult({ error: 'PIN 4-12 rakam olmalı' }); setVerifyBusy(false); return; }
    addTrace({ kind: 'event', msg: '═══ PIN doğrulama başlatıldı ═══' });
    try {
      const r = await fetch(`${API}/pin/verify`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(withReader({ pin: verifyForm.pin })),
      });
      const d = await r.json();
      setVerifyResult(d);
      (d.steps || []).forEach((s) => addTrace({
        kind: s.sw === '9000' ? 'ok' : 'warn',
        apdu: { name: s.name, command: s.command, response: s.response, sw: s.sw, swText: s.swText, tlv: s.tlv, ok: s.sw === '9000' },
      }));
      if (d.error) addTrace({ kind: 'error', msg: `PIN doğrulama: ${d.error}` });
      else addTrace({
        kind: d.correct ? 'ok' : 'error',
        msg: `PIN doğrulama: ${d.correct ? '✓ DOĞRU' : d.blocked ? '⛔ BLOKLU' : `✗ YANLIŞ (kalan ${d.triesLeft ?? '?'})`} · SW ${d.sw}`,
      });
    } catch { setVerifyResult({ error: 'Backend bağlantısı başarısız' }); }
    setVerifyBusy(false);
  };

  // Push each card-image APDU step to the trace dock with the same rich
  // structure Kart & EMV uses (command / response / SW / TLV). A GET DATA sweep
  // probes ~100 optional objects; the ones the card doesn't hold answer 6A88
  // (referenced data not found) etc. — those are pure noise and skipped entirely.
  const traceImageSteps = (steps, prefix = '') => {
    (steps || []).forEach((s) => {
      const benign = !s.ok && BENIGN_SW.has((s.sw || '').toUpperCase());
      if (benign && /GET DATA/i.test(s.name)) return; // GET DATA miss — don't log
      addTrace({ kind: s.ok ? 'ok' : (benign ? 'expected' : 'warn'), apdu: { name: prefix + s.name, command: s.command, response: s.response, sw: s.sw, swText: s.swText, tlv: s.tlv, durationMs: s.durationMs, ok: s.ok, benign } });
    });
  };

  // Extract the full card image (all personalised EMV tags) for CPV/VPA.
  const extractImage = async () => {
    setImageBusy(true); setCardImage(null);
    addTrace({ kind: 'event', msg: '═══ Kart image çıkarma başlatıldı ═══' });
    try {
      const r = await fetch(`${API}/card/image`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(withReader({})),
      });
      const d = await r.json();
      setCardImage(d);
      if (d.error) addTrace({ kind: 'error', msg: `Kart image: ${d.error}` });
      else {
        traceImageSteps(d.steps);
        addTrace({ kind: 'ok', msg: `Kart image: ${d.appCount} uygulama · ${d.totalTags} tag · ${d.totalRecords} kayıt (${d.durationMs}ms)` });
      }
    } catch { setCardImage({ error: 'Backend bağlantısı başarısız' }); }
    setImageBusy(false);
  };

  // Build a self-contained, printable HTML report of the full card image so the
  // logs can be saved/shared/opened in a browser (Mastercard CPV / Visa VPA).
  const cardImageHtml = (img) => {
    const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
    const CPLC = [
      ['icFabricator', 'IC Fabricator'], ['icType', 'IC Type'], ['osId', 'OS ID'],
      ['osReleaseDate', 'OS Release Date'], ['osReleaseLevel', 'OS Release Level'],
      ['icFabricationDate', 'IC Fabrication Date'], ['icSerialNumber', 'IC Serial Number'],
      ['icBatchId', 'IC Batch ID'], ['icModuleFabricator', 'Module Fabricator'],
      ['icModulePackagingDate', 'Module Packaging Date'], ['iccManufacturer', 'ICC Manufacturer'],
      ['icEmbeddingDate', 'Embedding Date'], ['icPrePersonalizer', 'Pre-Personalizer'],
      ['icPrePersoDate', 'Pre-Perso Date'], ['icPrePersoEquipId', 'Pre-Perso Equip ID'],
      ['icPersonalizer', 'Personalizer'], ['icPersonalizationDate', 'Personalization Date'],
      ['icPersoEquipId', 'Perso Equip ID'],
    ];
    const apps = img.applications.map((a) => {
      const cplc = a.cplc ? `<h3>CPLC — Card Production Life Cycle</h3><table class="kv">${CPLC.map(([k, l]) => a.cplc[k] ? `<tr><td>${esc(l)}</td><td class="mono">${esc(a.cplc[k])}</td></tr>` : '').join('')}</table>` : '';
      const rows = a.tags.map((t) => `<tr><td class="mono b">${esc(t.tag)}</td><td>${esc(t.name || '?')}</td><td class="mono val">${esc(t.value)}${t.ascii && /[A-Za-z]/.test(t.ascii) && (t.ascii.match(/\./g) || []).length / t.ascii.length < 0.25 ? ` <span class="asc">“${esc(t.ascii)}”</span>` : ''}</td><td class="src">${esc((t.sources || [t.source]).filter(Boolean).join(', '))}</td></tr>`).join('');
      // Per-record TLV tree — every EMV tag in the record, nested (like the trace).
      const recs = (a.records || []).filter((r) => r.nodes?.length).map((r) =>
        `<div class="te ok"><div class="te-head"><b>SFI${r.sfi} · Kayıt ${r.record}</b></div>` +
        (r.raw ? `<div class="te-apdu">${esc(r.raw)}</div>` : '') +
        `<div class="te-tlv">${tlvTreeHtml(r.nodes, esc)}</div></div>`).join('');
      return `<section class="app"><h2>${esc(a.scheme || '?')} · <span class="mono">${esc(a.aid)}</span>${a.label ? ` <span class="muted">(${esc(a.label)})</span>` : ''}</h2>
        <p class="meta">AIP ${esc(a.aip || '-')} · ${a.recordCount} kayıt · ${a.tagCount} tag · kaynak ${esc(a.source || '')}</p>
        ${cplc}
        <h3>Perso Tag Listesi (${a.tags.length})</h3>
        <table class="tags"><thead><tr><th>Tag</th><th>İsim</th><th>Değer</th><th>Kaynak</th></tr></thead><tbody>${rows}</tbody></table>
        ${recs ? `<h3>Kayıt TLV Ağacı</h3>${recs}` : ''}
      </section>`;
    }).join('');
    return `<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8"><title>Kart Image — ${esc(img.applications[0]?.scheme || 'EMV')}</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:24px;color:#1a1d21;background:#fff;font-size:14px}
  h1{font-size:20px;margin:0 0 4px} h2{font-size:16px;margin:24px 0 4px;border-bottom:2px solid #444;padding-bottom:4px}
  h3{font-size:13px;margin:16px 0 6px;color:#444;text-transform:uppercase;letter-spacing:.5px}
  .head{color:#666;font-size:12px;margin-bottom:16px} .meta{color:#666;font-size:12px;margin:2px 0 8px}
  .muted{color:#888} .mono{font-family:ui-monospace,Consolas,monospace} .b{font-weight:600} .val{word-break:break-all}
  .asc{color:#0a7d3c} .src{color:#888;font-size:11px}
  table{border-collapse:collapse;width:100%;margin:4px 0 8px} th,td{border:1px solid #ddd;padding:4px 8px;text-align:left;vertical-align:top}
  th{background:#f4f5f7;font-size:11px;text-transform:uppercase;letter-spacing:.4px;color:#555}
  .tags td:first-child{white-space:nowrap} .kv td:first-child{width:40%;color:#555}
  tbody tr:nth-child(even){background:#fafbfc}
  ${TLV_CSS}
  @media print{body{margin:0} h2{page-break-after:avoid} tr{page-break-inside:avoid} .te{break-inside:avoid}}
</style></head><body>
<h1>Kart Image — Perso Doğrulama Raporu</h1>
<p class="head">${img.appCount} uygulama · ${img.totalTags} tag · ${img.totalRecords} kayıt${img.durationMs != null ? ` · ${img.durationMs} ms` : ''} · Mastercard CPV / Visa VPA</p>
${apps}
</body></html>`;
  };

  const downloadImage = (fmt) => {
    if (!cardImage?.applications) return;
    let content, type = 'text/plain', ext = 'txt';
    if (fmt === 'json') { content = JSON.stringify(cardImage, null, 2); type = 'application/json'; ext = 'json'; }
    else if (fmt === 'html') { content = cardImageHtml(cardImage); type = 'text/html'; ext = 'html'; }
    else {
      content = cardImage.applications.map((a) =>
        `=== ${a.scheme || '?'} · ${a.aid}${a.label ? ' (' + a.label + ')' : ''} ===\nAIP ${a.aip || '-'} · ${a.recordCount} kayıt · ${a.tagCount} tag\n` +
        a.tags.map((t) => `${t.tag.padEnd(6)} ${(t.name || '').padEnd(44)} ${t.value}${t.sources ? '   [' + t.sources.join(',') + ']' : ''}`).join('\n')).join('\n\n');
    }
    const url = URL.createObjectURL(new Blob([content], { type }));
    const a = document.createElement('a');
    a.href = url; a.download = `card-image-${Date.now()}.${ext}`; a.click();
    URL.revokeObjectURL(url);
  };

  // Capture the current card's image into slot A or B for card-to-card compare.
  const captureCard = async (slot) => {
    setCaptureBusy(slot);
    addTrace({ kind: 'event', msg: `═══ Kart ${slot} yakalanıyor ═══` });
    try {
      const r = await fetch(`${API}/card/image`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(withReader({})),
      });
      const d = await r.json();
      if (d.error) addTrace({ kind: 'error', msg: `Kart ${slot}: ${d.error}` });
      else {
        (slot === 'A' ? setImageA : setImageB)(d);
        traceImageSteps(d.steps, `Kart ${slot} · `);
        addTrace({ kind: 'ok', msg: `Kart ${slot} yakalandı: ${d.appCount} uygulama · ${d.totalTags} tag` });
      }
    } catch { addTrace({ kind: 'error', msg: `Kart ${slot}: bağlantı hatası` }); }
    setCaptureBusy('');
  };

  // Capture the card image from a specific interface (contact / contactless
  // reader) so a dual-interface card's two personalisations can be compared.
  const captureIface = async (iface) => {
    const reader = readers.find((r) => iface === 'contactless' ? /contactless/i.test(r) : !/contactless/i.test(r));
    const name = iface === 'contactless' ? 'Temassız' : 'Contact';
    if (!reader) { addTrace({ kind: 'error', msg: `${name} okuyucu bulunamadı` }); return; }
    setCaptureBusy(iface);
    addTrace({ kind: 'event', msg: `═══ ${name} image çıkarılıyor ═══` });
    try {
      const r = await fetch(`${API}/card/image`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ reader }),
      });
      const d = await r.json();
      if (d.error) addTrace({ kind: 'error', msg: `${name}: ${d.error}` });
      else {
        (iface === 'contactless' ? setImageContactless : setImageContact)(d);
        traceImageSteps(d.steps, `${name} · `);
        addTrace({ kind: 'ok', msg: `${name} image: ${d.appCount} uygulama · ${d.totalTags} tag` });
      }
    } catch { addTrace({ kind: 'error', msg: `${name}: bağlantı hatası` }); }
    setCaptureBusy('');
  };

  const readImage = async (reader) => {
    const r = await fetch(`${API}/card/image`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ reader }),
    });
    return r.json();
  };
  const cardOn = async (reader) => { try { return !!(await (await fetch(`${API}/card?reader=${encodeURIComponent(reader)}`)).json()).atr; } catch { return false; } };

  // Read BOTH interfaces (contact + contactless) of the card at the reader,
  // guiding the physical move. The SDI011 contactless antenna can read the card
  // still in the contact slot (returning the contact perso), so we first wait
  // for the card to LEAVE the contact slot, then APPEAR on the contactless
  // reader, then read. Timeout → finish with contact only. onPhase reports
  // 'contact'|'remove'|'place'|'contactless'|''.
  const readDualImage = async ({ onPhase, cancelRef, prefix = '', onContact, onContactless }) => {
    const contactR = readers.find((r) => !/contactless/i.test(r));
    const clR = readers.find((r) => /contactless/i.test(r));
    const waitFor = async (fn, secs) => { for (let i = 0; i < secs && !cancelRef.current; i++) { if (await fn()) return true; await new Promise((r) => setTimeout(r, 1000)); } return false; };
    onPhase('contact');
    if (contactR) {
      try { const d = await readImage(contactR); if (!d.error) { onContact(d); traceImageSteps(d.steps, `${prefix}🔌 `); addTrace({ kind: 'ok', msg: `${prefix}🔌 Contact: ${d.appCount} uygulama · ${d.totalTags} tag` }); } else addTrace({ kind: 'error', msg: `${prefix}Contact: ${d.error}` }); }
      catch { addTrace({ kind: 'error', msg: `${prefix}Contact okuma hatası` }); }
    } else addTrace({ kind: 'error', msg: 'Temaslı okuyucu bulunamadı' });
    if (clR && contactR && !cancelRef.current) {
      onPhase('remove');
      const removed = await waitFor(async () => !(await cardOn(contactR)), 30);
      if (!removed) addTrace({ kind: 'warn', msg: `${prefix}Kart temaslı yuvadan çıkarılmadı — sadece contact` });
      else if (!cancelRef.current) {
        onPhase('place');
        const placed = await waitFor(() => cardOn(clR), 30);
        if (!placed) addTrace({ kind: 'warn', msg: `${prefix}Temassız kart algılanmadı — sadece contact` });
        else if (!cancelRef.current) {
          await new Promise((r) => setTimeout(r, 400)); // let the RF field settle
          onPhase('contactless');
          try { const d = await readImage(clR); if (!d.error) { onContactless(d); traceImageSteps(d.steps, `${prefix}📶 `); addTrace({ kind: 'ok', msg: `${prefix}📶 Contactless: ${d.appCount} uygulama · ${d.totalTags} tag` }); } else addTrace({ kind: 'error', msg: `${prefix}Contactless: ${d.error}` }); }
          catch { addTrace({ kind: 'error', msg: `${prefix}Contactless okuma hatası` }); }
        }
      }
    } else if (!clR) addTrace({ kind: 'error', msg: 'Temassız okuyucu bulunamadı' });
    onPhase('');
  };

  const extractDual = async () => {
    dualCancel.current = false;
    setImageContact(null); setImageContactless(null);
    addTrace({ kind: 'event', msg: '═══ Dual-interface image başlatıldı ═══' });
    await readDualImage({ onPhase: setDualPhase, cancelRef: dualCancel, onContact: setImageContact, onContactless: setImageContactless });
  };
  const cancelDual = () => { dualCancel.current = true; setDualPhase(''); };

  // Kart ↔ Kart: capture a whole card (both interfaces) into slot A or B.
  const captureCardDual = async (slot) => {
    cardDualCancel.current = false;
    const setC = slot === 'A' ? setImageA : setImageB;
    const setCl = slot === 'A' ? setImageAcl : setImageBcl;
    setC(null); setCl(null); setCardDualSlot(slot);
    addTrace({ kind: 'event', msg: `═══ Kart ${slot} (temaslı+temassız) yakalanıyor ═══` });
    await readDualImage({ onPhase: setCardDualPhase, cancelRef: cardDualCancel, prefix: `Kart ${slot} · `, onContact: setC, onContactless: setCl });
    setCardDualSlot('');
  };
  const cancelCardDual = () => { cardDualCancel.current = true; setCardDualPhase(''); setCardDualSlot(''); };

  // ── Offline Sertifika: verify the cert chain + CDA dynamic signature on one
  // interface. Reuses the full /api/emv/read flow (it already recovers Issuer/ICC
  // PK and does the CDA GENERATE AC + SDAD verify) but keeps the result separate.
  const runOdaVerify = async (iface) => {
    const reader = readers.find((r) => iface === 'contactless' ? /contactless/i.test(r) : !/contactless/i.test(r));
    const name = iface === 'contactless' ? 'Temassız' : 'Temaslı';
    const setter = iface === 'contactless' ? setOdaContactless : setOdaContact;
    if (!reader) { addTrace({ kind: 'error', msg: `${name} okuyucu bulunamadı` }); return; }
    setOdaBusy(iface);
    addTrace({ kind: 'event', msg: `═══ Offline sertifika doğrulama (${name}) ═══` });
    try {
      const ks = selectedKeyIdx >= 0 ? sessionKeys[selectedKeyIdx] : null;
      const r = await fetch(`${API}/emv/read`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reader, terminal: terminalProfile, ...(ks ? { keyLabel: ks.label, keyPan: ks.pan } : {}) }),
      });
      const d = await r.json();
      if (d.error) { setter({ error: d.error, interface: name }); addTrace({ kind: 'error', msg: `${name}: ${d.error}` }); }
      else {
        setter({ interface: name, scheme: d.cardData?.scheme, aid: d.applications?.[0]?.aid, pan: d.cardData?.panFormatted, oda: d.oda });
        traceImageSteps(d.steps, `${name} · `);
        if (d.oda && d.oda.capkFound) {
          const dyns = d.oda.dynamics && d.oda.dynamics.length ? d.oda.dynamics : (d.oda.dynamic ? [d.oda.dynamic] : []);
          const chainOk = d.oda.issuerPK?.ok && d.oda.iccPK?.ok;
          const real = dyns.filter((x) => x.kind !== 'none');
          const dynTxt = real.length
            ? real.map((x) => `${x.kind} ${(x.hashMatch != null ? x.hashMatch : x.ok) ? '✓' : x.structOk ? '◐' : '✗'}`).join(' · ')
            : 'dinamik imza yok';
          addTrace({ kind: chainOk ? 'ok' : 'warn', msg: `${name} ODA: zincir ${chainOk ? '✓' : '✗'} (Issuer/ICC PK) · ${dynTxt} · CAPK ${d.oda.rid} idx ${d.oda.capkIndex}` });
        } else if (d.oda && !d.oda.capkFound) {
          addTrace({ kind: 'warn', msg: `${name} ODA: CAPK bulunamadı (RID ${d.oda?.rid} idx ${d.oda?.capkIndex})` });
        } else {
          addTrace({ kind: 'warn', msg: `${name}: sertifika verisi (tag 90/9F46) bulunamadı — kart ODA sunmuyor olabilir` });
        }
      }
    } catch { setter({ error: 'Backend bağlantısı başarısız', interface: name }); addTrace({ kind: 'error', msg: `${name}: bağlantı hatası` }); }
    setOdaBusy('');
  };
  const clearOda = (iface) => (iface === 'contactless' ? setOdaContactless : setOdaContact)(null);

  // ── Uyumluluk: read the card image on one interface and run the perso
  // compliance / certification rule engine (EMV core + Mastercard CPV).
  const runComplianceCheck = async (iface) => {
    const reader = readers.find((r) => iface === 'contactless' ? /contactless/i.test(r) : !/contactless/i.test(r));
    const name = iface === 'contactless' ? 'Temassız' : 'Temaslı';
    const setter = iface === 'contactless' ? setCompContactless : setCompContact;
    if (!reader) { addTrace({ kind: 'error', msg: `${name} okuyucu bulunamadı` }); return; }
    setCompBusy(iface);
    addTrace({ kind: 'event', msg: `═══ Perso uyumluluk denetimi (${name}) ═══` });
    try {
      const r = await fetch(`${API}/compliance`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ reader, terminal: terminalProfile }),
      });
      const d = await r.json();
      if (d.error) { setter({ error: d.error }); addTrace({ kind: 'error', msg: `${name}: ${d.error}` }); }
      else {
        setter(d);
        const s = d.compliance.summary;
        addTrace({ kind: s.verdict === 'FAIL' ? 'error' : s.verdict === 'PASS' ? 'ok' : 'warn',
          msg: `${name} uyumluluk: ${s.verdict} · ${s.pass}✓ ${s.fail}✗ ${s.warn}⚠ (${d.compliance.scheme || '?'} · ${s.total} kural)` });
      }
    } catch { setter({ error: 'Backend bağlantısı başarısız' }); addTrace({ kind: 'error', msg: `${name}: bağlantı hatası` }); }
    setCompBusy('');
  };
  const clearCompliance = (iface) => (iface === 'contactless' ? setCompContactless : setCompContact)(null);

  // ── PDF Profil (Mastercard Profile Advisor) ↔ Kart ──
  const parseProfilePdfFile = async (file) => {
    setPdfBusy('parse'); setProfilePdf(null); setPdfCmpContact(null); setPdfCmpContactless(null);
    addTrace({ kind: 'event', msg: `═══ PDF profil yükleniyor: ${file.name} ═══` });
    try {
      const buf = await file.arrayBuffer();
      const r = await fetch(`${API}/profile/parse`, { method: 'POST', headers: { 'Content-Type': 'application/pdf' }, body: buf });
      const d = await r.json();
      if (d.error) { addTrace({ kind: 'error', msg: `PDF: ${d.error}` }); }
      else { setProfilePdf({ ...d, fileName: file.name }); addTrace({ kind: 'ok', msg: `PDF profil: ${d.count} tag · ${d.pages} sayfa — ${file.name}` }); }
    } catch { addTrace({ kind: 'error', msg: 'PDF yüklenemedi (backend?)' }); }
    setPdfBusy('');
  };
  const runPdfCompare = async (iface) => {
    if (!profilePdf) return;
    const reader = readers.find((r) => iface === 'contactless' ? /contactless/i.test(r) : !/contactless/i.test(r));
    const name = iface === 'contactless' ? 'Temassız' : 'Temaslı';
    const setter = iface === 'contactless' ? setPdfCmpContactless : setPdfCmpContact;
    if (!reader) { addTrace({ kind: 'error', msg: `${name} okuyucu bulunamadı` }); return; }
    setPdfBusy(iface);
    addTrace({ kind: 'event', msg: `═══ PDF ↔ Kart karşılaştırma (${name}) ═══` });
    try {
      const r = await fetch(`${API}/card/image`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ reader }) });
      const d = await r.json();
      if (d.error) { setter({ error: d.error }); addTrace({ kind: 'error', msg: `${name}: ${d.error}` }); }
      else { setter({ image: d, interface: name }); addTrace({ kind: 'ok', msg: `${name}: ${d.totalTags} tag okundu — PDF ile karşılaştırıldı` }); }
    } catch { setter({ error: 'Backend bağlantısı başarısız' }); }
    setPdfBusy('');
  };
  const clearPdfCmp = (iface) => (iface === 'contactless' ? setPdfCmpContactless : setPdfCmpContact)(null);

  // ── Terminal profili / senaryo testi ──
  useEffect(() => { fetch(`${API}/terminal/meta`).then((r) => r.json()).then(setTerminalMeta).catch(() => {}); }, []);
  // Run every scenario preset against the card and report TC/ARQC/AAC decisions.
  const runScenarios = async () => {
    setScenarioBusy(true); setScenarioResult(null);
    addTrace({ kind: 'event', msg: '═══ Senaryo testi başlatıldı ═══' });
    try {
      const r = await fetch(`${API}/scenario/run`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(withReader({})),
      });
      const d = await r.json();
      if (d.error) { setScenarioResult({ error: d.error }); addTrace({ kind: 'error', msg: `Senaryo: ${d.error}` }); }
      else {
        setScenarioResult(d);
        for (const s of d.results) addTrace({ kind: s.error ? 'error' : s.match ? 'ok' : 'warn', msg: `Senaryo ${s.name}: istenen ${s.expect} → kart ${s.decision || (s.error ? 'HATA' : '—')}` });
      }
    } catch { setScenarioResult({ error: 'Backend bağlantısı başarısız' }); }
    setScenarioBusy(false);
  };

  const emptyCapkForm = { scheme: '', rid: '', index: '', exponent: '03', modulus: '', hash: '' };

  const addCapk = async () => {
    setAddResult(null);
    try {
      const r = await fetch(`${API}/capk/add`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(addForm),
      });
      const d = await r.json();
      setAddResult(d);
      if (d.added) { addTrace({ kind: 'ok', msg: `CA anahtarı eklendi: ${addForm.rid} idx ${addForm.index}` }); setAddForm(emptyCapkForm); loadCapks(); }
    } catch {
      setAddResult({ added: false, reason: 'Backend bağlantısı başarısız' });
    }
  };

  // Load an existing key into the form for editing (hash left blank → auto-recomputed).
  const startEditCapk = (k) => {
    setCapkEdit({ origRid: k.rid, origIndex: k.index });
    setAddForm({ scheme: k.scheme, rid: k.rid, index: k.index, exponent: k.exponent, modulus: k.modulus, hash: k.hash || '' });
    setAddResult(null);
    setActiveTab('capk');
  };
  const cancelEditCapk = () => { setCapkEdit(null); setAddForm(emptyCapkForm); setAddResult(null); };

  const updateCapk = async () => {
    setAddResult(null);
    try {
      const r = await fetch(`${API}/capk/update`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...addForm, origRid: capkEdit.origRid, origIndex: capkEdit.origIndex }),
      });
      const d = await r.json();
      setAddResult(d.updated ? { added: true, ...d } : d);
      if (d.updated) { addTrace({ kind: 'ok', msg: `CA anahtarı güncellendi: ${addForm.rid} idx ${addForm.index}` }); setCapkEdit(null); setAddForm(emptyCapkForm); loadCapks(); }
    } catch {
      setAddResult({ added: false, reason: 'Backend bağlantısı başarısız' });
    }
  };

  const deleteCapk = async (k) => {
    try {
      const r = await fetch(`${API}/capk/delete`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ rid: k.rid, index: k.index }),
      });
      const d = await r.json();
      if (d.deleted) { addTrace({ kind: 'ok', msg: `CA anahtarı silindi: ${k.rid} idx ${k.index}` }); loadCapks(); }
      else addTrace({ kind: 'error', msg: `CAPK silinemedi: ${d.reason}` });
    } catch { addTrace({ kind: 'error', msg: 'CAPK silinemedi (backend?)' }); }
  };

  const runTest = async () => {
    let suite;
    try { suite = JSON.parse(suiteJson); }
    catch { addTrace({ kind: 'error', msg: 'Test paketi JSON hatalı' }); return; }
    setTestBusy(true);
    setTestResult(null);
    addTrace({ kind: 'event', msg: `▶ Test paketi çalışıyor: ${suite.name}` });
    try {
      const r = await fetch(`${API}/test/run`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(withReader({ suite })),
      });
      const d = await r.json();
      if (d.error) { addTrace({ kind: 'error', msg: d.error }); setTestResult({ error: d.error }); return; }
      setTestResult(d);
      d.results.forEach((res) => addTrace({ kind: res.pass ? 'ok' : 'error', msg: `${res.pass ? '✓' : '✗'} ${res.name} (${res.actualSw || '—'})` }));
      addTrace({ kind: d.ok ? 'ok' : 'error', msg: `Sonuç: ${d.passed}/${d.total} geçti` });
    } catch {
      addTrace({ kind: 'error', msg: 'Test çalıştırılamadı' });
    } finally {
      setTestBusy(false);
    }
  };

  const buildApdu = () => {
    const { cla, ins, p1, p2, data, le } = builder;
    const clean = (s) => s.replace(/\s/g, '').toUpperCase();
    let out = clean(cla) + clean(ins) + clean(p1) + clean(p2);
    const d = clean(data);
    if (d) out += (d.length / 2).toString(16).padStart(2, '0').toUpperCase() + d;
    if (clean(le)) out += clean(le);
    setRaw(out.replace(/(.{2})/g, '$1 ').trim());
  };

  // ── Report / export ──
  const reportCtx = () => ({ card, emv, testResult, trace, readers, mode });

  const downloadReport = () => {
    const url = URL.createObjectURL(new Blob([buildReportHtml(reportCtx())], { type: 'text/html' }));
    const a = document.createElement('a');
    a.href = url; a.download = `karttest-rapor-${Date.now()}.html`; a.click();
    URL.revokeObjectURL(url);
    addTrace({ kind: 'event', msg: 'Rapor indirildi (HTML)' });
  };

  const printReport = () => {
    const w = window.open('', '_blank');
    if (!w) { addTrace({ kind: 'error', msg: 'Pop-up engellendi — yazdırma açılamadı' }); return; }
    w.document.write(buildReportHtml(reportCtx()));
    w.document.close();
    w.focus();
    setTimeout(() => w.print(), 300);
  };

  const exportTrace = (fmt) => {
    let content, type, ext;
    if (fmt === 'json') {
      content = JSON.stringify(trace, null, 2); type = 'application/json'; ext = 'json';
    } else {
      content = traceCsv(trace);
      type = 'text/csv;charset=utf-8'; ext = 'csv';
    }
    const url = URL.createObjectURL(new Blob([content], { type }));
    const a = document.createElement('a');
    a.href = url; a.download = `trace-${Date.now()}.${ext}`; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="app">
      <header className="header">
        <div className="brand">
          <span className="logo">▣ KartTest</span>
          <span className="subtitle">Smart Card / EMV Test Tool</span>
        </div>
        <div className="header-badges">
          <span className={`chip ${cardPresent ? 'chip-on' : 'chip-off'}`}>{cardPresent ? '▣ Kart Var' : '▢ Kart Yok'}</span>
          {mode && <span className="chip chip-real">🔌 Gerçek</span>}
          <span className={`chip ${conn === 'ok' ? 'chip-on' : 'chip-err'}`}>{conn === 'ok' ? '● Bağlı' : '● Hata'}</span>
        </div>
      </header>

      <div className="reader-bar">
        {readers.map((r, i) => {
          const isContactless = /contactless/i.test(r);
          const st = readerStatus.find((s) => s.reader === r);
          const hasCard = st?.present;
          const isSelected = selectedReader === r;
          const shortName = r.replace(/^SCM Microsystems Inc\.\s*/, '');
          return (
            <button
              key={i}
              className={`reader-pill ${isSelected ? 'reader-selected' : ''} ${hasCard ? 'reader-hascard' : ''}`}
              title={`${r}\n${isSelected ? 'Seçili — tıkla: otomatik' : 'Tıkla: bu okuyucuyu hedefle'}`}
              onClick={() => setSelectedReader(isSelected ? null : r)}
            >
              <span className="reader-ico">{isContactless ? '📶' : '🔌'}</span>
              {shortName}
              <span className={`reader-tag ${isContactless ? 'tag-cl' : 'tag-ct'}`}>{isContactless ? 'Temassız' : 'Temaslı'}</span>
              {hasCard && <span className="reader-here">● kart</span>}
              {isSelected && <span className="reader-sel">✓ seçili</span>}
            </button>
          );
        })}
        {selectedReader && (
          <button className="reader-clear" onClick={() => setSelectedReader(null)} title="Otomatik seçime dön">✕ otomatik</button>
        )}
      </div>

      <nav className="tab-groups">
        {TAB_GROUPS.map((g) => (
          <button key={g.id} className={`tab-group ${activeGroup.id === g.id ? 'active' : ''}`} onClick={() => selectGroup(g)}><span className="tab-group-ico">{g.icon}</span> {g.label}</button>
        ))}
      </nav>
      <nav className="tabs">
        {activeGroup.tabs.map((t) => (
          <button key={t.id} className={`tab ${activeTab === t.id ? 'active' : ''}`} onClick={() => selectTab(t.id)}>{t.label}</button>
        ))}
      </nav>

      {activeTab === 'card' && (
        <CardTab
          emv={emv} emvBusy={emvBusy} cardPresent={cardPresent} runEmv={runEmv}
          sessionKeys={sessionKeys} selectedKeyIdx={selectedKeyIdx} setSelectedKeyIdx={setSelectedKeyIdx}
          uid={uid} uidBusy={uidBusy} readUid={readUid} card={card}
        />
      )}

      {activeTab === 'apdu' && (
        <ApduTab raw={raw} setRaw={setRaw} send={send} quick={QUICK}
          builder={builder} setBuilder={setBuilder} buildApdu={buildApdu} resp={resp} />
      )}

      {activeTab === 'test' && (
        <TestTab suites={suites} loadSuite={loadSuite} runTest={runTest} testBusy={testBusy}
          cardPresent={cardPresent} testResult={testResult} suiteJson={suiteJson} setSuiteJson={setSuiteJson} />
      )}

      {activeTab === 'capk' && (
        <CapkTab capks={capks} capkSchemes={capkSchemes} capkFilter={capkFilter} setCapkFilter={setCapkFilter}
          addForm={addForm} setAddForm={setAddForm} addCapk={addCapk} addResult={addResult}
          capkEdit={capkEdit} startEditCapk={startEditCapk} cancelEditCapk={cancelEditCapk}
          updateCapk={updateCapk} deleteCapk={deleteCapk} />
      )}

      {activeTab === 'keys' && (
        <KeysTab sessionKeys={sessionKeys} deleteSessionKey={deleteSessionKey}
          keyForm={keyForm} setKeyForm={setKeyForm} addSessionKey={addSessionKey} keyAddResult={keyAddResult}
          keyEdit={keyEdit} startEditKey={startEditKey} cancelEditKey={cancelEditKey} updateSessionKey={updateSessionKey} />
      )}

      {activeTab === 'pin' && (
        <PinTab pinForm={pinForm} setPinForm={setPinForm} changePin={changePin} pinBusy={pinBusy}
          pinResult={pinResult} sessionKeys={sessionKeys} cardPresent={cardPresent}
          verifyForm={verifyForm} setVerifyForm={setVerifyForm} verifyPin={verifyPin}
          verifyBusy={verifyBusy} verifyResult={verifyResult} />
      )}

      {activeTab === 'image' && (
        <CardImageTab cardImage={cardImage} imageBusy={imageBusy} cardPresent={cardPresent}
          extractImage={extractImage} downloadImage={downloadImage}
          imageA={imageA} imageB={imageB} captureBusy={captureBusy} captureCard={captureCard}
          clearA={() => { setImageA(null); setImageAcl(null); }} clearB={() => { setImageB(null); setImageBcl(null); }}
          imageAcl={imageAcl} imageBcl={imageBcl} captureCardDual={captureCardDual} cancelCardDual={cancelCardDual}
          cardDualPhase={cardDualPhase} cardDualSlot={cardDualSlot}
          imageContact={imageContact} imageContactless={imageContactless} captureIface={captureIface}
          clearContact={() => setImageContact(null)} clearContactless={() => setImageContactless(null)}
          extractDual={extractDual} cancelDual={cancelDual} dualPhase={dualPhase} />
      )}

      {activeTab === 'oda' && (
        <OdaTab odaContact={odaContact} odaContactless={odaContactless} odaBusy={odaBusy}
          runOdaVerify={runOdaVerify} clearOda={clearOda} />
      )}

      {activeTab === 'compliance' && (
        <ComplianceTab compContact={compContact} compContactless={compContactless} compBusy={compBusy}
          runComplianceCheck={runComplianceCheck} clearCompliance={clearCompliance} />
      )}

      {activeTab === 'profilepdf' && (
        <ProfilePdfTab profilePdf={profilePdf} pdfBusy={pdfBusy} parsePdf={parseProfilePdfFile}
          runPdfCompare={runPdfCompare} clearPdfCmp={clearPdfCmp}
          cmpContact={pdfCmpContact} cmpContactless={pdfCmpContactless} />
      )}

      {activeTab === 'terminal' && (
        <TerminalTab meta={terminalMeta} profile={terminalProfile} setProfile={setTerminalProfile}
          runScenarios={runScenarios} scenarioBusy={scenarioBusy} scenarioResult={scenarioResult}
          cardPresent={cardPresent} />
      )}

      {activeTab === 'report' && (
        <ReportTab downloadReport={downloadReport} printReport={printReport}
          card={card} emv={emv} testResult={testResult} trace={trace} />
      )}

      <TraceDock trace={trace} traceOpen={traceOpen} setTraceOpen={setTraceOpen}
        exportTrace={exportTrace} clearTrace={() => setTrace([])} traceRef={traceRef} />
    </div>
  );
}

export default App;
