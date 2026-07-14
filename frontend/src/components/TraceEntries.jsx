import { useState } from 'react';
import { TlvTree } from './TlvTree.jsx';

// Expandable APDU exchange in the trace: command → response → decoded TLV tree
export function ApduTraceEntry({ t }) {
  const [open, setOpen] = useState(false);
  const a = t.apdu;
  return (
    <div className={`apdu-entry t-${t.kind}`}>
      <div className="apdu-summary" onClick={() => setOpen((o) => !o)}>
        <span className="apdu-caret">{open ? '▾' : '▸'}</span>
        <span className="t-time">{t.time}</span>
        <span className="apdu-name">{a.name}</span>
        <span className={`sw ${a.ok ? 'sw-ok' : a.benign ? 'sw-dim' : 'sw-warn'}`}>{a.sw}</span>
        <span className="apdu-swtext">{a.swText}{a.benign ? ' · beklenen (dizin sonu)' : ''}</span>
        {a.durationMs != null && <span className="timing">⏱ {a.durationMs}ms</span>}
      </div>
      {open && (
        <div className="apdu-detail">
          <div className="apdu-line"><span className="apdu-dir send">→ Command</span><span className="mono">{a.command}</span></div>
          <div className="apdu-line"><span className="apdu-dir recv">← Response</span><span className="mono">{a.response}</span></div>
          <TlvTree nodes={a.tlv?.ok ? a.tlv.nodes : null} />
        </div>
      )}
    </div>
  );
}

// Expandable ARQC verification result in the trace
export function VerifyTraceEntry({ t }) {
  const [open, setOpen] = useState(true);
  const v = t.verify;
  return (
    <div className={`apdu-entry t-${t.kind}`}>
      <div className="apdu-summary" onClick={() => setOpen((o) => !o)}>
        <span className="apdu-caret">{open ? '▾' : '▸'}</span>
        <span className="t-time">{t.time}</span>
        <span className={`apdu-name verify-name ${v.match ? 'ok' : 'bad'}`}>{v.match ? '✓ ARQC DOĞRULANDI' : '✗ ARQC UYUŞMUYOR'}</span>
        <span className="apdu-swtext">{v.keyLabel} · {v.method}</span>
      </div>
      {open && (
        <div className="apdu-detail">
          <div className="apdu-line"><span className="apdu-dir recv">CID/ATC</span><span className="mono">{v.cid} / {v.atc}</span></div>
          <div className="apdu-line"><span className="apdu-dir send">Hesaplanan</span><span className={`mono ${v.match ? 'arqc-match' : 'arqc-bad'}`}>{v.computed}</span></div>
          <div className="apdu-line"><span className="apdu-dir recv">Kart ARQC</span><span className={`mono ${v.match ? 'arqc-match' : 'arqc-bad'}`}>{v.cardArqc}</span></div>
          {v.iccMk && <div className="apdu-line"><span className="apdu-dir">ICC MK</span><span className="mono">{v.iccMk}</span></div>}
          <div className="apdu-line"><span className="apdu-dir">Session</span><span className="mono">{v.sessionKey}</span></div>
          <div className="apdu-line"><span className="apdu-dir">MAC girdisi</span><span className="mono">{v.inputData}</span></div>
        </div>
      )}
    </div>
  );
}

// Plain single-line trace entry (events, errors, simple messages)
export function TraceLine({ t }) {
  return (
    <div className={`trace-line t-${t.kind}`}>
      <span className="t-time">{t.time}</span>
      <span className="t-arrow">{t.kind === 'send' ? '→' : t.kind === 'event' ? '◆' : '←'}</span>
      <span className="t-msg mono">{t.msg}</span>
    </div>
  );
}
