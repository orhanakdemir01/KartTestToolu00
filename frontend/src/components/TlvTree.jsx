import { useState } from 'react';

// Only render an ASCII rendering when the value looks like genuine text — real
// perso text (labels, names, AIDs) has few non-printable "." markers, whereas
// binary data (certificates, key remainders) is mostly dots and reads as noise.
export function looksTextual(ascii) {
  if (!ascii || !/[A-Za-z]/.test(ascii)) return false;
  const dots = (ascii.match(/\./g) || []).length;
  return dots / ascii.length < 0.25;
}

// Recursive TLV tree node: constructed tags expand to show children
export function TlvNode({ node, depth = 0 }) {
  const [open, setOpen] = useState(true);
  const hasKids = node.constructed && node.children?.length > 0;
  return (
    <div className="tlv-node" style={{ marginLeft: depth ? 16 : 0 }}>
      <div className="tlv-row" onClick={() => hasKids && setOpen(!open)}>
        <span className="tlv-tag">{node.tag}</span>
        <span className="tlv-name">{node.name || (node.constructed ? '(constructed)' : '(bilinmeyen tag)')}</span>
        <span className="tlv-len">len {node.length}</span>
        {hasKids && <span className="tlv-caret">{open ? '▾' : '▸'}</span>}
      </div>
      {!node.constructed && (
        <div className="tlv-val">
          <span className="mono">{node.value || '—'}</span>
          {looksTextual(node.ascii) && <span className="tlv-ascii">"{node.ascii}"</span>}
        </div>
      )}
      {node.decoded && (
        <div className="tlv-decoded">
          {node.decoded.map((line, i) => <div key={i} className="tlv-dec-line">↳ {line}</div>)}
        </div>
      )}
      {hasKids && open && node.children.map((c, i) => <TlvNode key={i} node={c} depth={depth + 1} />)}
    </div>
  );
}

// Renders a list of TLV nodes, or a placeholder when there is no structure
export function TlvTree({ nodes }) {
  if (!nodes || nodes.length === 0) return <p className="muted small">TLV yapısı yok (ham veri veya sadece SW).</p>;
  return <div className="tlv-tree">{nodes.map((n, i) => <TlvNode key={i} node={n} />)}</div>;
}
