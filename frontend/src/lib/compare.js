// İki test oturumunu (snapshot.state) karşılaştırır: kimlik, verdikt ve perso tag
// farkları. Sertifikasyon iş akışında "aynı kartın iki okuması" ya da "iki farklı
// kart" arasındaki değişimi bir bakışta görmek için.

const dutFields = (s) => {
  const cd = s?.emv?.cardData || {};
  return {
    scheme: cd.scheme || s?.card?.scheme || '—',
    pan: cd.panFormatted || '—',
    aid: s?.emv?.applications?.[0]?.aid || '—',
    expiry: cd.expiry || '—',
    atc: s?.emv?.genac?.atc || '—',
    atr: s?.card?.atr || '—',
  };
};

const compVerdict = (res) => {
  const c = res?.compliance;
  if (!c) return null;
  const s = c.summary || {};
  return { text: `${s.verdict} · ${s.pass ?? 0}✓ ${s.fail ?? 0}✗ ${s.warn ?? 0}⚠` };
};

const odaVerdict = (res) => {
  const o = res?.oda;
  if (!o) return null;
  if (!o.capkFound) return { text: 'CAPK YOK' };
  const dyns = (o.dynamics && o.dynamics.length ? o.dynamics : (o.dynamic ? [o.dynamic] : []))
    .filter((d) => d.kind !== 'none');
  const chainOk = o.issuerPK?.ok && o.iccPK?.ok;
  const dynTxt = dyns.length
    ? dyns.map((d) => `${d.kind} ${(d.hashMatch != null ? d.hashMatch : d.ok) ? '✓' : '✗'}`).join(' ')
    : 'imza yok';
  return { text: `${chainOk ? 'zincir ✓' : 'zincir ✗'} · ${dynTxt}` };
};

const arqcVerdict = (s) => {
  const v = s?.emv?.genac?.verify;
  if (!v || v.match == null) return v?.noKey ? { text: 'anahtar yok' } : null;
  return { text: v.match ? 'DOĞRULANDI ✓' : (v.keyPanMatch ? 'UYUŞMUYOR ✗' : 'doğrulanamadı') };
};

// cardImage'daki tüm perso tag'lerini düz bir haritaya indir (tag -> {value, name}).
const tagMapOf = (s) => {
  const m = {};
  for (const a of s?.cardImage?.applications || []) for (const t of a.tags || []) {
    if (!(t.tag in m)) m[t.tag] = { value: t.value, name: t.name };
  }
  return m;
};

export function buildComparison(A, B) {
  A = A || {}; B = B || {};
  const da = dutFields(A), db = dutFields(B);
  const idRow = (label, key) => ({ label, a: da[key], b: db[key], diff: da[key] !== db[key] });
  const identity = [
    idRow('Şema', 'scheme'), idRow('PAN', 'pan'), idRow('AID', 'aid'),
    idRow('Geçerlilik', 'expiry'), idRow('ATC', 'atc'), idRow('ATR', 'atr'),
  ];

  const vRow = (label, va, vb) => {
    const ta = va?.text ?? '—', tb = vb?.text ?? '—';
    return { label, a: ta, b: tb, diff: ta !== tb, both: va != null || vb != null };
  };
  const verdicts = [
    vRow('Uyumluluk · Temaslı', compVerdict(A.compContact), compVerdict(B.compContact)),
    vRow('Uyumluluk · Temassız', compVerdict(A.compContactless), compVerdict(B.compContactless)),
    vRow('ODA · Temaslı', odaVerdict(A.odaContact), odaVerdict(B.odaContact)),
    vRow('ODA · Temassız', odaVerdict(A.odaContactless), odaVerdict(B.odaContactless)),
    vRow('ARQC', arqcVerdict(A), arqcVerdict(B)),
  ].filter((r) => r.both);

  const ma = tagMapOf(A), mb = tagMapOf(B);
  const allTags = new Set([...Object.keys(ma), ...Object.keys(mb)]);
  const onlyA = [], onlyB = [], changed = []; let same = 0;
  for (const tag of allTags) {
    const a = ma[tag], b = mb[tag];
    const name = a?.name || b?.name || null;
    if (a && !b) onlyA.push({ tag, name, value: a.value });
    else if (b && !a) onlyB.push({ tag, name, value: b.value });
    else if (a.value !== b.value) changed.push({ tag, name, a: a.value, b: b.value });
    else same++;
  }
  const byTag = (x, y) => x.tag.localeCompare(y.tag);
  const diffCount = identity.filter((r) => r.diff).length + verdicts.filter((r) => r.diff).length
    + onlyA.length + onlyB.length + changed.length;
  return {
    identity, verdicts,
    tags: { onlyA: onlyA.sort(byTag), onlyB: onlyB.sort(byTag), changed: changed.sort(byTag), same },
    hasTags: allTags.size > 0,
    diffCount,
  };
}
