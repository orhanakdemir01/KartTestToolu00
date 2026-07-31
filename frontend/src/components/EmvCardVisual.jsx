// Paylaşılan kart yüzü görseli — Kart & EMV ve Kart Image sekmelerinde kullanılır.
// Kart okunmadan placeholder, okununca üzerine dolar. Mavi kart + marka işareti
// (şema logodan tanınır: Visa wordmark, Mastercard iki-daire).

// Şema marka işareti — Visa/Mastercard tanınır biçimde, diğerleri metin.
function SchemeMark({ scheme }) {
  if (scheme === 'Mastercard') return (
    <span className="sm-mc"><svg width="44" height="28" viewBox="0 0 44 28" aria-label="Mastercard">
      <circle cx="17" cy="14" r="12" fill="#eb001b" /><circle cx="27" cy="14" r="12" fill="#f79e1b" fillOpacity="0.9" />
    </svg></span>
  );
  if (scheme === 'Visa') return <span className="sm-visa">VISA</span>;
  if (scheme === 'Amex') return <span className="sm-txt">AMEX</span>;
  return <span className="sm-txt">{scheme || 'EMV'}</span>;
}

// Kart yüzü görseli — cardData yoksa placeholder, varsa üzerine dolar.
export function EmvCardVisual({ cardData, scheme, contactless }) {
  const has = !!cardData?.pan;
  return (
    <div className={`emv-card ${has ? '' : 'empty'}`}>
      <div className="emv-top">
        {contactless && (
          <span className="emv-nfc" title="temassız">
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round">
              <path d="M6 5a8 8 0 0 1 0 10" /><path d="M9.5 7a4.5 4.5 0 0 1 0 6" /><path d="M13 9a1.5 1.5 0 0 1 0 2" />
            </svg>
          </span>
        )}
        <SchemeMark scheme={scheme} />
      </div>
      <div className="emv-chip" aria-label="çip">
        <svg width="38" height="28" viewBox="0 0 46 34" fill="none" xmlns="http://www.w3.org/2000/svg">
          <defs><linearGradient id="emvChip" x1="0" y1="0" x2="1" y2="1"><stop stopColor="#f5d97a" /><stop offset="1" stopColor="#c99a2e" /></linearGradient></defs>
          <rect x="0.5" y="0.5" width="45" height="33" rx="6" fill="url(#emvChip)" stroke="rgba(0,0,0,0.18)" />
          <rect x="6" y="5" width="34" height="24" rx="3" fill="none" stroke="rgba(0,0,0,0.28)" />
          <line x1="6" y1="17" x2="40" y2="17" stroke="rgba(0,0,0,0.28)" />
          <line x1="17" y1="5" x2="17" y2="29" stroke="rgba(0,0,0,0.28)" />
          <line x1="29" y1="5" x2="29" y2="29" stroke="rgba(0,0,0,0.28)" />
        </svg>
      </div>
      <div className="emv-pan mono">{has ? cardData.panFormatted : '•••• •••• •••• ••••'}</div>
      <div className="emv-bottom">
        <div><span className="emv-lbl">KART SAHİBİ</span><span>{has ? (cardData.cardholderName || '—') : '—'}</span></div>
        <div><span className="emv-lbl">VALID THRU</span><span className="mono">{has ? (cardData.expiry || '—') : '••/••'}</span></div>
      </div>
    </div>
  );
}

// Kart Image (perso tag) verisinden kart yüzü için { pan, panFormatted, isim, SKT, şema } çıkar.
export function cardDataFromImage(img) {
  const app = img?.applications?.[0];
  if (!app) return null;
  const find = (t) => (app.tags || []).find((x) => x.tag === t) || null;
  const t5a = find('5A'), t57 = find('57'), t5f20 = find('5F20'), t5f24 = find('5F24');
  let pan = null;
  if (t5a) pan = t5a.value.replace(/[\sF]/gi, '');
  else if (t57) { const v = t57.value.replace(/\s/g, ''); const dsep = v.indexOf('D'); if (dsep > 0) pan = v.slice(0, dsep); }
  const cd = { scheme: app.scheme };
  if (pan) { cd.pan = pan; cd.panFormatted = pan.replace(/(.{4})/g, '$1 ').trim(); }
  if (t5f20) cd.cardholderName = (t5f20.ascii || '').trim() || null;
  if (t5f24) { const v = t5f24.value.replace(/\s/g, ''); if (/^[0-9]{6}$/.test(v)) cd.expiry = v.slice(2, 4) + '/' + v.slice(0, 2); }
  return cd;
}
