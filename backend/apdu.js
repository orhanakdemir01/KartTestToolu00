// Low-level APDU transmission + response decoding helpers (shared by all routes).
import pcsc from './pcsc.js';
import { parseTlv, describeSw, INS } from './emv.js';

// True when a real PC/SC reader is connected and usable.
export const usingRealReader = () => pcsc.available && pcsc.listReaders().length > 0;

// Build a human description from INS + SW.
export function describeApdu(cmdHex, sw) {
  const c = cmdHex.replace(/\s/g, '').toUpperCase();
  const ins = c.slice(2, 4);
  const parts = [];
  if (INS[ins]) parts.push(INS[ins]);
  const swDesc = describeSw(sw);
  if (swDesc) parts.push(swDesc);
  return parts.join(' — ') || 'Yanıt';
}

// Strip the trailing SW (last 2 bytes) and TLV-parse the data portion.
export function tlvFromResponse(responseHex) {
  const bytes = responseHex.replace(/\s/g, '');
  if (bytes.length <= 4) return { nodes: [], ok: false }; // only SW, no data
  const data = bytes.slice(0, -4); // remove 2-byte SW
  return parseTlv(data);
}

// Low-level: send one APDU to the real card, return { response, sw }.
export async function transmitOnce(clean, reader) {
  if (!usingRealReader() || !pcsc.getActiveCard(reader)?.connected) {
    throw new Error('Okuyucuda kart yok');
  }
  const buf = Buffer.from(clean, 'hex');
  return pcsc.transmit(buf, reader);
}

// Send an APDU, transparently handling 61xx (GET RESPONSE) and 6Cxx (wrong Le).
export async function transmitChain(clean, reader) {
  let { response, sw } = await transmitOnce(clean, reader);

  // 6C XX → resend with correct Le
  if (sw.toUpperCase().startsWith('6C')) {
    const le = sw.slice(2);
    const base = clean.length >= 10 ? clean.slice(0, 8) : clean; // CLA INS P1 P2
    ({ response, sw } = await transmitOnce(base + le, reader));
  }

  // 61 XX → GET RESPONSE, accumulate data before SW
  let dataHex = response.replace(/\s/g, '').slice(0, -4);
  while (sw.toUpperCase().startsWith('61')) {
    const le = sw.slice(2);
    const gr = await transmitOnce('00C00000' + le, reader);
    const grHex = gr.response.replace(/\s/g, '');
    dataHex += grHex.slice(0, -4);
    sw = gr.sw;
    response = (dataHex + sw).replace(/(.{2})/g, '$1 ').trim();
  }
  return { response, sw };
}
