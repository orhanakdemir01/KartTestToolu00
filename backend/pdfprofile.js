// Parse a Mastercard Profile Advisor "Profile Report" PDF into a list of EMV
// tag → value entries, so the personalised profile can be compared against what
// the card actually returns. The report lays each data element out in fixed
// columns (Name · Tag · Type · Value · Help · Commentary); values wrap over
// several lines. We reconstruct rows by y-coordinate and read the Tag/Value
// columns by x-range, accumulating a value until the next tagged row.
import { getDocument } from 'pdfjs-dist/legacy/build/pdf.mjs';

const TAG_X = [116, 178];   // Tag column x-range
const VAL_X = [286, 380];   // Value column (excludes Help at ~384)
const NAME_X = [30, 116];   // Name column
const isTag = (s) => /^[0-9A-Fa-f]{2}([0-9A-Fa-f]{2})?$/.test((s || '').replace(/\s/g, ''));

export async function parseProfilePdf(buffer) {
  // pdfjs requires a plain Uint8Array, not a Node Buffer (a Uint8Array subclass).
  const data = Uint8Array.from(buffer);
  const doc = await getDocument({ data, useSystemFonts: true }).promise;
  const records = [];
  let section = null;
  for (let p = 1; p <= doc.numPages; p++) {
    const page = await doc.getPage(p);
    const tc = await page.getTextContent();
    const items = tc.items
      .map((it) => ({ s: it.str, x: it.transform[4], y: it.transform[5] }))
      .filter((i) => i.s && i.s.trim());
    items.sort((a, b) => b.y - a.y || a.x - b.x);
    // Group into visual rows by y.
    const rows = [];
    let cur = null;
    for (const i of items) {
      if (!cur || Math.abs(i.y - cur.y) > 3) { cur = { y: i.y, cells: [] }; rows.push(cur); }
      cur.cells.push(i);
    }
    let active = null;
    for (const row of rows) {
      const first = row.cells[0];
      const tagCell = row.cells.find((c) => c.x >= TAG_X[0] && c.x <= TAG_X[1] && isTag(c.s));
      const valCells = row.cells.filter((c) => c.x >= VAL_X[0] && c.x <= VAL_X[1]).sort((a, b) => a.x - b.x);
      const nameCells = row.cells.filter((c) => c.x >= NAME_X[0] && c.x <= NAME_X[1]);
      // Section header (fci / internal / …): a lone left-aligned lowercase word.
      if (!tagCell && row.cells.length === 1 && first.x < 60 && /^[a-z][a-z0-9 _-]+$/.test(first.s.trim()) && first.s.trim().length < 28) {
        section = first.s.trim(); active = null; continue;
      }
      if (tagCell) {
        active = { tag: tagCell.s.replace(/\s/g, '').toUpperCase(), section, name: nameCells.map((c) => c.s).join(' '), parts: [] };
        records.push(active);
      } else if (active && nameCells.length) {
        active.name += ' ' + nameCells.map((c) => c.s).join(' ');
      }
      if (active && valCells.length) for (const v of valCells) active.parts.push(v.s.replace(/\s/g, ''));
    }
  }
  const list = [];
  for (const r of records) {
    const value = r.parts.join('').replace(/[^0-9A-Fa-f]/g, '').toUpperCase();
    if (!value) continue; // data element with no value → skip
    list.push({ tag: r.tag, value, section: r.section || null, name: r.name.trim().replace(/\s+/g, ' ') });
  }
  // Tag → value map (first occurrence); `list` keeps every entry for multi-value.
  const tags = {};
  for (const e of list) if (!(e.tag in tags)) tags[e.tag] = e.value;
  return { pages: doc.numPages, count: list.length, tags, list };
}
