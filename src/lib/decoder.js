// Decoder workbench: base64, hex, URL, HTML entities, ROT13 — each op returns {out} or {error}
// so they chain. Ported from the Field Kit.

const ok = (out) => ({ out });
const fail = (error) => ({ error });

const ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", copy: "©", reg: "®", trade: "™",
  hellip: "…", mdash: "—", ndash: "–", lsquo: "‘", rsquo: "’", ldquo: "“", rdquo: "”" };

export const OPS = {
  base64_decode: (s) => {
    let t = s.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
    if (!t) return fail("Nothing to decode.");
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(t)) return fail("Not valid Base64.");
    while (t.length % 4 !== 0) t += "=";
    return ok(Buffer.from(t, "base64").toString("utf8"));
  },
  base64_encode: (s) => ok(Buffer.from(s, "utf8").toString("base64")),
  hex_decode: (s) => {
    const t = s.replace(/0x/gi, "").replace(/[^0-9a-fA-F]/g, "");
    if (!t) return fail("No hex digits found.");
    if (t.length % 2) return fail("Odd number of hex digits.");
    return ok(Buffer.from(t, "hex").toString("utf8"));
  },
  hex_encode: (s) => ok(Buffer.from(s, "utf8").toString("hex")),
  url_decode: (s) => { try { return ok(decodeURIComponent(s.replace(/\+/g, "%20"))); } catch { return fail("Bad percent-encoding."); } },
  url_encode: (s) => ok(encodeURIComponent(s)),
  html_decode: (s) => ok(s.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (m, e) => {
    if (/^#x/i.test(e)) { const cp = parseInt(e.slice(2), 16); return Number.isNaN(cp) ? m : String.fromCodePoint(cp); }
    if (e.startsWith("#")) { const cp = parseInt(e.slice(1), 10); return Number.isNaN(cp) ? m : String.fromCodePoint(cp); }
    return ENTITIES[e.toLowerCase()] ?? m;
  })),
  rot13: (s) => ok(s.replace(/[a-zA-Z]/g, (c) => String.fromCharCode((c <= "Z" ? 90 : 122) >= c.charCodeAt(0) + 13 ? c.charCodeAt(0) + 13 : c.charCodeAt(0) - 13))),
};

export const OP_NAMES = Object.keys(OPS);

// Run a chain of ops on the input; stops at the first failure and says where.
export function decodeLayers(input, ops) {
  const steps = [];
  let cur = String(input ?? "");
  const list = Array.isArray(ops) && ops.length ? ops : ["base64_decode"];
  for (const name of list) {
    const op = OPS[String(name || "").toLowerCase().trim()];
    if (!op) return { steps, error: `Unknown op "${name}". Available: ${OP_NAMES.join(", ")}.` };
    const r = op(cur);
    if (r.error) return { steps, error: `${name}: ${r.error}` };
    steps.push({ op: name, out: r.out });
    cur = r.out;
  }
  return { steps, out: cur };
}

const preview = (s, n = 400) => (s.length > n ? s.slice(0, n) + `… (${s.length} chars)` : s);
const printable = (s) => /^[\x09\x0a\x0d\x20-\x7e -￿]*$/.test(s);

export function renderLayers(r) {
  const lines = [];
  r.steps.forEach((s, i) => {
    lines.push(`${i + 1}. ${s.op}${printable(s.out) ? "" : "  (binary — shown escaped)"}`);
    lines.push("   " + preview(printable(s.out) ? s.out : JSON.stringify(s.out)).replace(/\n/g, "\n   "));
  });
  if (r.error) lines.push(`\nStopped: ${r.error}`);
  else if (r.steps.length) lines.push(``, `Final (${r.out.length} chars): ${preview(r.out)}`);
  return lines.join("\n");
}
