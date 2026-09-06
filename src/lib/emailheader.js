// Email header analysis: the Received chain in order with per-hop delay, the
// authentication verdicts, and the mismatches phishing triage looks for. Ported from the Field Kit.

const MONTHS = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12 };
const NAMED_TZ = { UT: 0, GMT: 0, EST: -300, EDT: -240, CST: -360, CDT: -300, MST: -420, MDT: -360, PST: -480, PDT: -420 };

// RFC 2822 date ("Sat, 16 Aug 2026 02:00:00 -0400 (EDT)") -> ms since epoch, or null.
export function parseRfc2822(s) {
  const m = String(s || "").match(/(\d{1,2})\s+([A-Za-z]{3})\w*\s+(\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([+-]\d{4}|[A-Z]{2,4})?/);
  if (!m) return null;
  const mon = MONTHS[m[2].toLowerCase()];
  if (!mon) return null;
  let year = Number(m[3]);
  if (year < 100) year += year < 70 ? 2000 : 1900;
  let offMin = 0;
  const tz = m[7];
  if (tz && /^[+-]\d{4}$/.test(tz)) offMin = (tz.startsWith("-") ? -1 : 1) * (Number(tz.slice(1, 3)) * 60 + Number(tz.slice(3, 5)));
  else if (tz) offMin = NAMED_TZ[tz] ?? 0;
  const utc = Date.UTC(year, mon - 1, Number(m[1]), Number(m[4]), Number(m[5]), Number(m[6] || 0));
  return utc - offMin * 60000;
}

function isPublicV4(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((o) => !Number.isInteger(o) || o > 255)) return false;
  const [a, b] = p;
  if (a === 10 || a === 127 || a === 0) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 169 && b === 254) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  return true;
}

export function analyzeHeaders(raw) {
  const lines = String(raw || "").replace(/\r\n/g, "\n").split("\n");
  const unfolded = [];
  for (const line of lines) {
    if (!line.trim()) { if (unfolded.length) break; continue; }
    if (/^[ \t]/.test(line) && unfolded.length) unfolded[unfolded.length - 1] += " " + line.trim();
    else unfolded.push(line);
  }
  if (!unfolded.length) return { error: "No headers found. Paste the raw message source (View original / Show original)." };

  const fields = {}, received = [], auth = [];
  for (const h of unfolded) {
    const i = h.indexOf(":");
    if (i <= 0) continue;
    const k = h.slice(0, i).trim().toLowerCase(), v = h.slice(i + 1).trim();
    if (k === "received") received.push(v);
    else if (k === "authentication-results" || k === "received-spf") { auth.push(v); fields[k] ??= v; }
    else fields[k] ??= v;
  }

  // Received headers are prepended, so header order is newest-first.
  const hops = received.slice().reverse().map((r) => {
    const from = r.match(/from\s+([^\s;()]+)/i)?.[1] || null;
    const by = r.match(/\bby\s+([^\s;()]+)/i)?.[1] || null;
    // "from [10.0.0.5] (host [192.0.2.44])" carries the client's claimed address first and the
    // peer the receiving server actually saw second — prefer the first public one.
    const ips = [...r.matchAll(/[[(](?:IPv6:)?((?:\d{1,3}\.){3}\d{1,3})[\])]/g)].map((m) => m[1]);
    const ip = ips.find(isPublicV4) || ips[0] || null;
    const semi = r.lastIndexOf(";");
    const date = semi >= 0 ? parseRfc2822(r.slice(semi + 1)) : null;
    return { raw: r, from, by, ip, date, delay_s: null };
  });
  for (let i = 1; i < hops.length; i++) {
    if (hops[i - 1].date !== null && hops[i].date !== null) hops[i].delay_s = Math.round((hops[i].date - hops[i - 1].date) / 1000);
  }

  const verdict = (key) => {
    for (const a of auth) { const m = a.match(new RegExp(`${key}=(\\w+)`, "i")); if (m) return m[1].toLowerCase(); }
    return null;
  };
  const spf = verdict("spf"), dkim = verdict("dkim"), dmarc = verdict("dmarc");
  const originIp = hops.find((h) => h.ip && isPublicV4(h.ip))?.ip || null;

  const domainOf = (addr) => addr?.match(/@([a-z0-9.-]+)/i)?.[1]?.toLowerCase().replace(/[>\s].*$/, "") || null;
  const fromDom = domainOf(fields.from), rpDom = domainOf(fields["return-path"]), replyDom = domainOf(fields["reply-to"]);
  const warnings = [];
  if (fromDom && rpDom && fromDom !== rpDom) warnings.push(`From domain (${fromDom}) ≠ Return-Path domain (${rpDom}) — common in bulk mail, also in spoofing.`);
  if (fromDom && replyDom && fromDom !== replyDom) warnings.push(`Reply-To goes to a different domain (${replyDom}) than From (${fromDom}) — classic BEC pattern.`);
  for (const [k, v] of [["SPF", spf], ["DKIM", dkim], ["DMARC", dmarc]]) {
    if (v === "fail" || v === "permerror" || v === "softfail") warnings.push(`${k} verdict: ${v}.`);
  }
  hops.forEach((h, i) => { if (i > 0 && h.delay_s !== null && h.delay_s < -60) warnings.push(`Hop ${i + 1} is timestamped ${-h.delay_s}s BEFORE the previous hop — clock skew or a forged Received header.`); });

  return { fields, hops, spf, dkim, dmarc, origin_ip: originIp, warnings };
}

const fmtDelay = (s) => s === null ? "" : s < 0 ? `${s}s` : s < 60 ? `+${s}s` : s < 3600 ? `+${Math.round(s / 60)}m` : `+${(s / 3600).toFixed(1)}h`;

export function renderHeaders(r) {
  if (r.error) return r.error;
  const f = r.fields;
  const lines = [
    `From        ${f.from || "(none)"}`,
    `Reply-To    ${f["reply-to"] || "(none)"}`,
    `Return-Path ${f["return-path"] || "(none)"}`,
    `Subject     ${f.subject || "(none)"}`,
    `Auth        SPF ${r.spf || "?"} · DKIM ${r.dkim || "?"} · DMARC ${r.dmarc || "?"}`,
    `Origin IP   ${r.origin_ip || "no public IP in the chain"}`,
    ``,
    `Received chain (origin first, ${r.hops.length} hop${r.hops.length === 1 ? "" : "s"}):`,
  ];
  r.hops.forEach((h, i) => {
    lines.push(`  ${String(i + 1).padStart(2)}. ${h.from || "?"}${h.ip ? ` [${h.ip}]` : ""} → ${h.by || "?"}` +
      `${h.date !== null ? `  ${new Date(h.date).toISOString().replace("T", " ").slice(0, 19)}Z` : ""}${h.delay_s !== null ? `  ${fmtDelay(h.delay_s)}` : ""}`);
  });
  lines.push(``, r.warnings.length ? `Warnings:\n${r.warnings.map((w) => "  ! " + w).join("\n")}` : "No triage warnings: domains agree, authentication did not fail, hops are in order.");
  return lines.join("\n");
}
