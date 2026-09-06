// Timestamp parsing and conversion: Unix epoch (s/ms/µs), Windows FILETIME, ISO 8601 and
// free-form date strings. Ported from the Field Kit.

const FILETIME_EPOCH_DIFF = 116444736000000000n; // 100-ns ticks between 1601-01-01 and 1970-01-01

export function parseTimestamp(input, nowMs = Date.now()) {
  const t = String(input || "").trim();
  if (!t) return { error: "Give a timestamp: epoch digits, ISO 8601, an RFC 2822 date, a Windows FILETIME, or 'now'." };
  if (/^now$/i.test(t)) return { ms: nowMs, source: "current time" };
  if (/^-?\d+$/.test(t)) {
    const digits = t.replace("-", "").length;
    if (digits <= 10) return { ms: Number(t) * 1000, source: "Unix epoch (seconds)" };
    if (digits <= 13) return { ms: Number(t), source: "Unix epoch (milliseconds)" };
    if (digits <= 16) return { ms: Math.trunc(Number(t) / 1000), source: "Unix epoch (microseconds)" };
    const ms = Number((BigInt(t) - FILETIME_EPOCH_DIFF) / 10000n);
    return { ms, source: "Windows FILETIME (100-ns ticks since 1601)" };
  }
  const d = Date.parse(t);
  if (!Number.isNaN(d)) return { ms: d, source: "date string" };
  return { error: `Could not parse "${t}" — use epoch digits, ISO 8601, an RFC 2822 date, a FILETIME, or 'now'.` };
}

export function relative(ms, nowMs = Date.now()) {
  let d = (nowMs - ms) / 1000;
  const future = d < 0;
  d = Math.abs(d);
  const u = d < 60 ? `${Math.round(d)} seconds` : d < 3600 ? `${Math.round(d / 60)} minutes` : d < 86400 ? `${(d / 3600).toFixed(1)} hours` : `${(d / 86400).toFixed(1)} days`;
  return future ? `in ${u}` : `${u} ago`;
}

export function formats(ms, nowMs = Date.now()) {
  const d = new Date(ms);
  const filetime = (BigInt(ms) * 10000n + FILETIME_EPOCH_DIFF).toString();
  return {
    iso: d.toISOString(), utc: d.toUTCString(), epoch_s: Math.trunc(ms / 1000), epoch_ms: ms, epoch_us: `${ms}000`,
    filetime, relative: relative(ms, nowMs), weekday: d.toLocaleDateString("en-US", { weekday: "long", timeZone: "UTC" }),
  };
}

export function renderTimestamp(p, f) {
  if (p.error) return p.error;
  return [
    `${f.iso}  (${f.weekday}, ${f.relative})`,
    `  read as       ${p.source}`,
    `  UTC           ${f.utc}`,
    `  epoch s/ms/µs ${f.epoch_s} / ${f.epoch_ms} / ${f.epoch_us}`,
    `  FILETIME      ${f.filetime}`,
  ].join("\n");
}
