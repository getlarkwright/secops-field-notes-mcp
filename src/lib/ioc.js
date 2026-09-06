// IOC extraction and defang/refang. Ported from the Field Kit. Defanged input is refanged
// first, so pasting straight from a report works.

export function refang(t) {
  let x = String(t || "");
  x = x.replace(/\[(?:\.|dot)\]/gi, ".").replace(/\((?:\.|dot)\)/gi, ".").replace(/\{(?:\.|dot)\}/gi, ".");
  x = x.replace(/\[(?:at|@)\]|\((?:at|@)\)|\{(?:at|@)\}/gi, "@");
  x = x.replace(/\[:\/\/\]|\[:\]\/\/|\[\/\/\]/g, "://");
  x = x.replace(/\bhxxp(s?)\b/gi, (_, s) => "http" + s.toLowerCase()).replace(/\bfxp\b/gi, "ftp");
  x = x.replace(/\[:(\d+)\]/g, ":$1");
  return x;
}

export function defang(t) {
  let x = String(t || "");
  x = x.replace(/\bhttps:\/\//gi, "hxxps[://]").replace(/\bhttp:\/\//gi, "hxxp[://]").replace(/\bftp:\/\//gi, "fxp[://]");
  x = x.replace(/([a-z0-9._%+-]+)@([a-z0-9.-]+\.[a-z]{2,})/gi, "$1[at]$2");
  x = x.replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, (m) => m.replace(/\./g, "[.]"));
  x = x.replace(/\b(?:[a-z0-9_-]+\.)+[a-z]{2,}\b/gi, (m) => m.replace(/\./g, "[.]"));
  return x;
}

// File suffixes the domain regex would misread as a TLD.
const FILE_EXTS = new Set(["php", "exe", "dll", "pdf", "doc", "docx", "xls", "xlsx", "txt", "ps1", "bat", "zip", "rar", "js", "html",
  "htm", "png", "jpg", "jpeg", "gif", "py", "sh", "bin", "dat", "tmp", "log", "ini", "cfg", "dmg", "iso", "msi", "vbs", "lnk", "json",
  "xml", "csv", "yml", "yaml", "md", "crt", "pem", "key", "jar", "apk", "elf", "scr", "gz", "tar", "bz2", "7z"]);

const validV4 = (s) => s.split(".").every((o) => /^\d{1,3}$/.test(o) && Number(o) <= 255);

function expandV6(s) {
  s = String(s || "").trim();
  if (!/^[0-9a-f:]+$/i.test(s) || (s.match(/::/g) || []).length > 1) return null;
  let parts;
  if (s.includes("::")) {
    const [l, r] = s.split("::");
    const left = l ? l.split(":") : [], right = r ? r.split(":") : [];
    const mid = 8 - left.length - right.length;
    if (mid < 0) return null;
    parts = [...left, ...Array(mid).fill("0"), ...right];
  } else parts = s.split(":");
  if (parts.length !== 8 || parts.some((p) => !/^[0-9a-f]{1,4}$/i.test(p))) return null;
  return parts.map((p) => p.toLowerCase().padStart(4, "0"));
}

function compressV6(groups) {
  const s = groups.map((g) => g.replace(/^0+/, "") || "0");
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8; i++) {
    if (s[i] !== "0") continue;
    let j = i;
    while (j < 8 && s[j] === "0") j++;
    if (j - i > bestLen) { bestLen = j - i; best = i; }
    i = j - 1;
  }
  if (bestLen < 2) return s.join(":");
  return s.slice(0, best).join(":") + "::" + s.slice(best + bestLen).join(":");
}

const dedupe = (xs) => [...new Set(xs)];

export function extractIocs(input) {
  const t = refang(input);
  const urls = dedupe([...t.matchAll(/\bhttps?:\/\/[^\s"'<>()[\]{}]+/gi)].map((m) => m[0].replace(/[.,;:]+$/, "")));
  const emails = dedupe([...t.matchAll(/\b[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi)].map((m) => m[0].toLowerCase()));
  const ips = dedupe([...t.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)].map((m) => m[0]).filter(validV4));
  const ips6 = dedupe([...t.matchAll(/\b[0-9a-fA-F:]*::?[0-9a-fA-F:.]+\b/g)].map((m) => m[0])
    .filter((s) => s.includes(":") && expandV6(s)).map((s) => compressV6(expandV6(s))));
  const domains = dedupe([...t.matchAll(/\b(?:[a-z0-9_-]+\.)+([a-z]{2,})\b/gi)]
    .filter((m) => !FILE_EXTS.has(m[1].toLowerCase())).map((m) => m[0].toLowerCase()));
  const hex = (n) => dedupe([...t.matchAll(new RegExp(`\\b[0-9a-fA-F]{${n}}\\b`, "g"))].map((m) => m[0].toLowerCase()).filter((s) => /[a-f]/.test(s)));
  const cves = dedupe([...t.matchAll(/\bCVE-\d{4}-\d{4,7}\b/gi)].map((m) => m[0].toUpperCase()));
  const r = { ips, ips6, domains, urls, emails, cves, md5: hex(32), sha1: hex(40), sha256: hex(64) };
  r.total = Object.values(r).reduce((a, v) => a + (Array.isArray(v) ? v.length : 0), 0);
  return r;
}

export function renderIocs(r, defanged = true) {
  if (!r.total) return "No indicators found — no IPs, domains, URLs, emails, CVE ids or hashes in that text.";
  const out = [`${r.total} indicator${r.total === 1 ? "" : "s"}${defanged ? " (defanged — safe to paste into a ticket)" : ""}:`, ""];
  const sec = (name, xs) => {
    if (!xs.length) return;
    out.push(`# ${name} (${xs.length})`);
    for (const x of xs) out.push(defanged ? defang(x) : x);
    out.push("");
  };
  sec("IPv4", r.ips); sec("IPv6", r.ips6); sec("Domains", r.domains); sec("URLs", r.urls); sec("Emails", r.emails);
  sec("CVEs", r.cves); sec("MD5", r.md5); sec("SHA-1", r.sha1); sec("SHA-256", r.sha256);
  return out.join("\n").trim();
}
