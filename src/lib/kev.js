// CISA Known Exploited Vulnerabilities — one public JSON feed, no key. Fetched once per
// process and kept for an hour, so a triage session does not re-download 1.7 MB per question.

const FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const TTL_MS = 60 * 60 * 1000;
let cache = null; // { at, byId: Map, released, count }

export async function loadKev(force = false) {
  if (!force && cache && Date.now() - cache.at < TTL_MS) return cache;
  const res = await fetch(FEED, { headers: { "user-agent": "secops-field-notes-mcp" }, signal: AbortSignal.timeout(20000) });
  if (!res.ok) throw new Error(`KEV feed returned HTTP ${res.status}`);
  const d = await res.json();
  const byId = new Map();
  for (const v of d.vulnerabilities || []) byId.set(String(v.cveID).toUpperCase(), v);
  cache = { at: Date.now(), byId, released: d.dateReleased, count: byId.size, version: d.catalogVersion };
  return cache;
}

export async function lookupKev(ids) {
  const wanted = [...new Set(String(ids || "").toUpperCase().match(/CVE-\d{4}-\d{4,7}/g) || [])];
  if (!wanted.length) return { error: "Give one or more CVE ids, e.g. CVE-2021-44228 (any text containing them works)." };
  const k = await loadKev();
  const rows = wanted.map((id) => ({ id, entry: k.byId.get(id) || null }));
  return { rows, released: k.released, count: k.count };
}

export function renderKev(r) {
  if (r.error) return r.error;
  const inKev = r.rows.filter((x) => x.entry);
  const head = `${inKev.length} of ${r.rows.length} in CISA's Known Exploited Vulnerabilities catalog (${r.count} entries, released ${r.released}).`;
  const blocks = r.rows.map(({ id, entry: e }) => {
    if (!e) return `${id}\n  not in KEV — no confirmed in-the-wild exploitation on CISA's list. That is not "not exploited"; it is "not on this list".`;
    const days = Math.round((Date.parse(e.dueDate) - Date.parse(e.dateAdded)) / 86400000);
    return [
      `${id} — ${e.vendorProject} ${e.product}: ${e.vulnerabilityName}`,
      `  EXPLOITED IN THE WILD · added ${e.dateAdded} · federal due date ${e.dueDate} (${days}-day window)` +
        (e.knownRansomwareCampaignUse === "Known" ? " · USED IN RANSOMWARE CAMPAIGNS" : ""),
      `  ${e.shortDescription}`,
      `  Required action: ${e.requiredAction}`,
      ...(e.cwes?.length ? [`  CWE: ${e.cwes.join(", ")}`] : []),
      ...(e.notes ? [`  Notes: ${String(e.notes).split(";")[0].trim()}`] : []),
    ].join("\n");
  });
  return [head, ...blocks].join("\n\n");
}
