// CVSS v3.1 base score, straight from the FIRST specification. Ported from the Field Kit.

export const METRICS = {
  AV: ["N", "A", "L", "P"], AC: ["L", "H"], PR: ["N", "L", "H"], UI: ["N", "R"],
  S: ["U", "C"], C: ["N", "L", "H"], I: ["N", "L", "H"], A: ["N", "L", "H"],
};
export const LABELS = {
  AV: "Attack Vector", AC: "Attack Complexity", PR: "Privileges Required", UI: "User Interaction",
  S: "Scope", C: "Confidentiality", I: "Integrity", A: "Availability",
};
export const OPTION_NAMES = {
  AV: { N: "Network", A: "Adjacent", L: "Local", P: "Physical" },
  AC: { L: "Low", H: "High" },
  PR: { N: "None", L: "Low", H: "High" },
  UI: { N: "None", R: "Required" },
  S: { U: "Unchanged", C: "Changed" },
  C: { N: "None", L: "Low", H: "High" },
  I: { N: "None", L: "Low", H: "High" },
  A: { N: "None", L: "Low", H: "High" },
};

// FIRST's Roundup: smallest number, to one decimal, that is >= the input — done in
// integer arithmetic so 4.0000001-style float noise does not push a 4.0 to 4.1.
function roundup(x) {
  const i = Math.round(x * 100000);
  if (i % 10000 === 0) return i / 100000;
  return (Math.floor(i / 10000) + 1) / 10;
}

export function severity(score) {
  if (score <= 0) return "None";
  if (score < 4) return "Low";
  if (score < 7) return "Medium";
  if (score < 9) return "High";
  return "Critical";
}

export function parseVector(str) {
  const m = {};
  const body = String(str || "").trim().replace(/^CVSS:3\.[01]\//i, "");
  for (const p of body.split("/")) {
    const kv = p.split(":");
    if (kv.length === 2) {
      const k = kv[0].toUpperCase();
      if (METRICS[k]) m[k] = kv[1].toUpperCase();
    }
  }
  for (const k of Object.keys(METRICS)) {
    if (!(k in m)) return { error: `Vector is missing ${k} (${LABELS[k]}).` };
  }
  return { metrics: m };
}

export function score(m) {
  for (const k of Object.keys(METRICS)) {
    if (!METRICS[k].includes(m[k])) return { error: `Missing or invalid metric: ${k} (${LABELS[k]}) — allowed: ${METRICS[k].join(", ")}.` };
  }
  const av = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  const ac = { L: 0.77, H: 0.44 };
  const prU = { N: 0.85, L: 0.62, H: 0.27 };
  const prC = { N: 0.85, L: 0.68, H: 0.5 };
  const ui = { N: 0.85, R: 0.62 };
  const cia = { H: 0.56, L: 0.22, N: 0 };
  const changed = m.S === "C";
  const iss = 1 - (1 - cia[m.C]) * (1 - cia[m.I]) * (1 - cia[m.A]);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const expl = 8.22 * av[m.AV] * ac[m.AC] * (changed ? prC : prU)[m.PR] * ui[m.UI];
  const base = impact <= 0 ? 0 : roundup(Math.min(changed ? 1.08 * (impact + expl) : impact + expl, 10));
  return {
    score: base, severity: severity(base),
    vector: `CVSS:3.1/AV:${m.AV}/AC:${m.AC}/PR:${m.PR}/UI:${m.UI}/S:${m.S}/C:${m.C}/I:${m.I}/A:${m.A}`,
    impact: Math.round(Math.max(impact, 0) * 10) / 10, exploitability: Math.round(expl * 10) / 10, metrics: m,
  };
}

export function cvssFromInput({ vector, metrics }) {
  if (vector) {
    const p = parseVector(vector);
    if (p.error) return p;
    return score(p.metrics);
  }
  if (metrics && typeof metrics === "object") {
    const m = {};
    for (const [k, v] of Object.entries(metrics)) m[String(k).toUpperCase()] = String(v).toUpperCase().slice(0, 1);
    return score(m);
  }
  return { error: "Give a CVSS 3.1 vector string, or the eight base metrics." };
}

export function renderCvss(r) {
  if (r.error) return r.error;
  const rows = Object.keys(METRICS).map((k) => `  ${LABELS[k].padEnd(20)} ${OPTION_NAMES[k][r.metrics[k]]}`);
  const lines = [
    `${r.score.toFixed(1)}  ${r.severity.toUpperCase()}`,
    `  ${r.vector}`,
    ``,
    ...rows,
    ``,
    `  Impact ${r.impact.toFixed(1)} · Exploitability ${r.exploitability.toFixed(1)}${r.metrics.S === "C" ? " · scope changed (×1.08)" : ""}`,
  ];
  if (r.metrics.AV === "N" && r.metrics.PR === "N" && r.metrics.UI === "N") {
    lines.push(``, `Network-reachable, no privileges, no user interaction: this is the shape that gets exploited at scale. Treat exposure, not just the score.`);
  }
  return lines.join("\n");
}
