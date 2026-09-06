// JWT decoding — decode only, no verification, and the output says so. Ported from the Field Kit.

function b64url(s) {
  let t = String(s || "").trim().replace(/-/g, "+").replace(/_/g, "/");
  while (t.length % 4 !== 0) t += "=";
  return Buffer.from(t, "base64").toString("utf8");
}

export function decodeJwt(token) {
  const t = String(token || "").trim().replace(/^Bearer\s+/i, "");
  if (!t) return { error: "Give a token." };
  const parts = t.split(".");
  if (parts.length !== 3) return { error: `A JWT has three dot-separated parts — got ${parts.length}.` };
  let header, payload;
  try { header = JSON.parse(b64url(parts[0])); } catch { return { error: "Header is not valid Base64URL JSON." }; }
  try { payload = JSON.parse(b64url(parts[1])); } catch { return { error: "Payload is not valid Base64URL JSON." }; }
  const warnings = [];
  const alg = String(header.alg ?? "").toLowerCase();
  if (alg === "none") warnings.push('alg is "none" — this token is UNSIGNED. Nothing should accept it.');
  if (header.alg === undefined) warnings.push("No alg in header.");
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp === "number") {
    if (payload.exp < now) warnings.push(`Expired ${Math.round((now - payload.exp) / 60)} minutes ago (exp ${new Date(payload.exp * 1000).toISOString()}).`);
    else if (payload.exp - (payload.iat || now) > 86400 * 30) warnings.push(`Long-lived: expires ${new Date(payload.exp * 1000).toISOString()} — more than 30 days of validity.`);
  } else warnings.push("No exp claim — the token never expires on its own.");
  if (typeof payload.nbf === "number" && payload.nbf > now) warnings.push(`Not valid yet (nbf ${new Date(payload.nbf * 1000).toISOString()}).`);
  return { header, payload, signature: parts[2], warnings };
}

export function renderJwt(r) {
  if (r.error) return r.error;
  const fmt = (o) => JSON.stringify(o, null, 2).split("\n").map((l) => "  " + l).join("\n");
  const times = ["iat", "nbf", "exp"].filter((k) => typeof r.payload[k] === "number")
    .map((k) => `  ${k.padEnd(4)} ${new Date(r.payload[k] * 1000).toISOString()}`);
  return [
    "Header:", fmt(r.header), "", "Payload:", fmt(r.payload),
    ...(times.length ? ["", "Times:", ...times] : []),
    "", `Signature: ${r.signature.slice(0, 24)}… (${r.signature.length} chars) — NOT verified; this tool only decodes.`,
    ...(r.warnings.length ? ["", ...r.warnings.map((w) => "  ! " + w)] : []),
  ].join("\n");
}
