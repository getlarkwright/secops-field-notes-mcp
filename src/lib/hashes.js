// Hash identification by shape. Ported from the Field Kit.

export function identifyHash(h) {
  const t = String(h || "").trim();
  if (!t) return { error: "Give a hash to identify." };
  const hex = (n) => new RegExp(`^[0-9a-f]{${n}}$`, "i").test(t);
  let kind, note = "";
  if (/^\$2[aby]\$/.test(t)) { kind = "bcrypt"; note = "Salted, work-factor hash. Crack cost scales with the cost parameter — the 2-digit number after the prefix."; }
  else if (/^\$argon2/i.test(t)) { kind = "Argon2"; note = "Memory-hard password hash. Good sign in a leaked database, bad news for cracking."; }
  else if (t.startsWith("$6$")) { kind = "SHA-512 crypt (Unix shadow)"; }
  else if (t.startsWith("$5$")) { kind = "SHA-256 crypt (Unix shadow)"; }
  else if (t.startsWith("$1$")) { kind = "MD5 crypt (Unix shadow)"; note = "Legacy; fast to crack. Anything still using it should be migrated."; }
  else if (t.startsWith("$y$")) { kind = "yescrypt (Unix shadow)"; }
  else if (/^[0-9a-f]{32}:[0-9a-f]{32}$/i.test(t)) { kind = "LM:NT hash pair (secretsdump style)"; note = "The NT half is unsalted MD4 — pass-the-hash usable as-is. If the LM half is not aad3b435b51404ee…, LM hashes are still being stored."; }
  else if (hex(32)) { kind = "32 hex — MD5 (file/IOC) or NTLM (credential)"; note = "Same length, different meaning: a file hash in a threat report, or an NT hash from a dump. Context decides."; }
  else if (hex(40)) { kind = "40 hex — SHA-1"; }
  else if (hex(56)) { kind = "56 hex — SHA-224"; }
  else if (hex(64)) { kind = "64 hex — SHA-256"; }
  else if (hex(96)) { kind = "96 hex — SHA-384"; }
  else if (hex(128)) { kind = "128 hex — SHA-512"; }
  else if (/^[A-Za-z0-9+/_-]{16,}={0,2}$/.test(t)) { kind = "Looks Base64-encoded — decode it first"; note = "Run decode_layers on it; the hash is probably inside."; }
  else { kind = "Not a common hash format"; }
  return { input: t, kind, note, length: t.length };
}

export function renderHash(r) {
  if (r.error) return r.error;
  return `${r.kind}\n  ${r.length} characters${r.note ? `\n  ${r.note}` : ""}`;
}
