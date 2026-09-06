// Spawns the real server over stdio and exercises every tool with a positive and a negative
// case. The positive controls are published values: FIRST's own CVSS examples, CISA's catalog,
// and headers with a known hop order.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const HEADERS = `Return-Path: <bounce@mailer.example-news.com>
Received: from mx3.corp.example (mx3.corp.example [203.0.113.30])
\tby inbox.corp.example with ESMTPS; Sat, 5 Sep 2026 10:00:20 -0400
Received: from relay.example-news.com (relay.example-news.com [198.51.100.9])
\tby mx3.corp.example with ESMTPS; Sat, 5 Sep 2026 10:00:15 -0400
Received: from [10.0.0.5] (unknown [192.0.2.44])
\tby relay.example-news.com with ESMTPSA; Sat, 5 Sep 2026 09:59:50 -0400
Authentication-Results: mx3.corp.example; spf=pass smtp.mailfrom=example-news.com; dkim=pass; dmarc=fail
From: "IT Helpdesk" <helpdesk@corp.example>
Reply-To: helpdesk-reset@evil-mail.example
To: someone@corp.example
Subject: Password expires today
Date: Sat, 5 Sep 2026 09:59:49 -0400

body starts here`;

const JWT_NONE = Buffer.from('{"alg":"none","typ":"JWT"}').toString("base64url") + "." + Buffer.from('{"sub":"admin","iat":1700000000}').toString("base64url") + ".";
const B64_HEX = Buffer.from(Buffer.from("cmd.exe /c whoami", "utf8").toString("hex")).toString("base64");

const CASES = [
  ["cvss_score", { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" }, ["10.0  CRITICAL"]],
  ["cvss_score", { vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }, ["9.8  CRITICAL"]],
  ["cvss_score", { vector: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N" }, ["1.8  LOW"]],                       // FIRST calculator: 1.8
  ["cvss_score", { metrics: { AV: "N", AC: "L", PR: "L", UI: "N", S: "U", C: "H", I: "N", A: "N" } }, ["6.5  MEDIUM"]],
  ["cvss_score", { vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H" }, ["missing A"]],
  ["extract_iocs", { text: "beacon to hxxp://evil[.]example/x.php from 198[.]51[.]100[.]7, hash d41d8cd98f00b204e9800998ecf8427e, see CVE-2021-44228; sender bad[at]evil[.]example" }, ["IPv4 (1)", "198[.]51[.]100[.]7", "Domains (1)", "evil[.]example", "URLs (1)", "CVE-2021-44228", "MD5 (1)"]],
  ["extract_iocs", { text: "nothing here but words" }, ["No indicators"]],
  ["defang_text", { text: "http://evil.example/a and admin@evil.example" }, ["hxxp[://]evil[.]example", "admin[at]evil[.]example"]],
  ["defang_text", { text: "hxxps[://]evil[.]example", mode: "refang" }, ["https://evil.example"]],
  ["analyze_email_headers", { headers: HEADERS }, ["3 hops", "192.0.2.44", "DMARC fail", "Reply-To goes to a different domain", "helpdesk", "+25s"]],
  ["analyze_email_headers", { headers: "" }, ["No headers"]],
  ["identify_hash", { hash: "$2b$12$abcdefghijklmnopqrstuuVWXYZ0123456789abcdefghijklmnopq" }, ["bcrypt"]],
  ["identify_hash", { hash: "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0" }, ["LM:NT"]],
  ["identify_hash", { hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" }, ["SHA-256"]],
  ["identify_hash", { hash: "hello world" }, ["Not a common hash"]],
  ["decode_jwt", { token: "Bearer " + JWT_NONE }, ['"sub": "admin"', "UNSIGNED", "never expires"]],
  ["decode_jwt", { token: "not.a.jwt.really" }, ["three dot-separated parts"]],
  ["convert_timestamp", { value: "1700000000" }, ["2023-11-14T22:13:20.000Z", "Unix epoch (seconds)", "133444736000000000"]],
  ["convert_timestamp", { value: "133444736000000000" }, ["2023-11-14T22:13:20.000Z", "FILETIME"]],
  ["convert_timestamp", { value: "Sat, 5 Sep 2026 09:59:49 -0400" }, ["2026-09-05T13:59:49.000Z"]],
  ["convert_timestamp", { value: "yesterday-ish" }, ["Could not parse"]],
  ["decode_layers", { input: B64_HEX, ops: ["base64_decode", "hex_decode"] }, ["cmd.exe /c whoami", "1. base64_decode", "2. hex_decode"]],
  ["decode_layers", { input: "uryyb jbeyq", ops: ["rot13"] }, ["hello world"]],
  ["decode_layers", { input: "!!!", ops: ["base64_decode"] }, ["Stopped", "Not valid Base64"]],
  ["lookup_kev", { cves: "CVE-2021-44228" }, ["1 of 1", "Log4j", "EXPLOITED IN THE WILD", "RANSOMWARE"]],
  ["lookup_kev", { cves: "CVE-2099-99999" }, ["0 of 1", "not in KEV"]],
  ["lookup_kev", { cves: "nothing" }, ["Give one or more CVE"]],
  ["latest_field_note", { count: 2 }, ["Security"]],
];

const client = new Client({ name: "smoke-test", version: "0.0.0" }, { capabilities: {} });
await client.connect(new StdioClientTransport({ command: "node", args: [new URL("../src/index.js", import.meta.url).pathname] }));
const { tools } = await client.listTools();
console.log(`tools advertised: ${tools.length} — ${tools.map((t) => t.name).join(", ")}\n`);

let failed = 0;
for (const [name, args, expect] of CASES) {
  const res = await client.callTool({ name, arguments: args });
  const text = (res.content || []).map((c) => c.text || "").join("\n");
  const missing = expect.filter((e) => !text.toLowerCase().includes(e.toLowerCase()));
  const label = `${name}(${Object.keys(args).join(",")})`;
  if (missing.length) { failed++; console.log(`FAIL ${label}\n  missing: ${missing.join(" | ")}\n  got:\n${text.split("\n").map((l) => "    " + l).join("\n")}\n`); }
  else console.log(`pass ${label}`);
}
await client.close();
console.log(failed ? `\n${failed} case(s) failed` : `\nall ${CASES.length} cases passed`);
process.exit(failed ? 1 : 0);
