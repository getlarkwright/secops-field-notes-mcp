#!/usr/bin/env node
// secops-field-notes-mcp — the SecOps Field Notes toolbox as MCP tools.
// Everything runs locally: scoring, extraction, decoding and header analysis never open a
// socket. The one exception is lookup_kev, which fetches CISA's public catalog. No account,
// no telemetry, nothing of yours is read from disk.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

import { cvssFromInput, renderCvss } from "./lib/cvss.js";
import { extractIocs, renderIocs, defang, refang } from "./lib/ioc.js";
import { analyzeHeaders, renderHeaders } from "./lib/emailheader.js";
import { identifyHash, renderHash } from "./lib/hashes.js";
import { decodeJwt, renderJwt } from "./lib/jwt.js";
import { parseTimestamp, formats, renderTimestamp } from "./lib/timestamp.js";
import { decodeLayers, renderLayers, OP_NAMES } from "./lib/decoder.js";
import { lookupKev, renderKev } from "./lib/kev.js";

const str = (v, fallback = "") => (typeof v === "string" ? v : v === undefined || v === null ? fallback : String(v));

const TOOLS = [
  {
    name: "cvss_score",
    description:
      "Score a vulnerability with CVSS v3.1, exactly as the FIRST specification computes it. Give a vector string " +
      "(CVSS:3.1/AV:N/AC:L/...) or the eight base metrics; returns the base score, severity band, normalised vector, " +
      "and the impact/exploitability sub-scores.",
    inputSchema: {
      type: "object",
      properties: {
        vector: { type: "string", description: "e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
        metrics: { type: "object", description: "Alternative to vector: {AV, AC, PR, UI, S, C, I, A} with single-letter values." },
      },
    },
    run: (a) => renderCvss(cvssFromInput({ vector: str(a.vector), metrics: a.metrics })),
  },
  {
    name: "extract_iocs",
    description:
      "Pull every indicator out of a blob of text — a report, an alert, a mail — and return them sectioned and " +
      "defanged, ready for a ticket: IPv4, IPv6, domains, URLs, emails, CVE ids, MD5/SHA-1/SHA-256. Defanged input " +
      "(hxxp, [.], [at]) is refanged first, so pasting from another report works. Filenames are not mistaken for domains.",
    inputSchema: {
      type: "object",
      properties: { text: { type: "string" }, defanged: { type: "boolean", description: "Defang the output (default true)." } },
      required: ["text"],
    },
    run: (a) => renderIocs(extractIocs(str(a.text)), a.defanged !== false),
  },
  {
    name: "defang_text",
    description: "Defang or refang indicators in text: http→hxxp[://], dots→[.], @→[at], and back. Use before pasting live URLs into anything that auto-links.",
    inputSchema: {
      type: "object",
      properties: { text: { type: "string" }, mode: { type: "string", description: "'defang' (default) or 'refang'." } },
      required: ["text"],
    },
    run: (a) => (str(a.mode).toLowerCase() === "refang" ? refang(str(a.text)) : defang(str(a.text))),
  },
  {
    name: "analyze_email_headers",
    description:
      "Phishing triage on raw email headers: the Received chain in chronological order with per-hop delay, the " +
      "originating public IP, SPF/DKIM/DMARC verdicts, and the mismatches that matter — From vs Return-Path domain, " +
      "Reply-To pointing elsewhere (BEC), authentication failures, hops timestamped before the previous one.",
    inputSchema: { type: "object", properties: { headers: { type: "string", description: "The raw message source, or at least the header block." } }, required: ["headers"] },
    run: (a) => renderHeaders(analyzeHeaders(str(a.headers))),
  },
  {
    name: "identify_hash",
    description: "Identify a hash by shape: bcrypt, Argon2, yescrypt, the Unix crypt family, LM:NT pairs, and hex-length MD5/NTLM, SHA-1, SHA-224/256/384/512 — with what that shape implies for cracking or reuse.",
    inputSchema: { type: "object", properties: { hash: { type: "string" } }, required: ["hash"] },
    run: (a) => renderHash(identifyHash(str(a.hash))),
  },
  {
    name: "decode_jwt",
    description: "Decode a JWT's header and payload (no verification — it says so), show iat/nbf/exp as dates, and flag alg:none, missing alg, expiry, tokens that never expire, and long-lived tokens.",
    inputSchema: { type: "object", properties: { token: { type: "string", description: "The token, with or without a 'Bearer ' prefix." } }, required: ["token"] },
    run: (a) => renderJwt(decodeJwt(str(a.token))),
  },
  {
    name: "convert_timestamp",
    description: "Turn any timestamp into every form an investigation needs: Unix epoch in s/ms/µs (detected by digit count), Windows FILETIME, ISO 8601, RFC 2822 dates, or 'now' — with UTC, weekday and relative time.",
    inputSchema: { type: "object", properties: { value: { type: "string" } }, required: ["value"] },
    run: (a) => { const p = parseTimestamp(str(a.value)); return renderTimestamp(p, p.error ? null : formats(p.ms)); },
  },
  {
    name: "decode_layers",
    description:
      `Peel a layered payload: run a chain of operations (${OP_NAMES.join(", ")}) and see every intermediate result. ` +
      "Default chain is a single base64_decode. Stops at the first step that fails and says which.",
    inputSchema: {
      type: "object",
      properties: { input: { type: "string" }, ops: { type: "array", items: { type: "string" }, description: `Ops in order, from: ${OP_NAMES.join(", ")}` } },
      required: ["input"],
    },
    run: (a) => renderLayers(decodeLayers(str(a.input), a.ops)),
  },
  {
    name: "lookup_kev",
    description:
      "Is this CVE exploited in the wild? Checks CISA's Known Exploited Vulnerabilities catalog: date added, the " +
      "federal due date, whether it is used in ransomware campaigns, and the required action. Accepts any text " +
      "containing CVE ids. The only tool here that touches the network; the catalog is cached for an hour.",
    inputSchema: { type: "object", properties: { cves: { type: "string", description: "One or more CVE ids, or text containing them." } }, required: ["cves"] },
    run: async (a) => {
      try { return renderKev(await lookupKev(str(a.cves))); }
      catch (e) { return `Could not fetch the KEV catalog (${e.message}). It is at https://www.cisa.gov/known-exploited-vulnerabilities-catalog`; }
    },
  },
  {
    name: "latest_field_note",
    description: "The most recent This Week in Security episodes — what got exploited, what to patch, what it means for the systems you defend. Reads a public RSS feed.",
    inputSchema: { type: "object", properties: { count: { type: "number", description: "How many recent episodes (default 3)." } } },
    run: async (a) => {
      const count = Math.max(1, Math.min(10, Number(a.count) || 3));
      try {
        const res = await fetch("https://secopsfieldnotes.com/podcast/feed.xml", { headers: { "user-agent": "secops-field-notes-mcp" }, signal: AbortSignal.timeout(10000) });
        if (!res.ok) throw new Error(`feed returned ${res.status}`);
        const xml = await res.text();
        const unescape = (s) => s.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#0?39;|&apos;/g, "'");
        const items = [...xml.matchAll(/<item>([\s\S]*?)<\/item>/g)].slice(0, count).map((m) => {
          const get = (tag) => { const t = m[1].match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`)); return t ? unescape(t[1].replace(/<!\[CDATA\[|\]\]>/g, "")).trim() : ""; };
          return { title: get("title"), date: get("pubDate").replace(/\s\d{2}:\d{2}:\d{2}.*$/, ""), summary: get("description").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").slice(0, 300) };
        });
        if (!items.length) return "No episodes found in the feed right now.";
        return `Latest from This Week in Security:\n\n${items.map((i) => `${i.date} — ${i.title}\n  ${i.summary}`).join("\n\n")}`;
      } catch (e) {
        return `Could not reach the feed (${e.message}).`;
      }
    },
  },
];

const server = new Server({ name: "secops-field-notes", version: "0.1.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })) }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const tool = TOOLS.find((t) => t.name === req.params.name);
  if (!tool) return { content: [{ type: "text", text: `Unknown tool: ${req.params.name}` }], isError: true };
  try { return { content: [{ type: "text", text: await tool.run(req.params.arguments || {}) }] }; }
  catch (e) { return { content: [{ type: "text", text: `${tool.name} failed: ${e.message}` }], isError: true }; }
});
await server.connect(new StdioServerTransport());
