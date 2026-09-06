# secops-field-notes-mcp

The things a security analyst does by hand a dozen times a shift, as tools your coding agent can
call: score a CVE, pull the indicators out of a report and defang them for the ticket, read a
phishing email's headers properly, work out what kind of hash that is, decode a JWT, turn a
timestamp into something a human can read, peel a base64-of-hex payload, and check whether a CVE
is on CISA's exploited-in-the-wild list.

Free, MIT, no account, no telemetry. Everything except the KEV lookup runs entirely on your machine.

## Install

Pin the version.

**Claude Code**

```
claude mcp add secops-field-notes -- npx -y github:labaccessnow/secops-field-notes-mcp#v0.1.0
```

**Claude Desktop, Cursor, or any client with a JSON config**

```json
{
  "mcpServers": {
    "secops-field-notes": {
      "command": "npx",
      "args": ["-y", "github:labaccessnow/secops-field-notes-mcp#v0.1.0"]
    }
  }
}
```

**Docker**

```json
{
  "mcpServers": {
    "secops-field-notes": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "ghcr.io/labaccessnow/secops-field-notes-mcp:0.1.0"]
    }
  }
}
```

Node 18 or newer for the npx route. Also in the official MCP registry as
`io.github.labaccessnow/secops-field-notes-mcp`.

## Tools

| Tool | What it answers | Network |
|---|---|---|
| `cvss_score` | CVSS 3.1 base score from a vector or the eight metrics, exactly as FIRST computes it | none |
| `extract_iocs` | Every IP, domain, URL, email, CVE id and hash in a blob of text — refanged on the way in, defanged on the way out | none |
| `defang_text` | hxxp[://], [.], [at] and back | none |
| `analyze_email_headers` | The Received chain in order with hop delays, the origin IP, SPF/DKIM/DMARC, and the mismatches phishing triage looks for | none |
| `identify_hash` | bcrypt, Argon2, yescrypt, Unix crypt, LM:NT, MD5/NTLM, SHA-1/224/256/384/512 — by shape, with what that implies | none |
| `decode_jwt` | Header, payload, times as dates; flags alg:none, expiry, tokens that never expire | none |
| `convert_timestamp` | Epoch s/ms/µs, Windows FILETIME, ISO 8601, RFC 2822 — into every form | none |
| `decode_layers` | Chain base64 / hex / URL / HTML-entity / ROT13 decoding and see each layer | none |
| `lookup_kev` | Is this CVE exploited in the wild — CISA KEV date added, due date, ransomware use, required action | CISA feed, cached 1h |
| `latest_field_note` | What got exploited this week | RSS |

### analyze_email_headers

Paste the raw source. It unfolds the headers, reads the `Received` lines in chronological order
(they are stored newest-first), computes the delay at each hop, finds the first public IP in the
chain, reads the authentication verdicts, and then says what a triage analyst would say:

```
From        "IT Helpdesk" <helpdesk@corp.example>
Reply-To    helpdesk-reset@evil-mail.example
Auth        SPF pass · DKIM pass · DMARC fail
Origin IP   192.0.2.44

Received chain (origin first, 3 hops):
   1. [10.0.0.5] [192.0.2.44] → relay.example-news.com  2026-09-05 13:59:50Z
   2. relay.example-news.com [198.51.100.9] → mx3.corp.example  2026-09-05 14:00:15Z  +25s
   3. mx3.corp.example [203.0.113.30] → inbox.corp.example  2026-09-05 14:00:20Z  +5s

Warnings:
  ! From domain (corp.example) ≠ Return-Path domain (mailer.example-news.com) …
  ! Reply-To goes to a different domain (evil-mail.example) than From (corp.example) — classic BEC pattern.
  ! DMARC verdict: fail.
```

### cvss_score

The arithmetic is the FIRST specification's, including the Roundup function done in integer
arithmetic so floating-point noise never pushes a 4.0 to a 4.1. Log4Shell's vector scores 10.0;
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` scores 9.8. Both are in the test suite.

## What it does not do

- No account, no signup, no key. No telemetry.
- Nothing is read from your disk; every input is text you pass in.
- No verification of JWT signatures — it decodes, and says so on every result.
- One network call in the package: `lookup_kev` fetches CISA's public catalog (about 1.7 MB) and keeps
  it for an hour. Everything else never opens a socket.
- It does not query VirusTotal, AbuseIPDB or any enrichment service. Those need keys and accounts; this
  server is for the work you do before and after them.

## Licence

MIT. Written by James Son — network, security, and automation engineer. The logic is the same as the
free Field Kit desktop app's security tools, so the two stay in step. Corrections welcome.
