Language: [简体中文](README.md) | [English](README_EN.md)

Important notice: all techniques, ideas, and tooling described here are provided only for security learning, research, and authorized testing. Do not use them for illegal activity or profit-driven abuse. You are responsible for your own actions.

### Introduction

Authors: [p0desta](https://github.com/p0desta/), [Y0!0](https://github.com/hooray195), [0cat](https://github.com/0cat-r)

Team: [0x727](https://github.com/0x727)

BypassPro is a Burp Suite extension for finding bypass points during authorized offensive security and penetration testing, including 403/401 access-control bypasses and WAF/parser differential bypasses.

Runtime: Java 8 compatible. The project uses `source/target=8` in `pom.xml`; builds can be produced with JDK 8+.

This project is a second development based on [p0desta/AutoBypass403-BurpSuite](https://github.com/p0desta/AutoBypass403-BurpSuite). Thanks to p0desta for the original open-source project and permission to publish this fork.

### Quick Navigation

- [Quick Start](#quick-start)
- [Which Entry Should I Use?](#which-entry-should-i-use)
- [Cases Only](#cases)
- [BypassPro 5.1 Highlights](#bypasspro-51-highlights)
  - [Modes](#modes)
  - [Manual WAF Workbench](#manual-waf-workbench)
  - [Gh0st Bits](#gh0st-bits)
  - [Raw Socket Sending](#raw-socket-sending)
  - [Configuration](#configuration)
  - [Dashboard and Results](#dashboard-and-results)
- [Auto Access Bypass](#auto-access-bypass)
- [Auto WAF Bypass](#auto-waf-bypass)
- [Manual WAF](#manual-waf)

### BypassPro 5.1 Highlights

BypassPro 5.1 turns the old single-purpose 403 bypass workflow into a combined Burp extension with:

- automated access-control bypass checks,
- automated WAF bypass mutation,
- a Manual WAF workbench for request editing and payload composition,
- Gh0st Bits payload generation,
- optional Raw Socket sending,
- YAML-based configuration.

#### Modes

**Auto Access Bypass**

- Entry: `Send to BypassPro (Access Control)` or Dashboard `AutoScan`.
- Config: `profiles.auto_access_bypass`.
- Purpose: 401/403, unauthorized access, access-control bypass testing.
- Rule groups: `suffix`, `prefix`, `boundary_insert`, `headers`.

**Auto WAF Bypass**

- Entry: `Send to BypassPro (WAF)`.
- Config: `profiles.auto_waf_bypass`.
- Purpose: automatically generate WAF bypass variants for a selected request.
- Capabilities:
  - path/header mutation,
  - body charset encoding: UTF-16, UTF-16BE, UTF-16LE, UTF-32, UTF-32BE, UTF-32LE, IBM037,
  - gzip body transform,
  - Content-Type spoofing,
  - Gh0st Bits automatic candidates.

**Manual WAF**

- Entry: `Send to BypassPro (Manual WAF)`.
- Purpose: a repeater-like workbench focused on WAF and parser-differential bypass research.
- Features:
  - Burp native `IMessageEditor` with Pretty / Raw / Hex support,
  - editable host / port / HTTPS target,
  - Send / Cancel / Reset / Undo / Redo,
  - Follow Redirect, using `general.max_redirects` as the global hop limit,
  - request/response History.

#### Manual WAF Workbench

The tool area is grouped by purpose:

- **Obfuscation & Noise**: control characters, dirty bytes, null bytes, traversal and path boundary mutations.
- **Data Encoding**: URL encode, Path encode, double URL encode, mixed encode, Unicode escape, Base64, charset transforms.
- **Char Mutation**: fullwidth characters, homoglyphs, zero-width characters, case mutation.
- **Header Bypass**: X-Forwarded-For, X-Client-IP, X-Remote-Addr, Referer, HTTP/1.0, and related headers.
- **Body Bypass**: form / multipart / JSON conversion, gzip, HTTP/1.0.
- **Gh0st Bits**: Java char-to-byte truncation, loose parsers, and template-based exploit-chain construction.

Selection rules:

- If text is selected, the selected range has highest priority.
- If the same selected bytes appear multiple times, BypassPro asks for scope: selected occurrence / all / Nth occurrence.
- For URL encoding operations where safe characters do not change by default, BypassPro asks for scope first, then asks whether to force every UTF-8 byte into `%XX`.
- If no safe scope can be inferred, it asks the user to select text first.
- After mutation, the editor keeps the caret/selection near the changed position.

#### Gh0st Bits

Gh0st Bits is for testing parser differences around Java `char` to `byte` truncation, loose percent-hex parsing, and multi-stage decoding.

Common manual capabilities:

- Ghost encode: minimal dangerous-set, full ASCII, letters, digits, symbols.
- Ghost restore preview: simulate low 8-bit or low 7-bit restoration.
- Candidate lookup: select a single ASCII character and inspect possible Ghost characters.
- Common payload helpers: `.%u002e`, CRLF, `.jsp`, `@type`, `class`.
- Parser helpers: fastjson `\x4_`, fastjson `\u`, jackson `\u`, Unicode digits, Jetty `%2>`, Fullwidth URL, Tomcat `%HH`.

Important clarification: Gh0st Bits is not a fixed payload and is not equivalent to "Chinese characters mean vulnerability". The characters are only a visual representation of bytes that may be restored differently by downstream components.

#### Raw Socket Sending

Manual WAF supports three send modes:

- `Auto`: default; uses Raw Socket when the request line or headers contain non-ASCII bytes that Burp may normalize.
- `Burp`: force Burp `makeHttpRequest`.
- `Raw`: force Raw Socket.

Raw Socket bypasses Burp's client-side normalization and does not use Burp's upstream proxy / SOCKS settings. It is intended for labs, CTFs, and authorized testing where exact bytes matter.

#### Configuration

The config file uses a profile-based structure:

```yaml
general:
  threads: 5
  max_redirects: 3
  similarity_threshold: 0.85
  lang: zh

profiles:
  auto_access_bypass:
    ...
  auto_waf_bypass:
    ...
  manual_waf_bypass:
    ghost_bits:
      ...
```

Notes:

- External config path: `~/.config/BypassPro/BypassPro-config.yaml`.
- First startup copies the built-in template to the external config path.
- Config UI supports Reload / Reinit / Save General / Save WAF Options.
- `general.max_redirects` is shared by Dashboard automatic mode and Manual WAF Follow Redirect. Default: `3`.
- `general.lang` supports `zh` and `en`.

#### Dashboard and Results

Dashboard controls:

- `AutoScan`: listen to Proxy responses and automatically scan 401/403 responses.
- `Follow Redirect`: control whether Dashboard automatic/send tasks follow `301/302/303/307/308`. Default: off.
- `Threads`: current scan concurrency from `general.threads`.
- `Req`, progress bar, `Err`, and `Clear`.

Follow Redirect is snapshotted when a task starts. Changing the checkbox later only affects new AutoScan / Send tasks.

Dashboard columns:

- `id`
- `tool`
- `Title`
- `Method`
- `Length`
- `Request URL`
- `MIME Type`
- `HTTP Status`
- `Redirect`
- `Reason`

Result attribution:

- `Request URL` always shows the actual fuzz target.
- If Follow Redirect is enabled and the final response comes from another URL, `Request URL` still stays on the fuzz target.
- `Redirect` shows redirect state, for example:
  - `false`
  - `true 0/3`
  - `true 1/3`
- Hover the `Redirect` cell to see the full chain, for example `/download.do;.css -> /nolimit.jsp`.
- `Reason` only explains why the row was recorded, such as status change, similarity difference, or a Ghost Bits signature. It does not contain redirect settings.

### Which Entry Should I Use?

| Entry | Location | Best for | Config |
| --- | --- | --- | --- |
| AutoScan | Dashboard `AutoScan` | Automatically scanning Proxy 401/403 responses | `profiles.auto_access_bypass` |
| Send to BypassPro (Access Control) | Context menu | Testing one request for access-control bypass | `profiles.auto_access_bypass` |
| Send to BypassPro (WAF) | Context menu | Automatically generating WAF bypass variants | `profiles.auto_waf_bypass` |
| Send to BypassPro (Manual WAF) | Context menu | Manual payload composition and byte-level testing | `profiles.manual_waf_bypass` |

Simple choice:

- Use `AutoScan` when browsing a site and looking for 401/403 bypass opportunities.
- Use `Access Control` when you want to test one specific request.
- Use `WAF` when you want automatic body/path/header mutation.
- Use `Manual WAF` when you need precise selection, encoding, Raw Socket sending, and repeated comparison.

### Auto Access Bypass

Auto Access Bypass targets 401/403 and access-control bypass testing.

Triggers:

- Dashboard `AutoScan`.
- Context menu `Send to BypassPro (Access Control)`.

Rules:

- `suffix`: append variants to the path.
- `prefix`: insert variants before each path segment.
- `boundary_insert`: insert tokens at directory boundaries.
- `headers`: add or replace spoofing headers.

Dashboard records candidates when response status/body differences meet the configured threshold. `Reason` may show:

```text
status:403 -> 200
sim:0.42 < 0.85
class changed
```

### Auto WAF Bypass

Auto WAF Bypass generates variants from:

- path/header rules,
- body charset transforms,
- gzip body transform,
- Content-Type spoofing,
- Gh0st Bits candidates.

Auto Gh0st Bits does not invent a brand-new CVE payload by default. It mutates suspicious tokens or parser structures already present in the original request. Template-based exploit-chain probes are opt-in in the YAML config.

Example: query value already contains traversal semantics.

```http
GET /api/download?file=../../etc/passwd HTTP/1.1
Host: target.com
```

Auto may produce a `ghost:eq` candidate:

```http
GET /api/download?file=阮阮/阮阮/etc/passwd HTTP/1.1
Host: target.com
```

This means "same backend-restored semantics, different visible representation"; it is not a vulnerability confirmation by itself.

### Manual WAF

Basic workflow:

1. Send a request to `Manual WAF`.
2. Select the exact text you want to mutate.
3. Use a tool button in the lower tool area.
4. Inspect status, Ghost restore preview, and response diff hints.
5. Choose send mode: `Auto`, `Burp`, or `Raw`.
6. Click `Send`; results appear in the response viewer and History.

### Quick Start

- Start with `AutoScan` to quickly cover common 401/403 scenarios.
- Re-test suspicious rows with `Send to BypassPro (Access Control)` or `Send to BypassPro (WAF)`.
- Use `Manual WAF` for precise, iterative payload research.
- Use `Follow Redirect` only when redirects are part of the workflow you want to validate; otherwise keep it off to avoid confusing a redirect target with the actual fuzz target.

### Cases

The Chinese README contains the full historical case notes and screenshots:

- [Gh0st Bits 实操案例](README.md#gh0st-bits-实操案例)
- [历史案例](README.md#历史案例)

Those cases include older BypassPro examples and may not represent the exact 5.x workflow.
