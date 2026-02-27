# EP48: Sam Erb - Client-Side Security Notes

## Metadata
- **Guest:** Sam Erb (Google Security Engineer, Bug Bounty Triager)
- **Hosts:** Justin Gardner (@rhynorater), Joel Margolis (teknogeek)
- **Episode:** Critical Thinking Bug Bounty Podcast - Episode 48
- **Episode Link:** https://www.criticalthinkingpodcast.io
- **Twitter:** @urbysam (two Vs)

> **Note:** This episode is primarily focused on hacker methodology, career journey, reconnaissance tooling (bufferover.run), and Google's VRP program structure. Client-side specific content is limited but the actionable techniques discussed below are high-value.

---

## Technique: Google Open Redirect via /amp as a Chain Gadget

### How It Works

Google maintains intentional open redirects as part of its core business (being a search engine that directs users to external sites). The `/amp` endpoint is one such redirect that can be chained with other vulnerabilities.

Step-by-step:

1. You find an open redirect on a Google property, but it only allows redirects to `*.google.com` domains
2. Chain it with Google's `/amp` endpoint which redirects to arbitrary external domains
3. The result is a full open redirect from a trusted Google origin to any attacker-controlled domain

```
[Victim clicks link]
        |
        v
https://vulnerable.google.com/redirect?url=https://google.com/amp/s/evil.com
        |
        v
https://google.com/amp/s/evil.com   (Google's intentional open redirect)
        |
        v
https://evil.com                     (Attacker-controlled)
```

### Why This Works

Google considers certain open redirects as intentional behavior tied to business functionality (search engine redirecting users to results). The `/amp` endpoint specifically exists to serve AMP (Accelerated Mobile Pages) content and inherently redirects to third-party domains. When your initial redirect is scoped only to `*.google.com`, the `/amp` gadget breaks out of that restriction.

### Where To Apply This

- Chain with any vulnerability that requires a same-origin or same-site redirect on Google properties
- OAuth flows where the `redirect_uri` is validated to only allow `google.com` but you need to exfiltrate tokens to an external domain
- Phishing chains where a trusted Google domain increases click-through rates
- Any Google property that restricts redirect targets to Google-owned domains

Sam's note from triage side: Check Google's invalid reports page at `bughunters.google.com` -- some open redirects are explicitly listed as won't-fix, but **unintentional** ones and **JavaScript URI redirects** that escalate to XSS are accepted and rewarded.

---

## Technique: Client-Side JavaScript Redirect to XSS (javascript: URI in Redirect Sinks)

### How It Works

Sam specifically calls out that Google accepts reports where an open redirect can be escalated to cross-site scripting via the `javascript:` URI scheme. This occurs when a redirect is implemented client-side using JavaScript navigation sinks.

Step-by-step:

1. Identify a client-side redirect that reads a URL parameter (e.g., `redirectTo`, `next`, `return_url`)
2. The redirect is implemented via a JavaScript sink like `window.location.href = userInput` or `location.assign(userInput)`
3. If no protocol validation exists, inject `javascript:alert(document.domain)` as the redirect target
4. The browser executes the JavaScript in the context of the vulnerable origin

```javascript
// Vulnerable pattern -- redirect parameter flows to location sink
// File: app-bundle.js

// SOURCE: URL parameter
const params = new URLSearchParams(window.location.search);
const redirectUrl = params.get('redirect');

// NO VALIDATION: no protocol check, no allowlist
// SINK: direct assignment to location
if (redirectUrl) {
    window.location.href = redirectUrl;  // <-- SINK: XSS if javascript: URI
}

// Attack URL:
// https://target.com/login?redirect=javascript:alert(document.cookie)
```

```
[Attacker crafts URL]
        |
        v
https://target.com/page?redirect=javascript:alert(document.cookie)
        |
        v
URLSearchParams extracts "javascript:alert(document.cookie)"
        |
        v
window.location.href = "javascript:alert(document.cookie)"
        |
        v
Browser executes JS in context of target.com --> XSS
```

### Why This Works

Client-side redirects implemented via `window.location`, `location.assign()`, or `location.replace()` will execute `javascript:` URIs. Unlike server-side 302 redirects, the browser treats `javascript:` as a valid protocol for these APIs and executes the payload in the current origin's context. This converts what appears to be a "mere" open redirect into full XSS.

### Where To Apply This

- Any SPA (Single Page Application) that handles redirects client-side after login/logout flows
- OAuth callback handlers that redirect based on a `state` or `redirect` parameter
- Google properties specifically -- Sam confirms these are rewarded when found
- General rule from CLAUDE.md knowledge base: **signIn/signOut redirect parameters are frequent XSS/open redirect targets** (this matches reports #1, #2, #3 from confirmed findings)

---

## Technique: Same-Site Cookie Behavior Differences in Client-Side vs Server-Side Redirects

### How It Works

Justin raises a critical nuance about redirect types and cookie handling. When a redirect happens via JavaScript (client-side), the browser treats it differently than a server-side 302 redirect in terms of which cookies are sent.

```
=== Server-Side Redirect (302) ===

[Third-party site] ---> [302 Redirect to target.com]
                              |
                              v
                         Browser follows redirect
                         SameSite=Lax cookies: SENT (top-level navigation)
                         SameSite=Strict cookies: NOT SENT (cross-site origin)


=== Client-Side JavaScript Redirect ===

[Page on target.com] ---> window.location.href = "https://target.com/api/action"
                              |
                              v
                         Browser navigates
                         SameSite=Lax cookies: SENT
                         SameSite=Strict cookies: SENT (same-site origin!)
```

### Why This Works

Same-Site cookie enforcement depends on the **initiator** of the request. When a JavaScript redirect executes on a page already within the target's origin, the browser considers it a same-site request. This means `SameSite=Strict` cookies are included -- cookies that would be stripped if the same redirect happened from a cross-site context via a 302 or a link click from an attacker's page.

This matters because:
- An open redirect on `target.com` that is client-side (JS-based) can be used to perform actions that require `SameSite=Strict` cookies
- The same redirect as a server-side 302 from a third-party context would NOT carry those cookies
- This makes client-side open redirects strictly more dangerous than server-side ones for CSRF-like chains

### Where To Apply This

- When you find an open redirect and need to determine if it can be used to bypass SameSite cookie protections
- CSRF chains where the target relies on `SameSite=Strict` as a defense
- Token theft scenarios where authentication tokens are in `SameSite=Strict` cookies
- Any attack chain where you need full cookie context and have a same-origin open redirect gadget

---

## Technique: Protobuf Request Manipulation for Hidden Parameter Discovery

### How It Works

Google heavily uses Protocol Buffers (protobuf) for API communication. Sam and the hosts discuss techniques for reversing and manipulating protobuf requests to discover hidden functionality. Google released a Burp extension (using Protoscope) for decoding/re-encoding protobufs.

Step-by-step:

1. Intercept protobuf requests in Burp (they appear as binary blobs, often base64 encoded)
2. Use Google's Burp extension or Protoscope CLI to decode the binary protobuf into human-readable field/value pairs
3. Note that protobuf field names are NOT transmitted -- only field index numbers and types
4. Look for **gaps in field numbering** (e.g., fields 1, 2, 5 exist -- what are 3 and 4?)
5. Inject values at missing field indexes to discover hidden/unused parameters

```
=== Decoded Protobuf Request (field numbers only, no names) ===

Field 1 (string): "user@example.com"     // likely email
Field 2 (int32):  1                       // likely some flag/type
Field 5 (string): "search query"          // likely search term

// MISSING: Fields 3 and 4 -- what do they do?

=== Attack: Inject values at missing field indexes ===

Field 1 (string): "user@example.com"
Field 2 (int32):  1
Field 3 (string): "admin"                 // <-- INJECTED: test string
Field 4 (int32):  1                       // <-- INJECTED: test int
Field 5 (string): "search query"
```

```
[Intercept protobuf request in Burp]
        |
        v
[Decode with Protoscope / Google Burp Extension]
        |
        v
[Identify field indexes: 1, 2, 5]
        |
        v
[Note missing fields: 3, 4]
        |
        v
[Inject values at missing indexes with different types]
        |
        v
[Observe response changes -- new data? errors? behavior change?]
```

### Why This Works

Protobuf definitions often include fields that the client doesn't populate in normal usage. These fields may be:
- Deprecated but still processed server-side
- Internal/admin fields not exposed in the UI
- Feature flags or debug parameters
- Fields used by other clients (mobile, internal tools) but not the web app

Since the server-side protobuf definition includes ALL fields, injecting values at unused indexes can trigger hidden functionality. The key insight from Sam: **"if you see missing fields, try putting something in there... especially missing indexes."**

### Where To Apply This

- Any Google property (virtually all use protobuf)
- gRPC-web applications (protobuf over HTTP)
- Any modern application using protobuf for client-server communication
- Mobile API endpoints that share protobuf definitions with web endpoints
- Tools: Google's Burp extension (Protoscope-based), blackboxprotobuf, protobuf-inspector

---

## Technique: JavaScript Bundle Monitoring for New Attack Surface Detection

### How It Works

Sam describes building custom automation to monitor JavaScript bundles (webpack) for changes, specifically extracting API endpoints from minified code to detect new attack surface as it launches.

Step-by-step:

1. Fetch the target's HTML page and extract JavaScript bundle URLs (webpack chunks)
2. Download and parse the JavaScript bundles
3. Use regex/custom parsers to extract API endpoint patterns from minified code
4. Diff results between runs to detect new endpoints
5. Alert (e.g., Discord notification) when new endpoints appear
6. Immediately test new endpoints before other hunters find them

```bash
# Conceptual pipeline (Sam built this custom in ~4 languages + bash)

# Step 1: Fetch main page, extract JS bundle URLs
curl -s https://target.com | grep -oE 'src="[^"]*\.js"' > bundles.txt

# Step 2: Download all JS bundles
while read url; do curl -s "$url" >> all_bundles.js; done < bundles.txt

# Step 3: Extract API endpoints using regex pattern matching
# Target followed consistent patterns like: "/api/v2/endpoint_name"
rg -oN '"/api/v[0-9]+/[a-zA-Z_/]+"' all_bundles.js | sort -u > endpoints_new.txt

# Step 4: Diff against previous run
diff endpoints_old.txt endpoints_new.txt > new_endpoints.txt

# Step 5: Alert on new findings
if [ -s new_endpoints.txt ]; then
    # Send Discord webhook notification
    curl -X POST "$DISCORD_WEBHOOK" \
         -H "Content-Type: application/json" \
         -d "{\"content\": \"New endpoints found:\\n$(cat new_endpoints.txt)\"}"
fi

# Step 6: Archive current run for next diff
cp endpoints_new.txt endpoints_old.txt
```

```
[Cron job / scheduled task]
        |
        v
[Fetch HTML + JS bundles from target]
        |
        v
[Parse webpack bundles for API endpoint patterns]
        |
        v
[Diff against previous scan results]
        |
        v
[New endpoint detected!] ---> [Discord alert]
        |
        v
[Manually test new endpoint immediately]
        |
        v
[First to find bugs in newly launched features]
```

### Why This Works

When a development team deploys new features, the API endpoints are often referenced in the client-side JavaScript before any documentation or UI exposure. By monitoring the JS bundles, you detect new attack surface at deployment time -- often before the feature is even fully launched or linked in the UI. This gives you a first-mover advantage over other hunters.

Sam's key insight: **"When you know a program well, it can become a very easy way to find bugs. Because as soon as something launches, you can just be like, okay, I'm just gonna go test it, and you're the first one there."**

### Where To Apply This

- Long-term targets where you invest in understanding the codebase structure
- Programs with active development and frequent deployments
- SPAs using webpack/bundlers where API routes are embedded in client JS
- Combined with Burp or manual testing of each newly discovered endpoint
- Particularly effective on targets like Airbnb (Sam's example) where similar vulnerability patterns repeat across new features

---

## Technique: TLS Certificate Scanning for Hidden Origins and Dev Instances

### How It Works

Sam built bufferover.run's TLS endpoint by scanning the entire public internet for TLS certificates, including **self-signed** and invalid certificates. This reveals development instances, origin servers behind CDNs, and internal infrastructure that has no public DNS entry.

Step-by-step:

1. Scan IP ranges for hosts responding on port 443 (and other TLS ports)
2. Collect TLS certificates including self-signed and expired ones
3. Extract hostnames from certificate Subject Alternative Names (SANs) and Common Names (CNs)
4. Cross-reference discovered hostnames with your target's domain patterns
5. Access discovered origin servers and dev instances directly by IP

```
[Scan entire IPv4 space on port 443]
        |
        v
[Collect ALL TLS certs (including self-signed)]
        |
        v
[Extract SANs/CNs from certificates]
        |
        v
[Filter for target domain patterns]
        |
        v
Found: 203.0.113.42 serves cert for "dev-internal.target.com" (self-signed)
Found: 198.51.100.7 serves cert for "staging.target.com" (expired)
Found: 192.0.2.15 serves cert for "target.com" (origin server, no CDN)
        |
        v
[Direct access to origin/dev/staging -- bypass WAF/CDN]
        |
        v
[Find bugs on less-hardened instances]
[Find shared secrets between dev and prod]
```

### Why This Works

- Development and staging servers often have self-signed TLS certificates that are never indexed by certificate transparency logs
- Origin servers behind CDNs (Cloudflare, Akamai, etc.) still serve their real TLS certificates when accessed directly by IP
- Developers often share secrets (API keys, signing keys, session secrets) between dev and prod environments
- Dev instances are almost always less hardened than production
- Open-source libraries sometimes use **static secrets** that end up in production

### Where To Apply This

- Finding origin servers to bypass WAF/CDN protections
- Discovering development/staging environments with weaker security
- Identifying shared secrets between dev and prod (Sam: "you'll find a lot of shared secrets between development and production")
- Finding endpoints that exist without DNS routing (internal only, accessed by IP)
- Tools: Censys, Shodan, or custom scanners (Sam scanned entire internet in 24 hours for ~$500/month bare metal)

---

## Key Quotes

> **Sam on open redirects at Google:** "There's a few cases where we have intentional open redirects that do have security properties... ones that aren't intentional might get rewarded."

> **Sam on JavaScript URI redirects:** He specifically distinguishes between open redirects (often won't-fix at Google) and "JavaScript redirects" / "redirect to cross-site scripting" -- the latter being accepted for bounty.

> **Justin on client-side redirects and cookies:** "When you do a client-side redirect via JavaScript, you're sending different cookies along if you had just done it from a third-party top-level nav."

> **Sam on protobuf hidden fields:** "If you see missing fields, try putting something in there... especially missing indexes... you have like fields one, two and five, like what are three and four?"

> **Sam on dev environments:** "I'll go and find a development environment, find their origin servers... see if things can get reflected into prod or vice versa... you find somewhere on GitHub like a random IP address that happens to be the origin server and that can be huge."

> **Sam on shared secrets:** "You'll find a lot of shared secrets between development and production. And development won't be as locked down, so you just get access to the secrets more often than not."

> **Sam on JS monitoring:** "When you know a program well, it can become a very easy way to find bugs. Because as soon as something launches, you can just be like, okay, I'm just gonna go test it, and you're the first one there."

> **Sam on going deep:** "I'll spend like 10 hours going off and reading an RFC... once you get fixated on something might be vulnerable, then it's hard to think about other things."

---

## Resources & References

| Resource | URL/Description |
|----------|----------------|
| Google Bug Hunters | https://bughunters.google.com |
| Google VRP Invalid Reports Page | bughunters.google.com (invalid reports / redirects section) |
| Google Abuse VRP | Listed under bughunters.google.com programs |
| Protobuf Burp Extension | Released by Google VRP team (uses Protoscope) |
| Protoscope CLI | Released by the Protobuf team for decoding/encoding without .proto definitions |
| bufferover.run | DNS and TLS recon service (acquired by Recorded Future) |
| DNS Prep (Sam's tool) | GitHub - pre-sorted DNS data for hierarchical searching |
| Hacking Google Series | YouTube documentary series (Episode 4: Bug Hunters) |
| Project Sonar (Rapid7) | Public internet scanning dataset (now requires registration) |
| BIMI Protocol | Brand Indicators for Message Identification (email phishing vector discussed) |
| Sam Erb Twitter | @urbysam |

---

## Summary Table

| # | Technique | Type | Impact | Complexity |
|---|-----------|------|--------|------------|
| 1 | Google /amp Open Redirect Chain Gadget | Open Redirect | Medium -- enables phishing, OAuth token theft chains | Low |
| 2 | JavaScript URI in Client-Side Redirect Sinks | DOM XSS | High -- full XSS from redirect parameter | Low |
| 3 | Same-Site Cookie Bypass via Client-Side Redirects | Cookie Security Bypass | High -- bypasses SameSite=Strict, enables CSRF chains | Medium |
| 4 | Protobuf Hidden Field Injection | Parameter Tampering | Variable -- can unlock hidden server-side functionality | Medium |
| 5 | JavaScript Bundle Monitoring for New Endpoints | Recon / Attack Surface Discovery | Medium -- first-mover advantage on new features | Medium |
| 6 | TLS Certificate Scanning for Hidden Origins/Dev | Recon / Infrastructure Discovery | High -- WAF bypass, shared secrets, weaker security | Medium |
