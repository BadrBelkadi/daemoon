# EP21: Corben Leo - Recon, Hacking Methodology & Entrepreneurship - Client-Side Security Notes

## Metadata
- **Podcast:** Critical Thinking Bug Bounty Podcast
- **Episode:** 21
- **Hosts:** Justin Gardner (Rhynorater)
- **Guest:** Corben Leo (@hacker_)
- **Topics:** DNS rebinding, local network access restrictions, WebSocket port scanning, JavaScript file analysis for endpoint discovery
- **Client-Side Relevance:** Low-to-Moderate. The episode is primarily about Corben Leo's background, recon methodology, and entrepreneurship. Client-side content is concentrated in the news section covering DNS rebinding and browser-based local network attacks, plus methodology discussion on JS file analysis.

---

> **Note:** This episode has limited dedicated client-side exploitation content. The majority covers recon methodology, career advice, writing/reporting tips, and entrepreneurship. The actionable client-side material is extracted below.

---

## 1. DNS Rebinding - State of the Art (2023)

Referenced article: "State of DNS Rebinding in 2023" by NCC Group.

### How It Works

DNS rebinding exploits the gap between DNS resolution and the browser's Same-Origin Policy. An attacker-controlled domain initially resolves to an attacker IP, then "rebinds" to a victim's internal IP, allowing the attacker's page (running in the browser) to make requests to internal services as if they share the same origin.

```
Step 1: Victim visits attacker.com
        Browser resolves attacker.com -> attacker IP (e.g., 1.2.3.4)
        Page loads attacker's JavaScript

Step 2: Attacker's DNS server changes the A record
        attacker.com -> 127.0.0.1 (or 0.0.0.0, or internal IP)

Step 3: Attacker's JS makes fetch/XHR to attacker.com
        Browser re-resolves DNS -> now points to internal service
        Request goes to internal service with attacker.com origin

    [Victim Browser]
         |
         |  1. GET attacker.com --> [Attacker Server 1.2.3.4]
         |     <-- loads malicious JS
         |
         |  2. DNS TTL expires / cache evicted
         |
         |  3. fetch("http://attacker.com/api/secret")
         |     DNS resolves attacker.com --> 127.0.0.1
         |     --> Request hits localhost service
         |     <-- Response readable by attacker JS (same origin!)
         |
         v
    [Internal Service on 127.0.0.1]
```

### Chrome Multi-A Record Instant Rebinding to 0.0.0.0

Chrome has a specific behavior with DNS records that return multiple IP addresses (multi-A records). When one IP fails, Chrome automatically falls back to the next IP in the record. This allows **instant** rebinding without waiting for DNS TTL expiry.

```
;; attacker's DNS zone file
attacker.com.  A  1.2.3.4      ; attacker server (primary)
attacker.com.  A  0.0.0.0      ; fallback to all-interfaces bind

;; Attack flow:
;; 1. Browser loads page from 1.2.3.4
;; 2. Attacker takes down 1.2.3.4 (or it times out)
;; 3. Browser falls back to 0.0.0.0 for subsequent requests
;; 4. JS on the page can now read responses from services
;;    bound to 0.0.0.0 on the victim machine
```

**Key constraint discussed:** This multi-A instant rebind currently only works to rebind to `0.0.0.0`, not arbitrary private IPs like `127.0.0.1` or `192.168.x.x`. Services must be listening on all interfaces (bound to `0.0.0.0`) to be reachable.

### Why This Works

- The Same-Origin Policy is based on scheme + host + port. DNS rebinding changes what IP the "host" resolves to without changing the origin string.
- `0.0.0.0` is technically not classified the same way as `127.0.0.1` or RFC1918 private address space in Chrome's network access checks, creating a gap.
- Chrome's multi-A fallback is a performance feature (try next IP if first fails) that doubles as an instant rebinding primitive.

### Chrome Local Network Access Restrictions (Upcoming)

Chrome is rolling out restrictions on local network access from public websites. This is tracked via a **Chrome Deprecation Trial**, which allows developers to request a token to retain the functionality during the transition period.

```
;; What's changing:
;; - Public websites will be blocked from making requests to:
;;   - 127.0.0.0/8 (loopback)
;;   - 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (private)
;;   - link-local addresses
;;
;; - Developers who still need this can request a deprecation trial token
;; - This will be enforced in upcoming Chrome versions
;;
;; Impact on bug bounty:
;; - DNS rebinding to private IPs will be mitigated in modern Chrome
;; - 0.0.0.0 rebinding may still work (tracked separately)
;; - Older Chrome versions (common in enterprise) remain vulnerable
```

### Where To Apply This

- **Internal tool exploitation:** Many development tools (webpack-dev-server, Jupyter notebooks, Docker APIs, Redis, Elasticsearch) bind to `0.0.0.0` by default. If a target's employees run such tools, DNS rebinding from a public page can reach them.
- **Bug bounty programs with internal assets:** Enterprise targets where employees use outdated Chrome versions are particularly vulnerable since local network restrictions are not yet enforced.
- **Electron apps:** Many Electron-based desktop applications embed Chromium but may lag behind Chrome's security patches, leaving DNS rebinding viable longer.
- **Tools:** Singularity (DNS rebinding framework) and Rhynorater's custom DNS rebinding tool were mentioned as still functional for targeting `0.0.0.0`-bound services.

---

## 2. WebSocket Port Scanning (Browser-Based)

### How It Works

Even with local network access restrictions being rolled out, WebSocket-based port scanning still works. This technique uses timing side-channels on WebSocket connection attempts to enumerate open ports on localhost or LAN hosts.

```javascript
// Conceptual WebSocket port scanner
// Measures connection time to infer open vs closed ports

async function scanPort(host, port) {
    return new Promise((resolve) => {
        const start = performance.now();
        const ws = new WebSocket(`ws://${host}:${port}`);

        ws.onopen = () => {
            // Port is open and accepts WebSocket upgrades
            const elapsed = performance.now() - start;
            ws.close();
            resolve({ port, status: 'open', time: elapsed });
        };

        ws.onerror = () => {
            // Timing difference reveals port state:
            // - Fast error (~1-5ms): port open, rejected upgrade (RST)
            // - Slow error (~1000ms+): port closed or filtered (timeout)
            const elapsed = performance.now() - start;
            resolve({
                port,
                status: elapsed < 100 ? 'open' : 'closed',
                time: elapsed
            });
        };

        // Safety timeout
        setTimeout(() => {
            ws.close();
            resolve({ port, status: 'filtered', time: 5000 });
        }, 5000);
    });
}

// Scan common local service ports
// const targets = [3000, 5000, 8080, 8443, 9200, 6379, 27017];
// for (const port of targets) {
//     const result = await scanPort('127.0.0.1', port);
//     console.log(result);
// }
```

```
    [Attacker Page in Victim's Browser]
         |
         |--- WebSocket('ws://127.0.0.1:8080') --> fast error = OPEN
         |--- WebSocket('ws://127.0.0.1:8081') --> slow timeout = CLOSED
         |--- WebSocket('ws://127.0.0.1:3000') --> fast error = OPEN
         |--- WebSocket('ws://127.0.0.1:9200') --> fast error = OPEN (Elasticsearch!)
         |
         v
    Attacker now knows which services run on victim's machine
```

### Why This Works

- WebSocket connections are not subject to CORS preflight checks.
- The timing difference between a TCP RST (port open but not a WebSocket server) and a TCP timeout (port closed/filtered) is measurable from JavaScript.
- Chrome's upcoming local network access restrictions may not fully cover WebSocket connection attempts or the timing side-channel.

### Where To Apply This

- **Reconnaissance phase of DNS rebinding:** Before attempting a full DNS rebinding attack, use WebSocket port scanning to confirm which services are actually running on the target machine.
- **Fingerprinting internal infrastructure:** Identify developer tools, databases, and services running on bug bounty target employees' machines when they visit an attacker-controlled page.
- **Chaining with other vulnerabilities:** Combine with XSS on a target domain to scan the internal network from a more trusted origin context.

---

## 3. JavaScript File Analysis for Endpoint & API Discovery

While not a "vulnerability" per se, the methodology discussed for extracting endpoints from JavaScript files is directly relevant to client-side security analysis. Hidden endpoints found in JS bundles often lack proper authorization or expose internal APIs.

### How It Works

```
    [Target: dashboard.example.com]
         |
         |  1. Directory brute-force finds /js/ directory
         |
         |  2. Brute-force for .js files within /js/
         |     Found: /js/app.bundle.js, /js/admin.chunk.js
         |
         |  3. Read JS files, extract:
         |     - API base URLs (api.internal.example.com)
         |     - Endpoint paths (/api/v2/users/export)
         |     - ASPX/PHP endpoints on other hosts
         |     - OAuth callback URLs
         |     - postMessage targets
         |
         |  4. Enumerate discovered adjacent hosts
         |     api.internal.example.com --> new attack surface
         |
         v
    [Previously unknown internal API surface]
```

```javascript
// What to look for in JS bundles (grep patterns):

// API hosts and base URLs
// fetch("https://api.internal.example.com/v2/
// axios.defaults.baseURL = "https://backend.example.com"
// const API_URL = process.env.REACT_APP_API || "https://staging-api.example.com"

// Hidden admin/debug endpoints
// "/admin/impersonate"
// "/debug/pprof"
// "/__internal/healthcheck"

// postMessage targets (relevant for DOM XSS)
// parent.postMessage({type: "auth", token: ...}, "https://...")
// window.addEventListener("message", function(e) { ... })

// Redirect parameters
// redirectUrl, returnTo, next, redirect_uri, callback
// window.location.href = params.get("redirect")
```

### Why This Works

- Modern SPAs (React, Angular, Vue) ship their entire routing table and API integration code to the browser in JS bundles.
- Webpack/bundler output often includes references to internal, staging, or development API endpoints that were meant to be environment-specific but leaked into production builds.
- CSS files can also contain references (via `url()` for backgrounds/fonts) that reveal internal paths and hostnames.

### Where To Apply This

- **Before deep-diving into an application:** Extract all API endpoints and adjacent hosts from JS bundles to map the full attack surface.
- **Client-side vulnerability hunting:** Look for `postMessage` listeners, `innerHTML` assignments, `eval()` calls, and redirect parameter handling within the extracted JS.
- **Recursive discovery:** Use discovered endpoints to find additional JS files, which may reference further endpoints -- creating a recursive discovery chain (as Corben described: brute-force JS files --> find new directories --> find more JS files --> extract ASPX endpoints).

---

## 4. Outdated Browser Versions in Enterprise Targets

Brief but relevant mention: many bug bounty target organizations run outdated Chrome versions (sometimes 6-10+ versions behind). This means browser-level mitigations (local network access restrictions, SameSite cookie defaults, CORS changes, etc.) may not be in effect.

### Where To Apply This

- When targeting enterprise applications, do not assume modern browser protections are in place.
- Check `User-Agent` strings in HTTP logs or error pages to fingerprint the Chrome version in use.
- Attacks that are "patched" in latest Chrome (DNS rebinding to private IPs, certain CSRF vectors, cookie-related attacks) may still work against organizations running older versions.

---

## Master Summary Table

| # | Technique | Type | Impact | Complexity |
|---|-----------|------|--------|------------|
| 1 | DNS rebinding via multi-A records to 0.0.0.0 | Local network access | Read/write to local services bound on 0.0.0.0 | Medium |
| 2 | Chrome local network access deprecation bypass (0.0.0.0 gap) | Browser restriction bypass | Access to local services despite new restrictions | Low |
| 3 | WebSocket-based port scanning | Reconnaissance / info leak | Enumerate open ports on localhost and LAN | Low |
| 4 | JS bundle endpoint extraction for client-side analysis | Reconnaissance | Discover hidden APIs, postMessage handlers, redirect sinks | Low |
| 5 | Exploiting outdated Chrome in enterprise targets | Browser restriction bypass | Use attacks mitigated in modern Chrome | Low-Medium |

---

## Key Quotes

> "There's a rebind that you can do in Chrome that's instant, using a record that has multiple IP addresses that it resolves to. And that can rebind only to 0.0.0.0, which is like sort of a private IP address. I mean, technically you can access local services, but it's not necessarily specifically a loopback or local IP address space." -- Justin Gardner (Rhynorater)

> "The WebSocket port scanner still works. So you can still do timing attacks against local services and services on the local network using a WebSocket port scanner." -- Justin Gardner (Rhynorater)

> "Good thing all these bug bounty programs are in outdated versions of Chrome still, right? Everyone's ten versions behind." -- Corben Leo

> "I'll find a directory called like JavaScript and I'll just brute force for JavaScript files. I've also tried to find CSS files because sometimes I'll do like import image from like this and it'll be like some super long directory that you might not be able to find." -- Corben Leo

> "The JavaScript file might reference some other APIs and then working on those too, because it's all a part of this like one bigger application." -- Corben Leo

> "Don't put restrictions on ideas before you try it. Oh, there's no way that could work. You'd be surprised by how much code is just strung together with who knows what. There's just weird services that interpret things differently. You never know." -- Corben Leo

---

## Resources & References

- **State of DNS Rebinding in 2023** - NCC Group article covering current DNS rebinding techniques and browser mitigations
- **Singularity** - DNS rebinding attack framework (NCC Group)
- **Chrome Local Network Access** - Chrome deprecation trial for local network request restrictions
- **Chrome 0.0.0.0 rebinding issue** - Tracked Chrome bug for multi-A record rebinding to 0.0.0.0
- **ffuf (fuzz faster u fool)** - Web fuzzer discussed for directory brute-forcing and virtual host enumeration
- **Douglas Day (@ArchangelDDay)** - "100 Bug Bounty Rules" Twitter thread referenced in the episode
- **TalkBack by LTAM** - Cybersecurity news aggregator mentioned as a resource
