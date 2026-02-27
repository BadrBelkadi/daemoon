# EP32: Solo News Roundup - Race Conditions, Points.com, & Sandwich Attacks - Client-Side Security Notes

## Metadata
- **Host:** Justin Gardner (@rhynorater)
- **Co-host:** Joel (absent - sick)
- **Format:** Solo news roundup
- **Episode:** 32
- **Episode Link:** ctbb.show
- **Write-ups Covered:**
  1. James Kettle - "Smashing the State Machine" (Race Conditions)
  2. Soroush (soroush.me) - IIS Cookieless Session Auth Bypass
  3. Ophion Security (Roshan) - Shopify Account Takeover via Shop Pay OAuth
  4. Sam Curry - "Hacking Points.com" (Airline/Hotel Rewards)
  5. Lupin & Holmes - "Zero Click ATO with the Sandwich Attack" (UUID v1)

---

> **Client-Side Content Assessment:** This episode is primarily focused on server-side techniques (race conditions, SSRF-like secondary context attacks, JWT weak secrets, UUID brute forcing). However, there are several client-side relevant segments: IIS cookieless session injection leading to reflected XSS, OAuth client-side flow abuse on Shopify, session fixation via URL-injected session tokens, and JavaScript source code analysis methodology. These are extracted in detail below.

---

## 1. IIS Cookieless Session Path Injection for XSS

Covered from Soroush's research on IIS/ASP.NET cookieless session handling.

### How It Works

1. ASP.NET supports "cookieless sessions" where the session ID is embedded directly in the URL path
2. The format is: `/(S(session_value))/` inserted into the URL path
3. IIS strips this segment internally via `RemoveAppPathModifier` before routing the request
4. An attacker can inject arbitrary content into the `(S(...))` segment
5. When the server resolves a tilde (`~`) path to an actual path, the injected session value can be reflected into the response body
6. If reflected without encoding, this achieves XSS

```
Normal request:
GET /webform/protected/page.aspx HTTP/1.1

Bypassed request (path restriction bypass):
GET /webform/(S(anything))/protected/page.aspx HTTP/1.1
               ^^^^^^^^^^^^^^^
               This entire segment gets STRIPPED by IIS internally
               so IIS processes: /webform/protected/page.aspx
               but the reverse proxy / WAF saw a different path

XSS via tilde path resolution:
GET /webform/(S(<script>alert(1)</script>))/~/ HTTP/1.1
               ^^^^^^^^^^^^^^^^^^^^^^^^^^^
               If reflected into body during path resolution = XSS
```

### The Path Bypass Mechanism (ASCII Diagram)

```
Attacker Request:
  /webform/(S(x))/prot(S(y))ected/page.aspx
       |
       v
  [Reverse Proxy / WAF]
       |  Sees: /webform/(S(x))/prot(S(y))ected/page.aspx
       |  Does NOT match /webform/protected/* rule
       |  --> ALLOWS the request through
       v
  [IIS / ASP.NET]
       |  RemoveAppPathModifier() runs
       |  Strips ALL (S(...)), (A(...)), (F(...)) segments
       |  Resolves to: /webform/protected/page.aspx
       |  --> Processes the restricted page
       v
  [Response returned to attacker]
```

### The Three Cookieless Token Types

```
/(S(value))/   -->  Session ID          (most commonly discussed)
/(A(value))/   -->  Anonymous ID        (also works for bypass)
/(F(value))/   -->  Forms Auth Token    (also works for bypass)

All three are stripped by RemoveAppPathModifier.
WAF bypass: if they block (S(...)), try (A(...)) or (F(...))
```

### Why This Works

IIS processes cookieless session tokens at a layer below the reverse proxy or WAF. The proxy sees the full raw URL including the `(S(...))` segment and evaluates path-based access rules against that raw URL. IIS then strips the session segment before routing, resulting in a completely different effective path than what the proxy evaluated.

For the XSS variant specifically: when IIS resolves a tilde (`~`) path to a physical path, the session value from the URL can be reflected into the HTTP response body. If this reflection happens without HTML encoding, an attacker can inject script tags through the session segment.

### Where To Apply This

- **Target identification:** Any IIS + ASP.NET application (check `Server: Microsoft-IIS` header, `.aspx` extensions)
- **Path restriction bypass:** When endpoints are blocked by a reverse proxy (NGINX, Apache, cloud WAF) sitting in front of IIS
- **XSS hunting:** Specifically look for tilde path resolution (`/~/`) in ASP.NET apps and test if the cookieless session value reflects into the response
- **Automation potential:** Justin specifically calls this out as a good candidate for mass XSS scanning: scan for ASP.NET sites, inject XSS payloads via `(S(...))`, check if reflected in response body
- **Session fixation angle:** Since `(F(...))` injects a forms authentication token via the URL, if you can get a victim to click a URL containing your session token, you may achieve session fixation

```
# Quick test for path bypass (manual):
# 1. Find a restricted path that returns 403
curl -s -o /dev/null -w "%{http_code}" https://target.com/admin/

# 2. Try cookieless session injection
curl -s -o /dev/null -w "%{http_code}" https://target.com/(S(x))/admin/

# 3. If 403 -> 200, the bypass works. Try A and F variants too:
curl -s -o /dev/null -w "%{http_code}" https://target.com/(A(x))/admin/
curl -s -o /dev/null -w "%{http_code}" https://target.com/(F(x))/admin/

# Quick test for reflected XSS:
curl -s https://target.com/(S(%3Cscript%3Ealert(1)%3C%2Fscript%3E))/~/
# Check if <script>alert(1)</script> appears unencoded in response body
```

---

## 2. Shopify Shop Pay OAuth Flow Abuse (Client-Side OAuth Hijack)

Covered from Ophion Security (Roshan)'s Shopify account takeover write-up.

### How It Works

1. Attacker creates a Shop account with an unverified email (the target victim's email)
2. The application stores the unverified email as the actual primary email on the account (bad design pattern)
3. Shopify stores have a "Sign in with Shop" OAuth feature that can be enabled/disabled per store
4. **Key client-side insight:** Even when "Sign in with Shop" is disabled in the store UI, the OAuth endpoint is still accessible by directly navigating to it
5. Attacker uses their Shop account (with the victim's unverified email) to initiate the OAuth flow directly
6. The OAuth flow trusts the email from the Shop account and authenticates the attacker as the victim on the Shopify store
7. Attacker manually obtains the required authentication cookies by hitting specific endpoints

```
Attack Flow:

  [Attacker]
       |
       | 1. Creates Shop account with victim@email.com (unverified)
       v
  [Shop Account: victim@email.com (unverified)]
       |
       | 2. Directly navigates to OAuth endpoint
       |    (bypasses UI - "Sign in with Shop" appears disabled)
       v
  [Shop Pay OAuth Endpoint]  <-- Hidden but still active
       |
       | 3. OAuth flow returns auth cookies
       |    Shop account email = victim@email.com
       |    OAuth trusts this email
       v
  [Shopify Store]
       |
       | 4. Store authenticates attacker as victim@email.com
       v
  [Account Takeover - attacker has victim's store account]
```

### Why This Works

Two client-side-relevant issues compound here:

1. **Hidden OAuth endpoints remain functional:** Disabling a feature in the UI does not remove the server-side endpoint. The OAuth flow for "Sign in with Shop" is accessible via direct URL navigation even when the store admin has disabled the feature toggle. This is a classic case where client-side UI state does not reflect server-side authorization state.

2. **Unverified email treated as primary email:** The application stores the unverified email in the primary email field with a separate `is_verified` flag, rather than storing it in a pending/unverified field. The OAuth flow then trusts this unverified email for authentication decisions.

### Where To Apply This

- **Any OAuth "Sign in with X" feature** that can be toggled on/off: always test if the endpoint still works when the UI says it is disabled. Directly navigate to the OAuth authorization URL.
- **Unverified email flows:** Whenever a platform allows you to specify an email that has not yet been confirmed, test whether that unverified email is trusted in other authentication contexts (OAuth, SSO, password reset, API tokens).
- **Cookie analysis methodology:** Justin emphasizes stripping all cookies from requests to identify which ones actually provide authentication. Use Burp's "Request Minimizer" or manually remove cookies one by one. This reveals which cookies are security-critical vs. tracking fluff.

```
# Methodology for finding hidden OAuth endpoints:

# 1. Check for OAuth endpoints even when feature appears disabled
#    Look in JavaScript source files for OAuth redirect URLs:
#    Example patterns to grep for in JS bundles:
rg -n "shop.*oauth|shopify.*auth|sign.*in.*shop" ./js-files/
rg -n "authorize\?client_id|oauth/authorize|/auth/login" ./js-files/

# 2. Check for the standard OAuth flow parameters
#    Even if the button is hidden, the endpoint may accept:
#    /oauth/authorize?client_id=XXX&redirect_uri=XXX&scope=XXX

# 3. Test with an unverified email account
#    Register -> set email to target -> do NOT verify -> attempt OAuth
```

### Justin's Rule on Unverified Emails

> "Anytime you have an unverified email, this is specifically interesting when there's only one email associated with your account. This is not like a change email sort of feature. This is when you've signed up for an account and the only email they have associated with you is this unverified email."

The dangerous implementation pattern:

```javascript
// INSECURE: unverified email stored as primary
user = {
    email: "victim@email.com",      // <-- attacker-controlled, unverified
    is_email_verified: false,        // <-- flag exists but OAuth doesn't check it
    // ...
}

// SECURE: separate field for unverified email
user = {
    email: null,                     // <-- empty until verified
    pending_email: "victim@email.com", // <-- stored separately
    // ...
}
```

---

## 3. JavaScript Source Code Analysis for Hidden Endpoints and Admin Functionality

Referenced across the Sam Curry Points.com write-up. While not a single "technique," this is critical client-side methodology.

### How It Works

1. Register for an account on a management console / dashboard (e.g., `console.points.com` allowed public registration)
2. Examine the JavaScript files powering the dashboard
3. Identify API endpoints, admin actions, hidden functionality, and authorization tokens referenced in the JS
4. Reconstruct those API calls manually, even for actions you should not have access to

```
Methodology:

  [Public Registration on Admin Console]
       |
       | 1. Register account on console.points.com
       v
  [Authenticated Dashboard - Limited Permissions]
       |
       | 2. Open browser DevTools -> Sources tab
       |    OR download all JS files
       v
  [JavaScript Bundle Analysis]
       |
       | 3. Search for:
       |    - API endpoint paths (/api/v1/admin/*, /internal/*)
       |    - Authorization headers / token patterns
       |    - Hidden routes / admin-only components
       |    - Hardcoded secrets, API keys
       v
  [Reconstruct Admin API Calls]
       |
       | 4. Replay requests in Burp with your low-priv token
       |    Test if authorization is enforced server-side
       v
  [Potential: IDOR, Priv Escalation, Data Leak]
```

### Why This Works

Client-side JavaScript bundles for admin dashboards frequently contain references to all API endpoints the application supports, including those the current user should not have access to. The JavaScript is shipped to the browser regardless of the user's role because the application relies on client-side routing/UI to hide admin features rather than (or in addition to) server-side authorization checks.

### Where To Apply This

- **Multi-tenant management portals** that allow public registration (SaaS admin dashboards, partner portals, developer consoles)
- **Any application where you can register an account** and access a dashboard: always read the JavaScript files
- Justin notes he has made "six figures in bounties from this exact scenario"

```
# Quick methodology for JS analysis:

# 1. Download all JS files from target
# (Use browser DevTools Network tab, or tools like getJS, hakrawler, etc.)

# 2. Search for API endpoints
rg -n "api/v[0-9]|/admin/|/internal/" ./js-files/
rg -n "fetch\(|axios\.|\.get\(|\.post\(" ./js-files/

# 3. Search for authorization patterns
rg -n "Bearer|Authorization|x-api-key|token" ./js-files/

# 4. Search for hidden routes
rg -n "path:|route:|/admin|/manage|/console" ./js-files/

# 5. Use Wayback Machine to find old documentation
# Sam used Wayback Machine to read docs about how the Points API works
```

---

## 4. Client-Side Session Fixation via URL-Based Session Tokens (IIS)

An extension of the IIS cookieless session technique discussed in Section 1, with a specific client-side attack angle.

### How It Works

1. IIS cookieless sessions allow session tokens to be embedded in the URL path: `/(S(session_id))/`
2. The `(F(...))` variant embeds a forms authentication token in the URL
3. An attacker can craft a URL containing their own session token
4. If the victim clicks this link, their browser sends a request with the attacker's session token embedded in the path
5. IIS extracts and uses this token, potentially associating the victim's actions with the attacker's session

```
Attacker crafts URL:
  https://target.com/(F(attackers_auth_token))/sensitive/action.aspx
                      ^^^^^^^^^^^^^^^^^^^^^^^^^
                      Attacker's forms auth token injected into URL

  Victim clicks link
       |
       v
  [IIS extracts (F(...)) from path]
       |
       | IIS processes this as the forms authentication token
       v
  [Victim's request executes under attacker's auth context]
       |
       | Any sensitive action (linking account, updating data)
       | gets associated with the attacker's session
       v
  [Attacker gains access to victim's data via their own session]
```

### Why This Works

IIS treats the `(S(...))`, `(A(...))`, and `(F(...))` URL segments as legitimate session/auth identifiers. This is by design for cookieless session support. The security issue arises when:
- The application does not validate that the session token matches the expected origin
- There is no CSRF protection on sensitive actions
- The application allows session tokens to be set via URL (client-side path traversal / link sharing)

### Where To Apply This

- ASP.NET applications running on IIS with cookieless sessions enabled
- Combine with social engineering (send victim a link with your session token)
- Look for sensitive state-changing actions that can be performed after clicking the crafted link

---

## Master Summary Table

| # | Technique | Type | Impact | Complexity |
|---|-----------|------|--------|------------|
| 1 | IIS Cookieless Session XSS via `(S(...))` path injection | Reflected XSS | Medium-High (script execution in victim's browser) | Low (single crafted URL) |
| 2 | Shopify Shop Pay hidden OAuth endpoint abuse | OAuth Flow Abuse / Account Takeover | Critical (full ATO) | Medium (requires understanding OAuth flow + cookie handling) |
| 3 | JavaScript source analysis for hidden admin API endpoints | Information Disclosure / Client-Side Recon | Varies (enables further attacks) | Low (just read the JS files) |
| 4 | IIS URL-based session fixation via `(F(...))` | Session Fixation | Medium-High (victim actions under attacker's session) | Low-Medium (crafted URL + social engineering) |

---

## Key Quotes

> "Even though a store may not have the Sign in with Shop feature fully enabled and displayed in their store, it is still possible to access the Shop Pay OAuth directly via this endpoint."
> -- Ophion Security write-up, highlighted by Justin

> "Any features that you can turn on or off or that are accessible part of the time but not accessible the other part of the time, you have to validate that. Just because it's not in the UI or just because it's not a part of the normal flow doesn't mean you can't force navigate to it."
> -- Justin Gardner

> "The next thing we did was to examine the JavaScript that powered the dashboard. We discovered that the website console.points.com appeared to be utilized by points.com employees for executing administrative actions concerning customer accounts, rewards programs, and managing components of the website itself."
> -- Sam Curry write-up, highlighted by Justin

> "I've personally made six figures in bounties from this exact scenario."
> -- Justin Gardner, on finding admin functionality via JS analysis of publicly-registerable management consoles

> "Figure out what is resulting in authentication, what is affecting the application directly. And once you've narrowed that down, you have a much greater chance finding vulnerabilities in those components because there isn't so much fluff around."
> -- Justin Gardner, on stripping cookies to identify auth-critical ones

---

## Resources & References

- **James Kettle - Smashing the State Machine:** PortSwigger Research (Defcon presentation, race conditions - primarily server-side)
- **Soroush Dalili - IIS Cookieless Session Auth Bypass:** soroush.me (CVE from 2023, IIS path bypass + XSS)
- **isek.pl blog:** Referenced by Soroush for XSS via tilde path resolution with cookieless sessions (author: Paveo)
- **Ophion Security - Shopify Account Takeover:** ophionsecurity.com (Shop Pay OAuth abuse)
- **Sam Curry - Hacking Points.com:** samcurry.net - "Leaking Secrets and Unlimited Miles, Hacking the Largest Airline and Hotel Rewards Platform"
- **Sam Curry - Attacking Secondary Contexts in Web Applications:** Presentation (referenced as "mandatory reading")
- **Ian Carroll - Cookie Monster:** Tool for brute-forcing JWT secrets and session configurations
- **Lupin & Holmes - Sandwich Attack (UUID v1):** landh.tech (primarily server-side, UUID brute force)
- **Alex Chapman - Bug Bounty Automation Development Diary:** Twitter series
- **Monka - ShortNameGuesser:** IIS short name enumeration tool using GPT
- **CVSS Advisor:** cvssadvisor.com
- **ctbb.show:** Critical Thinking Bug Bounty Podcast newsletter

---

## Note on Client-Side Content Density

This episode is heavily weighted toward server-side techniques. The major topics -- HTTP/2 single-packet race conditions, SSRF-like secondary context attacks, JWT weak secret brute forcing, and UUID v1 sandwich attacks -- are all server-side. The client-side relevant content extracted above (IIS cookieless XSS, OAuth flow abuse, JS source analysis, session fixation) represents the subset of techniques that involve browser-side behavior, client-side code analysis, or attacks that execute in the victim's browser context.
