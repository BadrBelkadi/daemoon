# EP40: Mentoring Beginners in Bug Bounty (with Kodai & So) - Client-Side Security Notes

## Metadata
- **Podcast:** Critical Thinking Bug Bounty Podcast
- **Episode:** 40
- **Host:** Justin (top-ranked HackerOne hunter)
- **Guests:** Kodai (aka Kodai Chodai) and So (aka Mokuso, security engineer at GMO Japan)
- **Focus:** Bug bounty mentorship, beginner learning paths, collaboration
- **Client-Side Content Density:** MINIMAL -- this episode is primarily about mentorship methodology, learning strategies, and the beginner journey. Client-side technical content is incidental, not the focus.

---

## Important Note

This episode contains **very limited client-side hacking content**. It is a mentorship-focused conversation between Justin and two of his mentees (Kodai and So) about how beginners can learn bug bounty effectively. The technical references below are brief mentions within that broader discussion, not deep dives.

---

## Concept: The Browser as a Distinct Security Boundary (Three-Party Model)

### Context from Episode
So describes a key "aha moment" in his learning journey: realizing that the security model is not simply "client vs. server" but involves **three distinct parties** -- the server, the client-side code, and the browser itself.

### How It Works
1. The **server** sends responses (HTML, JS, headers, cookies)
2. The **client-side code** (JavaScript) executes logic in the browser
3. The **browser** enforces its own security policies independently of both

```
Traditional (incorrect) mental model:
    [Client] <-------> [Server]

Corrected three-party model:
    [Server] --response--> [Browser Engine] --executes--> [Client-Side JS]
                                |
                                |-- Enforces SOP, CORS, cookie rules
                                |-- Manages tab isolation / origin segmentation
                                |-- Maintains stored state (cookies, localStorage)
                                |-- Applies CSP, X-Frame-Options, etc.
```

### Why This Matters
- A `curl` request returns raw data. A browser request invokes an entire security engine on top of that data.
- Browser-level restrictions (Same-Origin Policy, cross-origin isolation, SameSite cookies) are **not visible** in raw HTTP traffic alone.
- Understanding this distinction is prerequisite to grasping:
  - Why DOM XSS is different from reflected XSS
  - Why SameSite cookie attributes block CSRF in browsers but not in Burp/curl
  - Why postMessage origin checks matter (browser enforces delivery, not the server)
  - Why CSP exists as a browser-side defense layer

### Where To Apply This
- When reviewing client-side JS, remember the browser is a separate enforcement layer
- When testing CSRF, remember SameSite cookie behavior is browser-enforced
- When testing postMessage handlers, remember the browser mediates message delivery between origins
- When testing DOM XSS, remember the browser parses and renders the DOM -- the server never sees the payload in DOM-based attacks

---

## Concept: SameSite Strict Cookies vs. CSRF

### Context from Episode
Justin tells a brief anecdote about attempting a CSRF attack against So's music account (described as a premium "Go-to Music" account). The attack failed, and Justin says he "learned some stuff about SameSite Strict cookies that day."

### How It Works
```
Attacker's CSRF page (evil.com):
    <form action="https://music-app.com/api/delete-account" method="POST">
        <input type="hidden" name="confirm" value="true">
    </form>
    <script>document.forms[0].submit();</script>

Expected flow:
    evil.com --cross-origin POST--> music-app.com/api/delete-account
                                        |
                                        v
                              Browser checks cookie SameSite attribute
                                        |
                          SameSite=Strict? --> Cookie NOT sent --> CSRF fails
                          SameSite=Lax?    --> Cookie NOT sent (POST) --> CSRF fails
                          SameSite=None?   --> Cookie sent --> CSRF succeeds
```

```
# SameSite cookie attribute behavior on cross-site requests:
#
# SameSite=Strict:
#   - Cookie NEVER sent on cross-site requests
#   - Blocks both GET and POST CSRF
#   - Even top-level navigation from another site won't carry the cookie
#
# SameSite=Lax (default in modern browsers):
#   - Cookie sent on top-level GET navigations (clicking a link)
#   - Cookie NOT sent on cross-site POST, iframe, fetch, XHR
#   - Blocks POST-based CSRF but allows GET-based state changes
#
# SameSite=None (requires Secure flag):
#   - Cookie always sent, even cross-site
#   - CSRF is possible if no other protections exist
```

### Why This Works (or doesn't)
Modern browsers default to `SameSite=Lax`, meaning most traditional CSRF attacks via cross-origin form submissions no longer work. `SameSite=Strict` is even more restrictive. This is a **browser-enforced** defense -- the server sets the attribute, but the browser decides whether to attach the cookie.

### Where To Apply This
- Always check the `Set-Cookie` header for SameSite attributes before investing time in CSRF
- If SameSite=Lax, look for state-changing GET endpoints (these remain vulnerable)
- If SameSite=Strict, CSRF is largely dead unless you find a same-site gadget (subdomain XSS, etc.)
- Remember: SameSite is "site" not "origin" -- subdomains of the same registrable domain are considered same-site

---

## Concept: 403 Bypass Techniques (Path Normalization)

### Context from Episode
So briefly mentions that experienced hackers know to try path manipulation when hitting a 403 on `/admin`, and references nginx configuration knowledge as context for why certain bypasses work.

### How It Works
```
# Standard request blocked:
GET /admin HTTP/1.1       --> 403 Forbidden

# Path normalization bypass attempts:
GET /admin/               --> May return 200 (trailing slash)
GET /admin%0a/            --> Newline injection in path (nginx specific)
GET /Admin                --> Case variation
GET //admin               --> Double slash
GET /./admin              --> Dot-slash
GET /admin..;/            --> Semicolon path parameter (Tomcat/Java)
GET /%2fadmin             --> URL-encoded slash
GET /admin%20             --> Trailing space/encoding

# Why this works:
#   Reverse proxy (nginx) ----normalizes path----> Backend (app server)
#
#   If the access control rule is on the proxy:
#       nginx blocks: /admin
#       nginx passes: /admin%0a/  (not matched by rule)
#       backend normalizes: /admin%0a/ --> /admin (serves content)
#
#   The inconsistency between proxy path matching and
#   backend path normalization creates the bypass.
```

### Where To Apply This
- When you encounter a 403, do not immediately move on
- Identify the backend technology stack (nginx, Apache, Tomcat, Express, etc.)
- Each stack has known path normalization quirks
- This is relevant to client-side security when admin panels expose JavaScript files or configuration that could be leveraged for further attacks

---

## Mentioned But Not Elaborated

The following topics were **name-dropped** by the guests as things they are learning or have encountered, but were not discussed in technical detail:

| Topic | Who Mentioned | Context |
|-------|---------------|---------|
| XSS | Kodai | Listed as a vulnerability type he is currently studying |
| CSRF | Kodai & Justin | Kodai studying it; Justin's anecdote about SameSite blocking his CSRF attempt |
| Cross-origin / Cross-site restrictions | So | Referenced as difficult to understand for beginners; browser-enforced |
| Client-side vs. server-side distinction | So | Key learning moment about the three-party model |
| JavaScript file reading | Justin | Mentions reading JS files "ten times" when deep-testing a target |
| Front-end source code review | So | Aspires to do source code analysis similar to what Assetnote and s1r1us do |

---

## Key Quotes

> "There was one moment I realized that it's not just server side and client side... there is browser. Client side. And server side. Client side and browser -- there's just a ton of things you cannot understand especially with like cross-site thing, cross-origin thing."
> -- **So**, on his breakthrough moment understanding browser security boundaries

> "I tried to do a CSRF and I deleted his Go-to Music account via CSRF because it had a premium account and I learned some stuff about SameSite Strict cookies that day."
> -- **Justin**, on learning from failed attacks during mentorship

> "We all get to the point where we've read the JavaScript files ten times and we need to hack this target and we can't hack it and you're exhausted and you hate it."
> -- **Justin**, on the grind of client-side source code review

> "Behaviors of web browsers in general maybe could be very counterintuitive... browser internals, understanding what kind of limitations there are in the browser and maybe even what kind of capabilities there are in the browser."
> -- **Kodai**, on what beginners struggle with most

> "Every time you try to go to /admin you're gonna get 403 right, but you can't trust that 403. You got to try admin/, admin %0A/... if you know what the backend is like, if you have ever seen nginx configuration once, you might think about that."
> -- **So**, on path normalization bypasses and the value of foundational knowledge

---

## Resources & References

| Resource | Context |
|----------|---------|
| PortSwigger Web Security Academy | Kodai mentions returning to it when stuck on real targets |
| Assetnote blog posts | So aspires to do similar semi-white-box security research |
| s1r1us (researcher) | So references their front-end focused vulnerability research as a goal |
| HackerOne reports | Both mentees read disclosed reports as a learning method |
| Ryota (Japanese hacker) | So's additional mentor, strong in white-box analysis |

---

## Master Summary Table

| # | Technique/Concept | Type | Impact | Complexity |
|---|-------------------|------|--------|------------|
| 1 | Three-party model (server / client-side / browser) | Conceptual | Foundation for all client-side understanding | Low |
| 2 | SameSite cookie CSRF prevention | CSRF Defense | Blocks traditional cross-origin CSRF | Low-Medium |
| 3 | 403 bypass via path normalization | Access Control Bypass | Access to restricted endpoints | Medium |
| 4 | JavaScript source code review (grinding) | Recon / Source Analysis | Discover DOM XSS, client-side logic flaws | High |

---

*Note: This episode is overwhelmingly focused on mentorship philosophy, learning strategies, and the personal journeys of two beginner hackers. The client-side security content extracted above represents the entirety of what was discussed technically. For episodes with dense client-side exploitation content, see other episodes in this series.*
