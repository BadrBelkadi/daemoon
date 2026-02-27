# EP23: Hacking Setups, NGINX Bypasses & Live Event Strategies - Client-Side Security Notes

## Metadata
- **Podcast:** Critical Thinking - Bug Bounty Podcast
- **Episode:** 23
- **Hosts:** Justin Gardner (Rhynorater), Joel Margolis (Teknogeek)
- **Topics Covered:** Live hacking event strategies, TLD infrastructure research (hack.compute blog), VMware vRealize NGINX reverse proxy bypass, Zoom VISS scoring system, physical hacking setups (desks, monitors, chairs, peripherals)

---

## Client-Side Content Assessment

**This episode contains minimal client-side security content.** The technical security discussions focus on server-side and infrastructure topics:

1. **TLD/ccTLD root server hacking** -- infrastructure-level DNS takeover research by InfoSecAU/Shubs, ZLZ, Brett, and Reese (hack.compute.com blog). Not client-side.
2. **VMware vRealize Network Insight NGINX bypass** -- server-side reverse proxy misconfiguration leading to authentication bypass and command injection. Not client-side.
3. **Zoom VISS (Vulnerability Impact Scoring System)** -- discussion about a replacement for CVSS. Process/policy topic, not technical client-side.
4. **Main topic: Physical hacking setups** -- desks, monitors, chairs, keyboards, mice, Chromebooks, remote hacking via ZeroTier + Caido. Not security-related.

No DOM XSS, postMessage, CSP bypass, iframe tricks, open redirect, CSRF, OAuth client-side flow, or JavaScript exploitation techniques were discussed in this episode.

---

## Tangentially Relevant Technical Notes

### NGINX Reverse Proxy Location Bypass via Dot-Slash Path Normalization

While this is a **server-side** technique (not client-side), it is worth documenting as it can be chained with client-side attacks for auth bypass scenarios.

**Context:** A write-up by summoning.team (researcher: Sina / @SinSynology) on CVEs for VMware vRealize Network Insight.

#### How It Works

1. An NGINX reverse proxy uses `location` directives to restrict access to sensitive backend paths (e.g., `/saas/rest/sasservlet`).
2. The restricted `location` block requires authentication or denies access entirely.
3. There is a second `location` block that proxies to the same backend but without the same restrictions.
4. By prepending `./` (dot-slash) to the path, the request bypasses the NGINX `location` matching rule but the backend still resolves it to the same endpoint.
5. The backend treats `/./saas/rest/sasservlet` the same as `/saas/rest/sasservlet` due to path normalization.
6. The attacker reaches an unauthenticated endpoint that was supposed to be restricted.

```nginx
# NGINX config (simplified from the write-up)

# This location block enforces auth for the sensitive servlet
location /saas/rest/sasservlet {
    # Authentication required
    # Proxy to backend
    proxy_pass http://backend:8080/saas/rest/sasservlet;
}

# This location block is more permissive
location / {
    # No authentication enforcement
    proxy_pass http://backend:8080;
}
```

```
Attacker request:
  GET /./saas/rest/sasservlet HTTP/1.1
       ^
       |--- dot-slash causes NGINX to NOT match the restricted location block
            but the backend normalizes the path and serves the same endpoint

NGINX location matching:
  "/./saas/rest/sasservlet" does NOT match "/saas/rest/sasservlet"
  --> Falls through to the permissive "/" location block
  --> No auth enforced

Backend path normalization:
  "/./saas/rest/sasservlet" --> "/saas/rest/sasservlet"
  --> Serves the restricted endpoint without auth
```

```
Attacker                    NGINX Reverse Proxy              Backend Server
   |                              |                               |
   |  GET /./saas/rest/...        |                               |
   |----------------------------->|                               |
   |                              |  Does not match restricted    |
   |                              |  location block               |
   |                              |                               |
   |                              |  Matches "/" catch-all        |
   |                              |  (no auth required)           |
   |                              |                               |
   |                              |  proxy_pass with ./path       |
   |                              |------------------------------->|
   |                              |                               |
   |                              |  Backend normalizes path      |
   |                              |  Serves /saas/rest/... content|
   |                              |<-------------------------------|
   |<-----------------------------|                               |
   |  Response from restricted    |                               |
   |  endpoint (no auth!)         |                               |
```

#### Why This Works

NGINX performs literal string matching on `location` directives (for prefix matching). The path `/./saas/rest/sasservlet` is not a prefix match for `/saas/rest/sasservlet`, so NGINX routes it through the permissive catch-all block. However, the backend web server normalizes `/./ ` to `/` during path resolution, treating the request as if it targeted the restricted path directly.

#### Where To Apply This

- Any target using NGINX as a reverse proxy with path-based access controls
- Enterprise appliances (VMware, Cisco, Fortinet, etc.) that front internal APIs with NGINX
- Can be chained with client-side attacks if the bypassed endpoint returns user-controlled content or redirects
- Similar class to "off-by-slash" NGINX misconfigurations

---

## Bug Bounty Strategy Notes (Non-Technical, But Relevant to Finding Client-Side Bugs)

### "Ask Yourself Why" on Black Box Testing

Justin shared a methodology insight relevant to finding deeper client-side bugs:

- When you find a bug, **pause and ask why it worked**
- Determine what it reveals about the developers' coding patterns and infrastructure decisions
- Use that understanding to find **similar bugs** across the same application
- Example: If a developer mishandles user input in one endpoint, the same pattern likely exists in other endpoints because developers copy patterns

### Systemic Bug Patterns

Joel expanded on this:

- Bugs are often **systemic** -- the same flawed pattern gets copied across an application
- If you find an IDOR with one ID type (e.g., user ID), test the same bypass method with other ID types (group ID, org ID, etc.)
- Read company documentation to find functionality that sounds unusual or inconsistent with actual behavior

### Live Hacking Event Approach

- Stick to one target rather than jumping between multiple targets
- Use public documentation (Salesforce was cited as having good docs) to understand backend architecture
- Correlate bugs with documented infrastructure to find more bugs in the same class

---

## Summary Table

| # | Topic | Type | Relevance to Client-Side | Notes |
|---|-------|------|--------------------------|-------|
| 1 | TLD/ccTLD root server hacking | Infrastructure | None | DNS infrastructure research by hack.compute group |
| 2 | NGINX dot-slash location bypass | Server-Side | Indirect (can chain with client-side) | VMware vRealize CVE, summoning.team write-up |
| 3 | Zoom VISS scoring system | Policy/Process | None | CVSS replacement, concerns about complexity |
| 4 | "Ask yourself why" methodology | Strategy | Applicable to client-side hunting | Finding systemic patterns in codebases |
| 5 | Physical hacking setup | Lifestyle | None | Desks, monitors, chairs, peripherals |

---

## Key Quotes

> "I really need to put some CPU cycles into... why did that work? What does this bug tell me about the mistakes that companies will be making in their infrastructure and in their coding practices?" -- Justin Gardner

> "Oftentimes when something goes wrong, it's a systemic problem... a developer has seen a pattern somewhere else and they're just copying that pattern." -- Joel Margolis

> "If you put like a dot slash before your path, that's equivalent in routing, it's equivalent to like going to that path, but it gets handled differently by the nginx config. That lets you bypass like the nginx config rule, but still hit that path." -- Joel Margolis

> "Try and find things that are inconsistent or sound like weird functionality, because it might be something that's vulnerable by design that you can exploit." -- Joel Margolis

---

## Resources & References

- **hack.compute.com** -- Blog post on hacking ccTLD root servers (by Shubs/InfoSecAU, ZLZ, Brett, Reese)
- **summoning.team** -- VMware vRealize Network Insight NGINX bypass write-up (researcher: Sina / @SinSynology on Twitter)
- **Zoom VISS** -- Zoom's Vulnerability Impact Scoring System (announced by Roy from Zoom's bug bounty program)
- **Behind This Website** -- GitHub repo by John Keegan for identifying website owners (useful for responsible disclosure when no bug bounty program exists)
- **Synergy by Symless** -- Software KVM for sharing mouse/keyboard across multiple computers and OSes
- **ZeroTier** -- VPN/virtual network tool for remote access to home lab (used with Caido for remote hacking)
- **Caido** -- Lightweight web security testing proxy (used as lightweight alternative to Burp Suite)

---

*This episode is primarily focused on physical hacking setups and bug bounty event strategy. Client-side security content is minimal to nonexistent.*
