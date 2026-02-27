# EP20: Hacker Brain Hacks - Client-Side Security Notes

## Metadata
- **Podcast:** Critical Thinking Bug Bounty Podcast
- **Episode:** 20
- **Hosts:** Justin Gardner (Rhynorater), Joel Margolis (Teknogeek)
- **Primary Topic:** Bug bounty mentality, motivation, workflow optimization, and common psychological pitfalls (procrastination, imposter syndrome, burnout, analysis paralysis)

---

> **NOTE: This episode contains virtually no client-side web security content.** The entire conversation covers bug bounty mindset topics: procrastination vs. education, analysis paralysis when picking programs, automation obsession, imposter syndrome, recon pitfalls, identifying good vs. bad rabbit holes, burnout management, and goal-setting. The only technical vulnerability discussed is a LinkedIn URN injection (server-side data exposure), which is not a client-side technique. The notes below extract the only tangentially relevant content.

---

## 1. LinkedIn URN Injection -- Data Exposure via API Decoration Expansion

This is discussed briefly at the end of the episode as a newly disclosed report. It is **not a client-side vulnerability** but is included here because it involves API parameter manipulation that could be tested from a browser and the URN resolution pattern has conceptual relevance to client-side data leakage via API abuse.

### How It Works

1. LinkedIn's internal API (Voyager) uses a URN (Uniform Resource Name) system to reference objects: `urn:li:<object_type>:<id>`
2. The attacker discovered that certain profile text fields (e.g., the website field) accept URN values instead of plain text
3. When the Voyager API is queried with a decoration/expansion parameter, it resolves any URN values found in the response
4. By placing a URN like `urn:li:fs_emailAddress:<target_id>` into a profile text field, then querying the API with the expansion parameter, the API resolves the URN and returns the actual email address in the `included` section of the response
5. This allowed enumeration of the entire database of email addresses by iterating over IDs

```
// The URN format used:
//   urn:li:fs_emailAddress:<numeric_id>
//
// Attack flow:
//
// Attacker                          LinkedIn Voyager API
//    |                                      |
//    |  1. PUT profile website field =      |
//    |     "urn:li:fs_emailAddress:123"     |
//    |  ----------------------------------> |
//    |                                      |  (stores URN as text)
//    |                                      |
//    |  2. GET /voyager/api/profile?        |
//    |     decorationId=FULL_PROFILE        |
//    |  ----------------------------------> |
//    |                                      |  (sees URN in field,
//    |                                      |   resolves it against DB)
//    |                                      |
//    |  3. Response includes:               |
//    |     "included": [{                   |
//    |       "emailAddress": "victim@..."   |
//    |     }]                               |
//    |  <---------------------------------- |
//    |                                      |
//    |  4. Iterate over IDs to dump all     |
//    |     email addresses                  |
//    |                                      |
```

### Why This Works

The Voyager API blindly resolves any URN it encounters in a response field during decoration expansion. There is no authorization check verifying that the requesting user has permission to access the object referenced by the URN. The system trusts that URN values in profile fields were placed there by the system itself, not by an attacker.

### Where To Apply This

- **Microsoft/LinkedIn ecosystem:** The hosts note that URN-based object resolution may exist across other Microsoft-owned services since LinkedIn is a Microsoft property (acquired 2016). Justin mentions similar patterns appeared in the Starbucks 99-million-record leak he found with Sam Curry
- **Any API that uses internal object reference schemes:** If you see structured identifiers like `urn:`, `ref:`, `obj:`, or similar patterns in API responses, test whether placing those identifiers in writable fields causes the API to resolve and return the referenced objects
- **Decoration/expansion parameters:** Look for query parameters like `decorationId`, `expand`, `fields`, `include`, or `resolve` that instruct the API to hydrate nested references -- these are the trigger for this class of bug

---

## 2. Sequence Diagram Tool for POC Documentation

Not a vulnerability technique, but a workflow tool mentioned at the top of the episode. DemonDev (d3mondev) shared `sequencediagram.org`, a tool for creating sequence diagrams useful for documenting multi-step exploitation chains (e.g., postMessage relay attacks, OAuth flows, CSRF chains).

### Where To Apply This

- When writing reports for multi-step client-side attack chains (iframe embedding -> postMessage -> DOM XSS), a sequence diagram makes the flow immediately clear to triagers
- Useful for diagramming proxy/redirect chains, CORS exploitation flows, or any multi-party browser interaction

---

## 3. Cloudflare Tunnels for Hosting Exploit POCs

The hosts discuss Cloudflare D tunnels (similar to ngrok) as a method to expose a local server via a public Cloudflare-hosted endpoint. This is relevant to client-side exploitation because many client-side attacks require an attacker-controlled page to be hosted somewhere.

### How It Works

```
// Local machine                     Cloudflare Edge          Victim Browser
//    |                                   |                        |
//    | 1. cloudflared tunnel             |                        |
//    |    --url localhost:8080           |                        |
//    | --------------------------------> |                        |
//    |    (tunnel established)           |                        |
//    |                                   |                        |
//    |                                   | 2. https://random.     |
//    |                                   |    trycloudflare.com   |
//    |                                   | <--------------------- |
//    |                                   |                        |
//    | 3. Request forwarded              |                        |
//    | <-------------------------------- |                        |
//    |                                   |                        |
//    | 4. Serve malicious HTML           |                        |
//    |    (XSS POC, postMessage          |                        |
//    |     exploit page, etc.)           |                        |
//    | --------------------------------> | ---------------------> |
//    |                                   |                        |
```

### Where To Apply This

- Hosting attacker-controlled pages for postMessage exploitation POCs where the exploit requires loading an attacker page that iframes the target
- Serving JavaScript payloads for `<script src="">` injection chains
- Hosting OAuth redirect landing pages during client-side OAuth flow exploitation
- The Cloudflare domain has high reputation, which may bypass corporate firewalls or next-gen security filters that block unknown/low-reputation domains
- Raw TCP tunneling is also supported, useful for exfiltration endpoints in blind XSS scenarios

---

## Master Summary Table

| # | Topic | Type | Relevance to Client-Side | Notes |
|---|-------|------|--------------------------|-------|
| 1 | LinkedIn URN Injection | Server-side API abuse | Low -- API parameter manipulation testable from browser | Test URN/object reference resolution in any API with expansion params |
| 2 | sequencediagram.org | Tooling / Reporting | Indirect -- improves POC documentation for client-side chains | Useful for multi-step browser exploitation reports |
| 3 | Cloudflare Tunnels | Infrastructure / Tooling | Medium -- enables hosting attacker pages for client-side POCs | High-reputation domain, useful for postMessage/iframe/OAuth exploits |

---

## Key Quotes

> "I make all these talks about recon to help you find more apps to hack. That's the goal. So do your recon until you found an interesting app to hack and then just hack that app instead of doing recon eternally."
> -- Jay Haddix (quoted by Justin from Episode 12)

> "When you're hacking, hack. When you're automating, automate. Take notes on what things you want to automate, come back to it later, but stay in the zone."
> -- Justin Gardner (Rhynorater)

> "Write down all your attack vectors and go... do it again. He found four more bugs, one of them which was a crit."
> -- Justin Gardner, on the value of exhaustive attack surface enumeration

> "I bet I know everything about this application. I bet no one here knows more about this application than I do... And I got taken to school that day."
> -- Justin Gardner, on depth of application knowledge at live hacking events

---

## Resources & References

- **sequencediagram.org** -- Tool for creating sequence diagrams for POC documentation
- **SubReconGPT** by Jay Haddix (jhaddix) -- Python tool that uses ChatGPT to generate bespoke subdomain wordlists from existing subdomain data
- **Kaido** -- Web proxy alternative to Burp Suite (~$10/month or $100/year vs Burp's $500/year)
- **Cloudflare Tunnels (cloudflared)** -- Free tunnel service for exposing local servers via Cloudflare's edge network (blog on iq.thc.org)
- **LinkedIn URN Injection report** by UltraPOWA -- "Entire Database of Emails Exposed Through URN Injection" (disclosed on LinkedIn/HackerOne)
- **Episode 12** -- Jay Haddix recon methodology episode (referenced for recon philosophy)
- **Episode 13** -- How to pick a good bug bounty program (referenced for program selection advice)
