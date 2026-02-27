# EP34: Hackers vs. Program Managers Debate - Client-Side Security Notes

## Metadata
- **Podcast:** Critical Thinking Bug Bounty Podcast
- **Episode:** 34
- **Guests:** Justin Gardner (@rhynorater), Joel Margolis (teknogeek)
- **Format:** Debate -- Justin represents hackers, Joel represents program managers
- **Episode Link:** https://ctbb.show

---

## Client-Side Content Assessment

**This episode contains minimal client-side hacking content.** The episode is a debate about bug bounty program management: zero-day policies, disclosure rules, internal dupes, CVSS scoring, budgets, triage timing, retesting/bypasses, and live hacking events. It is almost entirely about the business and operational side of bug bounty, not technical exploitation.

The only client-side technique mentioned is a brief news segment about a new XSS event handler vector.

---

## 1. `onscrollend` XSS Event Handler (Chrome)

### How It Works

1. Chrome introduced support for the `onscrollend` event handler on elements.
2. This event fires when a scroll action completes on any element -- not just `<body>` or `<div>`, but any element including custom/unknown elements like `<xss>`.
3. By combining `onscrollend` with Chrome's auto-scroll-to-fragment feature (navigating to `#elementId` in the URL hash), the scroll event fires automatically without user interaction.
4. This bypasses WAFs and filter lists that maintain a blocklist of known event handlers (e.g., `onerror`, `onload`, `onfocus`, `onmouseover`) because `onscrollend` is new and not yet in most blocklists.

```html
<!--
  XSS vector using onscrollend event handler.
  The <xss> tag is a custom/unknown element -- browsers don't reject it.
  The id="x" allows the hash fragment #x to auto-scroll to it.
  The style forces the element to be scrollable.
  When the browser scrolls to #x, the scroll completes and onscrollend fires.
-->
<xss id="x" style="overflow:auto;height:50px;" onscrollend="alert(document.domain)">
  <div style="height:1000px;"></div>
</xss>

<!--
  Trigger URL (no user interaction needed):
  https://vulnerable.example.com/page?param=<payload>#x

  The #x fragment causes Chrome to auto-scroll to the element,
  which triggers the onscrollend handler.
-->
```

```
Attacker crafts URL with payload + #x fragment
        |
        v
Victim clicks link --> Browser renders injected <xss> element
        |
        v
Browser auto-scrolls to #x (hash fragment navigation)
        |
        v
Scroll completes --> onscrollend fires --> JavaScript executes
        |
        v
XSS achieved (zero interaction)
```

### Why This Works

- WAFs and sanitization libraries maintain lists of dangerous event handlers. New event handlers added to browsers create a window of opportunity before those lists are updated.
- The `onscrollend` handler works on any element, including non-standard/custom elements, which makes it harder for tag-based filters to block.
- Chrome's auto-scroll-to-fragment behavior means the scroll event fires without any user interaction beyond clicking the link, making the XSS zero-click after navigation.

### Where To Apply This

- Use when you have reflected or stored XSS but the application or WAF blocks common event handlers (`onerror`, `onload`, `onfocus`, `onmouseover`, etc.).
- Useful against applications that use an allowlist/blocklist approach to event handler filtering rather than proper output encoding or CSP.
- Short shelf life: once filter lists (like those in DOMPurify, WAF rulesets, etc.) add `onscrollend`, this specific bypass closes. But the general pattern (new browser event handlers as WAF bypasses) recurs every time browsers add new events.
- Source: PortSwigger Research (Twitter / blog post). Follow @PortSwiggerRes for similar drops.

---

## Master Summary Table

| # | Technique | Type | Impact | Complexity |
|---|-----------|------|--------|------------|
| 1 | `onscrollend` event handler XSS | DOM XSS / WAF Bypass | High (zero-interaction XSS) | Low |

---

## Key Quotes

> "Chrome now supports the `onscrollend` sort of event handler. So this is a great way to get past those pesky WAFs for, I don't know, hopefully a month or two until they update their word list or whatever. It works on any element. And if you combine this with the auto scroll to a specific element feature... you can just pop it without any interaction."
> -- Justin Gardner (@rhynorater)

> "I have tweet notifications turned on for PortSwigger Research because it's just one of those accounts that is constantly pumping out really, like immediately useful information... a screenshot and a link to their post about this specific vector and how you can use it. You know, it doesn't get much better than that."
> -- Joel Margolis (teknogeek)

---

## Non-Client-Side Content (Episode Summary)

The bulk of the episode is a hacker-vs-program-manager debate covering:

- **Zero-day policy:** Should programs pay for zero-days in third-party software deployed on in-scope assets? Joel argues limited remediation ability justifies reduced payouts; Justin argues impact should drive payment regardless of fault.
- **Disclosure:** Programs restrict disclosure via terms of service; researchers who disclose without permission risk safe harbor protections and platform bans.
- **Internal dupes:** Programs should be transparent (share timestamps/screenshots of internal tickets). If a vuln has been open internally for months without a fix, the program should still compensate researchers.
- **CVSS:** Both agree CVSS is imperfect. Programs should communicate their threat model and what they care about. Impact-based payment is preferred over rigid CVSS scoring.
- **Budgets:** Bug bounty budgets are carved from larger organizational budgets. Programs that consistently pay large bounties year-over-year may have internal security teams that are not learning from findings.
- **Triage timing:** Programs should pay minimum bounty at triage, not wait until resolution.
- **Retesting and bypasses:** Bypasses to incomplete fixes deserve compensation (at minimum a bonus), but are generally treated as the same root-cause issue. Researchers should not withhold known bypass vectors.
- **Live hacking events (LHEs):** Chaotic but valuable for building program-researcher relationships. Not every company is ready for one.

---

## Resources & References

- **PortSwigger Research `onscrollend` post:** Follow @PortSwiggerRes on Twitter for the original write-up and payload screenshot
- **Rezo's Prompt Injection Primer for Engineers:** A document outlining prompt injection risks for developers building AI tools
- **Gunnar Andrews (GoldenInfoSec) -- Recon Village talk on serverless architecture for bug bounty recon:** Available on the DEF CON YouTube channel (~40 min)
- **Jason Haddix -- Bug Hunter's Methodology (TBHM) Live Training Course:** Advanced bug bounty methodology course ($550 value)
- **CTBB Website:** https://ctbb.show (episodes, transcripts, contact form)
