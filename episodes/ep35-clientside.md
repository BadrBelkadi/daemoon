# EP35: D Day on Collaboration, Program Churning & 100 Bug Bounty Rules - Client-Side Security Notes

## Metadata
- **Guests:** D Day (Douglas) - Bug Bounty Hunter & Elastic Security
- **Hosts:** Justin Gardner (@rhynorater), Joel Margolis (teknogeek)
- **Episode:** 35 - Critical Thinking Bug Bounty Podcast
- **Date Reviewed:** 2026-02-25

---

## Client-Side Content Assessment

**This episode contains no actionable client-side security content.**

The entire episode (approximately 45 minutes of transcript before it cuts off due to a technical audio issue) covers the following non-client-side topics:

1. **D Day's origin story** - How he went from B-Sides Portland attendee to top Elastic bug bounty hunter to running Elastic's bug bounty program
2. **Live hacking event collaboration strategies** - Full-split collabs vs solo hacking, scope splitting, communication during pair hacking, managing flow states during video calls
3. **High-level methodology** - Focusing on user management/role matrices, user invite flows, authorization bugs (IDOR-style), business logic errors, paywall bypasses
4. **Program churning strategy** - Spending time on small programs with $500-$1000 payouts, 30-minute initial assessment, 3-hour no-bug time limit, moving on quickly
5. **Discussion of D Day's "100 Very Short Bug Bounty Rules" tweet thread** - Only surface-level discussion before the audio cut out

The transcript ends abruptly at ~45 minutes when D Day's AirPods die mid-conversation. They were about to discuss "match and replace rules to find new endpoints" (Rule #13 from D Day's tweet thread) but never got to the actual technical explanation.

No DOM XSS, CSP bypasses, iframe tricks, postMessage exploitation, open redirects, CSRF, browser quirks, JavaScript exploitation, or OAuth client-side flow content was discussed.

---

## Tangentially Relevant Methodology Notes

While not client-side specific, these methodology points from D Day could inform target selection for client-side testing:

### Target Assessment Heuristic (First 30 Minutes)
D Day's approach to quickly assess a target focuses on server-side authorization complexity, but the same rapid assessment mindset applies to client-side attack surface:

- **Check user management complexity** - More role types = more attack surface (applies to client-side role checks too)
- **Check user invite flows** - These often involve token-based URLs, redirect parameters, and client-side state handling
- **Check subscription/paywall tiers** - Client-side paywall enforcement is a common finding

### Program Churning for Client-Side Hunters
D Day's strategy of churning through small programs with a 3-hour no-bug limit is applicable:
- Small programs often have weaker client-side security (no CSP, no sanitization)
- Less competition on these programs means client-side bugs are less likely to be duped
- Average bounty of ~$700 across 200-300 programs shows volume can compensate for lower individual payouts

---

## Summary Table

| # | Technique | Type | Impact | Complexity |
|---|-----------|------|--------|------------|
| - | No client-side techniques discussed | N/A | N/A | N/A |

---

## Key Quotes

> "I basically go straight to user management and I look, okay, how many different types of users are there?" -- D Day (on his first 30 minutes on a new target)

> "Over 50% of my bugs are on programs that offer like $500 mediums and $1,000 highs. And I just find a lot of them and I kind of turn through smaller programs." -- D Day

> "If I get to three hours and I haven't found anything, I'm usually not going to find something unless I put in another ten." -- D Day

> "I can't hack for more than three hours in one day." -- D Day

---

## Resources & References

- D Day's "100 Very Short Bug Bounty Rules" tweet thread (referenced but not linked in transcript)
- Ryan Holiday's "100 Very Short Stoic Rules for Life" (inspiration for D Day's thread)
- D Day's talk at a security conference (referenced as "my HomeSec talk") covering his methodology
