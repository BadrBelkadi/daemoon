# EP38: Mobile Hacking with Sergey Toshin (Baggy Pro) - Client-Side Security Notes

## Metadata
- **Podcast:** Critical Thinking Bug Bounty Podcast
- **Episode:** 38
- **Host:** Joel Margolis (teknogeek)
- **Guest:** Sergey Toshin (Baggy Pro) -- Founder of Oversecured, #1 hacker on Google Play Security Rewards & Samsung Bug Bounty
- **Primary Topic:** Mobile Application Security (Android & iOS)

---

> **NOTE: This episode contains minimal client-side web security content.** The entire conversation focuses on mobile application hacking (Android/iOS), the Oversecured scanner, JADX decompilation, Google Play VRP, and Samsung bug bounty. No DOM XSS, CSP bypasses, iframe tricks, postMessage exploitation, open redirects, CSRF, OAuth client-side flows, or JavaScript browser exploitation techniques are discussed. The notes below extract the only tangentially relevant content.

---

## 1. Android URI Parsing Bypasses (Mobile Deep Links)

Sergey references a published research piece called "Golden Android Techniques for URL Parsing Bypasses" (later expanded in the Oversecured blog as "Attack Vectors on the WebView" or similar).

### How It Works

While this is a **mobile** technique, it has conceptual parallels to client-side URL parsing confusion attacks on the web:

1. Android applications receive deep links (URIs) via Intents
2. The app parses the URI to extract the host, scheme, or path using Java/Android URL parsing APIs (`Uri.parse()`, `URL()`, etc.)
3. Different parsing implementations disagree on what the "host" component is for the same URI string
4. An attacker crafts a URI that passes a host validation check (e.g., `getHost()` returns `trusted.com`) but when the URI is actually loaded (e.g., in a WebView), it navigates to `attacker.com`

```
// Conceptual parallel to web-side URL parsing confusion
//
// Mobile (Android):
//   Uri.parse("https://trusted.com@attacker.com/path")
//     .getHost() --> behavior varies by parser
//
// Web (JavaScript) -- same class of bug:
//   new URL("https://trusted.com@attacker.com/path")
//     .hostname --> "attacker.com"
//
// If a web app validates the host via string matching but
// the browser resolves it differently, you get an open redirect
// or postMessage origin bypass.
```

### Why This Works

URL/URI parsing is not standardized across all implementations. Android's `android.net.Uri` class, Java's `java.net.URL`, and `java.net.URI` all parse edge-case URIs differently. The same class of bug affects JavaScript URL parsing in browsers (`new URL()` vs regex-based checks vs `location.hostname`).

### Where To Apply This

- When auditing **client-side JavaScript** that validates URLs before redirecting or loading them, test the same parsing confusion patterns (userinfo `@` symbol, backslash vs forward slash, fragment/query ordering, null bytes in older parsers)
- Deep link handlers in mobile apps that open WebViews are a direct bridge from mobile to client-side web -- XSS in a WebView loaded via a malicious deep link is functionally DOM XSS

---

## 2. Cross-Platform Vulnerability Reuse (Android to iOS)

Sergey describes a technique of finding deep link vulnerabilities on Android and then testing the same attack against the iOS version of the app.

### How It Works

```
Step 1: Decompile Android app (JADX)
        |
        v
Step 2: Identify deep link handlers and URL validation logic
        |
        v
Step 3: Find bypass on Android (e.g., URI parsing confusion)
        |
        v
Step 4: Test the SAME deep link / URL scheme on the iOS app
        |
        v
Step 5: iOS app often lacks the validation entirely
        --> Exploitable on iOS without needing to bypass anything
```

### Why This Works

Development teams often implement security checks on one platform but not the other. Android apps may have validation because the bug was previously reported, while the iOS counterpart was never audited for the same issue.

### Where To Apply This

- **Web parallel:** If you find a client-side validation bypass on the main web app, test the same flow on the mobile web version, AMP version, or embedded WebView version -- they often share routes but not defenses
- When a SPA has multiple entry points (main app, embedded iframe widget, mobile-optimized page), a fix applied to one entry point may be absent from others

---

## 3. WebView as a Client-Side Attack Surface

While not deeply discussed in this episode, Sergey and Joel reference that mobile apps using WebViews create a hybrid attack surface where traditional client-side web vulnerabilities (XSS, open redirect) become exploitable via mobile-specific entry points (Intents, deep links).

### How It Works

```
Attacker-Controlled Deep Link
        |
        v
Android Intent --> Activity
        |
        v
Activity extracts URL parameter from Intent
        |
        v
URL loaded in WebView (with JavaScript enabled)
        |
        v
If URL is attacker-controlled --> DOM XSS / credential theft
via JavaScript bridge (addJavascriptInterface)
```

### Where To Apply This

- When auditing mobile apps, any `WebView.loadUrl()` or `WKWebView` load call where the URL originates from an Intent extra or deep link parameter is a client-side sink
- `addJavascriptInterface` on Android creates a JavaScript-to-native bridge -- if you achieve XSS in the WebView, you can call native methods

---

## Summary Table

| # | Technique | Type | Impact | Complexity |
|---|-----------|------|--------|------------|
| 1 | URI/URL Parsing Confusion (mobile, parallels to web) | Open Redirect / Navigation Bypass | High (can lead to phishing, token theft) | Medium |
| 2 | Cross-Platform Vulnerability Reuse (Android findings applied to iOS/web) | Methodology | Varies | Low |
| 3 | WebView as Client-Side Attack Surface (deep link to XSS) | DOM XSS via Mobile Entry Point | High (JS execution in app context) | Medium |

---

## Key Quotes

> "I always publish everything I know. I don't have any hidden knowledge that I use when it's dark."
> -- Sergey Toshin, on sharing mobile security research publicly

> "Everyone is vulnerable. I got the confirmation, even super popular apps are vulnerable."
> -- Sergey Toshin, after earning nearly $1M from Google Play VRP in ~5 months

> "If you compare it to web bug bounties, there are like 500 people competing with you. [In mobile] there are maybe five."
> -- Sergey Toshin, on the competitive landscape of mobile hacking

> "I took for example Android application, checked deep links and then I tried to apply them to the iOS application and sometimes it worked -- there's a security check in Android application but there are no checks in iOS application."
> -- Sergey Toshin, on cross-platform vulnerability reuse

---

## Resources & References

- **Oversecured Blog:** Attack vectors on Android WebViews and URI parsing bypasses (referenced as "Golden Android Techniques for URL Parsing Bypasses")
- **Oversecured Scanner:** Commercial mobile app scanner for Android and iOS (founded by Sergey Toshin)
- **JADX:** Open-source Android APK decompiler -- primary tool used by Sergey for manual review
- **Google Play Security Rewards Program:** Google VRP extension covering apps with 100M+ installs
- **Samsung Bug Bounty Program:** Independent program run by Samsung for Samsung-specific device/app vulnerabilities
- **HackerOne -- Sergey Toshin's Profile:** Contains disclosed mobile vulnerability reports
