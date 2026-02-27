# EP31: Alex Chapman (AJXChapman) - Source Code Review, Browser Exploitation & Client-Server Trust - Client-Side Security Notes

## Metadata
- **Guest:** Alex Chapman (@AJXChapman)
- **Hosts:** Justin Gardner (@rhynorater), Joel Margolis (@teknogeek)
- **Episode:** Critical Thinking Bug Bounty Podcast - Episode 31
- **Date:** Late 2023
- **Episode Link:** https://www.criticalthinkingpodcast.io/

## Client-Side Content Assessment

**This episode has LIMITED direct client-side web security content.** The conversation is primarily focused on Alex Chapman's background, source code review methodology (sink-to-source), binary exploitation, headless browser RCE, protocol-level vulnerabilities (Perforce, JDBC), and bug bounty career advice. There are no discussions of DOM XSS, postMessage, CSP bypasses, iframe tricks, open redirects, CSRF, or OAuth client-side flows.

However, the following topics have indirect relevance to client-side security researchers:
1. Headless browser exploitation (Chrome renderer RCE)
2. Electron / CEF application analysis
3. Client-server trust boundary exploitation
4. Sink-first source code review methodology (applicable to DOM sink hunting)

---

## Technique 1: Headless Browser Exploitation (Chrome Renderer RCE)

Alex describes finding and exploiting outdated headless Chrome instances used in backend services to render content. This is relevant to client-side security because the attack chain often requires a client-side injection (XSS) as the initial entry point to deliver the browser exploit payload.

### How It Works

1. Identify a target service that uses headless Chrome (or similar browser engine) to render user-influenced content on the backend
2. Determine the exact Chrome/Chromium version in use (often outdated in backend deployments)
3. Find public CVEs and exploit research for that version range (GitHub Security Blog was cited as a resource)
4. Develop or adapt a V8 JavaScript exploit that achieves renderer RCE
5. Key insight: backend headless browsers often run with `--no-sandbox` for ease of deployment, meaning renderer RCE equals full system RCE with no sandbox escape needed

```
Attack Flow:

    Attacker Input           Backend Service           Headless Chrome
    (XSS / HTML injection)   (renders content)         (--no-sandbox)
         |                        |                         |
         |--- Inject payload ---->|                         |
         |                        |--- Render with -------->|
         |                        |    headless Chrome      |
         |                        |                         |--- V8 exploit
         |                        |                         |    triggers
         |                        |                         |
         |                        |<-- RCE on server -------|
         |                        |    (no sandbox)         |
```

```javascript
// Conceptual: What the attacker needs to get rendered by headless Chrome
// The actual exploit payload targets a specific V8 vulnerability (CVE-specific)
// and achieves arbitrary code execution in the renderer process.

// Step 1: Find the Chrome version
// - Check response headers, error pages, or JS engine behavior
// - Backend headless Chrome versions are often months/years behind

// Step 2: Match to known V8 CVEs
// - GitHub Security Blog has detailed exploitation write-ups
// - Look for type confusion, OOB read/write in V8

// Step 3: Check sandbox status
// - Most backend headless Chrome instances disable the sandbox:
//   chrome --headless --no-sandbox --disable-gpu ...
// - This means renderer RCE = full system RCE

// Step 4: Deliver via whatever injection point reaches the renderer
// - Could be stored XSS that gets "printed to PDF"
// - Could be HTML email rendered for preview
// - Could be any user content that passes through the headless browser
```

### Why This Works

- Backend services that use headless browsers for PDF generation, screenshot capture, or HTML rendering often run outdated versions because they are not user-facing and do not receive the same update pressure as desktop browsers.
- The `--no-sandbox` flag is commonly used in containerized/backend deployments because Chrome's sandbox requires specific Linux kernel capabilities that complicate Docker deployments. Without the sandbox, a renderer exploit gives direct OS-level code execution.
- The initial injection (often a client-side XSS or HTML injection) is just the entry point -- the real payload is a JavaScript browser exploit that targets the V8 engine.

### Where To Apply This

- Any target that does server-side HTML-to-PDF conversion (wkhtmltopdf, Puppeteer, Playwright, headless Chrome)
- Screenshot/thumbnail generation services
- HTML email preview renderers
- Report generation features that render user-supplied HTML
- Link preview / unfurl services
- Alex reported writing exploits for: 4 Chrome renderer RCEs, 1 PhantomJS RCE, 1 wkhtmltopdf RCE -- and reused each exploit across multiple targets via collaboration

---

## Technique 2: Electron / CEF Desktop Application Source Code Extraction

When desktop applications are in scope for a bug bounty program, they are frequently built with Electron or Chrome Embedded Framework (CEF). This means the source code is accessible for review.

### How It Works

1. Identify that a desktop application in scope uses Electron or CEF
2. Extract the application source code (Electron apps bundle their source in `app.asar`)
3. Review the extracted JavaScript/TypeScript source using standard source code review methodology
4. Look for dangerous sinks, insecure IPC, disabled web security flags, etc.

```bash
# Extracting source from an Electron app

# Step 1: Locate the .asar file
# macOS:
# /Applications/AppName.app/Contents/Resources/app.asar
# Windows:
# C:\Users\<user>\AppData\Local\Programs\AppName\resources\app.asar
# Linux:
# /opt/AppName/resources/app.asar

# Step 2: Extract using asar tool
npm install -g asar
asar extract app.asar ./extracted-source/

# Step 3: Review the extracted source
# Look for:
# - nodeIntegration: true (allows Node.js in renderer = XSS to RCE)
# - contextIsolation: false (allows renderer to access Node.js)
# - webSecurity: false (disables same-origin policy)
# - shell.openExternal() with user input (command injection)
# - Insecure IPC between main and renderer processes
# - innerHTML / dangerouslySetInnerHTML with user data
```

### Why This Works

- Electron apps are essentially Chromium browsers running a web application with access to Node.js APIs. The entire frontend source is shipped with the application.
- Developers often assume desktop apps are "trusted" environments and relax security settings that would be critical in a web browser.
- Any XSS in an Electron app with `nodeIntegration: true` or `contextIsolation: false` can be escalated to full RCE on the user's machine.

### Where To Apply This

- Any bug bounty program with a desktop application in scope
- Slack, Discord, VS Code, Notion, and hundreds of other Electron apps
- CEF-based applications (similar extraction process)
- Alex specifically calls out Electron/CEF apps as his first target when he sees desktop apps in scope

---

## Technique 3: Client-Server Trust Boundary Exploitation

Alex describes a general pattern where client applications trust server responses without validation. When an attacker can make a client connect to a malicious server, the server can instruct the client to perform dangerous actions. This applies to any protocol client, including browser-based applications that connect to user-specified backends.

### How It Works

1. Identify an application feature where a client connects to a user-specified or attacker-controllable server
2. Analyze the protocol between client and server -- what commands can the server send to the client?
3. Determine if the client blindly trusts and executes server commands
4. Build a malicious server that sends exploit commands to connecting clients

```
Trust Boundary Problem:

    Normal flow:
    Client -----> Trusted Server
    "What files do    "Here are your files,
     I need?"          write them to /project/src/"
                       (Server controls file paths and content)

    Attack flow:
    Client -----> Attacker's Server
    "What files do    "Write this file to /home/user/.ssh/authorized_keys"
     I need?"          OR "Write this file to ~/.bashrc"
                       OR "Run this command"
                       (Attacker controls file paths and content!)
```

### Perforce RCE (Specific Example)

Alex and Justin both independently found this vulnerability at a live hacking event. Perforce is a version control system where the server controls the client.

```python
# Conceptual Perforce malicious server (simplified)
# The real exploit implements the full Perforce protocol

# Perforce protocol flow:
# 1. Client connects to server
# 2. Server authenticates client (or just says "ok")
# 3. Server sends commands like "client-WriteFile"
# 4. Client writes files wherever the server tells it to
#
# The server command is literally "client-WriteFile" --
# it tells the client: write THIS content to THIS path

# Attack: Stand up a malicious Perforce server
# When a CI/CD system or developer connects to it:
# 1. Accept the authentication (always say "yes")
# 2. Send client-WriteFile with a path traversal
#    e.g., write to /home/user/.ssh/authorized_keys
#    or write a cron job, or overwrite .bashrc
# 3. Achieve RCE on the connecting system

# Where this appears in the wild:
# - CI/CD pipelines that clone from user-specified repos
# - Cloud platforms that let users "connect their VCS"
# - Any system where users provide a Perforce server URL
```

### Why This Works

- Protocol clients are designed with the assumption they will only connect to trusted, legitimate servers. The security boundary between "what the server can tell the client to do" and "what the client will actually do" is often nonexistent.
- Cloud CI/CD and low-code platforms changed the threat model: users can now specify arbitrary server connection strings, meaning an attacker can make the platform's client connect to a malicious server.
- Alex found this same class of vulnerability in 4-5 different client applications because the root cause (trusting the server) is systemic.

### Where To Apply This

- CI/CD systems that connect to user-specified version control servers (Git, SVN, Mercurial, Perforce)
- Low-code / no-code platforms with "connect your database" features (JDBC connection strings)
- Any application where users provide a connection string or server URL
- JDBC drivers specifically: query string parameters can enable file read/write, log file location control (arbitrary file write), or JNDI injection
- Browser-based applications that connect to WebSocket servers, GraphQL endpoints, or other user-specified backends

---

## Technique 4: Sink-First Source Code Review Methodology

Alex describes his approach to source code review: start at the sinks (dangerous functions) and work backwards to find sources (user input). This methodology is directly applicable to client-side vulnerability hunting (DOM XSS, etc.).

### How It Works

```
Traditional (Source-first):
    Find user input (URL params, postMessage, etc.)
         |
         v
    Trace forward through the code
         |
         v
    See if it reaches a dangerous sink
    (innerHTML, eval, location.href, etc.)


Alex's approach (Sink-first):
    Find dangerous sinks (eval, innerHTML, exec, etc.)
         |
         v
    Trace BACKWARDS through the code
         |
         v
    See if any path leads to attacker-controlled input
```

```javascript
// Applying sink-first to client-side JS review:

// Step 1: Find all dangerous sinks in the codebase
// Use ripgrep to find sinks:
// rg "innerHTML\s*=" ./src/
// rg "outerHTML\s*=" ./src/
// rg "document\.write" ./src/
// rg "eval\(" ./src/
// rg "Function\(" ./src/
// rg "setTimeout\(" ./src/   (when first arg is string)
// rg "setInterval\(" ./src/  (when first arg is string)
// rg "location\s*=" ./src/
// rg "location\.href\s*=" ./src/
// rg "location\.replace" ./src/
// rg "window\.open" ./src/
// rg "dangerouslySetInnerHTML" ./src/  (React)
// rg "v-html" ./src/                   (Vue)
// rg "\[innerHTML\]" ./src/            (Angular)
// rg "bypassSecurityTrust" ./src/      (Angular)

// Step 2: For each sink, trace backwards
// - What variable feeds into this sink?
// - Where does that variable come from?
// - Is there any sanitization in the path?
// - Can an attacker control any part of the input?

// Step 3: Identify the source
// - URL parameters (location.search, location.hash)
// - postMessage data
// - document.referrer
// - localStorage / sessionStorage
// - Cookie values
// - User-supplied form data
```

### Why This Works

- There are usually fewer dangerous sinks than potential sources in a codebase, making sink-first more efficient for finding high-impact bugs.
- You immediately know the impact: if you start at `eval()` or `innerHTML`, you know a successful trace means XSS or code execution. Starting at sources, you might trace through hundreds of safe code paths.
- Alex notes this approach helps him consistently find high/critical severity bugs rather than wasting time on lower-impact findings.

### Where To Apply This

- Any source code review (client-side JS, server-side code, open-source dependencies)
- Particularly effective for DOM XSS hunting in large JavaScript codebases
- Works well with automated tools: use Semgrep/CodeQL to find sinks, then manually trace backwards
- Alex specifically mentions using CodeQL, Semgrep, and Joern for automation

---

## Technique 5: JDBC Driver Exploitation via Connection String Parameters

While primarily a server-side technique, this is relevant when client-side applications or browser-based admin panels allow users to specify database connection strings.

### How It Works

1. Find a feature where users can provide a JDBC connection string
2. Inject or modify query string parameters in the JDBC URL
3. Exploit driver-specific features through these parameters

```
JDBC Connection String:
jdbc:mysql://attacker-server:3306/db?queryParam=value

Exploit possibilities via query string params:
+------------------------------------------+----------------------------+
| Parameter Abuse                          | Impact                     |
+------------------------------------------+----------------------------+
| Log file location override               | Arbitrary file write       |
| JNDI lookup injection                    | RCE (like Log4Shell)       |
| SSL certificate path                     | File read                  |
| Custom deserializer specification        | RCE via deserialization     |
+------------------------------------------+----------------------------+
```

### Why This Works

- JDBC drivers expose dozens of configuration options through URL query parameters
- Many of these options were designed for trusted developer use and have no security restrictions
- When cloud platforms let users "connect their own database," the JDBC URL becomes attacker input

### Where To Apply This

- Low-code/no-code platforms with "connect your database" features
- Admin panels that accept database connection strings
- Any feature where the JDBC URL or parts of it are user-controllable
- Two recent CVEs were raised against JDBC connectors for exactly these issues

---

## Master Summary Table

| # | Technique | Type | Impact | Complexity |
|---|-----------|------|--------|------------|
| 1 | Headless Browser Exploitation (Chrome RCE) | Browser Exploit / RCE | Critical | High |
| 2 | Electron/CEF Source Code Extraction & Review | Source Code Review / Client-Side | High-Critical | Medium |
| 3 | Client-Server Trust Boundary Exploitation | Protocol-Level / RCE | Critical | High |
| 4 | Sink-First Source Code Review | Methodology | Varies | Low-Medium |
| 5 | JDBC Connection String Parameter Injection | Server-Side / RCE | Critical | Medium |

---

## Key Quotes

> "I spend a significant portion of my time hacking in an IDE. I'll be pulling open source repos down, looking through the code, reading the code, trying to find issues and learn basically how a module works." -- Alex Chapman

> "If you really want to be able to understand a bug, you need to know how it was implemented, what assumptions a programmer would have made to introduce that bug, and ideally how to fix it." -- Alex Chapman

> "Generally the security boundary when a client connects to a server is less than when a server talks back to a client. There's a lot of programs that assume the client will only ever be used in an authorized way to connect to an authorized server." -- Alex Chapman

> "A large proportion of the time when you see headless browsers being used in a backend, the sandbox would have been disabled because it's easier to deploy that way. And that makes exploiting it so much easier." -- Alex Chapman

> "In my experience, every time I haven't had a full RCE POC, it's been downgraded to a medium or fobbed off." -- Alex Chapman (on the importance of full exploit development)

> "I tend to focus on the sinks and then work backwards from there." -- Alex Chapman (on source code review methodology)

> "I kind of hyper-focus on code execution wherever I can. Be that through command injection, deserialization, writing arbitrary files." -- Alex Chapman

> "If I can get one really high impact bug in the live hacking event, I'm happy." -- Alex Chapman

> "I've been playing around with CodeQL, Semgrep, Joern, and a few others to help with that and build up a methodology there." -- Alex Chapman

---

## Resources & References

- **Alex Chapman's Blog:** ajxchapman.github.io (includes Perforce RCE write-up and other research)
- **Alex Chapman's Twitter:** @AJXChapman
- **Alex Chapman's HackerOne:** hackerone.com/ajxchapman
- **GitHub Security Blog:** Detailed Chrome V8 exploitation write-ups (referenced by Alex as a key learning resource for browser exploitation)
- **Tools mentioned:** CodeQL, Semgrep, Joern (for automated source code analysis)
- **GitLab issue tracking:** Alex's personal workflow for tracking bug leads and writing reports
- **Perforce:** Version control system heavily used in game industry; client-WriteFile command enables arbitrary file write
- **JDBC drivers:** MySQL/MariaDB/DB2 connectors with CVEs for query string parameter abuse (log file write, JNDI injection)
- **Targets exploited:** PhantomJS, wkhtmltopdf, headless Chrome (4 different versions), Perforce client
