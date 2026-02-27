# EP37: Live Hacking Lessons from Japan with Lupin - Client-Side Security Notes

## Metadata
- **Podcast:** Critical Thinking Bug Bounty Podcast
- **Episode:** 37
- **Guests:** Lupin (Ronnie) - Security Researcher, Founder of Lupin & Holmes (LNH.tech)
- **Hosts:** Justin, Joel
- **Recorded:** In Nakone, Japan (post-live hacking event)
- **Key Focus Areas:** JavaScript static analysis, lazy-loaded Webpack reversing, GraphQL schema extraction from JS, UUID V1 prediction, blind XSS automation, semi-automation methodology

---

## Client-Side Techniques

---

### 1. Lazy-Loaded Webpack File Analysis for Hidden API Discovery

#### How It Works

Modern single-page applications (React, Angular, Vue) use Webpack to bundle JavaScript. Critical detail: **not all JS modules are loaded when you visit the page**. Webpack uses lazy loading (code splitting) to only fetch modules when needed by the current route/view.

**Step-by-step:**

1. Visit the target application (e.g., login page)
2. Observe in Burp/DevTools that only a small main bundle and a few chunk files load
3. Open the main JS bundle and locate the Webpack chunk manifest -- this contains references to ALL dynamically loaded JS files
4. Manually fetch ALL chunk files from the same directory, even ones never loaded in your session
5. Deobfuscate/beautify and analyze all chunks for hidden API endpoints, parameters, and logic

```javascript
// In the main Webpack bundle, you'll find something like this:
// This is the chunk manifest -- it maps chunk IDs to filenames
var chunkMap = {
  0: "vendors~main.abc123.js",    // <-- loaded on page visit
  1: "login.def456.js",           // <-- loaded on page visit (login route)
  2: "admin-panel.ghi789.js",     // <-- NEVER loaded (you're not admin)
  3: "checkout.jkl012.js",        // <-- NEVER loaded (you haven't reached checkout)
  4: "settings.mno345.js",        // <-- NEVER loaded (you're not authenticated)
  5: "internal-tools.pqr678.js"   // <-- NEVER loaded (hidden A/B test feature)
};

// The lazy loading mechanism:
__webpack_require__.e = function(chunkId) {
  // Creates a <script> tag to fetch the chunk only when needed
  var script = document.createElement('script');
  script.src = "/static/js/" + chunkMap[chunkId];
  // ...
};
```

```
Attacker's Workflow:

[Visit Login Page] --> [Burp captures: main.js, vendors.js, login.js]
        |
        |  (Only 3 of 6 chunks loaded!)
        v
[Open main.js] --> [Find chunk manifest with ALL filenames]
        |
        v
[Manually fetch: admin-panel.js, checkout.js, settings.js, internal-tools.js]
        |
        v
[Beautify + Analyze] --> [Discover hidden API endpoints, GraphQL queries,
                          admin-only functionality, unreleased A/B test features]
        |
        v
[Reconstruct API calls from JS] --> [Test for IDOR, broken access control,
                                      privilege escalation without ever
                                      having accessed those features in the UI]
```

#### Why This Works

- Webpack bundles ALL application code into chunk files at build time, regardless of whether the user has permission to access those features
- Lazy loading is a performance optimization, NOT a security boundary
- Admin panel code, unreleased features, and internal tools all get shipped to the client
- The JS files contain full API endpoint definitions, parameter names, request body structures, and business logic
- Even if you cannot log in or lack privileges, the client-side code reveals the entire API surface

#### Where To Apply This

- **Admin portals behind authentication**: You cannot log in, but the admin chunk files contain every admin API endpoint
- **A/B testing / feature flags**: Unreleased features have their API calls already in the JS, ready to be called directly -- as Lupin notes, these are often the easiest bugs because nobody has tested them yet
- **Any React/Angular/Vue/SPA application**: All use Webpack or similar bundlers with code splitting
- **Tools**: JS Weasel (automated Webpack unpacking), custom parsing scripts, or manual analysis
- **Combine with Cursor/AI**: Feed the extracted JS into an AI-assisted IDE for rapid understanding of complex/obfuscated code

---

### 2. GraphQL Schema Extraction from Client-Side JavaScript

#### How It Works

When a GraphQL API has introspection disabled, the complete schema is still often embedded in the client-side JavaScript files. Front-end frameworks generate typed GraphQL queries at build time, and these query definitions (including field names, types, and relationships) get bundled into the JS.

**Step-by-step:**

1. Identify a GraphQL endpoint (look for `/graphql` paths, `query {` patterns in JS)
2. Confirm introspection is disabled on the server
3. Extract ALL JS files (including lazy-loaded Webpack chunks per technique above)
4. Search for GraphQL query/mutation definitions in the JS code
5. Build a wordlist of all query names, field names, and type names
6. Feed the wordlist into Clairvoyance (GraphQL schema brute-forcer)
7. Visualize the reconstructed schema with GraphQL Voyager

```javascript
// What you find in the client-side JS files:

// Query definitions embedded in the frontend code:
const GET_USER_PROFILE = gql`
  query GetUserProfile($userId: ID!) {
    user(id: $userId) {     // <-- "user" query name, "id" parameter
      firstName             // <-- field name
      lastName              // <-- field name
      email                 // <-- field name (PII!)
      role                  // <-- field name (authz info!)
      adminSettings {       // <-- nested type (admin-only?)
        canDeleteUsers
        canViewLogs
      }
    }
  }
`;

// Admin mutation hidden in a lazy-loaded chunk:
const DELETE_USER = gql`
  mutation DeleteUser($userId: ID!) {
    deleteUser(id: $userId) {  // <-- admin mutation exposed in JS
      success
      message
    }
  }
`;

// Sometimes even the FULL introspection response is in the JS:
// Some GraphQL client libraries cache introspection results client-side
const INTROSPECTION_RESULT = {"__schema":{"queryType":{"name":"Query"},...}};
// ^ Check for this! If introspection is "disabled" on the server,
//   the JS may still contain the cached introspection response
```

```
Attack Flow:

[JS Files (all chunks)] --> [Extract all GraphQL strings]
         |                    - query names
         |                    - mutation names
         |                    - field names
         |                    - type names
         v
[Build Wordlist] --> [Feed to Clairvoyance]
                          |
                          |  Clairvoyance sends malformed queries
                          |  GraphQL "did you mean X?" suggestions
                          |  reveal the full schema
                          v
                    [Reconstructed Schema]
                          |
                          v
                    [GraphQL Voyager] --> [Visual map of entire API]
                          |
                          v
                    [Test for: IDOR, broken access control,
                     data leaks, admin operations accessible
                     to low-privilege users]
```

#### Why This Works

- GraphQL front-end code generators (Apollo, Relay, urql) embed complete query definitions in the JS bundle
- Disabling introspection on the server does NOT remove the schema from the client code
- Some GraphQL libraries even cache the full introspection response in client-side JS (Lupin has seen this multiple times)
- GraphQL servers often return "did you mean X?" suggestions for misspelled field names, which Clairvoyance exploits to brute-force the schema even without introspection
- The suggestion distance (how many characters off can trigger a suggestion) varies by framework, making some more vulnerable than others

#### Where To Apply This

- **Any application with a GraphQL API and introspection disabled**: The "security" of disabling introspection is theater if the JS reveals everything
- **Admin-only GraphQL endpoints accessible with low-privilege cookies**: As Lupin describes, authentication (having a cookie) and authorization (having admin role) are different -- you may be able to reach the endpoint but lack role-based access, or find that authorization is not enforced
- **Combine with JS Weasel**: Automates extraction of GraphQL queries from Webpack bundles into a ready-to-use wordlist
- **Tools**: Clairvoyance (schema brute-forcer), GraphQL Voyager (schema visualizer), JS Weasel (JS extraction)

---

### 3. AI-Assisted JavaScript Code Review (Cursor + JS Weasel Pipeline)

#### How It Works

Complex client-side applications (especially Google properties with proprietary protocols) have deeply nested function calls that make manual static analysis extremely time-consuming. The approach combines automated JS extraction with AI-assisted code comprehension.

**Step-by-step:**

1. Use JS Weasel to automatically unpack and extract all JS files from the target
2. Open the extracted JS codebase in Cursor (VS Code fork with integrated GPT-4)
3. Select specific code sections and ask the AI to explain the data flow
4. Iteratively provide additional function context as the AI requests it
5. Reconstruct the full API request format (including protobuf/RPC structures)

```
Pipeline:

[Target Application]
        |
        v
[JS Weasel] --> Extracts + unpacks Webpack bundles
        |         Identifies endpoints, API calls
        |         Lists GraphQL queries
        v
[Cursor IDE] --> Opens extracted JS as a project
        |
        |  "Explain this code. What API endpoint does it call?"
        |  "What parameters does function X expect?"
        |  "Which other function do you need context for?"
        |
        |  (Repeat 5-6 times, providing requested function definitions)
        |
        v
[Reconstructed API Request]
        - Full endpoint URL
        - Request body structure
        - Protobuf schema
        - Parameter types and names
        - Authentication requirements
```

```javascript
// Example: Google's batchExecute RPC protocol
// The JS is deeply nested and obfuscated:

function Xb(a) { return Yb(Zb(a, Ac(Bc(a.Cd)))); }
// ^ What does this do? Without AI, you'd spend hours tracing:
//   Xb -> Yb -> Zb -> Ac -> Bc -> a.Cd
//   Each function may be in a different chunk file

// With Cursor AI, you select this and ask:
// "What API call does this function chain construct?"
// AI: "This constructs a batchExecute RPC call to endpoint X.
//      I need the definition of Yb and Zb for full context."
// You provide those functions, AI reconstructs the full request.

// Result: A clear protobuf/JSON request template you can
// replay and modify in Burp, saving hours of manual reversing
```

#### Why This Works

- AI models are trained on massive codebases and can infer patterns even in obfuscated/minified JS
- Cursor's local search engine pre-filters relevant code before sending to the AI, managing context window limits
- The iterative approach (asking AI what additional context it needs) is more efficient than dumping everything
- Reduces 6-7 hours of manual code review to approximately 2 hours

#### Where To Apply This

- **Google applications** using batchExecute/protobuf RPC protocols
- **Any target with proprietary or obfuscated client-side protocols**
- **Complex SPA codebases** where tracing data flow through dozens of functions is impractical manually
- **Reconstructing API requests** when you can see the JS but cannot trigger the request through the UI (lacking auth/roles)

---

### 4. UUID V1 Prediction and Sandwich Attack for Account Takeover

#### How It Works

UUID V1 tokens are generated from timestamps (nanosecond precision), MAC address, and clock sequence -- NOT from random values like UUID V4. If a password reset token uses UUID V1, an attacker can predict the victim's token by sandwiching it between two known tokens.

**Step-by-step:**

1. Identify that the target uses UUID V1 for password reset tokens (check the version digit)
2. Generate a password reset for the **attacker** account (Token A1)
3. Immediately generate a password reset for the **victim** account (Token V)
4. Immediately generate another password reset for the **attacker** account (Token A2)
5. Extract the timestamp portions of Token A1 and Token A2
6. Brute-force all UUID values between A1 and A2 -- the victim's token V is somewhere in this range

```
UUID V1 Structure:
xxxxxxxx-xxxx-1xxx-yxxx-xxxxxxxxxxxx
|_time_low| |t_m| |clk| |__node___|
                ^
                |
         Version digit = 1 (UUID V1)

Breakdown:
- time_low (8 hex chars): Low 32 bits of timestamp
- time_mid (4 hex chars): Middle 16 bits of timestamp
- time_hi  (3 hex chars): High 12 bits of timestamp (after version nibble)
- clock_seq (4 hex chars): Clock sequence (constant per machine boot)
- node      (12 hex chars): MAC address (constant per machine)

Key insight: clock_seq + node are CONSTANT for the same machine.
Only the timestamp portion changes between UUIDs.
```

```
The Sandwich Attack:

Timeline:
    T1              T2              T3
    |               |               |
    v               v               v
[Reset Attacker] [Reset Victim] [Reset Attacker]
    |               |               |
    v               v               v
  Token A1        Token V         Token A2
  (known)         (unknown)       (known)

    A1 -------- V -------- A2
    |                       |
    |  Brute-force this     |
    |  range (hex +1)       |
    |_______________________|

Since UUID V1 timestamps are nanosecond-precision:
- A1 timestamp < V timestamp < A2 timestamp
- clock_seq and node are the SAME for all three (same server)
- Only need to increment the timestamp hex values from A1 to A2
- If script reaches A2 without finding V, something else is happening
  (the second bread slice gives you a known stopping point)
```

```python
# Conceptual attack script:
import uuid
import requests

# Step 1: Identify UUID V1
token = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
#                       ^ version = 1 --> UUID V1!

# Step 2: Sandwich attack
reset_attacker_1 = trigger_reset("attacker@evil.com")  # Token A1
reset_victim     = trigger_reset("victim@target.com")   # Token V (unknown)
reset_attacker_2 = trigger_reset("attacker@evil.com")  # Token A2

# Step 3: Extract timestamp from known tokens
# UUID V1 timestamp = time_hi + time_mid + time_low (concatenated)
# Convert to integer, iterate from A1_timestamp to A2_timestamp

a1_ts = extract_timestamp(reset_attacker_1)  # e.g., 0x1d180b4...
a2_ts = extract_timestamp(reset_attacker_2)  # e.g., 0x1d180b5...

# Step 4: Brute-force
for ts in range(a1_ts + 1, a2_ts):
    candidate_uuid = reconstruct_uuid_v1(
        timestamp=ts,
        clock_seq=extract_clock_seq(reset_attacker_1),  # Same!
        node=extract_node(reset_attacker_1)              # Same!
    )
    # Try the candidate token
    resp = requests.get(f"https://target.com/reset?token={candidate_uuid}")
    if resp.status_code == 200:
        print(f"[+] Victim token found: {candidate_uuid}")
        break
```

#### Why This Works

- UUID V1 is **deterministic** -- it is NOT random. It is derived from timestamp + MAC address + clock sequence
- The timestamp has nanosecond precision, but the range between two requests made milliseconds apart is still small enough to brute-force
- The MAC address and clock sequence are constant for a given server, so they can be extracted from any UUID generated by that server
- The "sandwich" provides both a lower bound and upper bound, making brute-force efficient and giving a clear signal if the approach is not working (you hit the upper bound without finding the token)
- Smashing the State research (James Kettle) could potentially reduce the time gap even further for sub-millisecond request processing, though UUID V1 nanosecond resolution may prevent actual collisions

#### Where To Apply This

- **Password reset tokens**: Most critical target -- leads to account takeover
- **Email verification tokens**: Account creation hijacking
- **Any security-sensitive token using UUID V1**: Invitation links, API keys, session identifiers
- **Quick identification**: Look at the 13th character of the UUID. If it is `1`, it is UUID V1
- **Combine with Smashing the State**: Single-packet attacks to minimize timestamp gap between attacker and victim resets

---

### 5. Blind XSS Automation with Context-Aware Payloads

#### How It Works

Lupin describes building a semi-automation framework for blind XSS that uses templates and smart payload matching rather than blindly spraying polyglot payloads everywhere. The system records request flows (login -> add product -> checkout) and replays them while mutating one parameter at a time.

```
Flow-Based Blind XSS Testing:

[Record Request Flow]
    |
    v
Request 1: POST /login         {username: "attacker", password: "..."}
Request 2: POST /cart/add       {product_id: "123", name: "Widget"}
Request 3: POST /cart/update    {cart_name: "My Cart", notes: "..."}
Request 4: POST /checkout       {shipping_addr: "...", payment: "..."}
Request 5: POST /order/confirm  {order_notes: "..."}
    |
    v
[Replay with Mutations]
    |
    +--> Run 1: Mutate Request 2 "name" field with blind XSS payload
    |     - If Response 2 matches expected response -> continue flow
    |     - If Response 2 diverges -> DROP, restart with next mutation
    |
    +--> Run 2: Mutate Request 3 "cart_name" field
    +--> Run 3: Mutate Request 3 "notes" field
    +--> Run 4: Mutate Request 4 "shipping_addr" field
    +--> Run 5: Mutate Request 5 "order_notes" field
    |
    v
[Wait for blind XSS callback]
    |
    v
Admin views order in admin panel -> payload fires
```

```
Error-Based Triggering Strategy (from research on log4j):

[Normal Flow: login -> browse -> checkout]
        |
        v
[Intentionally cause errors]
    - Invalid parameters
    - Oversized values
    - Malformed requests
    - Trigger rate limiting / IP ban
        |
        v
[Errors generate LOG ENTRIES with attacker-controlled data]
        |
        v
[Admin/SOC analyst views logs in admin panel]
        |
        v
[Blind XSS payload in log entry fires in admin browser context]
```

#### Why This Works

- Admin panels render user-submitted data (order names, notes, addresses, error logs) in HTML context
- Flow-based testing ensures the application reaches the correct state (e.g., a product must be in the cart before checkout)
- Error-based triggering increases the chance that attacker-controlled data appears in log viewers, incident response dashboards, and monitoring tools
- Smart payload selection (matching payload to rendering context) is more effective than spraying polyglot everywhere

#### Where To Apply This

- **E-commerce checkout flows**: Cart names, order notes, shipping addresses render in admin order management
- **Support ticket systems**: User-submitted text appears in agent dashboards
- **Error/logging systems**: Intentionally trigger errors with payloads in headers, parameters, user-agent
- **Any multi-step flow where data persists and is later viewed by admins**

---

### 6. A/B Test Feature Discovery via JavaScript Analysis

#### How It Works

Companies doing continuous deployment include unreleased features in their JavaScript bundles behind feature flags or A/B test conditions. These features are fully functional in the JS but not exposed in the UI.

```javascript
// Feature flag pattern in client-side JS:

// Common pattern 1: Direct flag check
if (window.__FEATURE_FLAGS__.newCheckoutV2) {
  // Unreleased checkout flow -- API endpoints are RIGHT HERE
  fetch('/api/v2/checkout/process', {
    method: 'POST',
    body: JSON.stringify({ cart_id: cartId, payment_method: pm })
  });
}

// Common pattern 2: A/B test assignment
if (abTest.getVariant('experiment_123') === 'treatment') {
  // New admin dashboard feature -- hidden but code is shipped
  loadAdminModule('/api/internal/admin/v3/dashboard');
}

// Common pattern 3: Environment-based
if (config.environment === 'staging' || config.enableBeta) {
  // Beta API with less security hardening
  apiClient.post('/api/beta/user/bulk-export', { format: 'csv' });
}
```

```
Discovery Flow:

[Extract ALL JS chunks] --> [Search for feature flag patterns]
        |                     - __FEATURE_FLAGS__
        |                     - abTest / experiment
        |                     - enableBeta / staging
        |                     - isEnabled / featureToggle
        v
[Identify unreleased API endpoints]
        |
        v
[Call endpoints directly] --> [Bypass feature flag check entirely]
        |                      (The flag is client-side only!)
        v
[Test for vulnerabilities in untested code]
    - Basic IDOR (nobody has security-tested this yet)
    - Missing authorization
    - Data leaks
```

#### Why This Works

- Feature flags are typically a client-side UI concern -- the server-side API endpoints exist and are accessible regardless of whether the flag is enabled
- A/B test code ships to ALL users, not just the test group
- Unreleased features are often less security-hardened because they have not been through full security review
- As Lupin notes: "I found so many bugs that were so easy, but just hidden in some JavaScript calls"

#### Where To Apply This

- **Any company doing continuous deployment** (most modern SaaS companies)
- **Monitor JS files over time**: New features appear in JS bundles before they are publicly launched
- **Look for basic vulnerabilities**: IDOR, missing auth, data exposure in unreleased features

---

### 7. SSRF Bypass via IP Format Manipulation

#### How It Works

Lupin describes a deep dive into the RFC for IP addresses that revealed IPs are fundamentally just 32-bit integers, and the dotted-quad format (192.168.1.1) is merely a convention. SSRF filters that block specific IPs can be bypassed using alternative representations.

```
IP Address Alternative Formats:

Standard:     127.0.0.1
Decimal:      2130706433              (single 32-bit integer)
Octal:        0177.0000.0000.0001    (leading zero = octal in many parsers)
Hex:          0x7f.0x00.0x00.0x01
Mixed:        0x7f.0.0.1             (hex first octet, decimal rest)
Shortened:    127.1                   (127.0.0.1 shorthand)
IPv6 mapped:  ::ffff:127.0.0.1
Overflow:     127.0.0.1.example.com  (parser confusion)

All of these resolve to 127.0.0.1 (localhost)
```

```
SSRF Filter Bypass:

[Application SSRF Filter]
    |
    |  Blocks: "127.0.0.1", "localhost", "0.0.0.0", "169.254.x.x"
    |
    v
[Attacker Input]
    |
    |  Uses: http://2130706433/admin    (decimal format)
    |    or: http://0x7f000001/admin    (hex format)
    |    or: http://0177.0.0.1/admin    (octal format)
    |
    v
[Filter passes -- does not match blocked patterns]
    |
    v
[URL library resolves IP correctly -> hits localhost]
    |
    v
[SSRF to internal services]
```

#### Why This Works

- The RFC specifies that an IP is a 32-bit integer but does not mandate the dotted-quad notation
- Most URL parsing libraries (libc `inet_aton`, Python `socket`, curl) accept ALL these formats
- SSRF blocklists typically only check for the standard dotted-quad format
- The inconsistency between the security filter's parser and the actual URL resolution library creates the bypass
- As Lupin says: "Every caller needs to interpret all the different kinds of formats, which is insane"

#### Where To Apply This

- **Any SSRF filter using string-based IP blocklisting**
- **Webhook URL validators**
- **Image/file fetch from user-supplied URLs**
- **Cloud metadata endpoint access** (169.254.169.254 has similar alternative representations)

---

### 8. DNS Rebinding (Forgotten Knowledge Reference)

Lupin briefly references DNS rebinding as a prime example of "forgotten knowledge" being rediscovered. Originally a network-level attack from 2005, it was later found to work against browser same-origin policy.

```
DNS Rebinding (high-level):

Step 1: Victim visits attacker.com
        DNS resolves to attacker IP (e.g., 1.2.3.4)
        Browser loads attacker's page + JavaScript

Step 2: Attacker's DNS TTL expires (set very low, e.g., 0-1 sec)

Step 3: Attacker's JS makes another request to attacker.com
        DNS now resolves to INTERNAL IP (e.g., 127.0.0.1 or 192.168.1.1)

Step 4: Browser thinks it is still talking to attacker.com (same origin)
        But request actually hits the victim's internal network

Result: Attacker's JavaScript can read responses from internal services
        while staying within the browser's same-origin policy
```

#### Where To Apply This

- Mentioned in the context of James Kettle's advice on hunting for "forgotten knowledge" -- old attack techniques that can be applied to new contexts
- Relevant for attacking internal services, IoT devices, and development environments accessible on local networks

---

### 9. Google batchExecute Protocol Reverse Engineering

#### How It Works

Google uses a proprietary RPC protocol called `batchExecute` across many of its applications. The protocol wraps protobuf-encoded requests in a specific JSON structure, making it difficult to test with standard tools.

```
Google batchExecute Request Structure (simplified):

POST /path/_/BatchExecute

Body (URL-encoded):
f.req=[[["rpcServiceName","[protobuf_payload_base64]",null,"generic"]]]

Where protobuf_payload_base64 is a nested, encoded protobuf message
containing the actual API parameters.

The challenge:
- Parameters are deeply nested in protobuf
- JS functions that build these requests are heavily obfuscated
- Function chains like: Xb(a) -> Yb(Zb(a, Ac(Bc(a.Cd))))
- Each function may live in a different Webpack chunk
```

```
Approach (Lupin + Justin):

[Justin: Manual Testing]                 [Lupin: Automation]
    |                                         |
    v                                         v
[Understand protocol structure]     [Build Burp extension / templates]
[Map request/response patterns]     [Automate protobuf encoding/decoding]
    |                                         |
    v                                         v
[Share findings] <--------> [Share tooling]
                    |
                    v
              [Reusable across ALL Google apps using batchExecute]
```

#### Why This Works

- batchExecute is used across many Google applications -- tooling built for one target transfers to all others
- The protocol creates a high barrier to entry for other researchers, reducing competition
- Semi-automation (understanding the protocol + building encoding/decoding helpers) preserves creative testing ability while eliminating repetitive encoding work

#### Where To Apply This

- **Any Google application** using batchExecute (Gmail features, Google Maps, Google Docs, etc.)
- **Any proprietary protocol**: The same approach (manual understanding + tooling) applies to any custom RPC/encoding scheme
- **Write-up referenced**: The hosts mention a specific write-up on batchExecute they planned to link

---

## Key Quotes

> "I found so many bugs that were so easy, but just hidden in some JavaScript calls that were made by the front end because I didn't have the privilege or anything." -- Lupin

> "If you manage to detect those A/B tests, you might end up with a new scope to play with, like a wider attack surface." -- Lupin

> "When there is a GraphQL, everything is always documented in the front end. I don't know why there are some libraries that even have introspection inside the JS. Like if it's not turned on, go check the JS and you can copy the introspection." -- Lupin

> "Instead of having six to seven hours of code review, do it maybe in two hours." -- Lupin (on using Cursor + AI for JS analysis)

> "Those mental cycles really inhibit creativity in hacking. Anytime you can reduce friction to testing... your brain will work more efficiently in that environment." -- Justin

> "You need to go hunt for forgotten knowledge. Stuff that other people missed for many, many years." -- Lupin (quoting James Kettle)

> "An IP can be so many things. It just needs to be a 32 bit integer, but they do not specify how... every caller needs to interpret all the different kinds of formats, which is insane." -- Lupin

> "No idea is stupid until proven wrong." -- Lupin (on combining Smashing the State with UUID V1 attacks)

---

## Resources & References

| Resource | Description |
|----------|-------------|
| [JS Weasel](https://github.com/) | Automated Webpack unpacking and JS endpoint extraction tool |
| [Cursor](https://cursor.sh) | AI-powered VS Code fork for code analysis (supports GPT-4 API key) |
| [Clairvoyance](https://github.com/nikitastupin/clairvoyance) | GraphQL schema brute-forcer using field suggestion leaks |
| [GraphQL Voyager](https://github.com/APIs-guru/graphql-voyager) | Interactive GraphQL schema visualization tool |
| [Smashing the State](https://portswigger.net/research/smashing-the-state-machine) | James Kettle's single-packet attack research for race conditions |
| [James Kettle - So You Want to Be a Security Researcher](https://portswigger.net/research/so-you-want-to-be-a-web-security-researcher) | Research methodology essay referenced by Lupin |
| [Lupin & Holmes](https://liandh.tech) | Lupin's security R&D company |
| [UUID V1 research (Vergeprites)](https://blog.vergeprites.com/) | Blog post on UUID V1 timestamp predictability |
| 42 School Network | Free programming school (no teachers, no fees, open 24/7) referenced by Lupin |

---

## Master Summary Table

| # | Technique | Type | Impact | Complexity |
|---|-----------|------|--------|------------|
| 1 | Lazy-Loaded Webpack File Analysis | Client-Side JS Recon | Hidden API endpoint discovery, privilege escalation vectors | Low |
| 2 | GraphQL Schema Extraction from JS | Client-Side JS Recon | Full API schema recovery when introspection disabled | Low-Medium |
| 3 | AI-Assisted JS Code Review (Cursor) | Tooling / Methodology | 3x faster code review, protobuf/RPC request reconstruction | Low |
| 4 | UUID V1 Sandwich Attack | Token Prediction / ATO | Account takeover via password reset token prediction | Medium |
| 5 | Blind XSS Flow Automation | XSS / Stored XSS | Admin panel compromise via context-aware blind XSS | Medium-High |
| 6 | A/B Test Feature Discovery in JS | Client-Side JS Recon | Unreleased feature access, untested endpoint discovery | Low |
| 7 | SSRF Bypass via IP Format Manipulation | SSRF | Internal service access, cloud metadata theft | Low |
| 8 | DNS Rebinding (reference) | Network / Browser | Internal network access from external attacker JS | High |
| 9 | Google batchExecute Protocol RE | Protocol Reverse Engineering | Testing proprietary Google RPC endpoints | High |

---

**Note:** This episode is rich in client-side JavaScript analysis methodology but is also heavily focused on general bug bounty strategy (pair hacking, collaboration, semi-automation philosophy, live hacking event tactics). The techniques above are the actionable client-side security content extracted from the discussion. The UUID V1 and SSRF content, while not purely client-side DOM attacks, are directly relevant to client-side researchers who encounter these patterns during JavaScript analysis.
