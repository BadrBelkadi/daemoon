# EP41: Generating Endless Attack Vectors - Client-Side Security Notes

## Metadata
- **Podcast:** Critical Thinking Bug Bounty Podcast
- **Episode:** 41 (Mini Episode)
- **Host:** Justin Gardner (@rhynorater)
- **Guest:** None (solo episode)
- **Primary Topic:** Methodology for generating attack vectors when you hit a plateau on a target
- **Referenced Talk:** Douglas Day (The Archangel) -- NahamCon 2023 talk on "Knows" within an application

---

> **NOTE:** This is a methodology-focused episode. Justin presents six techniques for discovering new attack vectors on any web application. The notes below extract and expand upon the client-side specific implications of each technique, with practical code examples and exploitation patterns.

---

## Technique 1: Re-enabling Disabled/Hidden UI Elements

Justin describes using a JavaScript bookmarklet to find every disabled and hidden element in the DOM and re-enable/unhide them. This exposes client-side code paths that the developer intended to restrict but may not have enforced server-side.

### How It Works

1. Application renders buttons, inputs, or entire form sections with `disabled` attribute or `display: none` / `visibility: hidden` CSS
2. The developer assumes the user cannot interact with these elements
3. Attacker runs a bookmarklet or match-replace rule that strips `disabled` attributes and overrides `display`/`visibility`
4. The now-enabled UI elements trigger client-side code paths (event handlers, form submissions, navigation flows) that may lack server-side validation

```javascript
// === Bookmarklet: Re-enable all disabled elements and unhide hidden elements ===
// Paste this as a bookmark URL (prefix with javascript:)

javascript:void(function(){
    // --- Phase 1: Remove "disabled" attribute from ALL elements ---
    // This targets <button disabled>, <input disabled>, <select disabled>, <textarea disabled>, etc.
    var disabled = document.querySelectorAll('[disabled]');
    for(var i = 0; i < disabled.length; i++){
        disabled[i].removeAttribute('disabled');
        // Visual indicator: green border so you can spot what was disabled
        disabled[i].style.border = '2px solid #00ff00';
    }
    console.log('[bookmarklet] Re-enabled ' + disabled.length + ' disabled elements');

    // --- Phase 2: Unhide elements with display:none or visibility:hidden ---
    var allElements = document.querySelectorAll('*');
    var unhidden = 0;
    for(var j = 0; j < allElements.length; j++){
        var style = window.getComputedStyle(allElements[j]);
        if(style.display === 'none'){
            allElements[j].style.display = 'block';
            allElements[j].style.border = '2px solid #ff6600'; // orange = was hidden
            unhidden++;
        }
        if(style.visibility === 'hidden'){
            allElements[j].style.visibility = 'visible';
            allElements[j].style.border = '2px solid #ff6600';
            unhidden++;
        }
    }
    console.log('[bookmarklet] Unhid ' + unhidden + ' hidden elements');

    // --- Phase 3: Remove readonly attributes from inputs ---
    var readonly = document.querySelectorAll('[readonly]');
    for(var k = 0; k < readonly.length; k++){
        readonly[k].removeAttribute('readonly');
        readonly[k].style.border = '2px solid #00ccff'; // cyan = was readonly
    }
    console.log('[bookmarklet] Removed readonly from ' + readonly.length + ' elements');
})();
```

```
Attacker View: Before vs After Bookmarklet
===========================================

BEFORE (normal user):
+------------------------------------------+
|  Account Settings                        |
|                                          |
|  Name:     [John Doe    ]                |
|  Email:    [j***@corp.com] (readonly)    |
|  Role:     [User       v] (disabled)     |
|                                          |
|  [Save Changes]                          |
|  [Delete Account] (grayed out/disabled)  |
+------------------------------------------+

AFTER (bookmarklet executed):
+------------------------------------------+
|  Account Settings                        |
|                                          |
|  Name:     [John Doe    ]                |
|  Email:    [j***@corp.com] (editable!)   |  <-- cyan border
|  Role:     [Admin      v] (editable!)    |  <-- green border
|                                          |
|  [Save Changes]                          |
|  [Delete Account] (clickable!)           |  <-- green border
+------------------------------------------+
         |
         v
  Now interact with these elements through the UI
  to discover the full client-side code path:
  - Does the "Role" dropdown trigger a JS handler that
    sends a different request body?
  - Does "Delete Account" go through a confirmation flow
    with additional parameters exposed in JS?
  - Is the readonly email field submitted in the form
    and accepted by the backend?
```

### Alternative: Burp/Caido Match-and-Replace

```
# Burp Suite Match & Replace Rule (Response Body)
# Strips all disabled attributes from HTML responses before they reach the browser

Match:    disabled="disabled"
Replace:  (empty)

Match:    disabled=""
Replace:  (empty)

Match:    disabled
Replace:  (empty)    # catches boolean attribute form: <button disabled>

# Also useful:
Match:    readonly="readonly"
Replace:  (empty)

Match:    style="display:none"
Replace:  style="display:block"

Match:    style="display: none"
Replace:  style="display: block"
```

### Why This Works

Developers frequently implement access control only in the UI layer. The disabled button or hidden div is the entire "security" mechanism. When a feature was developed first and tier-gating added later, the backend endpoints and client-side event handlers for those features often remain fully functional. Re-enabling the UI element lets you:

1. Walk through the intended UI flow (understanding request format, parameter names, multi-step sequences)
2. Trigger client-side JavaScript event handlers bound to those elements (which may construct requests, navigate, or modify DOM)
3. Discover that the backend accepts the request without any privilege check

### Where To Apply This

- Any SaaS application with tiered plans (free/pro/enterprise)
- Admin panels where certain actions are grayed out for non-admin roles
- Multi-step wizards where "Next" buttons are disabled until conditions are met client-side
- Forms with readonly fields that contain sensitive values (emails, IDs, roles)
- Settings pages that disable options based on account state

---

## Technique 2: Extracting Unsurfaced Data from API Responses

Justin describes looking for data returned by API endpoints that is not rendered in the UI. This indicates legacy features, bundled responses, or intentionally censored fields.

### How It Works

1. Navigate through the application normally while proxying traffic
2. For each API response, compare the full JSON response body to what is actually rendered in the DOM
3. Identify fields present in the response but absent from the UI
4. Investigate whether those fields correspond to removed features, higher-privilege views, or censored data

```
API Response vs. Rendered UI Gap Analysis
==========================================

GET /api/v1/user/profile
Response Body:
{
    "id": 12345,
    "name": "John Doe",              // <-- Shown in UI
    "email": "john@example.com",      // <-- Shown in UI (masked: j***@example.com)
    "role": "user",                   // <-- NOT shown in UI
    "is_staff": false,                // <-- NOT shown in UI  *** interesting ***
    "ssn_last4": "1234",              // <-- Shown in UI (masked)
    "ssn_full": "123-45-1234",        // <-- NOT shown in UI  *** data leak ***
    "legacy_api_key": "ak_live_...",  // <-- NOT shown in UI  *** data leak ***
    "internal_notes": "",             // <-- NOT shown in UI  *** legacy field ***
    "feature_flags": {                // <-- NOT shown in UI
        "beta_export": true,
        "admin_panel": false          // *** what if we flip this? ***
    }
}
```

```javascript
// === Quick console snippet to dump all JSON response data not visible in DOM ===
// Run this in DevTools after a page load to compare API data to rendered text

// Step 1: Intercept fetch responses (paste before navigating)
(function(){
    const origFetch = window.fetch;
    window.fetch = async function(...args){
        const response = await origFetch.apply(this, args);
        const clone = response.clone();
        try {
            const json = await clone.json();
            console.group('[API Response] ' + args[0]);
            // Recursively extract all string values from the JSON
            const allValues = [];
            function extract(obj, path){
                for(let key in obj){
                    if(typeof obj[key] === 'string' && obj[key].length > 0){
                        allValues.push({path: path + '.' + key, value: obj[key]});
                    } else if(typeof obj[key] === 'object' && obj[key] !== null){
                        extract(obj[key], path + '.' + key);
                    }
                }
            }
            extract(json, 'root');

            // Check which values appear in the visible DOM text
            const bodyText = document.body.innerText;
            allValues.forEach(function(item){
                if(!bodyText.includes(item.value)){
                    // This value is in the API response but NOT rendered in the UI
                    console.warn('[HIDDEN] ' + item.path + ' = ' + item.value);
                }
            });
            console.groupEnd();
        } catch(e){
            // Not JSON, ignore
        }
        return response;
    };
    console.log('[monitor] Fetch interceptor installed. Navigate the app now.');
})();
```

### Client-Side Specific Angle: Feature Flags and Role Indicators

```
Flow: Exploiting Client-Side Role/Tier Indicators
==================================================

Step 1: Identify the field that controls client-side behavior
         GET /api/me --> { "is_staff": false, "tier": "free" }
                |
                v
Step 2: Find where the client-side JS reads this value
         if (user.is_staff) { showAdminPanel(); }
         if (user.tier === 'enterprise') { enableExportButton(); }
                |
                v
Step 3: Use Burp/Caido match-replace on the API response
         Match:   "is_staff": false
         Replace: "is_staff": true

         Match:   "tier": "free"
         Replace: "tier": "enterprise"
                |
                v
Step 4: The CLIENT-SIDE now renders the staff/enterprise UI
        - Admin panels appear with additional navigation
        - Enterprise features become clickable
        - Additional JS code paths execute (possibly loading new endpoints)
                |
                v
Step 5: Interact with the newly exposed UI elements
        - If the backend also lacks checks --> full privilege escalation
        - If the backend blocks --> you still mapped hidden attack surface
```

### Why This Works

APIs frequently return a superset of data because:
- The same endpoint serves multiple clients (web, mobile, internal tools)
- Legacy fields were never removed from the serializer
- Sensitive data masking is implemented only in the frontend rendering layer
- Feature flags and role indicators are sent to the client so JavaScript can conditionally render UI

The censored-in-UI-but-present-in-API pattern is a direct information disclosure. The feature-flag-in-response pattern exposes the full client-side code for premium/staff features.

### Where To Apply This

- Any application with masked/censored fields (SSN, email, phone, API keys)
- SaaS platforms with tiered pricing (feature flags in API responses)
- Applications with admin/staff roles (role field in user object)
- Mobile apps that share the same API (mobile may surface different fields)
- Look up old JS files on the Wayback Machine to find code that consumed now-hidden API fields

---

## Technique 3: Client-Side Tier/RBAC Emulation via Match-Replace

Justin explains that applications with different user tiers (admin/user, free/premium, support/customer) often determine UI rendering based on a field in the API response. By modifying this response client-side, you can unlock the full premium/admin UI.

### How It Works

1. Create two accounts: one with the higher privilege tier, one with the lower
2. Compare the API responses between the two accounts to identify the differentiating field(s)
3. Set up a match-replace rule in your proxy to modify the low-privilege response to match the high-privilege one
4. The client-side JavaScript now renders the full high-privilege UI
5. Walk through every feature exposed in this elevated UI
6. Test whether the backend enforces the tier check on each action

```
Comparison Flow: Identifying the Client-Side Tier Indicator
============================================================

Account A (Free Tier):                Account B (Premium Tier):
GET /api/user/me                      GET /api/user/me
{                                     {
  "id": 100,                           "id": 200,
  "plan": "free",           <--diff-->  "plan": "premium",
  "features": {                         "features": {
    "export": false,         <--diff-->   "export": true,
    "api_access": false,     <--diff-->   "api_access": true,
    "custom_domain": false   <--diff-->   "custom_domain": true
  },                                    },
  "max_projects": 3,        <--diff-->  "max_projects": 999,
  "role": "member"                      "role": "member"
}                                     }

         |
         v

Match-Replace Rule (Proxy Response Modification):
  Target: Responses from /api/user/me
  Match:   "plan": "free"
  Replace: "plan": "premium"

  Match:   "export": false
  Replace: "export": true

  (repeat for each feature flag)
```

```javascript
// === Service Worker approach: intercept and modify responses in-browser ===
// Register this as a service worker to modify API responses without a proxy
// (Useful when proxy setup is inconvenient or for quick testing)

self.addEventListener('fetch', function(event) {
    // Only intercept the user profile endpoint
    if (event.request.url.includes('/api/user/me')) {
        event.respondWith(
            fetch(event.request).then(function(response) {
                return response.json().then(function(data) {
                    // Elevate tier client-side
                    data.plan = 'enterprise';
                    data.is_staff = true;
                    data.features = data.features || {};
                    data.features.export = true;
                    data.features.api_access = true;
                    data.features.custom_domain = true;
                    data.features.admin_panel = true;
                    data.max_projects = 99999;

                    return new Response(JSON.stringify(data), {
                        headers: response.headers
                    });
                });
            })
        );
    }
});
```

### Why This Works

The development cycle Justin describes is critical to understand:

```
Typical SaaS Development Timeline (Why Tiers Break)
=====================================================

Phase 1: Build all features
  --> Everything works for everyone
  --> All endpoints exist, all JS code is shipped

Phase 2: Add tier system
  --> Frontend: if (user.plan !== 'premium') hideButton();
  --> Backend: ??? (often forgotten or inconsistent)

Phase 3: Ship
  --> Frontend hides premium features for free users
  --> Backend endpoints for premium features are still callable
  --> JS code for premium features is still in the bundle
```

The frontend tier check is purely cosmetic. The JavaScript bundle contains all the code for all tiers because it is built once and served to everyone. The "restriction" is a conditional render that reads a field from the API response. Modifying that field unlocks the full UI and all its associated client-side logic.

### Where To Apply This

- Any SaaS with visible pricing tiers (free/starter/pro/enterprise)
- Applications with admin panels accessible via the same domain
- Support/agent portals that share the same codebase as the customer portal
- Applications where upgrading changes the UI without a page reload (indicates client-side tier check)

---

## Technique 4: Using the Application Like a Human (Exhausting UI Code Paths)

Justin describes methodically walking through every user journey in the UI without looking at the proxy. The goal is to get the application into every possible configured state, exposing code paths and features that targeted hacking might miss.

### How It Works

1. Open the application in a browser with proxy running passively in the background
2. Do NOT look at the proxy -- interact with the UI as a normal user would
3. Walk through every dropdown, every configuration option, every wizard step
4. Get the application into unusual configured states (e.g., selecting obscure device types from a dropdown)
5. After exhausting the UI, review the captured traffic for interesting endpoints and parameters

```
Exhaustive UI Walkthrough Strategy
====================================

Normal hacker approach:
  Login --> Burp --> Target tab --> Spider --> Attack endpoints
  (Misses: conditional UI, state-dependent features, multi-step flows)

Human-first approach:
  Login --> Use the app like a customer for 30-60 minutes
       |
       +--> Click every menu item
       +--> Open every settings page
       +--> Try every dropdown option (ALL of them, not just the first few)
       +--> Complete every wizard/setup flow
       +--> Upload files, create projects, invite users
       +--> Configure integrations, webhooks, notifications
       +--> Try every export/import option
       |
       v
  THEN review proxy traffic
       |
       +--> New endpoints discovered (ones the spider missed)
       +--> New parameters in request bodies
       +--> State-dependent API calls (only triggered in certain configs)
       +--> Client-side JS dynamically loaded for specific features
```

### Client-Side Specific Angle: Lazy-Loaded JavaScript

```
Why Exhaustive UI Walking Matters for Client-Side Analysis
===========================================================

Modern SPAs use code-splitting / lazy-loading:

  Main bundle (always loaded):
    - /static/js/main.chunk.js          (core app logic)

  Lazy-loaded chunks (loaded on navigation):
    - /static/js/settings.chunk.js      (loaded when you visit /settings)
    - /static/js/admin.chunk.js         (loaded when admin panel opens)
    - /static/js/integrations.chunk.js  (loaded when you configure integrations)
    - /static/js/export.chunk.js        (loaded when you click Export)

If you only spider the main page, you miss the lazy-loaded chunks.
If you walk through the UI, the browser fetches them all.

Each chunk may contain:
  - Additional postMessage listeners
  - Additional DOM sinks (innerHTML, eval, document.write)
  - Additional API endpoints and parameter handling
  - Additional client-side routing with URL parameter consumption
```

### Why This Works

Static analysis and automated spidering miss state-dependent code paths. A dropdown with 50 options might have 49 that render the same generic form, but the 50th loads a completely different component with unique functionality (as in Justin's SSRF-via-device-configuration example). The only way to discover these is to systematically try every option.

### Where To Apply This

- Applications with complex configuration interfaces (IoT, network gear, CMS)
- Multi-step wizards where later steps depend on earlier selections
- Applications with many dropdown/select options (each may trigger different JS)
- Any SPA using code-splitting (React lazy, Angular loadChildren, dynamic imports)

---

## Technique 5: Mining Documentation, Forums, and GitHub Issues for Attack Surface

Justin describes reading all available documentation, GitHub issues, forum posts, and help desk FAQs to discover features, boundaries, and known bugs that can be turned into security vulnerabilities.

### How It Works

1. Export/download all product documentation
2. Search for "cannot" statements, limits, boundaries, and restrictions
3. Search GitHub issues for keywords: `security`, `disclosure`, `leak`, `bypass`, `vulnerability`, `XSS`, `redirect`, `injection`
4. Read help desk FAQs for edge cases and workarounds
5. Cross-reference documented restrictions with actual application behavior

```
Documentation Mining Workflow
==============================

Step 1: Gather all docs
        Product docs --> PDF/offline export
        GitHub issues --> search with security keywords
        Forums/Community --> search for "workaround", "bug", "broken"
        Help desk FAQs --> look for "known issues", "limitations"
              |
              v
Step 2: Search for "cannot" statements
        "Users cannot access other users' data"
        "Free tier cannot use the export feature"
        "API keys cannot be used to access admin endpoints"
        "Uploaded files cannot exceed 10MB"
        "Subdomains cannot contain special characters"
              |
              v
Step 3: Test each "cannot" statement
        Can you access other users' data via IDOR?
        Can you call the export API on a free tier account?
        Can you use an API key on an admin endpoint?
        Can you upload a file > 10MB by modifying Content-Length?
        Can you inject special chars into subdomain fields?
              |
              v
Step 4: If you violate a documented "cannot" statement
        --> Strong bug report (reference the documentation)
        --> Hard for triage to dispute
```

### Client-Side Specific Angle: GitHub Issues Revealing Client-Side Bugs

```
GitHub Issue Mining for Client-Side Vulnerabilities
=====================================================

Search queries to run on the target's GitHub:
  - "XSS" in issues
  - "innerHTML" in issues
  - "redirect" in issues
  - "postMessage" in issues
  - "CSP" in issues
  - "iframe" in issues
  - "javascript:" in issues
  - "sanitize" OR "sanitization" in issues
  - "DOMPurify" in issues
  - "eval" in issues

What you are looking for:
  - Bug reports describing "weird behavior" that is actually a security issue
  - Discussions about sanitization approaches (reveals what sinks exist)
  - CSP change requests (reveals what the CSP allows/blocks)
  - iframe embedding discussions (reveals postMessage usage)
  - Redirect loop bugs (reveals redirect handling logic)

Example finding:
  GitHub Issue #4521: "Page sometimes loads with user's session in the URL"
  Developer response: "Known issue, we'll fix it"

  --> This reveals the application sometimes puts session tokens in URLs
  --> Test: Can you force this condition? (referrer leak, CSRF token in URL)
  --> Justin's actual technique: find a "bug" reported as non-security,
      then find a way to force it to happen to other users
```

### Why This Works

Documentation represents the developer's intended security model. Every "cannot" statement is an explicit security boundary. If you can violate it, you have a vulnerability that is difficult to dispute because the developer themselves documented the restriction. GitHub issues are even more valuable because they reveal bugs that developers acknowledged but may not have fully fixed, and they expose internal reasoning about how features work.

### Where To Apply This

- Open-source projects (full GitHub issue history available)
- Products with extensive documentation (enterprise SaaS, developer tools)
- Products with community forums (Discourse, Stack Overflow tags, Reddit)
- Products with public changelogs (look for security-related fixes that may be incomplete)

---

## Technique 6: Paywall Boundaries as Client-Side-Only Restrictions

Justin emphasizes that paywalls are frequently enforced only on the frontend. The premium features exist in the shipped JavaScript bundle and the backend endpoints are functional -- the only restriction is a client-side conditional check.

### How It Works

1. Pay for one premium account (investment in your testing)
2. Keep a second free-tier account
3. On the premium account, map all premium-only features, endpoints, and parameters
4. On the free account, attempt to call those same endpoints directly
5. Use the client-side tier emulation technique (Technique 3) to render the premium UI on the free account

```
Paywall Bypass Testing Flow
=============================

Premium Account                    Free Account
===============                    ============
1. Map premium features:           4. Replay premium API calls:
   - POST /api/export                 - POST /api/export
   - POST /api/custom-domain          - POST /api/custom-domain
   - GET  /api/analytics/advanced     - GET  /api/analytics/advanced
                |                              |
                v                              v
2. Note request format:            5. Check response:
   Headers, body params,              - 200 OK? --> Backend not enforcing tier
   auth tokens                        - 403?    --> Backend enforces (good)
                |                              |
                v                              v
3. Note any client-side             6. If 403, check:
   tier checks in JS:                 - Is it checking a role field you can
   if(plan==='premium')                 modify? (IDOR-style)
     showExportButton();              - Is it checking a header you control?
                                      - Is it checking a cookie you can set?

Alternative: Skip the proxy entirely
=====================================
   Free Account + Match-Replace on /api/user/me response
       |
       +--> "plan":"free" --> "plan":"premium"
       |
       v
   Client-side renders ALL premium UI
       |
       v
   Click premium features through the UI
   (browser sends real API calls)
       |
       v
   Check if backend accepts or rejects
```

```javascript
// === Console snippet: Find all tier-gating logic in loaded JS ===
// Searches all loaded scripts for common tier-checking patterns

(function(){
    var scripts = performance.getEntriesByType('resource')
        .filter(function(r){ return r.initiatorType === 'script'; })
        .map(function(r){ return r.name; });

    console.log('[tier-scan] Checking ' + scripts.length + ' loaded scripts...');

    // Common patterns that indicate client-side tier gating
    var patterns = [
        /plan\s*[=!]==?\s*['"](free|premium|pro|enterprise|starter|basic)/gi,
        /tier\s*[=!]==?\s*['"][\w]+/gi,
        /is_?premium/gi,
        /is_?staff/gi,
        /is_?admin/gi,
        /subscription/gi,
        /feature_?flag/gi,
        /can_?access/gi,
        /has_?feature/gi,
        /paywall/gi,
        /upgrade/gi
    ];

    scripts.forEach(function(url){
        fetch(url).then(function(r){ return r.text(); }).then(function(code){
            patterns.forEach(function(pat){
                var matches = code.match(pat);
                if(matches){
                    console.warn('[tier-scan] ' + url.split('/').pop() + ': ' + matches.join(', '));
                }
            });
        });
    });
})();
```

### Why This Works

Justin nails the root cause:

```
The Flawed Development Cycle
==============================

Phase 1: Developers build the full product
          All features, all endpoints, all client-side code
              |
              v
Phase 2: Product team decides on pricing tiers
          "Export is premium-only"
          "Advanced analytics is enterprise-only"
              |
              v
Phase 3: Frontend team adds tier checks
          if (user.plan !== 'premium') {
              document.getElementById('exportBtn').disabled = true;
          }
              |
              v
Phase 4: Backend team... may or may not add checks
          - Sometimes they do (403 Forbidden)
          - Sometimes they partially do (check on some endpoints, not all)
          - Sometimes they forget entirely (200 OK for everyone)
              |
              v
Phase 5: Over time, new premium features are added
          The frontend/backend enforcement gap widens
          Especially for features added under deadline pressure
```

The JavaScript bundle is shipped to all users. It contains the code for every tier. The conditional rendering is the only barrier. This is not a theoretical concern -- Justin states this pattern yields $2,000-$3,000 bounties regularly.

### Where To Apply This

- Any SaaS with a pricing page showing feature comparison tables
- Applications where upgrading changes the UI without a full page reload
- Applications where the "Upgrade" prompt appears client-side (not a server redirect)
- Products that offer free trials of premium features (the code is already there)

---

## Technique 7: RBAC Matrixing and UI Diffing Across Privilege Levels

Referenced from Douglas Day's talk and expanded by Justin: creating a formal matrix of what each role can do, then systematically testing cross-role access.

### How It Works

1. Identify all roles in the application (user, moderator, admin, support, staff, billing, etc.)
2. For each role, document every UI element visible, every API endpoint called, and every action available
3. Build a matrix comparing roles
4. For each action available to a higher role but not a lower one, test if the lower role can perform it via direct API call

```
RBAC Matrix Example
=====================

Action               | User  | Mod   | Admin | Staff | API Enforced?
---------------------|-------|-------|-------|-------|---------------
View own profile     |  Yes  |  Yes  |  Yes  |  Yes  |  Yes
Edit own profile     |  Yes  |  Yes  |  Yes  |  Yes  |  Yes
View other profiles  |  No   |  Yes  |  Yes  |  Yes  |  ??? TEST
Delete comments      |  No   |  Yes  |  Yes  |  Yes  |  ??? TEST
Access admin panel   |  No   |  No   |  Yes  |  Yes  |  ??? TEST
View support tickets |  No   |  No   |  No   |  Yes  |  ??? TEST
Export user data     |  No   |  No   |  Yes  |  No   |  ??? TEST
Manage billing       |  No   |  No   |  Yes  |  No   |  ??? TEST

Every "??? TEST" cell is an attack vector to investigate.
```

### Client-Side Specific Angle: Identifying Role Indicators for Match-Replace

```javascript
// === How to find what tells the client-side "you are an admin" ===

// Method 1: Search all JS source for role-checking patterns
// Use ripgrep on downloaded JS files:
//   rg -n "role|isAdmin|is_staff|permission|canAccess" ./js-files/

// Method 2: Compare API responses between accounts
// In DevTools console on low-privilege account:
fetch('/api/me').then(r => r.json()).then(d => {
    console.log('=== Low-privilege user object ===');
    console.log(JSON.stringify(d, null, 2));
    // Look for: role, permissions, is_admin, is_staff, tier, plan,
    //           feature_flags, capabilities, scopes, groups
});

// Method 3: Check cookies and localStorage
console.log('=== Cookies ===');
console.log(document.cookie);
// Look for: role=user, tier=free, is_admin=0

console.log('=== localStorage ===');
for(var i = 0; i < localStorage.length; i++){
    var key = localStorage.key(i);
    console.log(key + ' = ' + localStorage.getItem(key));
}
// Look for: stored user objects, JWT tokens (decode the payload),
//           feature flag caches, permission arrays

// Method 4: Decode JWT from cookie/localStorage
// JWTs often contain role claims:
// { "sub": "user123", "role": "user", "plan": "free", "iat": ... }
// Modify and re-encode? No -- signature will fail.
// But: the CLIENT-SIDE reads the JWT payload to decide what to render.
// You can't forge the JWT, but you CAN intercept the /api/me response
// that the client actually uses for rendering decisions.
```

### Why This Works

Applications typically have a single codebase serving all roles. The role differentiation in the UI is driven by data from the API. By identifying and modifying this data client-side, you can:

1. Render the full admin/staff UI on a low-privilege account
2. Discover endpoints and parameters that you would never find through JS analysis alone
3. Understand the intended workflow for admin actions (making it easier to craft valid requests)

### Where To Apply This

- Enterprise applications with complex role hierarchies
- Applications with support/staff portals on the same domain
- Applications where role information is stored in client-accessible locations (cookies, localStorage, API responses)
- Applications using client-side routing that shows/hides admin routes based on role

---

## Master Summary Table

| # | Technique | Type | Impact | Complexity |
|---|-----------|------|--------|------------|
| 1 | Re-enabling Disabled/Hidden UI Elements | Client-Side Restriction Bypass | Medium-High (exposes hidden features, may lead to privilege escalation) | Low (bookmarklet or match-replace) |
| 2 | Extracting Unsurfaced Data from API Responses | Information Disclosure / Attack Surface Mapping | Medium (data leaks, legacy feature discovery) | Low (proxy inspection) |
| 3 | Client-Side Tier/RBAC Emulation via Match-Replace | Authorization Bypass / Privilege Escalation | High (access to premium/admin features) | Low-Medium (match-replace rules) |
| 4 | Exhaustive UI Walkthrough for Lazy-Loaded JS Discovery | Attack Surface Expansion | Variable (depends on what hidden code paths contain) | Low (just patience and thoroughness) |
| 5 | Documentation/GitHub Issue Mining | Attack Surface Mapping / Bug Discovery | Variable (can lead directly to exploitable bugs) | Low-Medium (research time) |
| 6 | Paywall Bypass via Client-Side Tier Gating | Authorization Bypass | High ($2K-$3K bounties per Justin) | Low (match-replace on tier field) |
| 7 | RBAC Matrixing and UI Diffing | Broken Access Control | High (systematic privilege escalation) | Medium (requires multiple accounts and systematic testing) |

---

## Key Quotes

> "Use the application like a human, not like a hacker."
> -- Justin Gardner, on the importance of understanding the application before attacking it

> "Reading the documentation and looking for cannot statements -- this is so underrated it's ridiculous."
> -- Justin Gardner, on mining documentation for explicit security boundaries

> "Sometimes during live hacking events when I'm brain fried and I can't be at my computer anymore, I'll take the documentation for a product, export it to a PDF or get it in some sort of form that I can get it on my e-reader, and I'll just take my e-reader out to a hammock and just leisure read through the documentation."
> -- Justin Gardner, on thorough documentation review

> "A lot of that stuff is just happening in the front end, and it's not being implemented on the backend as well after the functionality's already been developed."
> -- Justin Gardner, on why paywall bypasses work (the core client-side security insight)

> "Make sure you evaluate the security impact of your nos because sometimes there is no security impact."
> -- Douglas Day (quoted by Justin), on not over-reporting

> "If you can do that, it's very hard to debate that it's an issue, because then you can start talking to the program about this whole concept of user trust, where you've built documentation for your product, the user trusts you that this documentation is accurate, and then you've violated that trust."
> -- Justin Gardner, on referencing documentation in reports

---

## Resources & References

- **Douglas Day (The Archangel) -- NahamCon 2023 Talk:** Search YouTube for "NahamCon 2023 Douglas Day" or "NahamCon 2023 The Archangel" -- covers the concept of "knows" within an application, RBAC matrixing, and systematic attack vector generation
- **Critical Thinking Bug Bounty Podcast:** [criticalthinkingpodcast.io](https://criticalthinkingpodcast.io) -- contact: info@criticalthinkingpodcast.io
- **Burp Suite Match & Replace:** Built-in Burp feature under Proxy > Options > Match and Replace -- use for response modification to bypass client-side checks
- **Caido Match & Replace:** Similar functionality in the Caido proxy
- **Wayback Machine:** [web.archive.org](https://web.archive.org) -- look up old JavaScript files to find code that consumed API fields that are now hidden from the UI
- **JavaScript Bookmarklets:** One-click DOM manipulation tools stored as browser bookmarks -- prefix with `javascript:` and encode as a bookmark URL
