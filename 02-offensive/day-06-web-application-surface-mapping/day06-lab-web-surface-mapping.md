# Day 6: Web Application Surface Mapping

**Engagement target:** TechNova web application (lab)
**Scope:** `http://localhost:5000`, all surfaces authorized. Credentials provided: `testuser` / `password123`. Testing performed in an instructor-provided lab environment.
**Phase:** Offensive / red team, Day 6 (Week 2 opener)

## Objective

Build a complete application attack surface map before any payload fires: every endpoint, every parameter, every session mechanism. Three passes (unauthenticated, authenticated, admin), plus JavaScript source analysis, session/token analysis, cookie security audit, and response-header inspection. The output is the analytical foundation for Week 2 exploitation.

## Lab Setup

```bash
./start.sh
```

Brought up two containers (`day06-surface-mapping-technova-app-1`, `day06-surface-mapping-nexus-app-1`). Targets:
- TechNova App: `http://localhost:5000`
- Demo App: `http://localhost:5001`

Burp Suite Community set as intercepting proxy with intercept OFF, so all browsing is captured passively in HTTP history.

## Part A: Unauthenticated Surface (Pass 1)

### robots.txt

```
User-agent: *
Disallow: /admin/
Disallow: /secret/
Sitemap: /sitemap.xml
```

`robots.txt` is working against the application here: it advertises two "sensitive" paths instead of hiding them. Both were visited directly to test whether the Disallow lines map to real access control.

| Path | Result | Finding |
|------|--------|---------|
| `/admin/` | 404, JSON `{"error":"Not Found","server":"TechNova/3.0.0"}` | No admin UI at this path, but the error body leaks a custom server banner |
| `/secret/` | 200, "Restricted Area" page, fully readable | **Broken access control.** Labelled restricted, zero enforcement |

`/secret/` served `Access token: CODED{too_easy}`. This is a **decoy**: the lab states the real flag is split into two pieces, so a single self-contained flag sitting at a honeypot path is bait. Noted and set aside.

Note: `/secret` (no trailing slash) returns 308 redirect to `/secret/`, standard Flask/Werkzeug `strict_slashes` behaviour.

**Public endpoints reachable without auth:** `/`, `/login`, `/robots.txt`, `/sitemap.xml`, `/secret/`, plus the static assets `/static/css/style.css` and `/static/js/app.js`.

## Part B: Authenticated Surface (Pass 2)

Logged in as `testuser` and walked every authenticated page: Dashboard, Profile, Search, Upload. Dashboard confirmed the account context in plaintext: `Role: user | User ID: 42`.

### API discovery (Burp HTTP history)

| Method | Path | Status | Notes |
|--------|------|--------|-------|
| POST | `/login` | 200 | Sets `session_token` JWT cookie |
| GET | `/dashboard` | 200 | Authenticated landing page |
| GET | `/api/v1/products` | 200 | JSON product list, called by `loadDashboard()` |
| GET | `/profile` | 200 | Leaks `X-Debug-Token` header (see Part E) |
| GET | `/search` | 200 | Product search |
| GET | `/upload` | 200 | File upload form |
| POST | `/upload` | 200 | Upload handler, returns JSON |

`/api/v1/products` is the only data API the frontend calls during normal browsing. Everything else below came from reading the JS, not from clicking.

## Part C: JavaScript Source Analysis

### Hidden endpoints in /static/js/app.js

The frontend script (`// Version: 3.2.1`) defines two API bases and, importantly, a list the UI never calls:

```javascript
const API_BASE = "/api/v1";
const API_V2_BASE = "/api/v2";

// Internal API - DO NOT EXPOSE TO CLIENTS
// TODO: Remove before production deployment
function checkInternalStatus() { fetch(API_V2_BASE + "/internal/status") ... }
function checkInternalHealth() { fetch(API_V2_BASE + "/internal/health") ... }

// Admin endpoint references
const ADMIN_ENDPOINTS = [
    "/api/v1/admin/users",
    "/api/v2/internal/status",
    "/api/v2/internal/health",
    "/api/v2/debug"
];
```

The developer comments are themselves a finding: internal endpoints shipped to every client with a "DO NOT EXPOSE" note still attached. Each of the four was then accessed directly with the plain `user` session to test the privilege boundary (Part F).

## Part D: Session & Token Analysis

### Task 6: JWT decode

The `session_token` cookie is a JWT. Decoded (jwt.io / Burp Decoder):

**Header:** `{"alg":"HS256","typ":"JWT"}`

**Payload:**
```json
{
  "user_id": 42,
  "username": "testuser",
  "role": "user",
  "flag_part": "surf4c3",
  "iat": 1793977877,
  "exp": 1794064277
}
```

- **Signing algorithm:** HS256 (HMAC-SHA256, symmetric, single shared secret).
- **Token lifetime:** `exp - iat = 1794064277 - 1793977877 = 86400s = exactly 24 hours`.
- **Interesting claims:** `flag_part: "surf4c3"` is the first half of the flag. `role: "user"` is the claim that matters most for Week 2: it is a privilege field held client-side inside a signed token, which makes it the obvious target for forgery (alg-confusion / `alg:none`) or secret-cracking next.

The `a-string-secret-at-least-256-bits-long` text in the jwt.io secret box is that site's placeholder, not the application's key.

### Task 7: Cookie security audit

`session_token` attributes (from browser Storage inspector):

| Attribute | State | Attack enabled by its absence |
|-----------|-------|-------------------------------|
| HttpOnly | **Present (true)** | (Correctly set: blocks JS `document.cookie` theft, limits XSS token exfiltration) |
| Secure | **Missing (false)** | Token travels over plain HTTP, interceptable on the wire (the app is served over `http://`) |
| SameSite | **None** | No CSRF protection, cookie is attached on cross-site requests |

`SameSite=None` combined with a missing `Secure` flag is itself a misconfiguration: modern browsers normally reject `SameSite=None` cookies that are not also `Secure`.

## Part E: Response Header Analysis

### Task 8: Information leakage

| Header | Value | Significance |
|--------|-------|--------------|
| `Server` | `Werkzeug/3.1.9 Python/3.11.17` | Framework and language version disclosure on every response |
| `X-Debug-Token` | `dGVjaG5vdmEtaW50ZXJuYWwtdjI=` (on `/profile`) | Custom debug header, base64 encoded |
| `server` (JSON body, `/admin/` 404) | `TechNova/3.0.0` | Custom app banner, different version string from the real `Server` header |

Decoding the debug token (Burp Decoder, base64):

```
dGVjaG5vdmEtaW50ZXJuYWwtdjI=  ->  technova-internal-v2
```

Version strings are inconsistent across the app (`Werkzeug/3.1.9`, `TechNova/3.0.0`, JS comment `3.2.1`, debug endpoint `flask_version 3.0.0`), which is a minor finding on its own: it signals pieces maintained and versioned separately.

## Part F: Admin Surface (Pass 3)

### Task 9: Privilege boundary test

Each endpoint from `ADMIN_ENDPOINTS` was requested with the ordinary `testuser` (role `user`) session:

| Endpoint | Response as `user` | Verdict |
|----------|--------------------|---------|
| `/api/v1/admin/users` | 404, `{"error":"Not Found","server":"TechNova/3.0.0"}` | Restricted / not present. Boundary holds here |
| `/api/v2/internal/status` | **200**, returns `flag_part`, build date, environment | **Broken access control** |
| `/api/v2/internal/health` | **200**, returns service health + `uptime "127d 04h 33m"` | **Broken access control** |
| `/api/v2/debug` | **200**, returns `hostname`, `internal_ip`, versions | **Broken access control** |

The boundary is split: the single `/api/v1/admin/*` path is locked, but the entire `/api/v2/*` internal surface is wide open to any authenticated user. That version-prefix gap (v1 enforced, v2 not) is the core access-control finding of the day.

**Data leaked by the open v2 endpoints:**
- `/api/v2/internal/status`: `flag_part: "m4pp3d"`, `environment: "production"`, `build_date: "2026-03-15"`, note "Combine with the flag_part in your session token"
- `/api/v2/internal/health`: cache/database/queue all `connected`, `status: healthy`, `uptime: 127d 04h 33m` (patch-cadence intel: a host up 127 days is well behind on reboots/kernel updates)
- `/api/v2/debug`: `hostname: tn-web-prod-01`, `internal_ip: 10.0.1.15`, `flask_version: 3.0.0`, `python_version: 3.11.7` (internal network foothold detail for later lateral movement, plus confirmation this is a production box)

## Flag

Two pieces, assembled in order (the halves read as "surface mapped", which confirms ordering):

| Piece | Source |
|-------|--------|
| `surf4c3` | `flag_part` claim in the `session_token` JWT (Task 6) |
| `m4pp3d` | `flag_part` in `/api/v2/internal/status` response (Task 9) |

**`CODED{surf4c3_m4pp3d}`**

## Kill Chain Mapping

| PHASE | WHAT YOU DID | TOOLS / TECHNIQUES |
|-------|--------------|--------------------|
| Pre-Engagement | Confirmed scope, launched lab, set Burp as intercepting proxy | `./start.sh`, Burp Suite Community |
| Reconnaissance | Mapped unauthenticated surface, read `robots.txt` and `sitemap.xml` | Browser, Burp HTTP history |
| Enumeration | Authenticated walk of all pages, read `app.js` for hidden endpoints, decoded JWT and debug header | Burp history, view-source, jwt.io, Burp Decoder |
| Exploitation | Direct access to `/secret/` and open `/api/v2/*` endpoints with a plain user token | Broken access control (forced browsing) |
| Privilege Escalation | Confirmed `role` claim is client-held; identified JWT forgery / secret-crack as next step | JWT analysis (not yet exploited, Week 2) |
| Lateral Movement | Collected internal host/IP (`tn-web-prod-01`, `10.0.1.15`) from `/api/v2/debug` | Information disclosure |
| Persistence | N/A for this phase | - |
| Reporting | Surface map, findings, flag assembly, this write-up | Markdown |

## Key Takeaways

- `robots.txt` Disallow entries are a map of what the owner considers sensitive, not an access control. `/secret/` was labelled restricted and had zero enforcement.
- The real access-control failure was a version-prefix gap: `/api/v1/admin/*` enforced, the whole `/api/v2/*` internal surface open to any authenticated user.
- A JWT carries application architecture in its claims. A client-held `role` field is a Week 2 target, not a trustworthy authorization source.
- Missing `Secure` and `SameSite=None` are findings in their own right, independent of any other bug.
- JavaScript source is the single richest recon artifact here: it handed over `/api/v2`, the internal functions, and the full `ADMIN_ENDPOINTS` list the UI never touches.
- Response headers leaked framework versions, a base64 debug token, and (via the open debug endpoint) internal hostname and IP.

## Optional: Alternative and Better Approaches

Not run during the lab. Listed for learning and for a faster/cleaner repeat.

**Faster endpoint reachability sweep (instead of clicking each in the browser):**
```bash
# -b sends the session cookie; adjust the value to your token
curl -s -b "session_token=<JWT>" http://localhost:5000/api/v2/internal/status
curl -s -b "session_token=<JWT>" http://localhost:5000/api/v2/internal/health
curl -s -b "session_token=<JWT>" http://localhost:5000/api/v2/debug
curl -s -o /dev/null -w "%{http_code}\n" -b "session_token=<JWT>" http://localhost:5000/api/v1/admin/users
```

**Decode the JWT and the debug header on the command line:**
```bash
# JWT payload without a website
echo '<jwt>' | cut -d. -f2 | base64 -d 2>/dev/null | jq .
# X-Debug-Token
echo 'dGVjaG5vdmEtaW50ZXJuYWwtdjI=' | base64 -d
```

**jwt_tool for a full token audit in one shot** (also flags `alg` weaknesses, which is where Week 2 goes):
```bash
jwt_tool <jwt>
```

**Content discovery to catch paths not in robots.txt or the JS** (there may be endpoints neither source reveals):
```bash
ffuf -u http://localhost:5000/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -b "session_token=<JWT>" -mc 200,301,302,401,403
# API-specific wordlist for the v1/v2 surface
gobuster dir -u http://localhost:5000/api/v2 -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -c "session_token=<JWT>"
```

**Header inspection without the proxy:**
```bash
curl -sI http://localhost:5000/profile -b "session_token=<JWT>"   # see X-Debug-Token and Server
```

**Stealth note:** forced-browsing every admin endpoint and running `ffuf` generates a burst of 404s and 200s in the server log. In a real engagement, rate-limit, randomize user-agent, and prefer leads from `app.js` over blind fuzzing to stay quiet.
