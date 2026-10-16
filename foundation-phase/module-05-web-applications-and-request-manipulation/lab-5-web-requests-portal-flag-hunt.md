# Day 5 — Web Applications & Request Manipulation

**Lab:** The Portal Flag Hunt (ACME Corp web app)
**Date:** 2026-10-11
**Environment:** Kali + Firefox DevTools + Burp Suite Community, target `http://localhost:5000` (`day05-web-requests`)
**Flag:** `CODED{g3t_p0st_s0urc3}`

---

## Objective

Find a flag split into three parts hidden in a web app's admin portal, using three core web-testing techniques: reading page source, discovering a hidden endpoint, and manipulating the HTTP method of a request.

## Setup

```bash
cd ~/Desktop/Foundation\ Labs/day05-web-requests
sudo ./start.sh                  # builds vuln-app + log-server
# Web App:    http://localhost:5000
# Log Server: http://localhost:5001
```

The landing page (`ACME Corp Internal Portal`) links to Home, Shop, and a navbar item that isn't shown on the home page but is referenced in links: **Portal**.

---

## The 3-part flag hunt

### Part 1 — View Source (the hidden portal)

Browsing to `http://localhost:5000/portal` loads the **ACME Corp Admin Portal** login ("Authorized personnel only"). Right-click → **View Page Source** (`view-source:http://localhost:5000/portal`) exposes three things the rendered page hides, sitting in HTML comments:

```html
<!-- Debug creds: admin_portal / s3cur3_p4ss -->
<!-- flag part1: g3t_ -->
...
<script>
// TODO: remove debug endpoint /portal/api/debug before production launch
</script>
```

Three findings in one source read:
- **part1 = `g3t_`**
- leaked credentials: `admin_portal` / `s3cur3_p4ss`
- a reference to a hidden endpoint: `/portal/api/debug`

> HTML comments are stripped from the rendered view but ship in the raw response. Developers leave debug notes, credentials, and TODOs there assuming nobody looks — View Source is always step one.

### Part 2 — HTTP method manipulation (the debug endpoint)

Visiting `/portal/api/debug` in the browser (a **GET**) returns only a teaser:

```json
{"message":"Debug endpoint active. Try sending a POST request for more info.","status":"debug_mode"}
```

The endpoint behaves differently by HTTP method, so the flag part is gated behind a **POST**. Reproduced in **Burp Suite**:

1. Point Firefox at Burp via **FoxyProxy** (`127.0.0.1:8080`), **Intercept on**.
2. Browse to `/portal/api/debug` → Burp catches the `GET /portal/api/debug HTTP/1.1` request.
3. **Right-click → Send to Repeater** (`Ctrl+R`); turn Intercept off.
4. In Repeater, **right-click → Change request method** (flips `GET` → `POST`).
5. **Send.** The response body returns the flag part:

```json
{
  "flag_part":"p0st_",
  "message":"Debug endpoint - remove before production",
  "status":"debug_mode"
}
```

> **part2 = `p0st_`**
> Same URL, different method, different response. Browsers only issue GET (address bar) and POST (forms), so method-gated functionality is invisible to normal browsing — you need a tool like Burp Repeater or curl to send an arbitrary method. (Quick equivalents: `curl -X POST http://localhost:5000/portal/api/debug`, or in DevTools Console `fetch("/portal/api/debug",{method:"POST"}).then(r=>r.text()).then(console.log)`.)

### Part 3 — Authenticated access + inspect assets (the CSS comment)

Using the leaked creds (`admin_portal` / `s3cur3_p4ss`) on the portal login → **Access Granted**, "Welcome, Admin… There's nothing else to see here… or is there?" The hint points to the page's own assets. Opening **DevTools → Style Editor** (or Network tab) shows a second stylesheet, `dashboard.css`, loaded only on the authenticated dashboard. Its source contains:

```css
/* flag part3: s0urc3 */
```

> **part3 = `s0urc3`**
> Linked assets (CSS, JS) are part of the attack surface. Secrets dropped in a stylesheet comment never render on screen but are fully readable by anyone who opens the file.

### Assembled flag

```
part1 + part2 + part3
g3t_ + p0st_ + s0urc3
```

```
CODED{g3t_p0st_s0urc3}
```

---

## Kill Chain Mapping

*(Lockheed Martin Cyber Kill Chain)*

| Task | Kill Chain Stage | What I did |
|------|------------------|------------|
| Part 1 | **Reconnaissance** | Viewed page source of `/portal`; harvested leaked creds, flag part1, and a reference to the hidden `/portal/api/debug` endpoint from HTML comments |
| Part 2 | **Exploitation** | Manipulated the HTTP method (GET → POST) in Burp Repeater to trigger hidden debug functionality the app never exposed through normal browsing, returning flag part2 |
| Part 3 | **Actions on Objectives** | Authenticated to the restricted admin portal with the leaked credentials and extracted flag part3 from the authenticated-only `dashboard.css` |

---

## Tools & techniques used

| Tool / action | What it did |
|---------------|-------------|
| **View Page Source** | Read HTML comments hidden from the rendered page (creds, part1, endpoint hint) |
| **Burp Suite — Proxy / Intercept** | Captured the live request to the debug endpoint |
| **Burp Suite — Repeater** | Replayed the request with a changed method (GET → POST) to reach part2 |
| **Change request method** | Burp's one-click GET↔POST flip — the core "request manipulation" skill |
| **DevTools — Style Editor / Network** | Found and read `dashboard.css`, where part3 was commented |
| FoxyProxy | Routed Firefox traffic through Burp (`127.0.0.1:8080`) |

---

## Blue-team reflection

Everything in this hunt was a developer mistake that a defender (or a code review) should catch before production:

- **Secrets in client-delivered code** — credentials, a flag, and a debug endpoint were all sitting in HTML/CSS comments. Anything sent to the browser is readable by the user; secrets must never live in source, comments, or linked assets. A pre-deploy scan for comments/keywords (`password`, `debug`, `TODO`, `flag`) in shipped HTML/JS/CSS catches this cheaply.
- **A debug endpoint left enabled** — `/portal/api/debug` was flagged "remove before production launch" and never removed. Debug/admin routes should be disabled in production and, at minimum, require authentication. Server logs showing hits to undocumented endpoints are a detection signal.
- **Hardcoded / weak credentials** — `admin_portal` / `s3cur3_p4ss` in a comment means the "login" is no barrier at all. Credentials belong in a secrets manager, never in code, and should be rotated the moment they touch a repo or a page.
- **Method-based access with no real authZ** — gating data behind "POST instead of GET" is security by obscurity, not access control. Sensitive functionality needs real authentication and authorization regardless of HTTP method.

**Takeaway:** the client side is fully attacker-visible. View Source, linked assets, and alternate HTTP methods expose anything a developer assumed was hidden — so the fix is to assume nothing sent to the browser is secret, and to put real auth (not obscurity) in front of privileged functionality.

## Cleanup

```bash
./stop.sh
```
