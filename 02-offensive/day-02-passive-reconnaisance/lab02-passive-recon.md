# Day 2 — Passive Reconnaissance & OSINT

**Target:** technova-lab.com (web `:8080`, DNS `:5353`)
**Flag:** `CODED{pa55iv3_r3c0n}`

Mapped TechNova's entire footprint from public sources only — DNS, web OSINT, and a leaked paste — with zero packets to their actual infrastructure.

---

## Part A — DNS Enumeration

### Task 1: DNS Records
```bash
dig @localhost -p 5353 technova-lab.com        # A
dig @localhost -p 5353 technova-lab.com MX
dig @localhost -p 5353 technova-lab.com TXT
dig @localhost -p 5353 technova-lab.com NS
dig @localhost -p 5353 technova-lab.com SOA
```

| Record | Value |
|---|---|
| A | 185.220.101.42 |
| MX | mail (pri 10) → .45, mail-backup (pri 20) → .48 |
| TXT | `v=spf1 ip4:185.220.101.0/24 include:_spf.google.com ~all` plus a google-site-verification token |
| NS | ns1 → .42, ns2 → .43 |
| SOA | ns1.technova-lab.com / admin@technova-lab.com |

**IP addresses in use:** the main domain is one IP (185.220.101.42), but across all records and subdomains TechNova uses the **185.220.101.0/24** block (confirmed by the SPF `ip4` entry).

### Task 2: Subdomain Discovery
Names found in DNS records (NS, MX) and by viewing page sources; each A record resolved individually, and blog/docs resolved as CNAMEs.
```bash
dig @localhost -p 5353 admin.technova-lab.com A      # repeated per subdomain
dig @localhost -p 5353 blog.technova-lab.com CNAME
dig @localhost -p 5353 docs.technova-lab.com CNAME
```

| Subdomain | IP | Likely purpose |
|---|---|---|
| admin | 185.220.101.47 | Admin panel |
| mail | 185.220.101.45 | Primary mail server |
| mail-backup | 185.220.101.48 | Backup mail server |
| api | 185.220.101.42 | Production API |
| staging | 185.220.101.51 | Staging environment |
| dev | 185.220.101.50 | Dev environment (Jenkins :8080) |
| support | 185.220.101.42 | Support portal |
| status | 185.220.101.42 | Status page |
| blog | CNAME → technova.ghost.io | Blog (Ghost hosting) |
| docs | CNAME → technova-docs.readthedocs.io | Docs (Read the Docs) |

10 subdomains. api, support, and status all resolve to .42 (the same IP as the main technova-lab.com domain), so they're separate names served from one box. blog and docs aren't IPs at all; they're CNAMEs pointing to third-party hosts.

### Task 3: DNS Intelligence
- **Email security:** SPF only (`~all` = softfail, meaning unauthorized senders are flagged rather than rejected) plus a Google verification token. **No DMARC and no DKIM**, so domain spoofing is likely possible. That's the real finding.
- **Docs/blog hosting (CNAME):** `blog.technova-lab.com` is a CNAME to `technova.ghost.io` (blog on Ghost) and `docs.technova-lab.com` is a CNAME to `technova-docs.readthedocs.io` (docs on Read the Docs). Both point to third-party hosts, which is the subdomain-takeover pattern: if either account is ever deleted but the CNAME stays, an attacker can re-register it and serve content under the real domain.
- **SPF infrastructure:** `ip4:185.220.101.0/24` (their own block) plus `include:_spf.google.com`, so they send mail through **Google Workspace**.

---

## Part B — Web OSINT

### Task 4: Technology Fingerprinting
```bash
curl -i http://localhost:8080
```
- **Web server:** nginx/1.31.0
- **Framework:** Flask/2.3.2 (`X-Powered-By`)
- **Backend hints:** `X-Backend-Server: aws-ec2-prod-01`, which points to AWS EC2, and the name leaks it's a **prod** box. All three headers should be stripped; leaking them is information disclosure.

### Task 5: Employee Intelligence
**Email format:** `firstname.lastname@technova-lab.com` (consistent across all six, including sarah.alrashid)

| Name | Role | Email | External |
|---|---|---|---|
| Omar Khalil | Co-Founder & CTO | omar.khalil@ | LinkedIn |
| Sarah Al-Rashid | Co-Founder & CISO | sarah.alrashid@ | LinkedIn |
| James Wilson | Lead Developer, Project Chimera | james.wilson@ | github.com/jwilson-dev, linkedin.com/in/jameswilson-dev |
| Fatima Hassan | IT Manager | fatima.hassan@ | LinkedIn |
| Ahmed Nasser | DevOps Engineer | ahmed.nasser@ | GitHub |
| Layla Ibrahim | Frontend Developer | layla.ibrahim@ | (none) |

### Task 6: Hidden Information
- **robots.txt** disallows: `/admin/`, `/backup/`, `/internal/`, `/docs/api-v2-internal.html`, `/.git/`. It advertises exactly what they want hidden. The useful one here is `/docs/api-v2-internal.html`, which loads directly and serves an internal API doc that was never linked in the site navigation.
- **HTML comment** (team page, James's card): `using staging.technova-lab.com for Chimera testing. Config backups at dev.technova-lab.com/backups/`
- **/docs/api-v2-internal.html** internal API doc, Known Issues section leaks three things: `/v2/users` returns password hashes when `include_all=true`; CORS set to `*` on staging; Jenkins still on dev:8080, exposed to internet.

---

## Part C — Google Dorking

### Task 7: The Leaked Document
Keywords pulled from the site: **"Project Chimera"** plus employee name **James Wilson**. Paste sites are the usual dumping ground, so searched Pastebin:

```
Pastebin search: James Wilson project chimera
```

Found a guest paste "Project Chimera" (TechNova dev server config, marked DO NOT SHARE):
```
DB_HOST=10.10.50.12
DB_USER=dev_admin
DB_PASS=TechN0va2026!
API_KEY=sk-tn-xxxxxxxxxxxxxxxxxxxxxxx
INTERNAL_FLAG=CODED{pa55iv3_r3c0n}
```

**Flag:** `CODED{pa55iv3_r3c0n}`

The pivot is the whole lesson: team page (employee), then role (project name), then paste site, then credentials and flag, with zero packets to the target.

---

## Part D — Kill Chain Mapping

| Phase | What you did | Tools / Techniques |
|---|---|---|
| Pre-Engagement | RoE and scope (Day 1) | n/a |
| Reconnaissance | DNS enum, web OSINT, source review, dorking | dig, curl, robots.txt, Pastebin |
| Enumeration to Reporting | Not performed (passive phase) | n/a |

---

## Optional — better commands (not run)
```bash
# Zone transfer: dumps the whole zone (all subdomains + IPs + CNAMEs) in one query
dig @localhost -p 5353 technova-lab.com AXFR

# Resolve many names fast instead of one dig per subdomain
for s in admin mail staging api dev support status docs blog; do
  echo -n "$s -> "; dig @localhost -p 5353 +short $s.technova-lab.com
done
```
