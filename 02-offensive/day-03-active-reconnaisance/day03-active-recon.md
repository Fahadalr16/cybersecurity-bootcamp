# Day 3 — Active Reconnaissance (TechNova)

**Phase:** Offensive / Red Team · **Lab:** Active Recon
**Date:** 2026-10-21
**Target:** `127.0.0.1` (lab-hosted TechNova environment — all ports in scope)
**Toolkit:** Kali Linux · `nmap 7.991` · `netcat` · `ftp` · `curl`

---

## Summary

Went from zero to a full service map and a working internal picture of TechNova. Seven TCP ports open; version detection pinned down the web stack (nginx + PHP + MySQL) and SSH build. Two findings carry real weight: **anonymous FTP leaked plaintext database credentials and internal IPs**, and an **unauthenticated monitoring agent on 9999 handed over the entire internal host inventory** (including a database box and a Jenkins box). Flag recovered: `CODED{nm4p_m4st3r}`.

---

## Part A — Host Discovery & Port Scanning

### Task 1 — Verify the target is live

```bash
nmap -sn 127.0.0.1
```

Host is up. `-sn` is a *no-port-scan* sweep (host discovery only) — it answers "is it alive?" without touching any ports yet, keeping the first probe minimal.

### Task 2 & 3 — Port scan + service/version detection

First, find which ports are actually open:

```bash
nmap --open 127.0.0.1
```

`--open` filters the output down to ports in the `open` state (hiding `closed`/`filtered` noise), giving a clean target list. Then feed exactly those ports into a version scan rather than re-scanning everything:

```bash
nmap -sV -p 2121,2222,7777,8080,8888,9999,30000 127.0.0.1
```

`-sV` performs **version detection**: nmap talks to each open port and matches the response against its service-fingerprint database. Scoping `-p` to the already-known-open ports keeps the slower version probes fast and focused. Seven ports open:

| Port  | Proto | State | Service | Version |
|-------|-------|-------|---------|---------|
| 2121  | TCP   | open  | ftp     | — |
| 2222  | TCP   | open  | ssh     | OpenSSH 9.3 (protocol 2.0) |
| 7777  | TCP   | open  | cbt?    | — (unidentified) |
| 8080  | TCP   | open  | http    | nginx 1.24.0 |
| 8888  | TCP   | open  | http    | nginx 1.24.0 |
| 9999  | TCP   | open  | abyss?  | — (unidentified) |
| 30000 | TCP   | open  | tcpwrapped | — |

**Reading the map:**
- **TechNova (my target):** FTP `2121`, SSH `2222`, web `8080`, mystery `9999`.
- **8888 / 7777** belong to the *instructor demo* (Nexus Financial) running on the same host — picked up because the whole IP was in scope. Good reminder that an "all ports" scan can surface neighbours you weren't hunting.
- **30000 = `tcpwrapped`** means the TCP handshake completed but the service dropped the connection before saying anything — here it's the **FTP passive (PASV) data port** (see the `30000`-range ports in the FTP session below), not a real standalone service.
- The `?` services (`cbt?`, `abyss?`) are nmap's *best guesses* from the `/etc/services` port number — unconfirmed. Unknown services get investigated by hand (Task 7).

---

## Part B — Service Investigation

### Task 4 — Web server analysis

```bash
curl -i 127.0.0.1:8080
```

`-i` includes the response headers. What leaked:

- **`Server: nginx/1.24.0`** — web server + exact version.
- **`X-Powered-By: PHP/8.1.27`** — backend language and version, handed over directly in a header.
- **`X-Server-ID: tn-web-prod-01`** — internal hostname. The naming convention is itself intel: `tn` (TechNova) · `web` (role) · `prod` (production environment) · `01` (instance). That pattern predicts sibling hosts (`tn-db-prod-01`, etc.) — confirmed later by the monitoring agent.
- **HTML comment left in source:** `Server: nginx/1.24.0 | Backend: PHP 8.1.27 | DB: MySQL 8.0` — restates the stack and adds **MySQL 8.0**.

So the full stack (nginx 1.24.0 / PHP 8.1.27 / MySQL 8.0) is now known. Note PHP was exposed **twice** — in the `X-Powered-By` header *and* the comment. Each exact version is a direct lookup into known-CVE research for the next phase.

### Task 5 — SSH banner

```bash
nmap -p 2222 --script ssh-auth-methods 127.0.0.1
```

- **Supported auth methods:** `publickey`, `password`, `keyboard-interactive`.
- **Pre-auth banner:** *TechNova Solutions – Authorized Access Only · All connections are monitored and logged · Contact: security@technova-lab.com*

Offensively, the detail that matters is **`password` auth is enabled** — publickey-only would shut the door on guessing, but password auth keeps credential attacks (spraying/brute-force) on the table for later. The banner also confirms logging is on: I'm visible now.

> Note: the `SERVICE` column shows `EtherNetIP-1` on 2222 — that's just nmap's static port→name guess (port 2222 is registered to EtherNet/IP). Version detection already confirmed it's actually OpenSSH 9.3.

### Task 6 — FTP reconnaissance

First, scripted recon on the FTP port:

```bash
nmap -sC -sV -p 2121 127.0.0.1
```

This flagged the misconfiguration outright: **`ftp-anon: Anonymous FTP login allowed (FTP code 230)`**, banner `220 TechNova FTP Service v2.1`, and `ftp-syst` revealed the server's internal address `172.21.0.3` (a Docker bridge IP).

Then logged in anonymously and pulled everything:

```bash
ftp -P 2121 127.0.0.1
# Name: anonymous   (any/blank password accepted → 230 Login successful)
ls
get .flag
get backup-config.txt
get readme.txt
exit
```

Three files — note `.flag` is a **dotfile** (hidden, wouldn't show on a plain `ls` in a normal shell, but FTP lists it). Then:

```bash
cat backup-config.txt
```

**Sensitive information exposed** — this is the real payload of the lab:

- **Database credentials in plaintext:** `DB_USER=backup_reader` / `DB_PASS=r3adOnly_2026!` for `DB_NAME=technova_prod`.
- **Internal hosts:** `DB_HOST=10.10.20.15`, `BACKUP_HOST=10.10.20.30` (plus the `172.21.0.3` from the earlier script) — a first look at TechNova's internal `10.10.20.0/24` segment.
- **Backup job details:** service account `backup_svc`, path `/var/backups/technova`, cron schedule `0 2 * * *` (runs 02:00 daily).
- **Flag fragment:** `VERIFY_TOKEN=m4st3r`.

Anonymous FTP exposing a config file with live DB creds is a textbook real-world finding — a single misconfiguration handed over credentials *and* a map of the internal network.

### Task 7 — The mystery service (port 9999)

Fingerprint it first:

```bash
nmap -sC -sV -p 9999 127.0.0.1
```

Identified as **TechNova Internal Monitoring Agent v3.7.1** (`Node: tn-monitor-01`), advertising commands `STATUS, HEALTH, VERSION, HELP`. Then interacted manually:

```bash
nc 127.0.0.1 9999
status
health
version
```

What each command gave up:

- **`status`** → *All systems operational. 4 nodes active.*
- **`health`** → the **full internal node inventory** with live resource stats:
  - `tn-monitor-01`
  - `tn-web-prod-01`
  - `tn-db-prod-01` — Disk 88% `[WARNING]`
  - `tn-jenkins-01`
- **`version`** → `v3.7.1 (build 2026.03.01-rc2)`, `Protocol: TNMon/2.1`, and **`Build ID: nm4p`** (flag fragment).

The `health` output is the standout: an **unauthenticated** service just enumerated TechNova's internal hosts for me. That confirms a **database server** (`tn-db-prod-01` — which the FTP creds may unlock) and a **Jenkins server** (`tn-jenkins-01` — CI/CD boxes are a classic route to code execution and stored secrets). This is exactly the kind of intel that feeds lateral-movement planning later in the kill chain. Lesson lived: always poke unknown services by hand — `nc` pulled far more than the port list implied.

---

## Part C — NSE Scripts

### Task 8 — Default script scan

```bash
nmap -p 2222 --script default 127.0.0.1
nmap -p 8080 --script default 127.0.0.1
```

The **NSE** (Nmap Scripting Engine) `default` category runs a safe, standard bundle automatically. Beyond the basic scan:

- **Port 2222 → `ssh-hostkey`:** dumped the host's ECDSA (256-bit) and ED25519 key fingerprints. Useful for spotting **host-key reuse** — the same key on another box usually means a cloned image or shared host.
- **Port 8080 → `http-title`:** *TechNova Solutions* — the app title, confirming the web root without opening a browser.

> `--script default` is identical to the `-sC` flag — which I'd already used on ports 2121 and 9999 above.

---

## Flag Assembly

Two fragments, from the two things I had to *dig into* rather than just scan:

- **Service code** (from a service I interacted with — the 9999 monitoring agent's `version` output): `nm4p`
- **File code** (buried in a downloaded file — `backup-config.txt`): `m4st3r`

Format `CODED{service_code_file_code}`:

```
CODED{nm4p_m4st3r}
```

---

## Kill Chain Mapping

| Phase | What I did | Tools / techniques |
|-------|------------|--------------------|
| Pre-Engagement | Confirmed scope — all ports on target IP authorized | Rules of engagement check |
| Reconnaissance | Host discovery, open-port scan, version detection | `nmap -sn`, `nmap --open`, `nmap -sV` |
| Enumeration | Pulled banners, headers, auth methods, file listings, service menus | `curl -i`, `nc`, `ftp`, NSE (`ssh-auth-methods`, `ftp-anon`, `ftp-syst`, `default`) |
| Exploitation | Abused anonymous-FTP misconfig for unauthenticated file access; queried unauthenticated monitoring agent | `ftp` (anonymous login), `nc` |
| Privilege Escalation | *Not performed this lab* | — |
| Lateral Movement | *Not performed* — but harvested the inputs for it: DB creds `r3adOnly_2026!`, internal hosts `10.10.20.15` / `.30` / `172.21.0.3`, and the node inventory incl. `tn-db-prod-01` and `tn-jenkins-01` | — |
| Persistence | *Not performed this lab* | — |
| Reporting | This write-up | Markdown |

---

## Key Takeaways

- **Active scanning leaves tracks.** The moment I ran `-sV` I was generating logs on the target (the SSH banner literally says connections are monitored). Active recon trades stealth for detail.
- **Version detection is the bridge to vulnerability research.** Exact versions (nginx 1.24.0, PHP 8.1.27, OpenSSH 9.3, MySQL 8.0) are direct inputs into CVE lookups.
- **Unknown services get investigated by hand.** `nc` on 9999 turned a `?` in the port list into a full internal host map — a scanner alone would have missed it.
- **Anonymous FTP is a top real-world misconfig.** Here it leaked live DB credentials and internal IPs from a single file.
- **NSE turns a port list into actionable intelligence** — host keys, anon-login flags, HTTP titles, all automatically.

---

## Optional / Better Commands — *for learning (not run in this lab)*

> Everything above is exactly what I ran. These are sharper or more thorough alternatives worth knowing for next time.

- **Scan all 65,535 ports, not a known list**, so nothing hides on an odd port:
  ```bash
  nmap -p- 127.0.0.1
  ```
- **One pass instead of many** — since `-sC` *is* `--script default`, version + default scripts over every port in a single command:
  ```bash
  nmap -sC -sV -p- 127.0.0.1
  ```
- **Save evidence in all formats** (great for portfolio/reporting — normal, grepable, XML):
  ```bash
  nmap -sC -sV -p- -oA day03_technova 127.0.0.1
  ```
- **Don't forget UDP** — active recon that only scans TCP misses DNS/SNMP/etc.:
  ```bash
  nmap -sU --top-ports 20 127.0.0.1
  ```
- **Headers-only web check** (`-I` sends a `HEAD` request — just headers, no body):
  ```bash
  curl -I 127.0.0.1:8080
  ```
- **Banner-grab SSH without nmap** (raw first, or verbose client for the full handshake):
  ```bash
  nc 127.0.0.1 2222
  ssh -v -p 2222 127.0.0.1
  ```
- **`-A` for an aggressive all-in-one** (OS detection + version + default scripts + traceroute) when stealth isn't a concern:
  ```bash
  nmap -A -p- 127.0.0.1
  ```
