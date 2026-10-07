# Day 3 — Linux CLI & the Attacker's Toolkit

**Lab:** Linux CLI Scavenger Hunt (SSH target)
**Date:** 2026-10-07
**Environment:** Kali attacker box → Dockerised SSH target (`day03-kali`)
**Flag:** `CODED{ssh_3xpl0r3r}`

---

## Objective

Connect to a remote Linux target over SSH and follow a trail of planted clues to a hidden flag. Each clue is designed to require a different CLI technique — directory navigation, reading files, revealing hidden files, and decoding Base64.

## Target

| Field | Value |
|-------|-------|
| Host | `localhost` |
| Port | `2222` |
| User | `student` |
| Auth | password (`student123`) |

Lab brought up with `./start.sh`, which builds an Alpine-based SSH container and a web target, then exposes SSH on `2222` and HTTP on `8080`.

---

## Walkthrough

### 1. Connect over SSH

```bash
ssh student@localhost -p 2222
```

First connect prompts to trust the host's ED25519 key fingerprint (`yes`), which adds it to `~/.ssh/known_hosts`. Landed on the target as `student`.

```bash
whoami      # student
pwd         # /home/student
```

### 2. Explore the home directory

```bash
ls                 # documents
cd documents/
ls -l              # mission.txt, notes.txt
```

```bash
cat notes.txt
```

`notes.txt` held internal "do not share" loot — an admin portal URL (`http://10.0.0.5:8080/admin`) and a DB password (`Pr0d_DB_2024!`). Not needed for the flag, but exactly the kind of hardcoded-credentials-in-a-file find an attacker looks for.

```bash
cat mission.txt
```

Mission brief plus the first real hint:

> HINT: System administrators keep logs in `/var/log/`
> But not all files are visible with a regular `ls`...

The clue is doing two jobs: pointing at `/var/log`, and flagging that **hidden files** (dotfiles) are in play.

### 3. Reveal the hidden log

```bash
cd /var/log/
ls -l       # total 0  <- nothing visible
ls -la      # .audit_trail.log appears
```

This is the key CLI lesson of the lab: `ls` hides anything starting with `.`. Adding `-a` (all) exposes the dotfile. `-l` gives the long format (permissions, owner, size, date).

```bash
cat .audit_trail.log
```

The log planted the next pointer:

```
[2024-06-10 08:14:02] ALERT: encoded backup detected at /tmp/.backup/credentials.b64
```

### 4. Follow the trail into /tmp

```bash
cd /tmp/
ls -la              # .backup/ directory
cd .backup/
ls -al              # credentials.b64
cat credentials.b64
```

`/tmp` being the drop site is on-theme — it's world-writable (`drwxrwxrwt`, note the sticky-bit `t`) and the classic attacker staging area. The file was Base64:

```
TmljZSBkZWNvZGluZyEgVGhlIGZsYWcgaXMgaGlkZGVuIGluIC9vcHQvIC0tIHVzZSB0aGUgZmluZCBjb21tYW5kIHRvIGxvY2F0ZSBpdC4=
```

### 5. Decode the Base64

`cat` only shows the encoded blob — it has to be decoded:

```bash
base64 -d credentials.b64
# or
cat credentials.b64 | base64 -d
```

Output:

> Nice decoding! The flag is hidden in `/opt/` -- use the `find` command to locate it.

### 6. Locate and read the flag

```bash
cd /opt/
ls -al              # .secret/ directory
cat /opt/.secret/flag.txt
```

```
CODED{ssh_3xpl0r3r}
```

### 7. Cleanup

```bash
exit          # close the SSH session
./stop.sh     # tear down the containers
```

---

## Commands learned / reinforced

| Command | What it did here |
|---------|------------------|
| `ssh user@host -p <port>` | Connect to a remote host on a non-default port |
| `whoami` / `pwd` | Confirm current user and location after landing |
| `ls -l` | Long listing: permissions, owner, size, timestamp |
| `ls -la` | **Also show hidden dotfiles** — the crux of this lab |
| `cd`, `cat` | Navigate and read files |
| `base64 -d` | Decode a Base64-encoded file |
| `find /opt -type f` | Locate files when you only know the directory |

---

## The clue chain

```
home (mission.txt) → /var/log/.audit_trail.log → /tmp/.backup/credentials.b64
  → base64 decode → /opt/.secret/flag.txt → CODED{ssh_3xpl0r3r}
```

Every hop depended on knowing that a `.`-prefixed file is hidden from plain `ls`. Miss `-a` and the trail goes cold at step one.

---

## Blue-team reflection

Running this from the defender's seat, each attacker action leaves a signal worth detecting:

- **Reading hidden files in `/var/log`** — file-access auditing (auditd) on the log directory would catch an unexpected read of `.audit_trail.log` by a non-root user.
- **Activity in `/tmp/.backup`** — `/tmp` is world-writable and rarely monitored, which is exactly why it's a staging favourite. A new executable or dotfile here should alert.
- **Credentials in cleartext files** (`notes.txt`, the Base64 blob) — secrets sitting in `/home` and `/tmp` are a finding in themselves; real systems should keep them out of readable files and rotate anything exposed.

**Detection gap takeaway:** without auditd rules on `/var/log`, `/tmp`, and `/opt`, none of these reads would have generated a single alert.
