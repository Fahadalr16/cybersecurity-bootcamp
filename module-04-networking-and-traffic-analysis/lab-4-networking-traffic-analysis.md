# Day 4 — Networking & Traffic Analysis

**Lab:** The 3-Part Flag Hunt (PCAP analysis in Wireshark)
**Date:** 2026-10-08
**Environment:** Kali + Wireshark, analysing `pcaps/http_credentials.pcap` (`day04-networking`)
**Flag:** `CODED{N3TW0RK_4N4LYSTS_PR0}`

---

## Objective

Analyse a packet capture and recover a flag split across **three protocol layers** — DNS, HTTP, and TCP — then assemble it. Bonus: extract the cleartext login credentials visible in the capture.

## Setup

```bash
cd ~/Desktop/Foundation\ Labs/day04-networking
./start.sh                       # brings up vuln-app, log-server, nginx-target
wireshark pcaps/http_credentials.pcap
```

Capture contains 73 packets across DNS, HTTP, TCP (including one non-standard-port conversation).

---

## The 3-part flag hunt

### Part 1 — DNS (TXT record)

**Filter:** `dns`

DNS is mostly `A` lookups for normal-looking domains (google.com, cdn.example.com, api.acmecorp.com), but the very first query stands out: a **TXT** lookup for `flag.coded.local`. Selecting the response (packet 2) and expanding **Domain Name System → Answers → flag.coded.local: type TXT** reveals:

```
TXT: part1=N3TW0RK
```

> **part1 = `N3TW0RK`**
> TXT records are meant for arbitrary text, which makes them a classic covert channel for smuggling data in/out over DNS — a protocol almost always allowed through firewalls.

### Part 2 — HTTP (custom response header)

**Filter:** `http`

Following the HTTP traffic, the server's `200 OK` response to the first `POST /login` (packet 15) carries a non-standard header. Expanding **Hypertext Transfer Protocol** shows:

```
X-Flag-Part: _4N4LY
```

> **part2 = `_4N4LY`**
> `X-` prefixed headers are custom/non-standard. Hiding data in a header means it never shows on the rendered page but travels in every response — invisible unless you inspect the actual traffic.

### Part 3 — TCP (C2 beacon on a non-standard port)

**Filter:** `tcp`

Most TCP is the HTTP conversation on port 80. Scrolling down, a separate conversation appears: `10.0.0.50 → 10.13.37.100` on **port 4444** (packets 65–73, highlighted pink). Port 4444 is a well-known default for Metasploit/reverse shells — an immediate red flag. Right-click a packet → **Follow → TCP Stream** (stream 7):

```
BEACON CHECK-IN: agent_id=0x4F2A status=active
ACK: tasking=enumerate flag_part3=STS_PR0 next_beacon=30s
EXFIL: user_count=5 hostname=ACME-WEB-01
```

> **part3 = `STS_PR0`**
> This is simulated **C2 (command-and-control)** traffic: a beacon checking in, receiving tasking, and exfiltrating host info — all in cleartext on a non-standard port.

### Assembled flag

```
part1 + part2 + part3
N3TW0RK + _4N4LY + STS_PR0
```

```
CODED{N3TW0RK_4N4LYSTS_PR0}
```

---

## Bonus — credential extraction

**Filter:** `http.request.method == "POST"` (or just `http` and look at the `POST /login` packets)

Three cleartext logins were captured as `application/x-www-form-urlencoded` POST bodies (frames 12, 20, 28). Expanding **HTML Form URL Encoded** shows the username/password fields in plaintext.

| # | Username | Password |
|---|----------|----------|
| 1 | admin | `SuperSecret123` |
| 2 | bob | `letmein` |
| 3 | alice | `password1` |

> **Analyst note — parsed value vs. raw bytes.** Wireshark's *HTML Form URL Encoded* view displayed each password one character short — `SuperSecret12`, `letmei`, `password` — because the `Content-Length` header under-counted the request body by one byte, so the form decoder stopped early. The **hex pane (bytes actually on the wire)** shows the full values in the table above: `...SuperSecret123`, `...letmein`, `...password1`. When the parsed view and the raw hex disagree, the hex is ground truth. An attacker sniffing the wire reads the raw bytes, not the declared length — so the real credentials are the full-length ones.

### Why is transmitting credentials over HTTP dangerous?

HTTP is unencrypted, so everything — including usernames and passwords — travels as plaintext. Anyone positioned to see the traffic (a compromised router, a rogue device on the LAN, an attacker doing ARP spoofing on the same network) can capture the packets and read the credentials with zero effort, exactly as done here in Wireshark. HTTPS (TLS) fixes this by encrypting the payload end-to-end, so a sniffer sees only ciphertext.

---

## Filters & techniques used

| Filter / action | What it did |
|-----------------|-------------|
| `dns` | Isolate DNS; spotted the odd TXT record for `flag.coded.local` |
| `http` | Isolate HTTP; found the `X-Flag-Part` custom header |
| `tcp` | Isolate TCP; spotted the port 4444 C2 conversation |
| `http.request.method == "POST"` | Narrow to login submissions for credential extraction |
| **Follow → TCP Stream** | Reconstruct a full conversation (the C2 beacon exchange) |
| Hex / bytes pane | Verify true payload when the parsed view looked off |

---

## Blue-team reflection

Every part of this flag maps to a real detection opportunity:

- **DNS TXT exfiltration** — a TXT query to a weird internal name like `flag.coded.local` is abnormal. Baselining DNS and alerting on TXT queries / high-entropy or unusual domains catches data smuggled over DNS.
- **Suspicious HTTP headers** — custom `X-` headers carrying odd data, and cleartext logins over port 80, are both visible to any inline inspection (IDS, proxy). The real fix is forcing HTTPS so credentials aren't exposed in the first place.
- **C2 on a non-standard port** — an outbound connection to `10.13.37.100:4444` from an internal host is a textbook beacon. A server with no business reason for outbound connections making one is a high-priority alert; `4444` specifically should ring alarms.

**Takeaway:** cleartext protocols (HTTP, FTP, Telnet) expose everything to anyone watching the wire, and attackers lean on trusted protocols (DNS) and odd ports (4444) precisely because they often slip past monitoring. The defence is encryption in transit plus a baseline of "normal" so the abnormal stands out.

## Cleanup

```bash
./stop.sh
```
