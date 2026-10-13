# Day 8 — Bonus: HTTP vs HTTPS

**Lab:** Cryptography & Hashing — Task 4 bonus (`day08-crypto`)
**Date:** 2026-10-13
**Environment:** Kali + Wireshark, capture file `pcaps/https_comparison.pcap`

---

## Objective

Compare traffic on port **80 (HTTP)** against port **443 (HTTPS)** in the same capture, and show what an attacker sniffing the network can and cannot read.

---

## Port 80 (HTTP) — plaintext

Filter: `tcp.port == 80`. Packet 1 (`192.168.1.100 → 93.184.216.34`) is fully readable. The HTTP layer shows everything in plaintext, and the hex/ASCII pane confirms it on the wire:

```
GET /page1 HTTP/1.1
Host: example.com
Cookie: session=mysecrettoken
```

The **session token is right there in the clear** — `session=mysecrettoken`.

## Port 443 (HTTPS) — encrypted

Follow TCP Stream (stream 5), `192.168.1.100 → :443`. The conversation is encrypted application data — unreadable ciphertext. Nothing about the request, the path, or the cookie can be recovered from the bytes.

---

## What can you read in each?

- **HTTP (80):** the full request — method, URL, host, headers, and the **session cookie in plaintext**.
- **HTTPS (443):** nothing useful — only encrypted bytes after the TLS handshake.

## Why does this matter?

On HTTP, the payload is unencrypted, so an adversary sniffing the network can read the session token directly. Once they have that token, they can **replay it to impersonate the user without ever knowing the username or password** — this is *session hijacking*, and it bypasses login and MFA entirely. (It's the same outcome as the XSS cookie theft from the Day 6 web-vulns lab, just stolen by sniffing instead of injected script.)

On HTTPS the token is encrypted in transit, so a sniffer captures only ciphertext and the session stays protected. This is exactly why every site that handles sessions or credentials must use HTTPS, and why session cookies should also carry the `Secure` flag so the browser never sends them over plain HTTP.

## Key takeaway

**HTTPS encrypts traffic; HTTP exposes everything in plaintext** — the Day 4 Wireshark lesson, seen again at the protocol level: readable session token on 80, encrypted gibberish on 443.
