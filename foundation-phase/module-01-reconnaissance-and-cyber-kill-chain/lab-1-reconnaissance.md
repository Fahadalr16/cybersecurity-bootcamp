# Lab 1 — Reconnaissance & The Cyber Kill Chain

## Overview

A hands-on reconnaissance lab against `scanme.nmap.org` (Nmap's official, authorised practice target). The goal: gather information about a target using DNS, HTTP, and port-scanning tools, then map those actions onto the Cyber Kill Chain.

## Tools Used

| Tool | What it does |
|---|---|
| **nslookup** | Asks a DNS server what IP address a domain name points to — quick and simple. Used to find the target's IP in Task 1. |
| **dig** | Same DNS lookups as nslookup but with more detailed, scriptable output; can query specific record types (A, MX, NS, TXT). |
| **curl** | Sends HTTP requests from the terminal and shows the raw response (status code, headers, body) — useful for fingerprinting web servers and testing endpoints. |

---

## Tasks

### Task 1 — Find the IPv4 address of `scanme.nmap.org`
**Answer:** `45.33.32.156`

### Task 2 — Identify the web server software (name only, not version)
**Answer:** Apache (`Apache/2.4.7`)

### Task 3 — Identify the operating system the web server runs on
**Answer:** Ubuntu

### Task 4 — Request a page that does not exist. What HTTP status code is returned?
**Answer:** `HTTP/1.1 404 Not Found`

### Task 5 — Classify the recon actions against the Cyber Kill Chain

- **DNS lookup** → Reconnaissance (passive): querying a public DNS server for target info without touching the target directly.
- **HTTP headers** → Reconnaissance (active): sending requests directly to the target, which may be logged.

Follow-up observations:

- The target could reduce the information exposed by serving over HTTPS (443), adding a layer of security around the data returned.
- Active recon can be noticed: requests to the target are logged, so the target could trace the traffic back to the source.
- As a defender, I would monitor the source IP and its activity for signs of malicious intent before taking further action.

### Task 6 — Submit the flag
**Answer:** `CODED{45.33.32.156_apache_Ubuntu}`

### Task 7 — Run an nmap service-version scan. What ports are open?

```
PORT      STATE  SERVICE
22/tcp    open   ssh
53/tcp    open   domain
80/tcp    open   http
2000/tcp  open   cisco-sccp
5060/tcp  open   sip
9929/tcp  open   nping-echo
```

The scan reveals services beyond the web server found through manual recon — nmap surfaces open ports (SSH, DNS, SIP, etc.) that HTTP fingerprinting alone would not have shown (nmap --open scanme.nmap.org).

---

## Reflection / Lessons Learned

- Passive recon (DNS) is quieter and harder to attribute than active recon (HTTP requests, port scans), which generate logs on the target.
- A single tool gives a partial picture; combining DNS, HTTP, and nmap builds a fuller map of the target's attack surface.
- From a defender's standpoint, this is exactly the early-stage activity worth detecting — unusual scanning against exposed ports is an early Kill Chain signal.
