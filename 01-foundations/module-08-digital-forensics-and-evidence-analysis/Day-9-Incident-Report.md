# Day 8 — Incident Report

```
INCIDENT REPORT
===============

Date of Investigation: Oct 14 2026
Analyst Name: Fahad AlAbdulrazzaq

ATTACKER INFORMATION
  IP Address: 10.13.37.42
  Tools Used: sqlmap 1.7; WindowsUpdateHelper v2.1 (svc_update.exe), disguised as report.pdf;
		built in Windows recon tools (ipconfig, net, nltest)

ATTACK TIMELINE
  First Activity:   2026-03-15 14:25:00 ; Failed to logon as administrator (Event4625), start of
			windows brute force.
  Last Activity:    2026-03-15 15:15:20 UTS ; Path traversal attempt for /etc/passwd (blocked, 403)

ATTACK METHODS (list all observed)
  1. Brute force -> against Windows Administrator and admin portal's admin
  2. Privilege escalation
  3. SQL injection
  4. Data exfiltration
  5. Persistence -> malicious service WindowsUpdateHelper (auto start, SYSTEM) & created API key
  6. Masquerading -> executable disguised as report.pdf
  7. Path traversal -> (blocked, 403)

EVIDENCE SUMMARY
  - Suspicious web requests:  31
  - Failed login attempts:    131 (120 admin portal, 15 Windows)
  - Successful attacker logins: 2 (1 admin portal, 1 Windows)
  - Services installed:       1 (WindowsUpdateHelper -> C:\Temp\svc_update.exe)

IMPACT
  - Data accessed: Full database export and user list (admin portal); domain users and
			domain controllers (Windows)
  - Persistence:   WindowsUpdateHelper (auto start, survives reboot) ; API key created
			in admin portal (survives password reset)

RECOMMENDATIONS
  1. Stop brute force: add MFA and limited attempts
  2. Block malicious IP addresses through IDS and firewalls
```
