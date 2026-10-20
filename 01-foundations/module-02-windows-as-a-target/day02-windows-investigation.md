# Day 2 — Windows Investigation (Blue Perspective)

**Lab:** Compromised Windows machine — process, persistence & C2 investigation
**Status:** ⚠️ Not performed on-device
**Date:** 2026-10-07

---

## Note on this entry

This lab requires a **Windows 10/11** host with **PowerShell (Run as Administrator)**. My primary device is a Mac, so I did not run the hands-on portion on my own machine and therefore have no terminal log or screenshots to record here.

This file exists to keep the day's record complete and to document *why* there's no walkthrough, rather than leaving a gap in the sequence.

## What the lab covered

For reference, the objective was to investigate a simulated post-compromise Windows host and work through four tasks:

1. **Identify the suspicious process** — spot a process that wasn't started by the user, with its name and PID.
2. **Find the persistence mechanism** — locate the attacker's scheduled task (what it runs, when it triggers).
3. **Investigate the attacker's files** — determine the C2 server, beacon interval, and directories being scanned.
4. **Find the hidden flag** — recover a flag concealed in the artifacts.

## Methodology I'd use (study notes)

The intended tooling was PowerShell, built around:

- `Get-CimInstance Win32_Process` — list processes **with command lines** (`Get-Process` alone omits these)
- `Get-ScheduledTask` — enumerate persistence via scheduled tasks
- `Get-Content` — read the attacker's scripts and log files
- `Select-String` — grep files for C2 domains, beacon intervals, and flag formats

## To-do if I get a Windows environment

Re-run this lab in a Windows VM (or a borrowed/loaner Windows host) and add the full walkthrough with command output, to bring this day in line with the others.
