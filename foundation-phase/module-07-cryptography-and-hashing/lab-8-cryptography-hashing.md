# Day 8 — Cryptography & Hashing

**Lab:** Hash cracking (`day08-crypto`)
**Date:** 2026-10-13
**Environment:** Kali + Python + hashcat, `rockyou.txt` wordlist
**Flag:** `CODED{shadow}`

> Note: the bootcamp slides label this "Day 7," but it's the `day08-crypto` lab folder (the Day 7 slot was command injection). Filed under day08 to match the folder and keep the repo one-file-per-lab. The HTTP vs HTTPS bonus is written up separately in `day08-http-vs-https-bonus.md`.

---

## Objective

Crack weak password hashes with a wordlist and identify an unknown hashing algorithm by its properties.

## Setup

```bash
cd ~/Desktop/Foundation\ Labs/day08-crypto
ls        # hash_demo.py  hashes  pcaps
```

---

## Task 1 — Explore Hashing

Ran the provided demo:

```bash
python hash_demo.py
```

Key behaviours observed:

- **Deterministic:** the same input always produces the same hash. `MD5('hello')` gave `5d41402abc4b2a76b9719d911017c592` on every attempt.
- **Fixed length per algorithm** (this is how you fingerprint an unknown hash):

| Algorithm | Output length | Status |
|-----------|---------------|--------|
| MD5 | 32 hex chars (128 bits) | **weak — do not use** |
| SHA-1 | 40 hex chars (160 bits) | **weak — do not use** |
| SHA-256 | 64 hex chars (256 bits) | currently secure |

- **Avalanche effect:** changing a single character changes the entire hash, unpredictably:
  ```
  SHA-256('password')  = 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
  SHA-256('Password')  = e7cf3ef4f17c3999a94f2c6f612e8a888e5b1026878e4e19398b23bd38ec221a
  ```
  One capital letter gives a completely different digest. (This is *why* you can't "work backwards" from a hash — there's no pattern between input and output.)
- **All of them are extremely fast** — and for password storage, that speed is the *problem*: fast hashing means an attacker can try billions of guesses per second.

---

## Task 2 — Crack the Hashes

The file `hashes/weak_hashes.txt` held 6 hashes. Counting characters: **five were 32 chars (MD5)** and **one was 64 chars (SHA-256)** — the odd one out, identified by length before cracking anything.

Cracked the five MD5s with hashcat mode `0` against rockyou:

```bash
hashcat -a 0 -m 0 weak_hashes.txt /usr/share/wordlists/rockyou.txt.gz
```

hashcat reported `Token length exception: 1/6 hashes` — it skipped the one 64-char hash (wrong length for MD5) and cracked the other five. Result: **5/5 (100%) recovered** in ~1 second.

| MD5 hash | Password |
|----------|----------|
| `5f4dcc3b5aa765d61d8327deb882cf99` | password |
| `e10adc3949ba59abbe56e057f20f883e` | 123456 |
| `d0763edaa9d9bd2a9516280e9044d885` | monkey |
| `0d107d09f5bbe40cade3de5c71e9e9b7` | letmein |
| `8621ffdbc5698829397d97767ac13db3` | dragon |

> That these fell in ~1 second is the whole point: MD5 is so fast that a 14-million-word list is exhausted almost instantly. All five were also common rockyou passwords, so no real password strength protected them either.

---

## Task 3 — The Odd One Out

The sixth hash was 64 hex characters → **SHA-256**. Cracked with mode `1400`:

```bash
hashcat -m 1400 -a 0 weak_hashes.txt /usr/share/wordlists/rockyou.txt.gz
```

(hashcat now skipped the five MD5s — `Token length exception: 5/6 hashes` — and cracked the single SHA-256.)

```
0bb09d80600eec3eb9d7793a6f859bedde2a2d83899b70bd78e961ed674b32f4 : shadow
```

### Flag

```
CODED{shadow}
```

**How the odd one was identified:** purely by output length. 32 hex = MD5, 40 = SHA-1, 64 = SHA-256. No guessing the algorithm — the length is the fingerprint. SHA-256 is cryptographically strong, but it's still **fast and unsalted here**, so a weak password (`shadow`, a top rockyou entry) falls just as fast as an MD5 one. A strong algorithm doesn't save a weak password.

---

## Task 5 — Think Like a Defender

**What is the difference between hashing and encryption?**
Hashing is **one-way**: input → fixed-length digest, with no key and no way to reverse it. You can only verify by hashing a guess and comparing. It's used for password storage and integrity checks. Encryption is **two-way**: plaintext → ciphertext using a key (symmetric with a shared key, or asymmetric with a key pair), and the right key turns it back into plaintext. It's used to protect data you need to read again later (like HTTPS traffic). Rule of thumb: passwords are *hashed* (you never need the original back — you just compare); messages and files in transit are *encrypted* (the recipient must recover the original).

**Why are some algorithms considered insecure for password storage?**
Two reasons. (1) **Speed** — MD5, SHA-1 and SHA-256 were designed to be *fast*, which is exactly what you don't want for passwords: a fast hash lets an attacker try billions of guesses per second (this lab cracked 5 MD5s in ~1 second). (2) **Broken algorithms** — MD5 and SHA-1 also have known *collision* weaknesses. Password hashing should be deliberately **slow** and memory-hard, which is what bcrypt/scrypt/argon2 are built for.

**What is salting and why does it matter?**
A **salt** is a random value added to each password before hashing, stored alongside the hash. It matters because:
- Identical passwords produce *different* hashes (two users with `password` won't share a digest), so you can't spot reused passwords.
- It defeats **precomputed attacks** — rainbow tables and shared online hash lookups are useless because the attacker would need a separate table per salt.
- Every hash in this lab was **unsalted**, which is why a wordlist cracked them instantly. Salting wouldn't have stopped `password`/`123456` from eventually falling, but it forces the attacker to attack each hash individually instead of all at once.

Modern best practice: **bcrypt or argon2**, which salt automatically and are intentionally slow.

---

## Key takeaways

- Hashing is **one-way** — you can't reverse it, only guess-and-compare (brute force / wordlist).
- **Hash length fingerprints the algorithm:** 32 hex = MD5, 40 = SHA-1, 64 = SHA-256.
- **MD5 is fast and broken** — never use it for passwords. Speed is the enemy for password hashing.
- A **strong algorithm doesn't save a weak password** — `shadow` (SHA-256) fell as fast as the MD5s because it's a common word and the hash was unsalted.
- **Salting** makes identical passwords hash differently and defeats rainbow tables / online lookups.
- Modern password storage uses **bcrypt/argon2** with automatic salting and deliberate slowness.

## Cleanup

No containers for this lab — nothing to tear down.
