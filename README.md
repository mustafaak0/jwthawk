# 🔑 JWTHawk

> JWT security auditor — alg=none forgeries, cracked HMAC secrets, tampered claims, kid injection probes and secrets riding in payloads. Zero dependencies, pure Python stdlib.

[![Python](https://img.shields.io/badge/Python-3.8%2B-0D1117?style=for-the-badge&logo=python&logoColor=3776AB)](https://python.org)
[![Dependencies](https://img.shields.io/badge/Dependencies-0-00E676?style=for-the-badge&labelColor=0D1117)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-0D1117?style=for-the-badge&logoColor=00E676)](LICENSE)
[![Author](https://img.shields.io/badge/Author-mustafaak0-0D1117?style=for-the-badge&logo=github&logoColor=00E676)](https://github.com/mustafaak0)

No PyJWT, no `cryptography` — JWTHawk cracks HMAC secrets with `hmac`,
verifies RS256/384/512 with hand-rolled **RSA PKCS#1 v1.5 math**
(`EM = 00 01 FF..FF 00 || DigestInfo`, byte-for-byte), and even the demo's
signing keys come from a pure-stdlib Miller-Rabin keygen. The crypto *is*
the product.

## 🎯 Detections

| Finding | Logic | FP defense |
|---------|-------|------------|
| 🔓 **alg=none** | two-part form or `alg: none` (any case) | unsigned tokens flagged when the header *admits* it |
| 🗝️ **weak HMAC secret** | 116-candidate built-in wordlist (jwt.io's `your-256-bit-secret`, dev defaults, TR favourites) — bring rockyou via `--wordlist` | candidate must reproduce the MAC byte-for-byte, constant-time compare |
| ✍️ **tampered claims** | signature ≠ claims, against cracked secret, `--secret`, or JWKS key | only claimed when a key is *actually known* |
| 💉 **kid injection** | quote+operator SQLi, `../` traversal, `%00`, `{{7*7}}` SSTI markers | needs a marker *combo*, not any odd string; legit key IDs pass |
| 🌐 **jku / x5u SSRF bait** | header key-URL the verifier would fetch | reported as attack surface — presence, not exploitation |
| 🔀 **alg confusion** | `HS*` signature **and** `x5c`/`jwk` embedded in the same header | both signals together; either alone isn't flagged |
| ⏳ **expiry hygiene** | expired · no `exp` · 7d/30d+ lifetimes · future `nbf`/`iat` | 300s clock-skew tolerance (RFC 7519 §4.1) |
| 💳 **sensitive claims** | credential-shaped keys + **Luhn-validated** PANs (13–19 digits) | card numbers must pass the checksum; masked in output |
| ❓ **unknown alg** | anything outside the JWS standard set | explicit allowlist, typos like `HSa256` caught |

## 🚀 Usage

```bash
# offline demo: 12 synthetic tokens, planted findings, self-checking
python jwthawk.py --demo

# audit one token (or @file with one token per line)
python jwthawk.py "eyJhbGciOi..."

# wordlist attack on the HMAC secret (built-in + your own list)
python jwthawk.py "$TOKEN" --crack --wordlist rockyou.txt

# verify against a known secret / a JWKS (URL or @file)
python jwthawk.py "$TOKEN" --secret "our-real-key"
python jwthawk.py "$TOKEN" --jwks https://sso.example/.well-known/jwks.json

# pretty-print header & payload only
python jwthawk.py "$TOKEN" --decode
```

```
╭─ JWTHawk ───────────────────────────────────────────────────
│ token    : weak-secret
│ alg      : HS256 · typ JWT
│ subject  : admin · role admin
│ lifetime : iat 2025-12-16 18:46 → exp 2025-12-16 20:46
│ signature: verified with secret "secret123"
│
│ ● [WEAK-SECRET] HMAC secret cracked  →  85/100
│   secret = "secret123" (wordlist hit #3, 9 chars) — any reader of
│   this token can mint admin claims
│ verdict  : INSECURE · score 75/100 · grade B
╰──────────────────────────────────────────────────────────────
```

Exit codes: `0` no HIGH/CRIT · `1` HIGH/CRIT found (CI-ready) · `2` usage
error. Scores follow the house model: CRIT40 / HIGH25 / MED12 / LOW5 off
a 100 baseline, grades A–F, verdicts CLEAN → REVIEW → SUSPICIOUS →
INSECURE. `--json FILE` for machine-readable reports.

## 🧪 Verified on Synthetic Tokens

`--demo` plants 12 findings across ten attack tokens — alg=none,
crackable secret, post-signing rewrite, kid SQLi, jku SSRF bait,
RS256→HS256 confusion probe, password + Luhn-valid card in claims,
no-expiry, long-expired, JWKS-verified RSA forgery — plus two clean
tokens (one HS, one RSA) as false-positive traps. Self-check result:
**12/12 caught, 0 false positives, both clean tokens stayed clean**.

The demo runs the exact production code path. The RSA tokens are signed
by an on-the-fly 2048-bit keypair generated with a pure-stdlib
Miller-Rabin (`secrets.randbits` candidates, 24 witnesses), and the
tampered one is produced by rewriting the payload *after* signing —
so a passing verify/fail pair exercises the real PKCS#1 comparison.

## 🧠 How the Crypto Works (no libraries!)

```
HMAC    : secret hunt = hmac.new(word, "h.p", sha256) == sig
          compared with hmac.compare_digest — constant time
RS*     : EM = pow(sig_int, e, n) → 00 01 FF×k FF 00 || DigestInfo
          DigestInfo prefixes hardcoded per hash (sha256/384/512),
          ≥8 padding bytes enforced, big-endian JWK n/e decoded from
          base64url — no ASN.1 parser, no X.509, no dependencies
keygen  : demo keys = 2×1024-bit primes, Miller-Rabin ×24 rounds,
          d = e⁻¹ mod φ(n)  — all in ~30 lines of integer math
```

## 🔭 Roadmap

- [ ] ES256 verification with hand-rolled P-256 point math
- [ ] JWKS kid allowlist / pinning mode for CI gates
- [ ] strict base64url audit (trailing bits, non-canonical padding)
- [ ] PS* (RSA-PSS) verification

## ⚖️ Disclaimer

For tokens from systems **you are authorized to assess**.
Auth responsibly.

---

<div align="center">

*A leaked secret doesn't need to be stolen twice.*

</div>
