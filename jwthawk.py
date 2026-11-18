#!/usr/bin/env python3
"""
JWTHawk — JWT security auditor. Zero dependencies, pure Python stdlib.

Decodes a token, cracks weak HMAC secrets, verifies RSA signatures by
hand-rolled PKCS#1 v1.5 math (no PyJWT, no `cryptography`), and grades
what it finds like a pentester reading someone's auth flow:

  - alg=none / unsigned tokens    (the classic forgery)
  - weak HMAC secrets             (built-in wordlist, bring your own)
  - tampered payloads             (signature ≠ claims — forged token)
  - kid injection probes          (SQLi / SSTI / traversal in key IDs)
  - jku / x5u key-URL SSRF bait   (external key fetch = substitution risk)
  - algorithm confusion bait      (HS* alg + embedded x5c/jwk key)
  - expiry hygiene                (expired, missing exp, month-long lives)
  - sensitive claims              (passwords & Luhn-valid card numbers)

For tokens from systems you are authorized to assess. Auth responsibly.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import re
import secrets
import sys
import time
from dataclasses import dataclass, field

__version__ = "1.0.0"

# --------------------------------------------------------------------------
# constants / knowledge bases
# --------------------------------------------------------------------------

HS_ALGS = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}
RSA_ALGS = {"RS256": "sha256", "RS384": "sha384", "RS512": "sha512"}
KNOWN_ALGS = HS_ALGS.keys() | RSA_ALGS.keys() | {
    "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA", "none",
}

# CRIT40 / HIGH25 / MED12 / LOW5 → 0-100 score, A–F, house style
SEV_WEIGHT = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 12, "LOW": 5}
GRADE_BANDS = ((90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F"))

CLOCK_SKEW = 300          # seconds of future-timestamp tolerance (RFC 7519 §4.1)
LONG_LIFE_DAYS = 7        # exp-iat beyond this is a hygiene finding
VERY_LONG_LIFE_DAYS = 30  # ... and beyond this it gets worse
PAN_MIN, PAN_MAX = 13, 19  # plausible card-number length (Luhn decides)

# HMAC secret wordlist: the defaults real deployments actually ship, plus a
# few Turkish favourites (house tradition). Kept short & high-yield; bring
# rockyou with --wordlist.
WEAK_SECRETS = (
    "secret secret1 secret123 secrets secretkey secret_key jwt_secret "
    "jwtsecret supersecret super_secret mysecret my_secret your-256-bit-secret "
    "your_jwt_secret the_secret thesecret key keys mykey my_key api_key token "
    "tokensecret sign signing signing_key signingkey private privatekey "
    "private_key password password1 password123 pa55word changeme change_me "
    "default default_secret test test123 dev development dev_secret staging "
    "production prod secret! s3cr3t s3cr3t_k3y abc123 123456 1234567 "
    "12345678 123456789 1234567890 qwerty qwerty123 letmein welcome admin "
    "admin123 root toor iloveyou monkey dragon football baseball sunshine "
    "princess shadow master hello helloworld trustno1 whatever freedom "
    "asdfgh zxcvbn 1q2w3e4r qwe123 aa12345666 mustafa mustafa123 musti "
    "sifre sifre123 parola parola123 gizli gizlianahtar 1907 19071907 "
    "ankara istanbul 3434 1234 0000 1111 121212 666666 888888 "
    "jwt key-in-deploys-we-trust hunter2 trustme dontsharethis topsecret "
    "shhhh keyboard eniwtpo ivany tsolbr itsasecret opensesame sesame "
).split()

# claim keys that should never carry a live value inside a bearer token
SENSITIVE_KEY_RE = re.compile(
    r"pass(word)?|passwd|pwd|secret|api[_-]?key|private[_-]?key|"
    r"access[_-]?key|ssn|credit[_-]?card|card[_-]?num|^token$", re.I)

# kid values that smell like an injection probe, not a key selector
KID_SQLI_RE = re.compile(r"('|%27).*(or |1=1|--|#|;)", re.I)
KID_TRAVERSAL_RE = re.compile(r"(\.\./|\.\.%2f|%2e%2e|%00|\\x00)", re.I)
KID_SSTI_RE = re.compile(r"\{\{.*\}\}|\$\{.*\}")

# PKCS#1 v1.5 DigestInfo prefixes — verified byte-for-byte, no ASN.1 lib
DIGEST_INFO = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


class JwtError(Exception):
    """unrecoverable input problem (usage error, exit 2)."""


# --------------------------------------------------------------------------
# data types
# --------------------------------------------------------------------------

@dataclass
class Finding:
    tag: str
    title: str
    detail: str
    sev: str            # CRITICAL / HIGH / MEDIUM / LOW
    score: int          # 0-100, house-style confidence


@dataclass
class Report:
    label: str
    alg: str = ""
    typ: str = ""
    kid: str = ""
    header_extra: list = field(default_factory=list)   # jku/x5u/x5c/jwk notes
    header: dict = field(default_factory=dict)
    payload: dict = field(default_factory=dict)
    sig_note: str = ""                                 # signature verdict line
    secret: str = ""                                   # cracked/known secret
    findings: list = field(default_factory=list)

    @property
    def score(self) -> int:
        return max(0, 100 - sum(SEV_WEIGHT[f.sev] for f in self.findings))

    @property
    def grade(self) -> str:
        for floor, letter in GRADE_BANDS:
            if self.score >= floor:
                return letter
        return "F"

    @property
    def verdict(self) -> str:
        sevs = {f.sev for f in self.findings}
        if sevs & {"CRITICAL", "HIGH"}:
            return "INSECURE"
        if "MEDIUM" in sevs:
            return "SUSPICIOUS"
        if "LOW" in sevs:
            return "REVIEW"
        return "CLEAN"


# --------------------------------------------------------------------------
# JWS primitives — base64url, HMAC, hand-rolled RSA PKCS#1 v1.5
# --------------------------------------------------------------------------

def b64u_dec(seg: str) -> bytes:
    if re.search(r"[^A-Za-z0-9_\-=]", seg):
        raise JwtError("segment has non-base64url characters")
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def b64u_enc(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def split_token(token: str):
    parts = token.strip().split(".")
    if len(parts) == 2:                     # header.payload — unsigned form
        return parts[0], parts[1], ""
    if len(parts) != 3:
        raise JwtError("expected header.payload.signature (3 parts)")
    return parts


def hs_sign(alg: str, signing_input: str, secret: str) -> bytes:
    return hmac.new(secret.encode(), signing_input.encode("ascii"),
                    HS_ALGS[alg]).digest()


def rsa_pkcs1v15_verify(n: int, e: int, sig: bytes, msg: bytes,
                        hash_name: str) -> bool:
    """Textbook RS* verification: EM = 0x00 01 FF..FF 00 || DigestInfo."""
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    m = int.from_bytes(sig, "big")
    if m >= n:
        return False
    em = pow(m, e, n).to_bytes(k, "big")
    t = DIGEST_INFO[hash_name] + hashlib.new(hash_name, msg).digest()
    pad = k - len(t) - 3
    if pad < 8:                              # PKCS#1 demands ≥8 padding bytes
        return False
    return hmac.compare_digest(em, b"\x00\x01" + b"\xff" * pad + b"\x00" + t)


def jwks_rsa_key(jwks: dict, kid: str):
    """pick the RSA JWK matching kid (or the only key) → (n, e, kid_used)"""
    try:
        keys = jwks["keys"]
    except (TypeError, KeyError):
        raise JwtError("JWKS must be a {\"keys\": [...]} object")
    candidates = [k for k in keys if k.get("kty") == "RSA"]
    if kid:
        candidates = [k for k in candidates if k.get("kid") == kid] or \
                     [k for k in keys if k.get("kid") == kid]
    if not candidates:
        raise JwtError(f"no JWK matches kid {kid!r}")
    jwk = candidates[0]
    try:
        n = int.from_bytes(b64u_dec(jwk["n"]), "big")
        e = int.from_bytes(b64u_dec(jwk["e"]), "big")
    except KeyError:
        raise JwtError("RSA JWK missing n/e modulus fields")
    return n, e, jwk.get("kid", "")


def fetch_jwks(url: str) -> dict:
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=10) as r:   # nosec: user URL
            return json.loads(r.read().decode("utf-8"))
    except Exception as exc:
        raise JwtError(f"JWKS fetch failed: {exc}")


# --------------------------------------------------------------------------
# secret cracking — wordlist HMAC, constant-time compares
# --------------------------------------------------------------------------

def crack_secret(alg: str, signing_input: str, sig_b64: str, words,
                 deadline_s: float = 60.0):
    """try each word as the HMAC key; → (secret, index) or None."""
    try:
        sig = b64u_dec(sig_b64)
    except JwtError:
        return None
    start = time.monotonic()
    for i, word in enumerate(words, 1):
        if hmac.compare_digest(hs_sign(alg, signing_input, word), sig):
            return word, i
        if time.monotonic() - start > deadline_s:
            break
    return None


# --------------------------------------------------------------------------
# analysis
# --------------------------------------------------------------------------

def _num(claims: dict, name: str):
    v = claims.get(name)
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def _humanize_days(seconds: float) -> str:
    days = seconds / 86400
    for unit, size in (("year", 365), ("month", 30), ("day", 1)):
        if abs(days) >= size:
            n = int(abs(days) // size)
            return f"{n} {unit}{'s' if n != 1 else ''}"
    return "moments"


def _scan_sensitive(claims: dict):
    """→ (sensitive keys, Luhn-valid PAN strings) from top level + 1 nested"""
    keys, pans = [], []

    def visit(obj, depth=0):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    visit(v, depth + 1)
                elif v not in (None, "", False) and SENSITIVE_KEY_RE.search(k):
                    keys.append(k)
                elif isinstance(v, (str, int)):
                    _pan(v, pans)
        elif isinstance(obj, list):
            for v in obj:
                visit(v, depth + 1)

    def _pan(v, out):
        s = str(v)
        for chunk in re.findall(r"[\d \-]{13,23}", s):
            digits = re.sub(r"[ \-]", "", chunk)
            if PAN_MIN <= len(digits) <= PAN_MAX and digits.isdigit() \
                    and len(set(digits)) > 1 and _luhn_ok(digits):
                out.append(digits)

    visit(claims)
    return keys, pans


def audit(token: str, label: str = "token", secret: str = None,
          jwks: dict = None, words=None, now: float = None) -> Report:
    rep = Report(label=label)
    now = time.time() if now is None else now

    try:
        h_b64, p_b64, s_b64 = split_token(token)
    except JwtError as exc:
        rep.findings.append(Finding(
            "MALFORMED", "token structure broken", str(exc), "CRITICAL", 100))
        return rep

    # ---- decode header / payload (decode failures are findings, not exits)
    for name, seg, dest in (("header", h_b64, "header"),
                            ("payload", p_b64, "payload")):
        try:
            obj = json.loads(b64u_dec(seg).decode("utf-8"))
            if not isinstance(obj, dict):
                raise ValueError(f"{name} is not a JSON object")
            setattr(rep, dest, obj)
        except (JwtError, ValueError, UnicodeDecodeError) as exc:
            rep.findings.append(Finding(
                "MALFORMED", f"{name} undecodable", str(exc), "CRITICAL", 100))
    if rep.findings:
        return rep

    alg = str(rep.header.get("alg", ""))
    rep.alg, rep.typ = alg, str(rep.header.get("typ", ""))
    kid = rep.header.get("kid")
    rep.kid = kid if isinstance(kid, str) else ""
    signing_input = f"{h_b64}.{p_b64}"

    # ---- alg checks ------------------------------------------------------
    if not alg or alg.lower() == "none":
        rep.findings.append(Finding(
            "ALG-NONE", "alg=none — unsigned token", 
            "no signature at all: anyone can forge the claims; "
            "reject unless the token is intentionally opaque",
            "CRITICAL", 100))
    elif alg not in KNOWN_ALGS:
        rep.findings.append(Finding(
            "UNKNOWN-ALG", f"unrecognized alg {alg!r}",
            "not a JWS-standard algorithm name — typo, or a probe for "
            "parser fallback bugs (CVE-2016-10555 class)", "MEDIUM", 60))

    # ---- kid / key-location hygiene --------------------------------------
    if rep.kid:
        if KID_SQLI_RE.search(rep.kid) or KID_TRAVERSAL_RE.search(rep.kid) \
                or KID_SSTI_RE.search(rep.kid):
            rep.findings.append(Finding(
                "KID-INJECTION", "kid looks like an injection probe",
                f"kid={rep.kid!r} — SQLi/SSTI/path-traversal markers; if the "
                "verifier feeds kid to a query, template or path, it's owned",
                "CRITICAL", 95))
        if len(rep.kid) > 128:
            rep.findings.append(Finding(
                "KID-BLOAT", "oversized kid",
                f"{len(rep.kid)} chars — clogs key caches; also a classic "
                "hash-oracle padding oracle when kid is hashed", "LOW", 20))

    for param in ("jku", "x5u"):
        url = rep.header.get(param)
        if isinstance(url, str) and url:
            rep.header_extra.append(f"{param}={url}")
            rep.findings.append(Finding(
                "KEY-URL-SSRF", f"{param} points outside the token",
                f"{url!r} — verifier fetches keys from this URL; attacker-"
                "controlled jku/x5u = signature substitution + SSRF",
                "HIGH", 75))

    embedded = ("x5c" in rep.header) or ("jwk" in rep.header)
    if embedded:
        rep.header_extra.append("x5c/jwk in header")
    if alg in HS_ALGS and embedded:
        rep.findings.append(Finding(
            "ALG-CONFUSION", "symmetric alg + embedded public key",
            "HS* signature with x5c/jwk key material in the header — the "
            "classic RS256→HS256 confusion probe if the verifier re-parses "
            "the key", "HIGH", 80))

    # ---- signature verification ------------------------------------------
    if alg in HS_ALGS and s_b64:
        known = secret
        if known is None:
            hit = crack_secret(alg, signing_input, s_b64,
                               words if words is not None else WEAK_SECRETS)
            if hit:
                known, rank = hit
                sev = "CRITICAL" if len(known) < 8 else "HIGH"
                rep.findings.append(Finding(
                    "WEAK-SECRET", "HMAC secret cracked",
                    f'secret = "{known}" (wordlist hit #{rank}, '
                    f"{len(known)} chars) — any reader of this token can "
                    "mint admin claims", sev,
                    90 if sev == "CRITICAL" else 85))
        rep.secret = known or ""
        if known:
            if hmac.compare_digest(hs_sign(alg, signing_input, known),
                                   b64u_dec(s_b64)):
                rep.sig_note = f'verified with secret "{known}"'
            else:
                rep.findings.append(Finding(
                    "TAMPERED", "signature does not match the claims",
                    f'HMAC fails against known secret "{known}" — payload '
                    "was rewritten after signing (or secret rotated)",
                    "CRITICAL", 100))
                rep.sig_note = "claims rewritten after signing"
        else:
            rep.sig_note = "HMAC intact, secret resisted the wordlist"
    elif alg in RSA_ALGS and s_b64:
        if jwks is not None:
            try:
                n, e, kid_used = jwks_rsa_key(jwks, rep.kid)
                if rsa_pkcs1v15_verify(n, e, b64u_dec(s_b64),
                                       signing_input.encode("ascii"),
                                       RSA_ALGS[alg]):
                    rep.sig_note = f"RSA verified via JWKS kid {kid_used!r}"
                else:
                    rep.findings.append(Finding(
                        "TAMPERED", "RSA signature invalid",
                        "PKCS#1 v1.5 padding or digest mismatch against the "
                        "JWKS key — forged or corrupted token",
                        "CRITICAL", 100))
                    rep.sig_note = "RSA verify FAILED"
            except JwtError as exc:
                rep.sig_note = f"JWKS problem: {exc}"
        else:
            rep.sig_note = "asymmetric — pass --jwks to verify"

    # ---- time-claim hygiene ------------------------------------------------
    exp, iat = _num(rep.payload, "exp"), _num(rep.payload, "iat")
    nbf = _num(rep.payload, "nbf")
    if exp is not None:
        if exp <= now:
            rep.findings.append(Finding(
                "EXPIRED", "token expired",
                f"exp was {_humanize_days(now - exp)} ago — anything still "
                "accepting it has no clock check at all", "MEDIUM", 40))
        elif iat is not None and exp > iat:
            life_d = (exp - iat) / 86400
            if life_d >= VERY_LONG_LIFE_DAYS:
                rep.findings.append(Finding(
                    "LONG-LIVED", "absurdly long-lived token",
                    f"lifetime {_humanize_days(exp - iat)} — a stolen token "
                    "stays valuable for weeks", "HIGH", 45))
            elif life_d >= LONG_LIFE_DAYS:
                rep.findings.append(Finding(
                    "LONG-LIVED", "long-lived token",
                    f"lifetime {_humanize_days(exp - iat)} — prefer short "
                    "access tokens + refresh", "MEDIUM", 30))
    else:
        rep.findings.append(Finding(
            "NO-EXPIRY", "no exp claim",
            "token never expires: leak once, valid forever", "MEDIUM", 50))
    if nbf is not None and nbf > now + CLOCK_SKEW:
        rep.findings.append(Finding(
            "NBF-FUTURE", "not-yet-valid token",
            f"nbf is {_humanize_days(nbf - now)} in the future — clock skew "
            "or a frozen-verification probe", "MEDIUM", 45))
    if iat is not None and iat > now + CLOCK_SKEW:
        rep.findings.append(Finding(
            "IAT-FUTURE", "issued in the future",
            f"iat is {_humanize_days(iat - now)} ahead — minted on a "
            "mis-set clock", "LOW", 25))

    missing = [c for c in ("iat", "iss", "aud", "jti")
               if c not in rep.payload]
    if missing:
        rep.findings.append(Finding(
            "MISSING-CLAIMS", "standard claims absent",
            f"missing {', '.join(missing)} — weaker audience binding / "
            "replay story", "LOW", 10))

    # ---- sensitive payload --------------------------------------------------
    s_keys, pans = _scan_sensitive(rep.payload)
    if s_keys:
        rep.findings.append(Finding(
            "SENSITIVE-CLAIMS", "secrets riding inside the token",
            f"claim keys: {', '.join(sorted(set(s_keys)))} — tokens get "
            "logged and cached; keep credentials out of the payload",
            "HIGH", 80))
    if pans:
        masked = ", ".join(p[:4] + "*" * (len(p) - 8) + p[-4:] for p in pans)
        rep.findings.append(Finding(
            "PAN-IN-CLAIMS", "Luhn-valid card number in claims",
            f"card-shaped values: {masked} — PCI scope in a bearer token",
            "HIGH", 85))

    return rep


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

def _ts(claims: dict, name: str, now: float) -> str:
    v = _num(claims, name)
    if v is None:
        return "—"
    import datetime
    t = datetime.datetime.fromtimestamp(v).strftime("%Y-%m-%d %H:%M")
    if name == "exp":
        tail = _humanize_days(abs(v - now))
        return f"{t} (in {tail})" if v > now else f"{t} ({tail} ago)"
    return t


def render(rep: Report, now: float = None, out=print):
    now = time.time() if now is None else now
    out(f"╭─ JWTHawk ─{'─' * 50}")
    out(f"│ token    : {rep.label}")
    out(f"│ alg      : {rep.alg or '?'}"
        + (f" · typ {rep.typ}" if rep.typ else "")
        + (f' · kid "{rep.kid}"' if rep.kid else ""))
    if rep.header_extra:
        out(f"│ header   : {' · '.join(rep.header_extra)}")
    p = rep.payload
    who = p.get("sub") or p.get("client_id") or "?"
    out(f"│ subject  : {who}"
        + (f" · role {p['role']}" if isinstance(p.get("role"), str) else ""))
    out(f"│ lifetime : iat {_ts(p, 'iat', now)} → exp {_ts(p, 'exp', now)}")
    if rep.sig_note:
        out(f"│ signature: {rep.sig_note}")
    out("│")
    if not rep.findings:
        out("│ ✔ no findings — token looks tidy")
    for f in rep.findings:
        bullet = "●" if f.sev in ("CRITICAL", "HIGH") else "○"
        out(f"│ {bullet} [{f.tag}] {f.title}  →  {f.score}/100")
        out(f"│   {f.detail}")
    out(f"│ verdict  : {rep.verdict} · score {rep.score}/100 · "
        f"grade {rep.grade}")
    out(f"╰{'─' * 60}")


def report_json(reps) -> dict:
    if not isinstance(reps, list):
        reps = [reps]
    return {
        "tool": "jwthawk", "version": __version__,
        "tokens": [{
            "label": r.label, "alg": r.alg, "kid": r.kid,
            "header": r.header, "payload": r.payload,
            "signature": r.sig_note, "secret": r.secret,
            "findings": [{"tag": f.tag, "title": f.title, "detail": f.detail,
                          "severity": f.sev, "score": f.score}
                         for f in r.findings],
            "score": r.score, "grade": r.grade, "verdict": r.verdict,
        } for r in reps],
    }


# --------------------------------------------------------------------------
# offline demo — synthetic tokens, planted findings, self-check
# --------------------------------------------------------------------------

DEMO_STRONG = "Zx7$vQ2m&Lk9#pR4"      # not in any wordlist, on purpose
DEMO_NOW = 1765900000.0               # fixed clock → deterministic findings


def _hs_token(header: dict, payload: dict, secret: str,
              tamper: dict = None) -> str:
    h = b64u_enc(json.dumps(header, separators=(",", ":")).encode())
    p = b64u_enc(json.dumps(payload, separators=(",", ":")).encode())
    sig = b64u_enc(hs_sign(header["alg"], f"{h}.{p}", secret))
    if tamper:                          # rewrite claims, keep old signature
        payload = {**payload, **tamper}
        p = b64u_enc(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{sig}"


# --- tiny RSA for the demo: Miller-Rabin keygen + PKCS#1 signing, by hand ---

def _probably_prime(n: int, rounds: int = 24) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = 2 + secrets.randbelow(n - 3)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        c = secrets.randbits(bits) | (1 << bits - 1) | (1 << bits - 2) | 1
        if _probably_prime(c):
            return c


def _demo_rsa_jwk():
    """cached 2048-bit demo keypair → (private tuple, public JWK dict)"""
    global _DEMO_RSA
    try:
        return _DEMO_RSA
    except NameError:
        pass
    p, q = _gen_prime(1024), _gen_prime(1024)
    n, e = p * q, 65537
    d = pow(e, -1, (p - 1) * (q - 1))
    jwk = {"kty": "RSA", "kid": "demo-2026", "use": "sig", "alg": "RS256",
           "n": b64u_enc(n.to_bytes(256, "big")),
           "e": b64u_enc(e.to_bytes(3, "big"))}
    _DEMO_RSA = ((n, d), jwk)
    return _DEMO_RSA


def _rs256_token(payload: dict, tamper: dict = None) -> str:
    (n, d), jwk = _demo_rsa_jwk()
    header = {"alg": "RS256", "typ": "JWT", "kid": jwk["kid"]}
    h = b64u_enc(json.dumps(header, separators=(",", ":")).encode())
    p = b64u_enc(json.dumps(payload, separators=(",", ":")).encode())
    k = (n.bit_length() + 7) // 8
    t = DIGEST_INFO["sha256"] + hashlib.sha256(
        f"{h}.{p}".encode()).digest()
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    sig = b64u_enc(pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big"))
    if tamper:                          # rewrite claims, keep old signature
        p = b64u_enc(json.dumps({**payload, **tamper},
                                separators=(",", ":")).encode())
    return f"{h}.{p}.{sig}", jwk


def build_demo_tokens(now: float) -> dict:
    """label → (token, kwargs-for-audit); expected findings live in EXPECTED"""
    hour, day = 3600, 86400
    base = {"iss": "https://auth.corp.example", "aud": "api",
            "sub": "user-42", "iat": now, "nbf": now,
            "exp": now + 2 * hour, "jti": "9f0c-4a1b"}
    strong_header = {"alg": "HS256", "typ": "JWT"}

    clean = _hs_token(strong_header, {**base, "role": "reader"}, DEMO_STRONG)
    weak = _hs_token(strong_header,
                     {**base, "sub": "admin", "role": "admin"}, "secret123")
    tampered = _hs_token(strong_header, base, "secret123",
                         tamper={"sub": "superadmin"})
    expired = _hs_token(strong_header,
                        {**base, "iat": now - 181 * day,
                         "exp": now - 180 * day}, DEMO_STRONG)
    kid_sqli = _hs_token({**strong_header, "kid": "' OR '1'='1' --"},
                         base, DEMO_STRONG)
    jku = _hs_token(
        {**strong_header, "jku": "https://keys.attacker.example/jwks.json"},
        base, DEMO_STRONG)
    confusion = _hs_token({**strong_header,
                           "x5c": ["MIIBoDCCAUoCAQA="]},  # any DER-ish blob
                          base, DEMO_STRONG)
    sensitive = _hs_token(strong_header, {**base, "user": "ayse",
                                          "password": "Hunter2!",
                                          "card": "4111 1111 1111 1111"},
                          DEMO_STRONG)
    no_exp = _hs_token(strong_header, {"sub": "user-1", "iat": now},
                       DEMO_STRONG)

    h = b64u_enc(json.dumps({"alg": "none", "typ": "JWT"},
                            separators=(",", ":")).encode())
    p = b64u_enc(json.dumps({**base, "role": "admin"},
                            separators=(",", ":")).encode())
    alg_none = f"{h}.{p}"                                   # two-part form

    rs_ok, jwk = _rs256_token(base)
    rs_bad, _ = _rs256_token(base, tamper={"sub": "attacker"})
    jwks = {"keys": [jwk]}

    return {
        "alg-none": (alg_none, {}),
        "weak-secret": (weak, {}),
        # tampering invalidates the signature, so no wordlist can reconnect
        # it — this token is audited the way an operator would: known secret
        "tampered-hs": (tampered, {"secret": "secret123"}),
        "kid-sqli": (kid_sqli, {}),
        "jku-ssrf": (jku, {}),
        "alg-confusion": (confusion, {}),
        "sensitive-claims": (sensitive, {}),
        "no-expiry": (no_exp, {}),
        "expired": (expired, {}),
        "rs256-tampered": (rs_bad, {"jwks": jwks}),
        "rs256-clean": (rs_ok, {"jwks": jwks}),
        "hs256-clean": (clean, {}),
    }


EXPECTED = {
    "alg-none": {"ALG-NONE"},
    "weak-secret": {"WEAK-SECRET"},
    "tampered-hs": {"TAMPERED"},
    "kid-sqli": {"KID-INJECTION"},
    "jku-ssrf": {"KEY-URL-SSRF"},
    "alg-confusion": {"ALG-CONFUSION"},
    "sensitive-claims": {"SENSITIVE-CLAIMS", "PAN-IN-CLAIMS"},
    "no-expiry": {"NO-EXPIRY", "MISSING-CLAIMS"},
    "expired": {"EXPIRED"},
    "rs256-tampered": {"TAMPERED"},
    "rs256-clean": set(),
    "hs256-clean": set(),
}


def run_demo(json_out=None) -> int:
    tokens = build_demo_tokens(DEMO_NOW)
    print(f"JWTHawk {__version__} — offline demo (synthetic tokens, "
          "same code path as live audits; RSA keys generated + verified "
          "in pure stdlib)\n")
    planted, caught, fps = 0, 0, 0
    ok_all = True
    for label, expected in EXPECTED.items():
        token, kwargs = tokens[label]
        rep = audit(token, label=label, now=DEMO_NOW, **kwargs)
        render(rep, now=DEMO_NOW)
        print()
        tags = {f.tag for f in rep.findings}
        missing, extra = expected - tags, tags - expected
        if not missing and not extra:
            print(f"✔ {label}: {len(expected)}/{len(expected)} expected "
                  f"findings\n")
        else:
            ok_all = False
            print(f"✘ {label}: missing={sorted(missing)} "
                  f"unexpected={sorted(extra)}\n")
        planted += len(expected)
        caught += len(expected) - len(missing)
        fps += len(extra)
    verdict = "demo verified" if ok_all else "DEMO FAILED"
    print(f"{'✔' if ok_all else '✘'} {verdict}: {caught}/{planted} planted "
          f"findings · {fps} false positives · 2 clean tokens (HS+RSA) "
          f"stayed clean")
    if json_out:
        from pathlib import Path
        Path(json_out).write_text(
            json.dumps(report_json([
                audit(tokens[l][0], label=l, now=DEMO_NOW, **tokens[l][1])
                for l in EXPECTED]), indent=2, ensure_ascii=False),
            encoding="utf-8")
    return 0 if ok_all else 1


# --------------------------------------------------------------------------
# cli
# --------------------------------------------------------------------------

def _read_tokens(target: str):
    """bare token or @file with one token per line (# comments allowed)"""
    if not target.startswith("@"):
        return [("", target)]
    from pathlib import Path
    lines = Path(target[1:]).read_text(encoding="utf-8").splitlines()
    out = []
    for i, line in enumerate(lines, 1):
        line = line.strip()
        if line and not line.startswith("#"):
            out.append((f"line {i}", line))
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="jwthawk",
        description="JWT security auditor — decode, crack weak secrets, "
                    "verify RSA by hand, grade the claims. Zero dependencies")
    p.add_argument("token", nargs="?",
                   help="JWT to audit, or @file with one token per line")
    p.add_argument("--decode", action="store_true",
                   help="pretty-print header/payload instead of auditing")
    p.add_argument("--crack", action="store_true",
                   help="focus: wordlist attack on the HMAC secret")
    p.add_argument("--secret", help="known HMAC secret to verify against")
    p.add_argument("--jwks", help="JWKS URL (or @file) for RS256/384/512 "
                                  "verification")
    p.add_argument("--wordlist", metavar="FILE",
                   help="extra HMAC secret candidates (one per line)")
    p.add_argument("--json", metavar="FILE", help="write JSON report")
    p.add_argument("--demo", action="store_true",
                   help="offline demo: synthetic tokens, planted findings")
    p.add_argument("--version", action="version",
                   version=f"JWTHawk {__version__}")
    args = p.parse_args(argv)

    if args.demo:
        return run_demo(args.json)
    if not args.token:
        p.error("a token is required (or run --demo)")

    try:
        entries = _read_tokens(args.token)
    except OSError as exc:
        print(f"[!] cannot read token file: {exc}", file=sys.stderr)
        return 2

    words = list(WEAK_SECRETS)
    if args.wordlist:
        from pathlib import Path
        try:
            extra = [w.strip() for w in Path(args.wordlist).read_text(
                encoding="utf-8").splitlines()
                if w.strip() and not w.startswith("#")]
        except OSError as exc:
            print(f"[!] cannot read wordlist: {exc}", file=sys.stderr)
            return 2
        words += [w for w in extra if w not in words]

    jwks = None
    if args.jwks:
        try:
            if args.jwks.startswith("@"):       # local JWKS file
                from pathlib import Path
                jwks = json.loads(Path(args.jwks[1:]).read_text(
                    encoding="utf-8"))
            else:
                jwks = fetch_jwks(args.jwks)
        except (JwtError, OSError, ValueError) as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return 2

    # ---- decode mode ------------------------------------------------------
    if args.decode:
        try:
            h_b64, p_b64, s_b64 = split_token(entries[0][1])
            header = json.loads(b64u_dec(h_b64))
            payload = json.loads(b64u_dec(p_b64))
        except (JwtError, ValueError) as exc:
            print(f"[!] undecodable token: {exc}", file=sys.stderr)
            return 2
        now = time.time()
        print("╭─ JWTHawk decode " + "─" * 43)
        for title, obj in (("header", header), ("payload", payload)):
            pretty = json.dumps(obj, indent=2, ensure_ascii=False)
            print(f"│ {title:8}: " + pretty.replace("\n", "\n│ "))
        if s_b64:
            try:
                print(f"│ signature: {len(b64u_dec(s_b64))} bytes")
            except JwtError:
                print("│ signature: malformed base64url")
        else:
            print("│ signature: none (unsigned)")
        print(f"│ exp      : {_ts(payload, 'exp', now)}")
        print("╰" + "─" * 60)
        return 0

    # ---- crack mode -------------------------------------------------------
    if args.crack:
        label, token = entries[0]
        try:
            h_b64, p_b64, s_b64 = split_token(token)
            header = json.loads(b64u_dec(h_b64))
        except (JwtError, ValueError) as exc:
            print(f"[!] undecodable token: {exc}", file=sys.stderr)
            return 2
        alg = header.get("alg", "")
        print("╭─ JWTHawk crack " + "─" * 44)
        print(f"│ alg      : {alg or '?'} · wordlist {len(words)} candidates")
        if alg not in HS_ALGS:
            print("│ ✘ not an HMAC (HS*) algorithm — nothing to crack")
            print("╰" + "─" * 60)
            return 2
        t0 = time.monotonic()
        hit = crack_secret(alg, f"{h_b64}.{p_b64}", s_b64, words)
        dt = time.monotonic() - t0
        if hit:
            print(f'│ ✔ secret = "{hit[0]}"  (hit #{hit[1]}, {dt:.2f}s)')
            print("╰" + "─" * 60)
            return 0
        print(f"│ ✘ exhausted {len(words)} candidates in {dt:.2f}s — "
              "bring a bigger list with --wordlist")
        print("╰" + "─" * 60)
        return 1

    # ---- audit mode (default) ----------------------------------------------
    reps, worst = [], 0
    for label, token in entries:
        try:
            rep = audit(token, label=label or "token", secret=args.secret,
                        jwks=jwks, words=words)
        except JwtError as exc:
            print(f"[!] {label or 'token'}: {exc}", file=sys.stderr)
            return 2
        reps.append(rep)
        render(rep)
        print()
        if {f.sev for f in rep.findings} & {"CRITICAL", "HIGH"}:
            worst = 1
    if args.json:
        from pathlib import Path
        Path(args.json).write_text(
            json.dumps(report_json(reps), indent=2, ensure_ascii=False),
            encoding="utf-8")
        print(f"[+] json → {args.json}", file=sys.stderr)
    return worst


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        sys.exit(130)
