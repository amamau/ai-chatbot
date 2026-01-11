# -*- coding: utf-8 -*-
"""two_factor.py

TOTP (RFC 6238) + backup codes helpers.

No external dependencies.

Suggested users.json fields:
- two_factor_enabled: bool
- two_factor_secret: str (base32, no padding)
- two_factor_backup_hashes: list[{"salt": "...", "hash": "..."}]

Backup codes are generated as plain strings and shown once.
Store ONLY salted hashes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
import urllib.parse
from typing import Dict, List, Optional, Tuple


def _normalize_b32(secret: str) -> str:
    s = (secret or "").strip().replace(" ", "").upper()
    # keep only base32-ish characters (A-Z2-7) plus digits; be forgiving
    s = "".join(ch for ch in s if ch.isalnum())
    return s


def generate_base32_secret(nbytes: int = 20) -> str:
    """Generate a base32 secret (no padding)."""
    n = int(nbytes or 20)
    if n < 10:
        n = 10
    raw = secrets.token_bytes(n)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _b32decode(secret: str) -> bytes:
    s = _normalize_b32(secret)
    if not s:
        return b""
    pad = "=" * ((8 - (len(s) % 8)) % 8)
    return base64.b32decode(s + pad, casefold=True)


def totp_at(secret: str, for_time: Optional[int] = None, step: int = 30, digits: int = 6) -> str:
    """Compute a TOTP code for a given Unix time."""
    t = int(for_time if for_time is not None else time.time())
    st = max(1, int(step or 30))
    counter = int(t // st)

    key = _b32decode(secret)
    msg = counter.to_bytes(8, "big")
    hm = hmac.new(key, msg, hashlib.sha1).digest()

    offset = hm[-1] & 0x0F
    part = hm[offset : offset + 4]
    code_int = (int.from_bytes(part, "big") & 0x7FFFFFFF) % (10 ** int(digits or 6))
    return str(code_int).zfill(int(digits or 6))


def verify_totp(
    secret: str,
    code: str,
    at_time: Optional[int] = None,
    step: int = 30,
    digits: int = 6,
    window: int = 1,
) -> bool:
    """Verify a TOTP code with a +/- window drift."""
    d = int(digits or 6)
    c = "".join(ch for ch in (code or "").strip() if ch.isdigit())
    if len(c) != d:
        return False

    t = int(at_time if at_time is not None else time.time())
    st = max(1, int(step or 30))
    w = max(0, int(window or 0))

    for drift in range(-w, w + 1):
        cand = totp_at(secret, t + drift * st, step=st, digits=d)
        if secrets.compare_digest(cand, c):
            return True
    return False


def otpauth_uri(
    account_name: str,
    issuer: str,
    secret: str,
    digits: int = 6,
    period: int = 30,
) -> str:
    """Build an otpauth:// URI for authenticator apps."""
    acc = (account_name or "").strip()
    iss = (issuer or "").strip()
    label = f"{iss}:{acc}" if iss else acc
    params = {
        "secret": _normalize_b32(secret),
        "digits": str(int(digits or 6)),
        "period": str(int(period or 30)),
    }
    if iss:
        params["issuer"] = iss

    return "otpauth://totp/" + urllib.parse.quote(label) + "?" + urllib.parse.urlencode(params)


def generate_backup_codes(count: int = 10) -> List[str]:
    """Generate backup codes like 'ABCD-EFGH'."""
    n = max(1, min(50, int(count or 10)))
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no I, O, 0, 1
    codes: List[str] = []
    for _ in range(n):
        raw = "".join(secrets.choice(alphabet) for _ in range(8))
        codes.append(raw[:4] + "-" + raw[4:])
    return codes


def _hash_backup_code(code: str, salt: Optional[str] = None) -> Dict[str, str]:
    s = salt or secrets.token_hex(16)
    c = (code or "").strip().upper()
    h = hashlib.sha256((s + ":" + c).encode("utf-8")).hexdigest()
    return {"salt": s, "hash": h}


def backup_codes_to_hashes(codes: List[str]) -> List[Dict[str, str]]:
    return [_hash_backup_code(c) for c in (codes or []) if (c or "").strip()]


def verify_and_consume_backup_code(
    code: str,
    hashes: List[Dict[str, str]],
) -> Tuple[bool, List[Dict[str, str]]]:
    """Verify a backup code; if valid, consume it (remove from list)."""
    c = (code or "").strip().upper()
    if not c:
        return False, list(hashes or [])

    ok = False
    remaining: List[Dict[str, str]] = []
    for entry in (hashes or []):
        salt = str(entry.get("salt") or "")
        h = str(entry.get("hash") or "")
        if (not ok) and salt and h:
            cand = hashlib.sha256((salt + ":" + c).encode("utf-8")).hexdigest()
            if secrets.compare_digest(cand, h):
                ok = True
                continue
        remaining.append(entry)

    return ok, remaining


def verify_2fa_code(
    code: str,
    *,
    secret: str,
    backup_hashes: List[Dict[str, str]],
    window: int = 1,
) -> Tuple[bool, bool, List[Dict[str, str]]]:
    """Verify a TOTP code or a backup code.

    Returns: (ok, used_backup, new_backup_hashes)
    """
    c = (code or "").strip()
    if secret and verify_totp(secret, c, window=window):
        return True, False, list(backup_hashes or [])

    ok, remaining = verify_and_consume_backup_code(c, list(backup_hashes or []))
    if ok:
        return True, True, remaining

    return False, False, list(backup_hashes or [])
