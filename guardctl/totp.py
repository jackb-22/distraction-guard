"""RFC 6238 TOTP (stdlib only): enrollment secret generation, code
verification with replay protection, and escalating lockout state.

The secret never leaves this module's callers' control -- guardctl only
ever asks "is this code valid" and records a counter, never prints or logs
the secret after enrollment.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import time
from dataclasses import asdict, dataclass

DIGITS = 6
PERIOD = 30
WINDOW = 1  # +/- 1 step tolerance for clock drift

LOCKOUT_BASE_SECONDS = 15 * 60
LOCKOUT_MAX_SECONDS = 24 * 60 * 60
FAILURES_BEFORE_LOCKOUT = 5
LOCKOUT_DECAY_SECONDS = 7 * 24 * 60 * 60  # one escalation level decays per 7 days clean


def generate_secret(num_bytes: int = 20) -> bytes:
    return os.urandom(num_bytes)


def secret_to_base32(secret: bytes) -> str:
    return base64.b32encode(secret).decode("ascii").rstrip("=")


def base32_to_secret(b32: str) -> bytes:
    padded = b32 + "=" * (-len(b32) % 8)
    return base64.b32decode(padded.upper())


def provisioning_uri(secret: bytes, *, issuer: str = "DistractionGuard", account: str = "guard") -> str:
    b32 = secret_to_base32(secret)
    return (
        f"otpauth://totp/{issuer}:{account}?secret={b32}&issuer={issuer}"
        f"&digits={DIGITS}&period={PERIOD}&algorithm=SHA1"
    )


def hotp(secret: bytes, counter: int, digits: int = DIGITS) -> str:
    """RFC 4226 HOTP, the counter-based primitive TOTP is built on."""
    msg = struct.pack(">Q", counter)
    h = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    bincode = (
        ((h[offset] & 0x7F) << 24)
        | ((h[offset + 1] & 0xFF) << 16)
        | ((h[offset + 2] & 0xFF) << 8)
        | (h[offset + 3] & 0xFF)
    )
    return str(bincode % (10**digits)).zfill(digits)


def totp_counter(t: float, period: int = PERIOD) -> int:
    return int(t) // period


def verify(secret: bytes, code: str, *, now: float | None = None, last_counter: int = -1, window: int = WINDOW) -> int | None:
    """Check `code` against the time windows [now-window, now+window] steps,
    rejecting any counter <= last_counter (replay protection). Returns the
    accepted counter (to be persisted as the new last_counter), or None."""
    now = now if now is not None else time.time()
    base = totp_counter(now)
    code = code.strip()
    if not code.isdigit() or len(code) != DIGITS:
        return None
    for c in range(base - window, base + window + 1):
        if c <= last_counter:
            continue
        if hmac.compare_digest(code, hotp(secret, c)):
            return c
    return None


@dataclass
class LockoutState:
    failures: int = 0
    level: int = 0  # escalation level; each lockout increments it
    lockout_until: float = 0.0
    last_success_or_lockout: float = 0.0

    def to_json(self) -> dict:
        return asdict(self)

    @classmethod
    def from_json(cls, d: dict) -> "LockoutState":
        return cls(**{k: d.get(k, getattr(cls, k, 0)) for k in ("failures", "level", "lockout_until", "last_success_or_lockout")})


def is_locked_out(state: LockoutState, *, now: float | None = None) -> bool:
    now = now if now is not None else time.time()
    return now < state.lockout_until


def record_failure(state: LockoutState, *, now: float | None = None) -> LockoutState:
    now = now if now is not None else time.time()
    _maybe_decay(state, now)
    state.failures += 1
    if state.failures >= FAILURES_BEFORE_LOCKOUT:
        state.failures = 0
        state.level += 1
        duration = min(LOCKOUT_BASE_SECONDS * (2 ** (state.level - 1)), LOCKOUT_MAX_SECONDS)
        state.lockout_until = now + duration
        state.last_success_or_lockout = now
    return state


def record_success(state: LockoutState, *, now: float | None = None) -> LockoutState:
    now = now if now is not None else time.time()
    _maybe_decay(state, now)
    state.failures = 0
    state.lockout_until = 0.0
    state.last_success_or_lockout = now
    return state


def _maybe_decay(state: LockoutState, now: float) -> None:
    if state.level > 0 and state.last_success_or_lockout and (now - state.last_success_or_lockout) >= LOCKOUT_DECAY_SECONDS:
        state.level = max(0, state.level - 1)
        state.last_success_or_lockout = now
