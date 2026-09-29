"""Friend-code authentication flow: reads a code, verifies it against the
enrolled TOTP secret, and drives the lockout state machine. This is the
only path by which a LOOSEN command may proceed once guardctl is locked.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from guardctl import totp
from guardctl.state import StateDir

TOTP_SECRET_FILE = "totp.json"
AUTH_STATE_FILE = "auth.json"


class NotEnrolled(Exception):
    pass


class AuthDenied(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass
class AuthResult:
    ok: bool
    method: str  # "totp" | "root" | "none"
    reason: str | None = None


def is_enrolled(state: StateDir) -> bool:
    return state.path(TOTP_SECRET_FILE).exists()


def enroll(state: StateDir, *, issuer: str = "DistractionGuard", account: str = "guard") -> str:
    """Generate a new secret, persist it, and return the provisioning URI
    to render as a QR code. Overwrites any existing enrollment -- callers
    must confirm with the person doing the enrollment first."""
    secret = totp.generate_secret()
    state.write_json(TOTP_SECRET_FILE, {"secret_b32": totp.secret_to_base32(secret), "enrolled_at": time.time()}, mode=0o600)
    state.write_json(AUTH_STATE_FILE, totp.LockoutState().to_json(), mode=0o600)
    return totp.provisioning_uri(secret, issuer=issuer, account=account)


def _load_secret(state: StateDir) -> bytes:
    data = state.read_json(TOTP_SECRET_FILE, None)
    if data is None:
        raise NotEnrolled("no TOTP secret enrolled -- run `guardctl totp-enroll` first")
    return totp.base32_to_secret(data["secret_b32"])


def _load_lockout(state: StateDir) -> tuple[totp.LockoutState, int]:
    raw = state.read_json(AUTH_STATE_FILE, {})
    lockout = totp.LockoutState.from_json(raw)
    last_counter = raw.get("last_counter", -1)
    return lockout, last_counter


def _save_lockout(state: StateDir, lockout: totp.LockoutState, last_counter: int) -> None:
    data = lockout.to_json()
    data["last_counter"] = last_counter
    state.write_json(AUTH_STATE_FILE, data, mode=0o600)


def lockout_status(state: StateDir, *, now: float | None = None) -> tuple[bool, float]:
    """Returns (is_locked_out, seconds_remaining)."""
    now = now if now is not None else time.time()
    lockout, _ = _load_lockout(state)
    if totp.is_locked_out(lockout, now=now):
        return True, lockout.lockout_until - now
    return False, 0.0


def verify_code(state: StateDir, code: str, *, notify_fn=None, now: float | None = None) -> AuthResult:
    """Verify a single code against the enrolled secret, updating lockout
    state as a side effect. `notify_fn(title, body)` is called on a lockout
    transition, if provided."""
    now = now if now is not None else time.time()

    with state.locked("auth.lock"):
        secret = _load_secret(state)
        lockout, last_counter = _load_lockout(state)

        if totp.is_locked_out(lockout, now=now):
            remaining = int(lockout.lockout_until - now)
            return AuthResult(False, "totp", f"locked out for {remaining}s after too many failed codes")

        accepted_counter = totp.verify(secret, code, now=now, last_counter=last_counter)
        if accepted_counter is None:
            was_level = lockout.level
            totp.record_failure(lockout, now=now)
            _save_lockout(state, lockout, last_counter)
            if lockout.level > was_level and notify_fn:
                notify_fn(
                    "Distraction Guard: code lockout",
                    f"5 wrong codes -- locked out until {time.strftime('%H:%M', time.localtime(lockout.lockout_until))}",
                )
            return AuthResult(False, "totp", "incorrect code")

        totp.record_success(lockout, now=now)
        _save_lockout(state, lockout, accepted_counter)
        return AuthResult(True, "totp", None)


def caller_is_real_root(sudo_user: str | None) -> bool:
    """True when invoked directly as root (the friend via `su -`), as
    opposed to jack's NOPASSWD sudo wrapper (which always sets SUDO_USER)."""
    return sudo_user is None
