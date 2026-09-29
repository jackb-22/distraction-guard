"""RFC 6238 Appendix B test vectors (SHA1, 8-digit, key =
"12345678901234567890" ASCII). These are the standard's own published
vectors, not anything specific to a real enrolled secret."""
import time

import pytest

from guardctl.totp import (
    FAILURES_BEFORE_LOCKOUT,
    LOCKOUT_BASE_SECONDS,
    LockoutState,
    base32_to_secret,
    hotp,
    is_locked_out,
    provisioning_uri,
    record_failure,
    record_success,
    secret_to_base32,
    totp_counter,
    verify,
)

RFC_KEY = b"12345678901234567890"

RFC_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
]


@pytest.mark.parametrize("t,expected", RFC_VECTORS)
def test_rfc6238_vectors(t, expected):
    counter = totp_counter(t)
    assert hotp(RFC_KEY, counter, digits=8) == expected


def test_verify_accepts_correct_code_at_current_time():
    secret = b"a" * 20
    now = 1_700_000_000.0
    code = hotp(secret, totp_counter(now))
    accepted = verify(secret, code, now=now, last_counter=-1)
    assert accepted == totp_counter(now)


def test_verify_rejects_wrong_code():
    secret = b"a" * 20
    now = 1_700_000_000.0
    assert verify(secret, "000000", now=now, last_counter=-1) is None


def test_verify_accepts_within_window():
    secret = b"a" * 20
    now = 1_700_000_000.0
    prev_counter = totp_counter(now) - 1
    code = hotp(secret, prev_counter)
    accepted = verify(secret, code, now=now, last_counter=-1, window=1)
    assert accepted == prev_counter


def test_verify_rejects_outside_window():
    secret = b"a" * 20
    now = 1_700_000_000.0
    far_counter = totp_counter(now) - 5
    code = hotp(secret, far_counter)
    assert verify(secret, code, now=now, last_counter=-1, window=1) is None


def test_verify_rejects_replay():
    secret = b"a" * 20
    now = 1_700_000_000.0
    counter = totp_counter(now)
    code = hotp(secret, counter)
    # Already used this exact counter -> must reject even though the code
    # itself is numerically correct for this time window.
    assert verify(secret, code, now=now, last_counter=counter) is None


def test_verify_rejects_malformed_code():
    secret = b"a" * 20
    assert verify(secret, "abcdef", now=time.time(), last_counter=-1) is None
    assert verify(secret, "123", now=time.time(), last_counter=-1) is None


def test_base32_roundtrip():
    secret = b"\x01\x02\x03\x04\x05" * 4
    b32 = secret_to_base32(secret)
    assert base32_to_secret(b32) == secret


def test_provisioning_uri_contains_secret_and_issuer():
    secret = b"\x00" * 20
    uri = provisioning_uri(secret, issuer="DistractionGuard", account="nabu")
    assert uri.startswith("otpauth://totp/DistractionGuard:nabu?")
    assert "secret=" in uri
    assert "issuer=DistractionGuard" in uri


# --- lockout escalation ---

def test_lockout_after_five_failures():
    state = LockoutState()
    now = 1_700_000_000.0
    for _ in range(FAILURES_BEFORE_LOCKOUT - 1):
        record_failure(state, now=now)
        assert not is_locked_out(state, now=now)
    record_failure(state, now=now)
    assert is_locked_out(state, now=now)
    assert state.level == 1


def test_lockout_duration_escalates():
    state = LockoutState()
    now = 1_700_000_000.0
    for _ in range(FAILURES_BEFORE_LOCKOUT):
        record_failure(state, now=now)
    first_duration = state.lockout_until - now
    assert first_duration == LOCKOUT_BASE_SECONDS

    # Simulate a second lockout after the first has expired.
    now2 = state.lockout_until + 1
    for _ in range(FAILURES_BEFORE_LOCKOUT):
        record_failure(state, now=now2)
    second_duration = state.lockout_until - now2
    assert second_duration == LOCKOUT_BASE_SECONDS * 2


def test_lockout_caps_at_max():
    state = LockoutState(level=20)
    now = 1_700_000_000.0
    for _ in range(FAILURES_BEFORE_LOCKOUT):
        record_failure(state, now=now)
    from guardctl.totp import LOCKOUT_MAX_SECONDS
    assert state.lockout_until - now == LOCKOUT_MAX_SECONDS


def test_success_resets_failures_not_level():
    state = LockoutState()
    now = 1_700_000_000.0
    for _ in range(FAILURES_BEFORE_LOCKOUT):
        record_failure(state, now=now)
    assert state.level == 1
    record_success(state, now=state.lockout_until + 1)
    assert state.failures == 0
    assert state.level == 1  # level persists across a success
    assert not is_locked_out(state, now=state.lockout_until + 1)


def test_level_decays_after_clean_period():
    from guardctl.totp import LOCKOUT_DECAY_SECONDS
    state = LockoutState()
    now = 1_700_000_000.0
    for _ in range(FAILURES_BEFORE_LOCKOUT):
        record_failure(state, now=now)
    assert state.level == 1
    later = now + LOCKOUT_DECAY_SECONDS + 1
    record_success(state, now=later)
    assert state.level == 0


def test_level_does_not_decay_before_clean_period():
    from guardctl.totp import LOCKOUT_DECAY_SECONDS
    state = LockoutState()
    now = 1_700_000_000.0
    for _ in range(FAILURES_BEFORE_LOCKOUT):
        record_failure(state, now=now)
    soon = now + LOCKOUT_DECAY_SECONDS - 1
    record_success(state, now=soon)
    assert state.level == 1
