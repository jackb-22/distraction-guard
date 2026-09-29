import pytest

from guardctl import auth, totp
from guardctl.state import StateDir


def test_verify_before_enrollment_raises(tmp_path):
    s = StateDir(str(tmp_path))
    with pytest.raises(auth.NotEnrolled):
        auth.verify_code(s, "123456")


def test_enroll_then_verify_correct_code(tmp_path):
    s = StateDir(str(tmp_path))
    import re
    uri = auth.enroll(s)
    b32 = re.search(r"secret=([A-Z0-9]+)&", uri).group(1)
    secret = totp.base32_to_secret(b32)
    now = 1_700_000_000.0
    code = totp.hotp(secret, totp.totp_counter(now))
    result = auth.verify_code(s, code, now=now)
    assert result.ok
    assert result.method == "totp"


def test_verify_wrong_code_fails(tmp_path):
    s = StateDir(str(tmp_path))
    auth.enroll(s)
    result = auth.verify_code(s, "000000", now=1_700_000_000.0)
    assert not result.ok


def test_replay_same_code_rejected(tmp_path):
    s = StateDir(str(tmp_path))
    import re
    uri = auth.enroll(s)
    b32 = re.search(r"secret=([A-Z0-9]+)&", uri).group(1)
    secret = totp.base32_to_secret(b32)
    now = 1_700_000_000.0
    code = totp.hotp(secret, totp.totp_counter(now))
    r1 = auth.verify_code(s, code, now=now)
    assert r1.ok
    r2 = auth.verify_code(s, code, now=now)
    assert not r2.ok


def test_five_failures_locks_out(tmp_path):
    s = StateDir(str(tmp_path))
    auth.enroll(s)
    now = 1_700_000_000.0
    for _ in range(5):
        r = auth.verify_code(s, "000000", now=now)
    assert not r.ok
    locked, remaining = auth.lockout_status(s, now=now)
    assert locked
    assert remaining > 0


def test_lockout_blocks_even_correct_code(tmp_path):
    s = StateDir(str(tmp_path))
    import re
    uri = auth.enroll(s)
    b32 = re.search(r"secret=([A-Z0-9]+)&", uri).group(1)
    secret = totp.base32_to_secret(b32)
    now = 1_700_000_000.0
    for _ in range(5):
        auth.verify_code(s, "000000", now=now)
    correct = totp.hotp(secret, totp.totp_counter(now))
    result = auth.verify_code(s, correct, now=now)
    assert not result.ok
    assert "locked out" in result.reason


def test_lockout_notify_called_on_transition(tmp_path):
    s = StateDir(str(tmp_path))
    auth.enroll(s)
    now = 1_700_000_000.0
    calls = []
    for _ in range(5):
        auth.verify_code(s, "000000", now=now, notify_fn=lambda t, b: calls.append((t, b)))
    assert len(calls) == 1
    assert "lockout" in calls[0][0].lower()


def test_caller_is_real_root():
    assert auth.caller_is_real_root(None) is True
    assert auth.caller_is_real_root("jack") is False
