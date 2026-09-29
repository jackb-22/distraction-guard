import json
import re
import time
from pathlib import Path

import pytest

from guardctl import auth, cli, notify
from guardctl.cli import GuardCtx, run


def _no_op_resolver(hostname):
    return ([], [])  # tests never need real IPs; write_assets tests cover resolution itself


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.getpass, "getpass", lambda *a, **kw: "unused")
    c = GuardCtx(
        etc_dir=str(tmp_path / "etc"),
        local_dir=str(tmp_path / "etc" / "local"),
        private_dir=str(tmp_path / "etc" / "private"),
        lists_dir=str(tmp_path / "lists"),
        lexicon_path=str(tmp_path / "lexicon.txt"),
        compiled_policy_path=str(tmp_path / "compiled" / "policy.json"),
        state_dir=str(tmp_path / "state"),
        firefox_policy_path=str(tmp_path / "firefox-policies.json"),  # doesn't exist -> firefox write skipped
        ca_path=str(tmp_path / "ca.pem"),
        nft_path=str(tmp_path / "compiled" / "guard.nft"),
        decision_log_path=str(tmp_path / "decisions.jsonl"),
        dnsmasq_always_on_path=str(tmp_path / "dnsmasq" / "always-on.conf"),
        dnsmasq_sinkhole_off_path=str(tmp_path / "dnsmasq" / "sinkhole.conf.off"),
        sudo_user="jack",
        notifier=lambda title, body: None,
        resolver=_no_op_resolver,
    )
    return c


def test_status_before_any_compile(ctx):
    out = cli.cmd_status(ctx, [])
    assert "NOT LOADED" in out


def test_doctor_reports_all_ok(ctx, monkeypatch):
    import subprocess

    class FakeCompleted:
        def __init__(self, returncode=0, stdout=""):
            self.returncode = returncode
            self.stdout = stdout

    def fake_run(argv, **kwargs):
        if argv[0] == "timedatectl":
            return FakeCompleted(0, "yes")
        if argv[0] == "trust":
            return FakeCompleted(0, "Distraction Guard Local CA\n")
        return FakeCompleted(0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    from guardctl import watchdog
    monkeypatch.setattr(watchdog, "_check_admin_endpoint", lambda *a: True)
    run(ctx, ["compile"])
    out = cli.cmd_doctor(ctx, [])
    assert "all checks passed" in out
    assert "FAIL" not in out


def test_doctor_reports_failures(ctx, monkeypatch):
    import subprocess

    class FakeCompleted:
        def __init__(self, returncode=1, stdout=""):
            self.returncode = returncode
            self.stdout = stdout

    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: FakeCompleted(1, ""))
    out = cli.cmd_doctor(ctx, [])
    assert "one or more checks FAILED" in out
    assert "[FAIL]" in out


def test_doctor_never_raises_when_subprocess_missing(ctx, monkeypatch):
    import subprocess

    def boom(*a, **kw):
        raise FileNotFoundError("no such command")
    monkeypatch.setattr(subprocess, "run", boom)
    out = cli.cmd_doctor(ctx, [])  # must not raise
    assert "FAILED" in out


def test_compile_then_status(ctx):
    assert run(ctx, ["compile"]) == 0
    out = cli.cmd_status(ctx, [])
    assert "enforce=False" in out


def test_block_then_compile_reflected_in_policy(ctx):
    assert run(ctx, ["block", "example-blocked.com"]) == 0
    policy = ctx.current_policy()
    from dg_policy.hosts import HostKind
    assert policy.classify("example-blocked.com").kind == HostKind.BLOCK


def test_unknown_command_errors(ctx):
    assert run(ctx, ["not-a-real-command"]) == 2


def test_no_args_errors(ctx):
    assert run(ctx, []) == 2


def test_tighten_command_never_prompts_even_when_locked(ctx, monkeypatch):
    ctx.state.set_locked(True)

    def boom():
        raise AssertionError("should never prompt for a tighten command")
    ctx.code_reader = boom

    assert run(ctx, ["block", "example.com"]) == 0


def test_loosen_command_pre_lock_no_prompt(ctx):
    def boom():
        raise AssertionError("should never prompt before locking")
    ctx.code_reader = boom
    assert run(ctx, ["unblock", "example.com"]) == 0


def test_loosen_command_locked_requires_code(ctx):
    ctx.state.set_locked(True)
    auth.enroll(ctx.state)
    ctx.code_reader = lambda: "000000"  # wrong
    assert run(ctx, ["unblock", "example.com"]) == 1
    exceptions = ctx.read_local_list("exceptions.json")
    assert "example.com" not in exceptions


def test_loosen_command_locked_correct_code_succeeds(ctx):
    from guardctl import totp
    ctx.state.set_locked(True)
    uri = auth.enroll(ctx.state)
    secret = totp.base32_to_secret(re.search(r"secret=([A-Z0-9]+)&", uri).group(1))
    now = 1_700_000_000.0
    ctx.code_reader = lambda: totp.hotp(secret, totp.totp_counter(now))
    import guardctl.auth as auth_mod
    import time as time_mod
    monkey_now = now
    real_time = time_mod.time
    time_mod.time = lambda: monkey_now
    try:
        assert run(ctx, ["unblock", "example.com"]) == 0
    finally:
        time_mod.time = real_time
    exceptions = ctx.read_local_list("exceptions.json")
    assert "example.com" in exceptions


def test_real_root_bypasses_code_when_locked(ctx):
    ctx.state.set_locked(True)
    ctx.sudo_user = None  # real root, no SUDO_USER
    assert run(ctx, ["unblock", "example.com"]) == 0


def test_five_wrong_codes_locks_out(ctx):
    ctx.state.set_locked(True)
    auth.enroll(ctx.state)
    ctx.code_reader = lambda: "000000"
    for _ in range(5):
        run(ctx, ["unblock", f"example{_}.com"])
    locked_out, remaining = auth.lockout_status(ctx.state)
    assert locked_out


def test_allow_temp_validates_minutes(ctx):
    assert run(ctx, ["allow-temp", "example.com", "0"]) == 1
    assert run(ctx, ["allow-temp", "example.com", "9999"]) == 1
    assert run(ctx, ["allow-temp", "example.com", "30"]) == 0


def test_allow_temp_reflected_as_allow_temp_kind(ctx):
    run(ctx, ["allow-temp", "example.com", "30"])
    from dg_policy.hosts import HostKind
    policy = ctx.current_policy()
    assert policy.classify("example.com").kind == HostKind.ALLOW_TEMP


def test_add_term_never_echoes_and_output_has_no_term_text(ctx, monkeypatch, capsys):
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": "myspecialterm")
    assert run(ctx, ["add-term", "--strict"]) == 0
    captured = capsys.readouterr()
    assert "myspecialterm" not in captured.out
    assert "T-0001" in captured.out


def test_add_term_stored_privately_not_in_local_dir(ctx, monkeypatch):
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": "myspecialterm")
    run(ctx, ["add-term", "--contextual"])
    terms = ctx.read_terms()
    assert terms[0]["type"] == "contextual"
    assert terms[0]["parts"] == [["myspecialterm"]]
    # never written under local_dir (which a lower-privilege reader might see)
    assert not (ctx._local_path("terms.json")).exists()


def test_add_term_combo_two_parts(ctx, monkeypatch):
    values = iter(["alpha", "beta"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(values))
    run(ctx, ["add-term", "--combo"])
    terms = ctx.read_terms()
    assert terms[0]["type"] == "combo"
    assert terms[0]["parts"] == [["alpha"], ["beta"]]


def test_remove_term_unknown_id_errors(ctx):
    ctx.state.set_locked(False)
    assert run(ctx, ["remove-term", "T-9999"]) == 1


def test_disable_then_enable_list_round_trip(ctx):
    run(ctx, ["disable-list", "hagezi-nsfw"])
    assert "hagezi-nsfw" in ctx.read_local_list("disabled_lists.json")
    run(ctx, ["enable-list", "hagezi-nsfw"])
    assert "hagezi-nsfw" not in ctx.read_local_list("disabled_lists.json")


def test_test_url_reports_block(ctx):
    run(ctx, ["block", "reddit.com"])
    out = cli.cmd_test_url(ctx, ["https://www.reddit.com/r/x"])
    assert "BLOCK" in out


def test_audit_log_records_classification_and_auth(ctx):
    run(ctx, ["block", "example.com"])
    entries = ctx.state.read_audit()
    assert entries[-1]["classification"] == "tighten"
    assert entries[-1]["auth"] == "none"


def test_emergency_off_runs_every_step_even_if_some_fail(ctx, monkeypatch):
    import subprocess

    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        class R:
            returncode = 1 if argv[0] == "nft" else 0
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    out = cli.cmd_emergency_off(ctx, [])
    # every step attempted despite the first (nft) "failing"
    assert any(a[0] == "nft" for a in calls)
    assert any(a[:2] == ["systemctl", "disable"] for a in calls)
    assert any(a[0] == "nmcli" for a in calls)
    assert "nft table=FAILED" in out or "FAILED" in out


def test_emergency_off_deletes_nft_table_first(ctx, monkeypatch):
    import subprocess
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: calls.append(argv) or type("R", (), {"returncode": 0})())
    cli.cmd_emergency_off(ctx, [])
    assert calls[0][:3] == ["nft", "delete", "table"]


def test_emergency_off_available_pre_lock_without_code(ctx):
    ctx.state.set_locked(False)
    assert run(ctx, ["emergency-off"]) == 0  # no code_reader needed


def test_emergency_off_requires_code_once_locked(ctx, monkeypatch):
    import subprocess
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: type("R", (), {"returncode": 0})())
    ctx.state.set_locked(True)
    ctx.code_reader = lambda: "000000"  # wrong, no enrollment even
    assert run(ctx, ["emergency-off"]) == 1


class _FakeSystem:
    """Stands in for subprocess.run: records argv, and lets a test decide
    how the probe fetch and individual commands behave."""

    def __init__(self, *, probe_ok=True, arm_ok=True, disarm_ok=True, has_v6=False):
        self.calls = []
        self.probe_ok, self.arm_ok, self.disarm_ok, self.has_v6 = probe_ok, arm_ok, disarm_ok, has_v6

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        rc, out = 0, ""
        if argv[0] == "systemd-run":
            rc = 0 if self.arm_ok else 1
        elif argv[:2] == ["runuser", "-u"]:
            rc, out = (0, "200") if self.probe_ok else (7, "000")
        elif argv[:4] == ["ip", "-6", "route", "show"]:
            out = "default via fe80::1 dev wlo1" if self.has_v6 else ""
        elif argv[:2] == ["systemctl", "stop"] and argv[2:] == ["dg-autorevert.timer"]:
            rc = 0 if self.disarm_ok else 1
        return type("R", (), {"returncode": rc, "stdout": out, "stderr": ""})()

    def index(self, pred):
        return next(i for i, a in enumerate(self.calls) if pred(a))

    def ran(self, pred):
        return any(pred(a) for a in self.calls)


_is_arm = lambda a: a[0] == "systemd-run"  # noqa: E731
_is_nft_restart = lambda a: a[:2] == ["systemctl", "restart"] and "distraction-guard-nft.service" in a  # noqa: E731
_is_probe = lambda a: a[:2] == ["runuser", "-u"]  # noqa: E731
_is_revert = lambda a: a[:2] == ["/bin/sh", "-c"] and "nft delete table" in a[2]  # noqa: E731
_is_disarm = lambda a: a == ["systemctl", "stop", "dg-autorevert.timer"]  # noqa: E731


def test_emergency_on_aborts_before_nft_if_unhealthy(ctx, monkeypatch):
    import subprocess
    from guardctl import watchdog as watchdog_mod

    fake = _FakeSystem()
    monkeypatch.setattr(subprocess, "run", fake)
    monkeypatch.setattr(watchdog_mod, "check_health", lambda **kw: False)
    monkeypatch.setattr(time, "sleep", lambda s: None)

    rc = run(ctx, ["emergency-on"])
    assert rc == 1
    assert not fake.ran(_is_nft_restart)
    assert not fake.ran(_is_arm)


def test_emergency_on_applies_nft_when_healthy(ctx, monkeypatch):
    import subprocess
    from guardctl import watchdog as watchdog_mod

    fake = _FakeSystem()
    monkeypatch.setattr(subprocess, "run", fake)
    monkeypatch.setattr(watchdog_mod, "check_health", lambda **kw: True)
    ctx.sudo_user = "jack"

    rc = run(ctx, ["emergency-on"])
    assert rc == 0
    assert fake.ran(_is_nft_restart)
    assert fake.ran(_is_disarm)


def test_guarded_apply_arms_timer_before_touching_nft(monkeypatch):
    import subprocess
    fake = _FakeSystem()
    monkeypatch.setattr(subprocess, "run", fake)
    cli._apply_nft_guarded("jack")
    assert fake.index(_is_arm) < fake.index(_is_nft_restart) < fake.index(_is_probe) < fake.index(_is_disarm)
    assert not fake.ran(_is_revert)


def test_guarded_apply_probes_as_the_redirected_user(monkeypatch):
    import subprocess
    fake = _FakeSystem()
    monkeypatch.setattr(subprocess, "run", fake)
    cli._apply_nft_guarded("jack")
    probe = fake.calls[fake.index(_is_probe)]
    assert probe[:4] == ["runuser", "-u", "jack", "--"]
    assert cli.PROBE_URL in probe


def test_guarded_apply_probes_v6_only_when_there_is_a_v6_route(monkeypatch):
    import subprocess
    for has_v6, expected in ((False, {"-4"}), (True, {"-4", "-6"})):
        fake = _FakeSystem(has_v6=has_v6)
        monkeypatch.setattr(subprocess, "run", fake)
        cli._apply_nft_guarded("jack")
        assert {a[5] for a in fake.calls if _is_probe(a)} == expected


def test_guarded_apply_reverts_immediately_when_probe_fails(monkeypatch):
    import subprocess
    fake = _FakeSystem(probe_ok=False)
    monkeypatch.setattr(subprocess, "run", fake)
    with pytest.raises(cli.GuardError, match="reverted"):
        cli._apply_nft_guarded("jack")
    assert fake.index(_is_probe) < fake.index(_is_revert)
    assert not fake.ran(_is_disarm)


def test_guarded_apply_refuses_to_apply_if_timer_cannot_be_armed(monkeypatch):
    import subprocess
    fake = _FakeSystem(arm_ok=False)
    monkeypatch.setattr(subprocess, "run", fake)
    with pytest.raises(cli.GuardError, match="NOT applied"):
        cli._apply_nft_guarded("jack")
    assert not fake.ran(_is_nft_restart)


def test_guarded_apply_reports_failure_if_timer_cannot_be_disarmed(monkeypatch):
    # Traffic works, but claiming success would be a lie: the timer will
    # still pull the table in 90s.
    import subprocess
    fake = _FakeSystem(disarm_ok=False)
    monkeypatch.setattr(subprocess, "run", fake)
    with pytest.raises(cli.GuardError, match="WILL be removed"):
        cli._apply_nft_guarded("jack")


def test_apply_nft_is_internal_only(ctx):
    ctx.sudo_user = "jack"
    assert run(ctx, ["_apply-nft", "jack"]) == 1


def test_internal_command_refused_when_sudo_user_set(ctx):
    ctx.sudo_user = "jack"
    assert run(ctx, ["_notify-flush"]) == 1


def test_internal_command_allowed_as_real_root(ctx):
    ctx.sudo_user = None
    assert run(ctx, ["_notify-flush"]) == 0


def test_expire_prunes_past_entries(ctx):
    ctx.sudo_user = None
    ctx.state.set_locked(False)
    past = time.time() - 10
    future = time.time() + 10000
    ctx.write_local_list("temp_allows.json", [
        {"host": "expired.example", "expires_at": past},
        {"host": "still-good.example", "expires_at": future},
    ])
    run(ctx, ["_expire"])
    remaining = ctx.read_local_list("temp_allows.json")
    assert [a["host"] for a in remaining] == ["still-good.example"]


def test_refresh_recompiles_even_with_no_lists_toml(ctx):
    ctx.sudo_user = None
    assert run(ctx, ["_refresh"]) == 0
    assert ctx.current_policy() is not None


def test_refresh_also_writes_nft_and_dnsmasq_assets(ctx):
    ctx.sudo_user = None
    run(ctx, ["block", "example-blocked.com"])
    ctx.sudo_user = None
    run(ctx, ["_refresh"])
    assert Path(ctx.nft_path).exists()
    assert "example-blocked.com" in Path(ctx.dnsmasq_sinkhole_off_path).read_text()


def test_refresh_asset_write_failure_is_visible_not_silently_swallowed(ctx, capsys):
    # Regression test for the exact bug hit installing on the real machine:
    # a FileNotFoundError inside write_assets (missing templates/ dir) was
    # caught, queued as a silent notification, and never printed -- so
    # `guardctl _refresh` reported success while guard.nft was never
    # written. Simulate the same shape of failure (an asset path that
    # can't be created) and confirm it now surfaces in stdout.
    ctx.sudo_user = None
    ctx.nft_path = "/this/path/does/not/exist/and/cannot/be/created/guard.nft"
    rc = run(ctx, ["_refresh"])
    assert rc == 0  # must not crash the timer/install step
    out = capsys.readouterr().out
    assert "PROBLEMS" in out
    assert "ASSET WRITE FAILED" in out


def test_audit_records_totp_auth_when_locked(ctx):
    from guardctl import totp
    ctx.state.set_locked(True)
    uri = auth.enroll(ctx.state)
    secret = totp.base32_to_secret(re.search(r"secret=([A-Z0-9]+)&", uri).group(1))
    import time as time_mod
    now = 1_700_000_000.0
    ctx.code_reader = lambda: totp.hotp(secret, totp.totp_counter(now))
    real_time = time_mod.time
    time_mod.time = lambda: now
    try:
        run(ctx, ["unblock", "example.com"])
    finally:
        time_mod.time = real_time
    entries = ctx.state.read_audit()
    assert entries[-1]["auth"] == "totp"


def _write_decisions(ctx, n):
    with open(ctx.decision_log_path, "w") as f:
        for i in range(n):
            f.write(json.dumps({"ts": f"t{i}", "action": "would_block", "rule": "S-social", "host": "www.reddit.com", "path_head": "/r"}) + "\n")


def test_log_shows_proxy_decisions_by_default(ctx, capsys):
    _write_decisions(ctx, 3)
    assert run(ctx, ["log"]) == 0
    out = capsys.readouterr().out
    assert "would_block\tS-social\twww.reddit.com/r" in out


def test_log_dash_n_is_accepted(ctx, capsys):
    # Regression: `guardctl log -n 20` (as the install checklist says)
    # crashed with int('-n').
    _write_decisions(ctx, 30)
    assert run(ctx, ["log", "-n", "5"]) == 0
    lines = [l for l in capsys.readouterr().out.splitlines() if "would_block" in l]
    assert len(lines) == 5 and lines[-1].startswith("t29")


def test_log_audit_flag_shows_command_trail(ctx, capsys):
    run(ctx, ["block", "example.com"])
    capsys.readouterr()
    assert run(ctx, ["log", "--audit", "-n", "5"]) == 0
    assert "tighten" in capsys.readouterr().out


def test_log_rejects_garbage_args(ctx):
    assert run(ctx, ["log", "-n", "x"]) == 1


# --- class mode ------------------------------------------------------------

_CAL = """\
09/21/2026 @ 13:10 -> 09/21/2026 @ 14:25 {1W -> 12/23/2099 w1} |Class: A
09/22/2026 @ 08:40 -> 09/22/2026 @ 09:55 {1W -> 12/23/2099 w2} |Class: B
"""
_BM = """const BOOKMARKS = {
    classes: [['cw', 'courseworks', 'https://courseworks2.columbia.edu']],
    coms: [['z', 'zoom', 'https://www.zoom.com']],
    dev: [['gh', 'github', 'https://github.com'], ['cl', 'claude', 'https://claude.ai'], ['ge', 'gemini', 'https://gemini.google.com']],
    life: [['n', 'netflix', 'https://www.netflix.com']],
};"""


def _sync(ctx, tmp_path, cal=_CAL, bm=_BM):
    (tmp_path / "apts").write_text(cal)
    (tmp_path / "bookmarks.js").write_text(bm)
    return run(ctx, ["schedule-sync", "--calcurse", str(tmp_path / "apts"), "--bookmarks", str(tmp_path / "bookmarks.js")])


def test_schedule_sync_snapshots_windows_and_allowlist(ctx, tmp_path, capsys):
    assert _sync(ctx, tmp_path) == 0
    snap = ctx.read_local_dict("class_mode.json")
    assert [w["title"] for w in snap["windows"]] == ["Class: A", "Class: B"]
    assert snap["allow"] == ["courseworks2.columbia.edu", "github.com", "zoom.com", "zoom.us"]
    assert snap["pad_minutes"] == 5
    # classes + dev + coms, no exclusions: claude.ai is trusted (never
    # scanned) even though class mode still blocks it during class.
    assert snap["passthrough"] == ["claude.ai", "courseworks2.columbia.edu", "gemini.google.com", "github.com", "zoom.com", "zoom.us"]
    assert policy_passthrough(ctx) >= set(snap["passthrough"])
    policy = ctx.current_policy()
    assert len(policy.class_windows) == 2
    assert policy.class_allows("github.com") and policy.class_allows("cas.columbia.edu")
    assert not policy.class_allows("claude.ai")
    assert "Mon 13:10-14:25" in capsys.readouterr().out


def test_schedule_sync_adding_time_is_free_when_locked(ctx, tmp_path):
    _sync(ctx, tmp_path)
    ctx.state.set_locked(True)
    ctx.code_reader = lambda: (_ for _ in ()).throw(AssertionError("must not ask for a code"))
    more = _CAL + "09/25/2026 @ 10:10 -> 09/25/2026 @ 12:40 {1W -> 12/23/2099 w5} |Class: C\n"
    assert _sync(ctx, tmp_path, cal=more) == 0
    assert len(ctx.read_local_dict("class_mode.json")["windows"]) == 3


def test_schedule_sync_removing_class_needs_code_when_locked(ctx, tmp_path, capsys):
    _sync(ctx, tmp_path)
    ctx.state.set_locked(True)
    auth.enroll(ctx.state)
    ctx.code_reader = lambda: "000000"  # wrong
    assert _sync(ctx, tmp_path, cal=_CAL.splitlines()[0] + "\n") == 1
    assert "removes Tue 08:40-09:55 Class: B" in capsys.readouterr().out
    assert len(ctx.read_local_dict("class_mode.json")["windows"]) == 2  # unchanged


def test_schedule_sync_adding_allowed_site_needs_code_when_locked(ctx, tmp_path, capsys):
    _sync(ctx, tmp_path)
    ctx.state.set_locked(True)
    auth.enroll(ctx.state)
    ctx.code_reader = lambda: "000000"
    bm = _BM.replace("['gh', 'github', 'https://github.com']", "['gh', 'github', 'https://github.com'], ['yt', 'yt', 'https://youtube.com']")
    assert _sync(ctx, tmp_path, bm=bm) == 1
    assert "allows youtube.com during class" in capsys.readouterr().out


def test_schedule_sync_refuses_to_clear_everything(ctx, tmp_path):
    assert _sync(ctx, tmp_path, cal="09/21/2026 @ 08:00 -> 09/21/2026 @ 08:10 |Wake\n") == 1
    assert ctx.read_local_dict("class_mode.json") == {}


def test_schedule_command_before_setup(ctx, capsys):
    assert run(ctx, ["schedule"]) == 0
    assert "not set up" in capsys.readouterr().out


def test_set_enforce_on_then_off(ctx):
    Path(ctx.etc_dir).mkdir(parents=True, exist_ok=True)
    (Path(ctx.etc_dir) / "policy.toml").write_text("enforce = false\nlan_tcp_ports = []\n\n[content]\nthreshold = 8\n")
    assert run(ctx, ["set", "enforce", "true"]) == 0
    assert ctx.current_policy().enforce is True
    assert "threshold = 8" in (Path(ctx.etc_dir) / "policy.toml").read_text()
    assert run(ctx, ["set", "enforce", "false"]) == 0
    assert ctx.current_policy().enforce is False


def test_set_enforce_adds_key_before_first_table(ctx):
    import tomllib
    Path(ctx.etc_dir).mkdir(parents=True, exist_ok=True)
    (Path(ctx.etc_dir) / "policy.toml").write_text("[content]\nthreshold = 8\n")
    assert run(ctx, ["set", "enforce", "true"]) == 0
    data = tomllib.loads((Path(ctx.etc_dir) / "policy.toml").read_text())
    assert data["enforce"] is True and data["content"]["threshold"] == 8


def test_set_enforce_on_is_free_when_locked_but_off_needs_code(ctx):
    Path(ctx.etc_dir).mkdir(parents=True, exist_ok=True)
    (Path(ctx.etc_dir) / "policy.toml").write_text("enforce = false\n")
    ctx.state.set_locked(True)
    auth.enroll(ctx.state)
    ctx.code_reader = lambda: "000000"
    assert run(ctx, ["set", "enforce", "true"]) == 0
    assert run(ctx, ["set", "enforce", "false"]) == 1
    assert ctx.current_policy().enforce is True


def test_set_rejects_other_keys(ctx):
    assert run(ctx, ["set", "threshold", "1"]) == 1


def policy_passthrough(ctx):
    import json as _j
    return set(_j.loads(Path(ctx.compiled_policy_path).read_text())["passthrough"])


def test_schedule_sync_trusting_a_new_site_needs_code_when_locked(ctx, tmp_path, capsys):
    _sync(ctx, tmp_path)
    ctx.state.set_locked(True)
    auth.enroll(ctx.state)
    ctx.code_reader = lambda: "000000"
    bm = _BM.replace("coms: [['z', 'zoom', 'https://www.zoom.com']]", "coms: [['z', 'zoom', 'https://www.zoom.com'], ['sl', 'slack', 'https://app.slack.com']]")
    assert _sync(ctx, tmp_path, bm=bm) == 1
    assert "stops scanning app.slack.com (passthrough)" in capsys.readouterr().out


def test_log_shows_detail_when_present(ctx, capsys):
    with open(ctx.decision_log_path, "w") as f:
        f.write(json.dumps({"ts": "t", "action": "block", "rule": "C-class", "host": "x.com", "path_head": "/", "detail": "document"}) + "\n")
    run(ctx, ["log"])
    assert "C-class\tx.com/\t(document)" in capsys.readouterr().out


_BM_LIFE = _BM.replace("life: [['n', 'netflix', 'https://www.netflix.com']]",
                       "life: [['n', 'netflix', 'https://www.netflix.com'], ['y', 'youtube', 'https://www.youtube.com'], ['az', 'amazon', 'https://www.amazon.com/ref=nav_logo']]")


def test_schedule_sync_snapshots_daily_block(ctx, tmp_path):
    import datetime as dt
    assert _sync(ctx, tmp_path, bm=_BM_LIFE) == 0
    daily = ctx.read_local_dict("class_mode.json")["daily_block"]
    assert daily == {"start": "09:00", "end": "22:00",
                     "hosts": ["amazon.com", "max.com", "netflix.com", "youtu.be", "youtube.com"], "exempt": ["aws.amazon.com"]}
    p = ctx.current_policy()
    noon, late = dt.datetime(2026, 9, 21, 12, 0), dt.datetime(2026, 9, 21, 22, 30)
    assert p.daily_blocks("www.youtube.com", noon) and p.daily_blocks("m.youtube.com", noon)
    assert not p.daily_blocks("www.youtube.com", late)
    assert not p.daily_blocks("console.aws.amazon.com", noon)
    assert not p.daily_blocks("github.com", noon)


def test_schedule_sync_dropping_daily_site_needs_code_when_locked(ctx, tmp_path, capsys):
    _sync(ctx, tmp_path, bm=_BM_LIFE)
    ctx.state.set_locked(True)
    auth.enroll(ctx.state)
    ctx.code_reader = lambda: "000000"
    no_amazon = _BM_LIFE.replace(", ['az', 'amazon', 'https://www.amazon.com/ref=nav_logo']", "")
    assert _sync(ctx, tmp_path, bm=no_amazon) == 1
    assert "stops blocking amazon.com daily" in capsys.readouterr().out


def test_daily_block_shorter_hours_is_a_loosening():
    old = {"start": "09:00", "end": "22:00", "hosts": ["youtube.com"], "exempt": []}
    assert cli._daily_block_loosenings(old, {**old, "end": "21:00"})
    assert cli._daily_block_loosenings(old, {**old, "exempt": ["music.youtube.com"]})
    assert cli._daily_block_loosenings(old, {**old, "start": "08:00", "end": "23:00"}) == []


def test_set_youtube_restrict_moderate(ctx, monkeypatch):
    import subprocess
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: type("R", (), {"returncode": 0})())
    Path(ctx.etc_dir).mkdir(parents=True, exist_ok=True)
    (Path(ctx.etc_dir) / "policy.toml").write_text("enforce = true\n\n[content]\nthreshold = 8\n")
    assert run(ctx, ["set", "youtube_restrict", "moderate"]) == 0
    assert ctx.current_policy().raw["youtube_restrict"] == "moderate"
    ctx.state.set_locked(True)
    auth.enroll(ctx.state)
    ctx.code_reader = lambda: "000000"
    assert run(ctx, ["set", "youtube_restrict", "strict"]) == 0  # tightening: free
    assert run(ctx, ["set", "youtube_restrict", "moderate"]) == 1  # loosening: needs code
    assert run(ctx, ["set", "youtube_restrict", "off"]) == 1


def test_add_term_never_clears_directory_setgid(ctx, monkeypatch):
    # Regression: write_terms chmod'ed private/ to 0750, clearing setgid, so
    # later terms.json replacements got root's group and the proxy (group
    # distraction-guard) couldn't read them -- terms 2+ were never enforced.
    import stat
    priv = Path(ctx.private_dir)
    priv.mkdir(parents=True, exist_ok=True)
    os_mode = priv.stat().st_mode
    import os
    os.chmod(priv, 0o2750)
    values = iter(["one", "two"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(values))
    assert run(ctx, ["add-term", "--strict"]) == 0
    assert run(ctx, ["add-term", "--strict"]) == 0
    assert priv.stat().st_mode & stat.S_ISGID, "setgid was cleared"
    tf = priv / "terms.json"
    assert tf.stat().st_gid == priv.stat().st_gid
    assert stat.S_IMODE(tf.stat().st_mode) == 0o640
    assert len(ctx.read_terms()) == 2


def test_proxy_files_get_the_directory_group(ctx, tmp_path, monkeypatch):
    import os
    calls = []
    real_chown = os.chown
    monkeypatch.setattr(os, "chown", lambda path, uid, gid: calls.append(gid) or real_chown(path, uid, gid))
    ctx.write_local_list("blocks.json", ["x.com"])
    assert calls and calls[-1] == Path(ctx.local_dir).stat().st_gid


def test_doctor_flags_proxy_running_stale_policy(ctx, monkeypatch):
    import subprocess
    from guardctl import watchdog
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: type("R", (), {"returncode": 0, "stdout": "yes Distraction Guard"})())
    seen = {}
    monkeypatch.setattr(watchdog, "_check_admin_endpoint", lambda host, port, token, expected, timeout: seen.setdefault("h", expected) and False)
    run(ctx, ["compile"])
    out = cli.cmd_doctor(ctx, [])
    assert "[FAIL] proxy is enforcing the current policy" in out
    assert seen["h"] == ctx.current_policy().hash


def test_night_block_snapshot_and_wraparound(ctx, tmp_path):
    import datetime as dt
    assert _sync(ctx, tmp_path) == 0
    assert ctx.read_local_dict("class_mode.json")["night_block"] == {"start": "01:00", "end": "07:00"}
    p = ctx.current_policy()
    assert p.night_active(dt.datetime(2026, 9, 22, 3, 0))
    assert not p.night_active(dt.datetime(2026, 9, 22, 7, 0))
    assert not p.night_active(dt.datetime(2026, 9, 22, 0, 59))
    p.night_start, p.night_end = 23 * 60, 6 * 60  # wraps midnight
    assert p.night_active(dt.datetime(2026, 9, 22, 23, 30)) and p.night_active(dt.datetime(2026, 9, 22, 2, 0))
    assert not p.night_active(dt.datetime(2026, 9, 22, 12, 0))


def test_night_block_shortening_is_a_loosening():
    old = {"start": "01:00", "end": "07:00"}
    assert cli._night_block_loosenings(old, {"start": "02:00", "end": "07:00"})
    assert cli._night_block_loosenings(old, {"start": "01:00", "end": "01:00"})  # disabling
    assert cli._night_block_loosenings(old, {"start": "00:00", "end": "08:00"}) == []
    assert cli._night_block_loosenings(None, old) == []


def test_guarded_apply_accepts_proxy_block_page_as_working(monkeypatch):
    # During the night block the probe gets the proxy's own block page --
    # that proves the redirect path works, so it must not revert.
    import subprocess
    fake = _FakeSystem(probe_ok=False)
    real_call = fake.__call__
    def call(argv, **kw):
        r = real_call(argv, **kw)
        if argv[:2] == ["runuser", "-u"]:
            return type("R", (), {"returncode": 0, "stdout": "403 N-night", "stderr": ""})()
        return r
    monkeypatch.setattr(subprocess, "run", call)
    cli._apply_nft_guarded("jack")
    assert not any(_is_revert(a) for a in fake.calls)


def test_find_term_reports_id_without_echoing(ctx, monkeypatch, capsys):
    values = iter(["alpha", "beta", "Beta"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(values))
    run(ctx, ["add-term", "--strict"]); run(ctx, ["add-term", "--strict"])
    capsys.readouterr()
    assert run(ctx, ["find-term"]) == 0
    out = capsys.readouterr().out
    assert "T-0002 (strict)" in out and "beta" not in out.lower()


def test_schedule_sync_refuses_symlinks_and_foreign_files(ctx, tmp_path, capsys):
    import os
    (tmp_path / "bookmarks.js").write_text(_BM)
    os.symlink("/etc/hostname", tmp_path / "apts")
    rc = run(ctx, ["schedule-sync", "--calcurse", str(tmp_path / "apts"), "--bookmarks", str(tmp_path / "bookmarks.js")])
    assert rc == 1 and "symlinks" in capsys.readouterr().err
    rc = run(ctx, ["schedule-sync", "--calcurse", "/etc/hostname", "--bookmarks", str(tmp_path / "bookmarks.js")])
    assert rc == 1 and "isn't owned by jack" in capsys.readouterr().err


def _enroll_with(ctx, monkeypatch, code_fn):
    import subprocess
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: type("R", (), {"returncode": 0})())
    ctx.code_reader = code_fn
    return run(ctx, ["totp-enroll"])


def test_totp_enroll_requires_a_confirming_code(ctx, monkeypatch):
    from guardctl import totp
    def good():
        data = json.loads(ctx.state.path(auth.TOTP_SECRET_FILE).read_text())
        secret = totp.base32_to_secret(data["secret_b32"])
        return totp.hotp(secret, totp.totp_counter(time.time()))
    assert _enroll_with(ctx, monkeypatch, good) == 0
    assert auth.is_enrolled(ctx.state)


def test_totp_enroll_wrong_code_keeps_previous_secret(ctx, monkeypatch):
    assert _enroll_with(ctx, monkeypatch, lambda: "000000") == 1
    assert not auth.is_enrolled(ctx.state)  # nothing before -> nothing after
    auth.enroll(ctx.state)
    before = ctx.state.path(auth.TOTP_SECRET_FILE).read_text()
    assert _enroll_with(ctx, monkeypatch, lambda: "000000") == 1
    assert ctx.state.path(auth.TOTP_SECRET_FILE).read_text() == before


def test_read_code_default_prompts_without_a_readonly_stream(ctx, monkeypatch):
    # Regression: read_code passed open("/dev/tty") (read-only) to getpass,
    # which crashed writing the prompt -- "internal error: not writable".
    calls = []
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="", stream=None: calls.append((prompt, stream)) or "123456")
    monkeypatch.setattr(cli.os.path, "exists", lambda p: True)
    ctx.code_reader = None
    assert ctx.read_code() == "123456"
    assert calls == [("Friend code: ", None)]
