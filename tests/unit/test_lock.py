"""guardctl lock / unlock, against a simulated system: temp files for the
sudoers/polkit/loader paths, and a fake command runner that tracks group
membership and systemd units, so `sudo -l` reflects gpasswd changes."""
import json
import re
from pathlib import Path

import pytest

from guardctl import auth, cli, lock as lock_mod, notify, totp
from guardctl.cli import GuardCtx, run


class FakeSystem:
    def __init__(self, *, groups=("jack", "wheel", "docker"), docker_enabled=True, root_pw="P",
                 extra_sudo_rule=None, fail_on=None):
        self.groups = set(groups)
        self.units = {"docker.service": docker_enabled, "docker.socket": False}
        self.running = {u: e for u, e in self.units.items()}
        self.root_pw = root_pw
        self.extra_sudo_rule = extra_sudo_rule
        self.fail_on = fail_on  # argv[0] (+argv[1]) that should fail
        self.calls = []
        self.dropin = None  # set by the test to the drop-in path
        self.chattr = {}
        self.pw_changed = None  # ISO date; None = today

    def __call__(self, argv):
        self.calls.append(list(argv))
        key = " ".join(argv[:2])
        if self.fail_on and (argv[0] == self.fail_on or key == self.fail_on):
            return 1, "", f"simulated failure of {key}"
        if argv[:2] == ["passwd", "-S"]:
            import datetime as _dt
            return 0, f"root {self.root_pw} {self.pw_changed or _dt.date.today().isoformat()} 0 99999 7 -1\n", ""
        if argv[:2] == ["id", "-nG"]:
            return 0, " ".join(sorted(self.groups)) + "\n", ""
        if argv[0] == "gpasswd":
            (self.groups.discard if argv[1] == "-d" else self.groups.add)(argv[3])
            return 0, "", ""
        if argv[:2] == ["systemctl", "is-enabled"]:
            return (0 if self.units.get(argv[-1]) else 1), "", ""
        if argv[:2] == ["systemctl", "disable"]:
            for u in argv[3:]:
                self.units[u] = False
            return 0, "", ""
        if argv[:2] == ["systemctl", "enable"]:
            for u in argv[3:]:
                self.units[u] = True
            return 0, "", ""
        if argv[0] == "visudo":
            return 0, "", ""
        if argv[0] == "chattr":
            self.chattr[argv[2]] = argv[1]
            return 0, "", ""
        if argv[:2] == ["sudo", "-l"]:
            lines = ["User jack may run the following commands on nabu:"]
            if "wheel" in self.groups:
                lines.append("    (ALL : ALL) ALL")
            if self.dropin and Path(self.dropin).exists():
                lines.append("    (root) NOPASSWD: /usr/local/bin/guardctl, /usr/local/bin/guard-pkg")
            if self.extra_sudo_rule:
                lines.append(f"    {self.extra_sudo_rule}")
            return 0, "\n".join(lines) + "\n", ""
        return 0, "", ""


@pytest.fixture
def env(tmp_path, monkeypatch):
    fake = FakeSystem()
    paths = lock_mod.LockPaths(
        sudoers_dropin=str(tmp_path / "sudoers.d" / "10-distraction-guard"),
        polkit_rule=str(tmp_path / "polkit" / "50-distraction-guard.rules"),
        loader_conf=str(tmp_path / "boot" / "loader.conf"),
    )
    fake.dropin = paths.sudoers_dropin
    (tmp_path / "boot").mkdir()
    (tmp_path / "boot" / "loader.conf").write_text("timeout 3\neditor yes\ndefault arch.conf\n")
    ctx = GuardCtx(
        etc_dir=str(tmp_path / "etc"), local_dir=str(tmp_path / "etc" / "local"),
        private_dir=str(tmp_path / "etc" / "private"), lists_dir=str(tmp_path / "lists"),
        lexicon_path=str(tmp_path / "lex.txt"), compiled_policy_path=str(tmp_path / "compiled" / "policy.json"),
        state_dir=str(tmp_path / "state"), firefox_policy_path=str(tmp_path / "ff.json"),
        decision_log_path=str(tmp_path / "decisions.jsonl"), sudo_user="jack",
        notifier=lambda *a: None, resolver=lambda h: ([], []),
        lock_sys=lock_mod.Sys(paths=paths, run=fake),
    )
    Path(ctx.etc_dir).mkdir(parents=True)
    (Path(ctx.etc_dir) / "policy.toml").write_text("enforce = true\n")
    ctx.recompile()
    monkeypatch.setattr(cli, "cmd_doctor", lambda c, a: "all checks passed")
    uri = auth.enroll(ctx.state)
    secret = totp.base32_to_secret(re.search(r"secret=([A-Z0-9]+)&", uri).group(1))
    notify.setup(ctx.state)
    ctx.code_reader = lambda: totp.hotp(secret, totp.totp_counter(__import__("time").time()))
    return ctx, fake, paths, tmp_path


def test_lock_happy_path(env):
    ctx, fake, paths, tmp = env
    assert run(ctx, ["lock"]) == 0
    assert ctx.state.is_locked()
    assert fake.groups == {"jack"}
    assert fake.units["docker.service"] is False
    assert "jack ALL=(root) NOPASSWD: /usr/local/bin/guardctl, /usr/local/bin/guard-pkg" in Path(paths.sudoers_dropin).read_text()
    assert '"jack"' in Path(paths.polkit_rule).read_text()
    loader = Path(paths.loader_conf).read_text()
    assert "editor no" in loader and "editor yes" not in loader and "timeout 3" in loader
    assert fake.chattr[str(ctx.state.path("audit.log"))] == "+a"
    rec = lock_mod.load_record(ctx.state.root)
    assert rec["groups_removed"] == ["wheel", "docker"] and rec["docker_units_enabled"] == ["docker.service"]


def test_lock_always_needs_a_code_even_unlocked(env):
    ctx, fake, paths, tmp = env
    ctx.code_reader = lambda: "000000"
    assert not ctx.state.is_locked()
    assert run(ctx, ["lock"]) == 1
    assert not ctx.state.is_locked()
    assert fake.groups == {"jack", "wheel", "docker"}
    assert not Path(paths.sudoers_dropin).exists()


def test_dry_run_changes_nothing_and_needs_no_code(env, capsys):
    ctx, fake, paths, tmp = env
    ctx.code_reader = lambda: (_ for _ in ()).throw(AssertionError("no code for dry run"))
    before = Path(paths.loader_conf).read_text()
    assert run(ctx, ["lock", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "would 1." in out and "nothing was changed" in out
    assert Path(paths.loader_conf).read_text() == before
    assert fake.groups == {"jack", "wheel", "docker"} and not ctx.state.is_locked()
    assert not any(c[0] in ("gpasswd", "chattr", "visudo") for c in fake.calls)


@pytest.mark.parametrize("breakage", ["enforce", "enroll", "rootpw", "oldrootpw", "doctor"])
def test_failing_precheck_aborts_before_any_change(env, monkeypatch, breakage):
    ctx, fake, paths, tmp = env
    if breakage == "enforce":
        (Path(ctx.etc_dir) / "policy.toml").write_text("enforce = false\n"); ctx.recompile()
    elif breakage == "enroll":
        ctx.state.path(auth.TOTP_SECRET_FILE).unlink()
    elif breakage == "rootpw":
        fake.root_pw = "L"
    elif breakage == "oldrootpw":
        fake.pw_changed = "2026-01-01"  # set long ago -- by jack, not the friend
    elif breakage == "doctor":
        monkeypatch.setattr(cli, "cmd_doctor", lambda c, a: "one or more checks FAILED")
    assert run(ctx, ["lock"]) == 1
    assert fake.groups == {"jack", "wheel", "docker"}
    assert not Path(paths.sudoers_dropin).exists() and not ctx.state.is_locked()


def test_sudo_rule_goes_in_before_groups_are_removed(env):
    ctx, fake, paths, tmp = env
    run(ctx, ["lock"])
    visudo = next(i for i, c in enumerate(fake.calls) if c[0] == "visudo")
    gpasswd = next(i for i, c in enumerate(fake.calls) if c[0] == "gpasswd")
    assert visudo < gpasswd


@pytest.mark.parametrize("fail_on", ["visudo", "systemctl disable", "gpasswd", "chattr"])
def test_failure_rolls_everything_back(env, fail_on):
    ctx, fake, paths, tmp = env
    fake.fail_on = fail_on
    before_loader = Path(paths.loader_conf).read_text()
    assert run(ctx, ["lock"]) == 1
    assert not ctx.state.is_locked()
    assert fake.groups == {"jack", "wheel", "docker"}
    assert fake.units["docker.service"] is True
    assert Path(paths.loader_conf).read_text() == before_loader
    assert not Path(paths.sudoers_dropin).exists() and not Path(paths.polkit_rule).exists()


def test_other_sudo_rule_found_at_verify_rolls_back(env, capsys):
    ctx, fake, paths, tmp = env
    fake.extra_sudo_rule = "(ALL) NOPASSWD: /usr/bin/pacman"
    assert run(ctx, ["lock"]) == 1
    assert "/usr/bin/pacman" in capsys.readouterr().err
    assert fake.groups == {"jack", "wheel", "docker"} and not ctx.state.is_locked()


def test_lock_twice_refused(env):
    ctx, fake, paths, tmp = env
    run(ctx, ["lock"])
    assert run(ctx, ["lock"]) == 1


def test_unlock_needs_code_and_restores(env):
    ctx, fake, paths, tmp = env
    good = ctx.code_reader
    assert run(ctx, ["lock"]) == 0
    ctx.code_reader = lambda: "000000"
    assert run(ctx, ["unlock"]) == 1
    assert ctx.state.is_locked()
    # the same code can't be reused, so jump the clock to the next window
    import time as _t
    real = _t.time
    _t.time = lambda: real() + 60
    try:
        ctx.code_reader = good
        assert run(ctx, ["unlock"]) == 0
    finally:
        _t.time = real
    assert not ctx.state.is_locked()
    assert fake.groups == {"jack", "wheel", "docker"}
    assert fake.units["docker.service"] is True
    assert "editor yes" in Path(paths.loader_conf).read_text()
    assert not Path(paths.polkit_rule).exists()
    assert fake.chattr[str(ctx.state.path("audit.log"))] == "-a"


def test_sudo_commands_parser():
    out = ("User jack may run the following commands on nabu:\n"
           "    (ALL : ALL) ALL\n"
           "    (root) NOPASSWD: /usr/local/bin/guardctl, /usr/local/bin/guard-pkg\n")
    s = lock_mod.Sys(run=lambda a: (0, out, ""))
    assert lock_mod.sudo_commands(s, "jack") == ["ALL", "/usr/local/bin/guardctl", "/usr/local/bin/guard-pkg"]


def test_sudoers_template_passes_visudo(tmp_path):
    import shutil
    import subprocess
    visudo = shutil.which("visudo") or "/usr/bin/visudo"
    if not Path(visudo).exists():
        pytest.skip("visudo not installed")
    f = tmp_path / "rule"
    f.write_text(lock_mod._render("sudoers.in", "jack"))
    r = subprocess.run([visudo, "-cf", str(f)], capture_output=True, text=True)
    if "permission" in (r.stderr + r.stdout).lower() and r.returncode != 0:
        pytest.skip("visudo needs root here")
    assert r.returncode == 0, r.stdout + r.stderr


def test_doctor_reports_lock_integrity(env, monkeypatch):
    ctx, fake, paths, tmp = env
    run(ctx, ["lock"])
    monkeypatch.undo()  # real cmd_doctor
    import subprocess
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: type("R", (), {"returncode": 0, "stdout": "yes Distraction Guard"})())
    real = fake.__call__
    fake_lsattr = lambda argv: (0, "-----a--------e----- x\n", "") if argv[0] == "lsattr" else real(argv)
    ctx.lock_sys.run = fake_lsattr
    out = cli.cmd_doctor(ctx, [])
    assert "[OK] lock: jack is not in wheel or docker" in out
    assert "[OK] lock: boot menu editor disabled" in out
    fake.groups.add("wheel")
    out = cli.cmd_doctor(ctx, [])
    assert "[FAIL] lock: jack is not in wheel or docker" in out
    assert "[FAIL] lock: jack's sudo is only guardctl and guard-pkg" in out


def test_reassert_repairs_drift(env):
    ctx, fake, paths, tmp = env
    run(ctx, ["lock"])
    Path(paths.polkit_rule).unlink()
    Path(paths.loader_conf).write_text("timeout 3\neditor yes\n")
    fake.groups.add("wheel")
    fixed = lock_mod.reassert(ctx.lock_sys, "jack")
    assert set(fixed) == {"polkit rule", "boot editor", "wheel group"}
    assert "wheel" not in fake.groups and Path(paths.polkit_rule).exists()
    assert lock_mod.reassert(ctx.lock_sys, "jack") == []
