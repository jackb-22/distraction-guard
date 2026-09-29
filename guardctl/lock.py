"""`guardctl lock` / `guardctl unlock`: hand the off switch to the friend.

Locking takes away every route jack has to root:
- sudo, and polkit admin: both come from group `wheel` on this machine
- the `docker` group, which is root-equivalent (`docker run -v /:/host`)
- the systemd-boot menu editor (`init=/bin/bash` on the kernel command line)

What jack keeps:
- NOPASSWD sudo for exactly `guardctl` and `guard-pkg`. guardctl asks for a
  friend code for anything that loosens.
- A polkit rule letting him join new wifi networks. Safe because filtering
  is a per-UID redirect on output: network settings can't route his sockets
  around the proxy.

Every step records how to undo itself. A failure at any point unwinds the
completed steps in reverse, and nothing is marked locked. What was actually
changed is saved as a lock record, so `unlock` restores exactly the
pre-lock state rather than guessing.

All system access goes through a `Sys` object, so tests can run the whole
engine against temp files and a fake command runner.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
ALLOWED_SUDO_COMMANDS = ("/usr/local/bin/guardctl", "/usr/local/bin/guard-pkg")
REMOVED_GROUPS = ("wheel", "docker")
DOCKER_UNITS = ("docker.service", "docker.socket")
LOCK_RECORD = "lock-record.json"


class LockError(Exception):
    pass


@dataclass
class LockPaths:
    sudoers_dropin: str = "/etc/sudoers.d/10-distraction-guard"
    polkit_rule: str = "/etc/polkit-1/rules.d/50-distraction-guard.rules"
    loader_conf: str = "/boot/loader/loader.conf"


@dataclass
class Sys:
    """Thin seam over the real system. Tests replace `run` and point the
    paths at a temp dir."""
    paths: LockPaths = field(default_factory=LockPaths)
    run: Callable = None  # (argv) -> (returncode, stdout, stderr)

    def __post_init__(self):
        if self.run is None:
            self.run = _real_run

    def ok(self, argv: list[str]) -> str:
        rc, out, err = self.run(argv)
        if rc != 0:
            raise LockError(f"{' '.join(argv)} failed: {(err or out).strip()}")
        return out


def _real_run(argv: list[str]) -> tuple[int, str, str]:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        return r.returncode, r.stdout, r.stderr
    except (OSError, subprocess.SubprocessError) as e:
        return 127, "", str(e)


def _render(name: str, user: str) -> str:
    return (TEMPLATE_DIR / name).read_text().replace("@USER@", user)


def _write_root_file(path: str, text: str, mode: int | None) -> None:
    """Atomic write. mode=None skips chmod -- required on the FAT boot
    partition, where chmod fails with EPERM."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    tmp = path + ".dg-tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    if mode is not None:
        os.chmod(tmp, mode)
    os.replace(tmp, path)


# --- prechecks -------------------------------------------------------------

def root_password_set(sys_: Sys) -> bool:
    rc, out, _ = sys_.run(["passwd", "-S", "root"])
    fields = out.split()
    return rc == 0 and len(fields) > 1 and fields[1] == "P"


def root_password_fresh(sys_: Sys, *, today=None, max_days: int = 1) -> bool:
    """True if root's password was changed within `max_days`. Setting it is
    a ceremony step done by the friend, so an old password is one jack set
    (and knows) -- locking with it would leave him a way back to root."""
    import datetime as dt
    rc, out, _ = sys_.run(["passwd", "-S", "root"])
    fields = out.split()
    if rc != 0 or len(fields) < 3:
        return False
    try:
        changed = dt.date.fromisoformat(fields[2])
    except ValueError:
        return False
    return ((today or dt.date.today()) - changed).days <= max_days


def user_groups(sys_: Sys, user: str) -> set[str]:
    return set(sys_.ok(["id", "-nG", user]).split())


def sudo_commands(sys_: Sys, user: str) -> list[str]:
    """Every command `user` may run via sudo, per `sudo -l -U`. 'ALL' means
    unrestricted. Reads the group database, so it reflects gpasswd changes
    immediately (unlike the groups of an already-running session)."""
    out = sys_.ok(["sudo", "-l", "-U", user])
    cmds: list[str] = []
    for line in out.splitlines():
        m = re.match(r"^\s+\(.*?\)\s*(?:[A-Z_]+:\s*)*(.*)$", line)
        if m:
            cmds += [c.strip() for c in m.group(1).split(",") if c.strip()]
    return cmds


# --- the steps -------------------------------------------------------------

@dataclass
class Step:
    name: str
    do: Callable[[], None]
    undo: Callable[[], None] | None


def lock_steps(sys_: Sys, user: str, record: dict, state_dir: Path, audit_log: Path, set_locked) -> list[Step]:
    p = sys_.paths
    loader_backup = state_dir / "loader.conf.pre-lock"

    def sudoers_do():
        text = _render("sudoers.in", user)
        tmp = p.sudoers_dropin + ".dg-check"
        _write_root_file(tmp, text, 0o440)
        try:
            sys_.ok(["visudo", "-cf", tmp])
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        _write_root_file(p.sudoers_dropin, text, 0o440)

    def polkit_do():
        _write_root_file(p.polkit_rule, _render("polkit.rules.in", user), 0o644)

    def loader_do():
        path = Path(p.loader_conf)
        text = path.read_text() if path.exists() else ""
        record["loader_existed"] = path.exists()
        if path.exists():
            shutil.copyfile(path, loader_backup)
        lines = [l for l in text.splitlines() if not re.match(r"^\s*editor\b", l)]
        lines.append("editor no")
        _write_root_file(str(path), "\n".join(lines) + "\n", None)  # FAT: no chmod

    def loader_undo():
        if record.get("loader_existed"):
            shutil.copyfile(loader_backup, p.loader_conf)
        elif os.path.exists(p.loader_conf):
            os.unlink(p.loader_conf)

    def docker_do():
        enabled = [u for u in DOCKER_UNITS if sys_.run(["systemctl", "is-enabled", "--quiet", u])[0] == 0]
        record["docker_units_enabled"] = enabled
        if enabled:
            sys_.ok(["systemctl", "disable", "--now", *enabled])

    def docker_undo():
        if record.get("docker_units_enabled"):
            sys_.ok(["systemctl", "enable", "--now", *record["docker_units_enabled"]])

    def groups_do():
        have = user_groups(sys_, user)
        removed = []
        record["groups_removed"] = removed  # filled as we go, so undo is exact
        for g in REMOVED_GROUPS:
            if g in have:
                sys_.ok(["gpasswd", "-d", user, g])
                removed.append(g)

    def groups_undo():
        for g in record.get("groups_removed", []):
            sys_.ok(["gpasswd", "-a", user, g])

    def verify_do():
        cmds = sudo_commands(sys_, user)
        extra = [c for c in cmds if c not in ALLOWED_SUDO_COMMANDS]
        if extra:
            raise LockError(
                f"{user} still has other sudo rights after the lock: {', '.join(extra)}. "
                "Some rule outside the wheel group grants them (check /etc/sudoers and /etc/sudoers.d). "
                "Everything was rolled back; remove that rule, then lock again."
            )
        left = user_groups(sys_, user) & set(REMOVED_GROUPS)
        if left:
            raise LockError(f"{user} is still in {', '.join(sorted(left))}")

    def audit_do():
        audit_log.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(audit_log, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        os.close(fd)
        sys_.ok(["chattr", "+a", str(audit_log)])

    def audit_undo():
        sys_.run(["chattr", "-a", str(audit_log)])

    return [
        Step("install the restricted sudo rule (guardctl + guard-pkg only)", sudoers_do, lambda: _unlink(p.sudoers_dropin)),
        Step("allow joining wifi networks without admin (polkit rule)", polkit_do, lambda: _unlink(p.polkit_rule)),
        Step("disable the boot menu editor (editor no)", loader_do, loader_undo),
        Step("stop and disable rootful Docker", docker_do, docker_undo),
        Step(f"remove {user} from {' and '.join(REMOVED_GROUPS)}", groups_do, groups_undo),
        Step("verify sudo is limited to guardctl and guard-pkg", verify_do, None),
        Step("make the audit log append-only", audit_do, audit_undo),
        Step("mark the system locked", lambda: set_locked(True), lambda: set_locked(False)),
    ]


def _unlink(path: str) -> None:
    if os.path.exists(path):
        os.unlink(path)


def run_steps(steps: list[Step], *, dry_run: bool = False, log=print) -> None:
    """Run steps in order. On failure, undo completed steps in reverse and
    re-raise as LockError naming the failed step."""
    if dry_run:
        for i, s in enumerate(steps, 1):
            log(f"  would {i}. {s.name}")
        return
    done: list[Step] = []
    for i, s in enumerate(steps, 1):
        try:
            s.do()
        except Exception as e:  # noqa: BLE001 - any failure must roll back
            log(f"  FAILED {i}. {s.name}: {e}")
            rollback_errors = []
            for d in reversed(done):
                if d.undo is None:
                    continue
                try:
                    d.undo()
                    log(f"  rolled back: {d.name}")
                except Exception as ue:  # noqa: BLE001
                    rollback_errors.append(f"{d.name}: {ue}")
            msg = f"step {i} ({s.name}) failed: {e}. All earlier steps were rolled back."
            if rollback_errors:
                msg += " ROLLBACK PROBLEMS (fix as root): " + "; ".join(rollback_errors)
            raise LockError(msg) from e
        done.append(s)
        log(f"  done {i}. {s.name}")


def save_record(state_dir: Path, record: dict) -> None:
    p = state_dir / LOCK_RECORD
    _write_root_file(str(p), json.dumps(record, indent=2), 0o600)


def load_record(state_dir: Path) -> dict:
    p = state_dir / LOCK_RECORD
    return json.loads(p.read_text()) if p.exists() else {}


def unlock_steps(sys_: Sys, user: str, record: dict, state_dir: Path, audit_log: Path, set_locked) -> list[Step]:
    """Reverse of the lock, from what the lock record says it changed. The
    sudoers drop-in stays: harmless once wheel is back."""
    p = sys_.paths
    loader_backup = state_dir / "loader.conf.pre-lock"

    def groups():
        for g in record.get("groups_removed", list(REMOVED_GROUPS[:1])):
            sys_.ok(["gpasswd", "-a", user, g])

    def docker():
        if record.get("docker_units_enabled"):
            sys_.ok(["systemctl", "enable", "--now", *record["docker_units_enabled"]])

    def loader():
        if record.get("loader_existed") and loader_backup.exists():
            shutil.copyfile(loader_backup, p.loader_conf)

    return [
        Step(f"give {user} back {', '.join(record.get('groups_removed', ['wheel']))}", groups, None),
        Step("re-enable rootful Docker (if it was enabled)", docker, None),
        Step("restore the boot menu editor setting", loader, None),
        Step("remove the wifi polkit rule", lambda: _unlink(p.polkit_rule), None),
        Step("make the audit log normal again", lambda: sys_.run(["chattr", "-a", str(audit_log)]), None),
        Step("mark the system unlocked", lambda: set_locked(False), None),
    ]


# --- integrity (doctor) and self-repair (pacman hook) -----------------------

def integrity_checks(sys_: Sys, user: str, audit_log: Path) -> list[tuple[str, bool]]:
    """What must hold while locked. Used by `guardctl doctor`."""
    p = sys_.paths
    try:
        groups = user_groups(sys_, user)
    except LockError:
        groups = set(REMOVED_GROUPS)
    try:
        extra = [c for c in sudo_commands(sys_, user) if c not in ALLOWED_SUDO_COMMANDS]
    except LockError:
        extra = ["(sudo -l failed)"]
    try:
        loader_ok = any(re.match(r"^\s*editor\s+(no|0|false)\s*$", l) for l in Path(p.loader_conf).read_text().splitlines())
    except OSError:
        loader_ok = False
    rc, out, _ = sys_.run(["lsattr", str(audit_log)])
    return [
        (f"{user} is not in {' or '.join(REMOVED_GROUPS)}", not (groups & set(REMOVED_GROUPS))),
        (f"{user}'s sudo is only guardctl and guard-pkg", not extra),
        ("restricted sudo rule present", os.path.exists(p.sudoers_dropin)),
        ("wifi polkit rule present", os.path.exists(p.polkit_rule)),
        ("boot menu editor disabled", loader_ok),
        ("audit log is append-only", rc == 0 and "a" in out.split()[0] if out.split() else False),
    ]


def reassert(sys_: Sys, user: str) -> list[str]:
    """Re-apply the lock's system changes if something (a package update)
    undid them. Returns what was fixed."""
    p = sys_.paths
    fixed = []
    if not os.path.exists(p.sudoers_dropin):
        _write_root_file(p.sudoers_dropin, _render("sudoers.in", user), 0o440)
        fixed.append("sudoers rule")
    if not os.path.exists(p.polkit_rule):
        _write_root_file(p.polkit_rule, _render("polkit.rules.in", user), 0o644)
        fixed.append("polkit rule")
    try:
        text = Path(p.loader_conf).read_text()
    except OSError:
        text = ""
    if not any(re.match(r"^\s*editor\s+(no|0|false)\s*$", l) for l in text.splitlines()):
        lines = [l for l in text.splitlines() if not re.match(r"^\s*editor\b", l)] + ["editor no"]
        _write_root_file(p.loader_conf, "\n".join(lines) + "\n", None)
        fixed.append("boot editor")
    for g in sorted(user_groups(sys_, user) & set(REMOVED_GROUPS)):
        sys_.ok(["gpasswd", "-d", user, g])
        fixed.append(f"{g} group")
    return fixed
