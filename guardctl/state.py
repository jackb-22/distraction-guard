"""Root-owned mutable state: file locking, the lock flag, and the
append-only audit log. All paths are under /var/lib/distraction-guard/state
in production; tests pass a tmp_path root instead.
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import time
from pathlib import Path


class StateDir:
    def __init__(self, root: str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def path(self, *parts: str) -> Path:
        return self.root.joinpath(*parts)

    @contextlib.contextmanager
    def locked(self, name: str = ".lock"):
        """Exclusive advisory lock for a mutating command. Held for the
        duration of the `with` block."""
        lock_path = self.path(name)
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    # --- lock.json ---------------------------------------------------

    def is_locked(self) -> bool:
        p = self.path("lock.json")
        if not p.exists():
            return False
        try:
            return bool(json.loads(p.read_text()).get("locked", False))
        except (json.JSONDecodeError, OSError):
            return True  # present but unreadable: fail closed, never "unlocked"

    def set_locked(self, locked: bool) -> None:
        p = self.path("lock.json")
        data = {"locked": locked, "locked_at": time.time() if locked else None}
        _atomic_write_json(p, data, mode=0o600)

    # --- audit log -----------------------------------------------------

    def audit(self, *, command: str, classification: str, auth: str, summary: str, sudo_user: str | None) -> None:
        p = self.path("audit.log")
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "sudo_user": sudo_user,
            "command": command,
            "classification": classification,
            "auth": auth,  # none | totp | root
            "summary": summary,
        }
        line = json.dumps(entry, separators=(",", ":")) + "\n"
        # `guardctl lock` makes this file append-only (chattr +a). Open it
        # with O_APPEND and set the mode only at creation: chmod on an
        # append-only file fails with EPERM, which used to mean every
        # command would crash the moment the system was locked.
        fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(line)

    def read_audit(self, limit: int = 50) -> list[dict]:
        p = self.path("audit.log")
        if not p.exists():
            return []
        lines = p.read_text().splitlines()[-limit:]
        out = []
        for line in lines:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    # --- generic small JSON blobs (auth state, notify queue index) -----

    def read_json(self, name: str, default):
        p = self.path(name)
        if not p.exists():
            return default
        try:
            return json.loads(p.read_text())
        except (json.JSONDecodeError, OSError):
            return default

    def write_json(self, name: str, data, mode: int = 0o600) -> None:
        _atomic_write_json(self.path(name), data, mode=mode)


def _atomic_write_json(path: Path, data, mode: int) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    os.chmod(tmp, mode)
    os.replace(tmp, path)
