"""ntfy.sh notifications to the friend: a durable local queue (so a message
survives being offline) plus a flush that POSTs each queued message and
only deletes it on success. Uses urllib only -- no third-party HTTP client,
since this runs from the same unadorned root script as the rest of
guardctl.
"""
from __future__ import annotations

import json
import os
import secrets
import time
import urllib.error
import urllib.request
from pathlib import Path

from guardctl.state import StateDir

NOTIFY_CONFIG_FILE = "notify.json"
QUEUE_DIR = "notify-queue"
DEFAULT_SERVER = "https://ntfy.sh"
REQUEST_TIMEOUT = 10
# Found live: every command and heartbeat queued before notify-setup was
# still waiting when the friend subscribed, and the queue sent oldest-first
# -- so a new notification (e.g. an unblock) sat behind a backlog while
# ntfy.sh's anonymous rate limit (~60 burst) rejected the rest. Keep only
# the newest MAX_QUEUE, and stop at the first failed send instead of
# hammering the server with the remainder.
MAX_QUEUE = 20
STATUS_FILE = "notify-status.json"
_last_error = ""


class NotifyNotConfigured(Exception):
    pass


def is_configured(state: StateDir) -> bool:
    return state.path(NOTIFY_CONFIG_FILE).exists()


def setup(state: StateDir, *, server: str = DEFAULT_SERVER) -> str:
    """Generates a random, hard-to-guess topic name and persists it.
    Returns the subscribe URL to show the friend."""
    topic = secrets.token_urlsafe(24)
    state.write_json(NOTIFY_CONFIG_FILE, {"topic": topic, "server": server}, mode=0o600)
    # Anything queued before this was never deliverable to this subscriber.
    qdir = state.path(QUEUE_DIR)
    if qdir.exists():
        for f in qdir.glob("*.json"):
            f.unlink(missing_ok=True)
    return f"{server}/{topic}"


def _config(state: StateDir) -> dict:
    cfg = state.read_json(NOTIFY_CONFIG_FILE, None)
    if cfg is None:
        raise NotifyNotConfigured("run `guardctl notify-setup` first")
    return cfg


def enqueue(state: StateDir, title: str, body: str, *, priority: str = "default", flush: bool = True) -> None:
    """Write a message to the durable queue, then attempt to send it right
    away (best-effort; failures just leave it queued for the timer)."""
    qdir = state.path(QUEUE_DIR)
    qdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    fname = f"{time.time():.6f}-{secrets.token_hex(4)}.json"
    payload = {"title": title, "body": body, "priority": priority}
    tmp = qdir / (fname + ".tmp")
    tmp.write_text(json.dumps(payload))
    os.chmod(tmp, 0o600)
    os.replace(tmp, qdir / fname)
    if flush:
        flush_queue(state)


def flush_queue(state: StateDir) -> tuple[int, int]:
    """Attempt to send every queued message. Returns (sent, remaining)."""
    qdir = state.path(QUEUE_DIR)
    if not qdir.exists():
        return (0, 0)
    try:
        cfg = _config(state)
    except NotifyNotConfigured:
        return (0, len(list(qdir.glob("*.json"))))

    files = sorted(qdir.glob("*.json"))
    dropped = files[:-MAX_QUEUE] if len(files) > MAX_QUEUE else []
    for f in dropped:
        f.unlink(missing_ok=True)
    files = files[len(dropped):]
    if dropped:
        note = {"title": "Distraction Guard", "priority": "default",
                "body": f"{len(dropped)} older notifications were dropped from a backlog."}
        files.insert(0, None)  # sent first, then the rest in order
    sent = 0
    for i, f in enumerate(files):
        if f is None:
            payload = note
        else:
            try:
                payload = json.loads(f.read_text())
            except (json.JSONDecodeError, OSError):
                f.unlink(missing_ok=True)  # unreadable queue entry, drop it
                continue
        if not _send(cfg, payload):
            _record(state, False, _last_error)
            return (sent, len([x for x in files[i:] if x is not None]))
        if f is not None:
            f.unlink(missing_ok=True)
        sent += 1
    if sent:
        _record(state, True, f"sent {sent}")
    return (sent, 0)


def _record(state: StateDir, ok: bool, detail: str) -> None:
    try:
        state.write_json(STATUS_FILE, {"at": time.time(), "ok": ok, "detail": detail}, mode=0o600)
    except OSError:
        pass


def status(state: StateDir) -> dict:
    qdir = state.path(QUEUE_DIR)
    return {
        "configured": is_configured(state),
        "queued": len(list(qdir.glob("*.json"))) if qdir.exists() else 0,
        "last": state.read_json(STATUS_FILE, None),
    }


def _send(cfg: dict, payload: dict) -> bool:
    url = f"{cfg['server'].rstrip('/')}/{cfg['topic']}"
    body = payload["body"].encode("utf-8")
    headers = {
        "Title": payload.get("title", "Distraction Guard"),
        "Priority": payload.get("priority", "default"),
    }
    global _last_error
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            ok = 200 <= resp.status < 300
            _last_error = "" if ok else f"HTTP {resp.status}"
            return ok
    except urllib.error.HTTPError as e:
        _last_error = f"HTTP {e.code} {e.reason}" + (" (ntfy rate limit)" if e.code == 429 else "")
        return False
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        _last_error = f"{type(e).__name__}: {getattr(e, 'reason', e)}"
        return False


def send_test(state: StateDir) -> bool:
    """Send one message immediately (not queued) for the setup ceremony,
    where we want a definite yes/no, not "it'll arrive eventually"."""
    cfg = _config(state)
    return _send(cfg, {"title": "Distraction Guard", "body": "Test notification -- if you see this, notifications are working.", "priority": "default"})
