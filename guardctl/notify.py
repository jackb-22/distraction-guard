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


class NotifyNotConfigured(Exception):
    pass


def is_configured(state: StateDir) -> bool:
    return state.path(NOTIFY_CONFIG_FILE).exists()


def setup(state: StateDir, *, server: str = DEFAULT_SERVER) -> str:
    """Generates a random, hard-to-guess topic name and persists it.
    Returns the subscribe URL to show the friend."""
    topic = secrets.token_urlsafe(24)
    state.write_json(NOTIFY_CONFIG_FILE, {"topic": topic, "server": server}, mode=0o600)
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

    sent = 0
    remaining = 0
    for f in sorted(qdir.glob("*.json")):
        try:
            payload = json.loads(f.read_text())
        except (json.JSONDecodeError, OSError):
            f.unlink(missing_ok=True)  # unreadable queue entry, drop it
            continue
        if _send(cfg, payload):
            f.unlink(missing_ok=True)
            sent += 1
        else:
            remaining += 1
    return (sent, remaining)


def _send(cfg: dict, payload: dict) -> bool:
    url = f"{cfg['server'].rstrip('/')}/{cfg['topic']}"
    body = payload["body"].encode("utf-8")
    headers = {
        "Title": payload.get("title", "Distraction Guard"),
        "Priority": payload.get("priority", "default"),
    }
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def send_test(state: StateDir) -> bool:
    """Send one message immediately (not queued) for the setup ceremony,
    where we want a definite yes/no, not "it'll arrive eventually"."""
    cfg = _config(state)
    return _send(cfg, {"title": "Distraction Guard", "body": "Test notification -- if you see this, notifications are working.", "priority": "default"})
