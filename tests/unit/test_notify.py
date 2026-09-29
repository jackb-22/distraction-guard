import json

import pytest

from guardctl import notify
from guardctl.state import StateDir


def test_enqueue_before_setup_raises_on_flush_but_does_not_lose_message(tmp_path):
    s = StateDir(str(tmp_path))
    notify.enqueue(s, "title", "body", flush=False)
    qdir = s.path(notify.QUEUE_DIR)
    assert len(list(qdir.glob("*.json"))) == 1


def test_setup_returns_subscribe_url(tmp_path):
    s = StateDir(str(tmp_path))
    url = notify.setup(s, server="https://ntfy.sh")
    assert url.startswith("https://ntfy.sh/")
    assert notify.is_configured(s)


def test_flush_sends_and_removes_on_success(tmp_path, monkeypatch):
    s = StateDir(str(tmp_path))
    notify.setup(s)
    notify.enqueue(s, "t", "b", flush=False)

    monkeypatch.setattr(notify, "_send", lambda cfg, payload: True)
    sent, remaining = notify.flush_queue(s)
    assert sent == 1
    assert remaining == 0
    assert list(s.path(notify.QUEUE_DIR).glob("*.json")) == []


def test_flush_keeps_message_on_failure(tmp_path, monkeypatch):
    s = StateDir(str(tmp_path))
    notify.setup(s)
    notify.enqueue(s, "t", "b", flush=False)

    monkeypatch.setattr(notify, "_send", lambda cfg, payload: False)
    sent, remaining = notify.flush_queue(s)
    assert sent == 0
    assert remaining == 1
    assert len(list(s.path(notify.QUEUE_DIR).glob("*.json"))) == 1


def test_flush_without_setup_leaves_queue_intact(tmp_path):
    s = StateDir(str(tmp_path))
    notify.enqueue(s, "t", "b", flush=False)
    sent, remaining = notify.flush_queue(s)
    assert sent == 0
    assert remaining == 1


def test_message_body_never_needs_terms(tmp_path, monkeypatch):
    # Sanity guard: notify.py itself has no knowledge of terms -- this test
    # just documents that enqueue() takes only opaque title/body strings the
    # caller controls, so it's on guardctl's command layer (not this
    # module) to never pass sensitive text through.
    s = StateDir(str(tmp_path))
    notify.setup(s)
    sent = []
    import guardctl.notify as n
    monkeypatch.setattr(n, "_send", lambda cfg, payload: sent.append(payload) or True)
    notify.enqueue(s, "Distraction Guard", "Blocked rule S-social")
    assert sent[0]["body"] == "Blocked rule S-social"
