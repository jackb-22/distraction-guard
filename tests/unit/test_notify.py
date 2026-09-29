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


def test_backlog_capped_newest_kept_and_note_sent_first(tmp_path, monkeypatch):
    import time
    s = StateDir(str(tmp_path))
    notify.setup(s)
    for i in range(30):
        notify.enqueue(s, "t", f"msg{i}", flush=False)
        time.sleep(0.001)
    bodies = []
    monkeypatch.setattr(notify, "_send", lambda cfg, p: bodies.append(p["body"]) or True)
    assert notify.flush_queue(s) == (21, 0)
    assert "10 older notifications were dropped" in bodies[0]
    assert bodies[1] == "msg10" and bodies[-1] == "msg29"


def test_flush_stops_at_first_failure_and_records_it(tmp_path, monkeypatch):
    s = StateDir(str(tmp_path))
    notify.setup(s)
    for i in range(3):
        notify.enqueue(s, "t", f"m{i}", flush=False)
    calls = []
    def fail(cfg, p):
        calls.append(p)
        notify._last_error = "HTTP 429 Too Many Requests (ntfy rate limit)"
        return False
    monkeypatch.setattr(notify, "_send", fail)
    assert notify.flush_queue(s) == (0, 3)
    assert len(calls) == 1
    st = notify.status(s)
    assert st["queued"] == 3 and st["last"]["ok"] is False and "429" in st["last"]["detail"]


def test_setup_clears_undeliverable_backlog(tmp_path):
    s = StateDir(str(tmp_path))
    notify.enqueue(s, "t", "old", flush=False)
    notify.setup(s)
    assert notify.status(s)["queued"] == 0


def test_real_send_reports_rate_limit(tmp_path):
    import http.server, threading
    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(429); self.end_headers()
        def log_message(self, *a): pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.handle_request, daemon=True).start()
    ok = notify._send({"server": f"http://127.0.0.1:{srv.server_port}", "topic": "t"}, {"title": "x", "body": "y"})
    assert ok is False and "429" in notify._last_error and "rate limit" in notify._last_error
