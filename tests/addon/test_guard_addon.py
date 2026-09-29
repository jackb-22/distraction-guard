import asyncio
import json
from pathlib import Path

import pytest
from mitmproxy import http
from mitmproxy.proxy.mode_specs import ProxyMode
from mitmproxy.test import taddons, tflow

import guard_addon

REPO_BLOCK_PAGE = Path(__file__).resolve().parents[2] / "addon" / "block_page.html"


def _resp(content=b"message", headers=None):
    # tutils.tresp() builds http.Response(**kwargs) directly, which expects
    # headers to already be a real Headers object -- Response.make() handles
    # a plain str dict correctly (same as the addon's own block responses),
    # so use that instead for readable test setup.
    return http.Response.make(200, content, headers or {})


def _make_addon(policy_path, **opts):
    addon = guard_addon.Guard()
    tctx = taddons.context(addon)
    tctx.__enter__()
    tctx.configure(addon, guard_policy=policy_path, **opts)
    addon.running()
    return addon, tctx


def _flow(host="example.com", path="/", method="GET", headers=None, proxy_mode="transparent"):
    f = tflow.tflow()
    f.request.host = host
    f.request.headers.clear()
    for k, v in (headers or {}).items():
        f.request.headers[k] = v
    f.request.path = path
    f.request.method = method
    f.request.scheme = "https"
    f.client_conn.proxy_mode = ProxyMode.parse(f"{proxy_mode}@127.0.0.1:8080")
    return f


# --- requestheaders: blocking ---

def test_blocked_host_document_gets_html_block_page(fixture_policy):
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="www.reddit.com", headers={"sec-fetch-dest": "document"})
    addon.requestheaders(f)
    assert f.response is not None
    assert f.response.status_code == 403
    assert b"S-social" in f.response.content


def test_blocked_host_json_accept_gets_json_403(fixture_policy):
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="www.reddit.com", headers={"accept": "application/json"})
    addon.requestheaders(f)
    assert f.response.status_code == 403
    body = json.loads(f.response.content)
    assert body["rule"] == "S-social"


def test_allowed_host_passes_through(fixture_policy):
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="example.com", headers={"sec-fetch-dest": "document"})
    addon.requestheaders(f)
    assert f.response is None


def test_user_block_domain(fixture_policy):
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="blocked-example.com", headers={"sec-fetch-dest": "document"})
    addon.requestheaders(f)
    assert f.response is not None and f.response.status_code == 403


def test_path_rule_blocks_matching_path(fixture_policy):
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="www.example.com", path="/blocked/x", headers={"sec-fetch-dest": "document"})
    addon.requestheaders(f)
    assert f.response is not None and f.response.status_code == 403
    assert b"R-1" in f.response.content


def test_path_rule_does_not_block_other_paths(fixture_policy):
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="www.example.com", path="/ok", headers={"sec-fetch-dest": "document"})
    addon.requestheaders(f)
    assert f.response is None


def test_connect_method_blocked(fixture_policy):
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="example.com", method="CONNECT")
    addon.requestheaders(f)
    assert f.response is not None and f.response.status_code == 403


# --- shadow mode ---

def test_shadow_mode_logs_but_does_not_block(fixture_policy, tmp_path):
    import json as _json
    raw = _json.loads(open(fixture_policy).read())
    raw["enforce"] = False
    open(fixture_policy, "w").write(_json.dumps(raw))
    log_path = tmp_path / "decisions.jsonl"
    addon, tctx = _make_addon(fixture_policy, guard_log=str(log_path))
    f = _flow(host="www.reddit.com", headers={"sec-fetch-dest": "document"})
    addon.requestheaders(f)
    assert f.response is None
    content = log_path.read_text()
    assert "would_block" in content
    assert "S-social" in content


# --- search / SafeSearch ---

def test_google_safe_off_rewritten(fixture_policy):
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="www.google.com", path="/search?q=cats&safe=off")
    addon.requestheaders(f)
    assert f.response is None
    assert "safe=active" in f.request.path


def test_google_image_vertical_with_strict_term_blocks(fixture_policy):
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="www.google.com", path="/search?q=zorblax&udm=2")
    addon.requestheaders(f)
    assert f.response is not None and f.response.status_code == 403


def test_contextual_term_alone_in_plain_query_not_blocked(fixture_policy):
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="www.google.com", path="/search?q=widget")
    addon.requestheaders(f)
    assert f.response is None


def test_contextual_term_with_context_word_blocked(fixture_policy):
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="www.google.com", path="/search?q=widget+ctxword")
    addon.requestheaders(f)
    assert f.response is not None and f.response.status_code == 403


# --- YouTube ---

def test_youtube_shorts_blocked(fixture_policy):
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="www.youtube.com", path="/shorts/abc123")
    addon.requestheaders(f)
    assert f.response is not None and f.response.status_code == 403


def test_youtube_watch_allowed_and_restrict_header_set(fixture_policy):
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="www.youtube.com", path="/watch?v=xyz")
    addon.requestheaders(f)
    assert f.response is None
    assert f.request.headers.get("YouTube-Restrict") == "Strict"


# --- responseheaders / streaming ---

def test_non_html_response_streamed(fixture_policy):
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="example.com", headers={"sec-fetch-dest": "document"})
    addon.requestheaders(f)
    f.response = _resp(headers={"content-type": "video/mp4"})
    addon.responseheaders(f)
    assert f.response.stream is True


def test_html_response_not_streamed_when_scannable(fixture_policy):
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="example.com", headers={"sec-fetch-dest": "document"})
    addon.requestheaders(f)
    f.response = _resp(headers={"content-type": "text/html"})
    addon.responseheaders(f)
    assert f.response.stream is not True


def test_allow_temp_flow_streams_everything(fixture_policy, tmp_path):
    import json as _json
    raw = _json.loads(open(fixture_policy).read())
    raw["temp_allows"] = [{"host": "www.reddit.com", "expires_at": 9999999999}]
    open(fixture_policy, "w").write(_json.dumps(raw))
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="www.reddit.com", headers={"sec-fetch-dest": "document"})
    addon.requestheaders(f)
    assert f.response is None
    assert f.metadata.get("dg_allow") is True
    f.response = _resp(headers={"content-type": "text/html"})
    addon.responseheaders(f)
    assert f.response.stream is True


# --- response: content scoring ---

def test_response_strict_term_in_title_blocks(fixture_policy):
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="example.com", headers={"sec-fetch-dest": "document"})
    addon.requestheaders(f)
    html = "<html><head><title>all about zorblax</title></head><body>x</body></html>"
    f.response = _resp(content=html.encode(), headers={"content-type": "text/html"})
    addon.response(f)
    assert f.response.status_code == 403


def test_response_rta_label_blocks(fixture_policy):
    from dg_policy.content import RTA_LABEL
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="example.com", headers={"sec-fetch-dest": "document"})
    addon.requestheaders(f)
    html = f"<html><head><meta name='rating' content='{RTA_LABEL}'></head><body>hi</body></html>"
    f.response = _resp(content=html.encode(), headers={"content-type": "text/html"})
    addon.response(f)
    assert f.response.status_code == 403


def test_response_clean_page_passes(fixture_policy):
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="example.com", headers={"sec-fetch-dest": "document"})
    addon.requestheaders(f)
    html = "<html><head><title>Cats</title></head><body>hello world</body></html>"
    f.response = _resp(content=html.encode(), headers={"content-type": "text/html"})
    addon.response(f)
    assert f.response.status_code == 200


def test_youtube_watch_not_family_safe_blocks(fixture_policy):
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="www.youtube.com", path="/watch?v=xyz", headers={"sec-fetch-dest": "document"})
    addon.requestheaders(f)
    html = '<script>var x = {"isFamilySafe":false,"title":"whatever"};</script>'
    f.response = _resp(content=html.encode(), headers={"content-type": "text/html"})
    addon.response(f)
    assert f.response.status_code == 403


# --- error containment ---

def test_requestheaders_exception_contained_as_block(fixture_policy, monkeypatch):
    addon, tctx = _make_addon(fixture_policy)

    def boom(*a, **kw):
        raise RuntimeError("simulated bug")

    monkeypatch.setattr(addon, "_requestheaders", boom)
    f = _flow(host="example.com")
    addon.requestheaders(f)  # must not raise
    assert f.response is not None and f.response.status_code == 403


def test_response_exception_contained_as_block(fixture_policy, monkeypatch):
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="example.com", headers={"sec-fetch-dest": "document"})
    addon.requestheaders(f)
    f.response = _resp(content=b"<html></html>", headers={"content-type": "text/html"})

    def boom(*a, **kw):
        raise RuntimeError("simulated bug")

    monkeypatch.setattr(addon, "_response", boom)
    addon.response(f)  # must not raise
    assert f.response.status_code == 403


def test_no_policy_loaded_fails_closed(tmp_path):
    addon = guard_addon.Guard()
    tctx = taddons.context(addon)
    tctx.__enter__()
    tctx.configure(addon, guard_policy=str(tmp_path / "does-not-exist.json"))
    addon.running()
    f = _flow(host="example.com", headers={"sec-fetch-dest": "document"})
    addon.requestheaders(f)
    assert f.response is not None and f.response.status_code == 403


# --- regular mode / health ---

def test_regular_mode_health_endpoint_valid_token(fixture_policy):
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="guard.health", proxy_mode="regular", headers={"X-DG-Token": "secrettoken123"})
    addon.requestheaders(f)
    assert f.response is not None and f.response.status_code == 200
    assert b"fixturehash" in f.response.content


def test_regular_mode_health_endpoint_bad_token(fixture_policy):
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="guard.health", proxy_mode="regular", headers={"X-DG-Token": "wrong"})
    addon.requestheaders(f)
    assert f.response.status_code == 403


def test_regular_mode_non_health_blocked_by_default(fixture_policy):
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="example.com", proxy_mode="regular")
    addon.requestheaders(f)
    assert f.response.status_code == 403


def test_regular_mode_open_for_selftest(fixture_policy):
    addon, tctx = _make_addon(fixture_policy, guard_regular_open=True)
    f = _flow(host="example.com", proxy_mode="regular")
    addon.requestheaders(f)
    assert f.response is None


# --- server_connect (async) ---

def test_server_connect_kills_loopback():
    addon = guard_addon.Guard()
    with taddons.context(addon):
        addon.running()

        class FakeConn:
            def __init__(self, address=None, sni=None, error=None):
                self.address = address
                self.sni = sni
                self.error = error

        data = type("D", (), {})()
        data.server = FakeConn(address=("127.0.0.1", 443))
        data.client = FakeConn(sni="example.com")
        asyncio.run(addon.server_connect(data))
        assert data.server.error == "dg: loop"


def test_server_connect_pins_upstream_to_resolved_ip(fixture_policy, monkeypatch):
    addon, tctx = _make_addon(fixture_policy)

    class FakeConn:
        def __init__(self, address=None, sni=None, error=None):
            self.address = address
            self.sni = sni
            self.error = error

    data = type("D", (), {})()
    data.server = FakeConn(address=("93.184.216.34", 443))  # original dst, e.g. spoofed
    data.client = FakeConn(sni="example.com")

    class FakeLoop:
        async def getaddrinfo(self, host, port, type=None):
            assert host == "example.com"
            return [(2, 1, 6, "", ("10.10.10.10", port))]

    monkeypatch.setattr(asyncio, "get_running_loop", lambda: FakeLoop())
    asyncio.run(addon.server_connect(data))
    assert data.server.address == ("10.10.10.10", 443)


def _connect_to(addon, sni, monkeypatch):
    class FakeConn:
        def __init__(self, address=None, sni=None, error=None):
            self.address, self.sni, self.error = address, sni, error

    class FakeLoop:
        async def getaddrinfo(self, host, port, type=None):
            return [(2, 1, 6, "", ("10.10.10.10", port))]

    monkeypatch.setattr(asyncio, "get_running_loop", lambda: FakeLoop())
    data = type("D", (), {})()
    data.server = FakeConn(address=("93.184.216.34", 443))
    data.client = FakeConn(sni=sni)
    asyncio.run(addon.server_connect(data))
    return data.server


def test_server_connect_kills_blocked_host_when_enforcing(fixture_policy, monkeypatch):
    addon, tctx = _make_addon(fixture_policy)
    assert _connect_to(addon, "www.reddit.com", monkeypatch).error == "dg: blocked"


def test_server_connect_lets_blocked_host_through_in_shadow_mode(fixture_policy, monkeypatch, tmp_path):
    # Found live: shadow mode killed reddit.com at connect time -- blocking
    # for real, and logging nothing, since requestheaders never ran.
    import json
    raw = json.loads(open(fixture_policy).read())
    raw["enforce"] = False
    shadow = tmp_path / "shadow-policy.json"
    shadow.write_text(json.dumps(raw))
    addon, tctx = _make_addon(str(shadow))
    server = _connect_to(addon, "www.reddit.com", monkeypatch)
    assert server.error is None
    assert server.address == ("10.10.10.10", 443)


def test_block_page_shipped_file_substitutes_rule_id(monkeypatch):
    # guard_addon._block_page() reads /etc/distraction-guard/block_page.html
    # in production (install.sh copies addon/block_page.html there); here
    # we point it at the repo's own copy to verify the real shipped file
    # round-trips correctly, not the inline fallback.
    real_open = open

    def fake_open(path, *a, **kw):
        if path == "/etc/distraction-guard/block_page.html":
            path = str(REPO_BLOCK_PAGE)
        return real_open(path, *a, **kw)

    monkeypatch.setattr(guard_addon, "open", fake_open, raising=False)
    body = guard_addon._block_page("S-social")
    assert b"S-social" in body
    assert b"{{RULE_ID}}" not in body
    assert b"<html" in body


def test_server_connect_blocked_host_kills():
    pass  # covered indirectly via requestheaders BLOCK path; server_connect
    # only re-checks BLOCK as defense-in-depth for the case where a policy
    # reload happened between tls_clienthello and server_connect.


# --- class mode --------------------------------------------------------------

def _class_policy(fixture_policy, tmp_path, *, enforce=True, now_in_window=True):
    import datetime as dt
    raw = json.loads(open(fixture_policy).read())
    today = dt.date.today()
    weekday = today.weekday() if now_in_window else (today.weekday() + 3) % 7
    raw["enforce"] = enforce
    raw["passthrough"] = ["passthru-example.com", "claude.ai"]
    raw["class_mode"] = {
        "pad_minutes": 0,
        "windows": [{"title": "Class: Test", "weekday": weekday, "start": "00:00", "end": "23:59",
                     "start_date": "2000-01-01", "until": None, "skip": []}],
        "allow": ["courseworks2.columbia.edu", "github.com"],
    }
    p = tmp_path / "class-policy.json"
    p.write_text(json.dumps(raw))
    return str(p)


def _nav(host, **extra):
    return _flow(host=host, headers={"sec-fetch-dest": "document", "sec-fetch-mode": "navigate", **extra})


def test_class_mode_blocks_navigation_to_unlisted_site(fixture_policy, tmp_path):
    addon, tctx = _make_addon(_class_policy(fixture_policy, tmp_path))
    f = _nav("example.com")
    addon.requestheaders(f)
    assert f.response is not None and f.response.status_code == 403
    assert b"C-class" in f.response.content


def test_class_mode_allows_listed_and_sign_in_sites(fixture_policy, tmp_path):
    addon, tctx = _make_addon(_class_policy(fixture_policy, tmp_path))
    for host in ("courseworks2.columbia.edu", "github.com", "gist.github.com", "cas.columbia.edu", "accounts.google.com"):
        f = _nav(host)
        addon.requestheaders(f)
        assert f.response is None, host


def test_class_mode_lets_allowed_pages_load_from_anywhere(fixture_policy, tmp_path):
    # Courseworks' scripts come from cloudfront: judged by who asked.
    addon, tctx = _make_addon(_class_policy(fixture_policy, tmp_path))
    f = _flow(host="du11hjcvx0uqb.cloudfront.net", headers={
        "sec-fetch-dest": "script", "sec-fetch-mode": "no-cors", "sec-fetch-site": "cross-site",
        "referer": "https://courseworks2.columbia.edu/"})
    addon.requestheaders(f)
    assert f.response is None


def test_class_mode_blocks_blocked_sites_own_requests(fixture_policy, tmp_path):
    # Found live: YouTube/Gemini/Claude kept working in class -- their
    # service workers serve the page from browser storage, so only API
    # calls reached the network, and those used to pass.
    addon, tctx = _make_addon(_class_policy(fixture_policy, tmp_path))
    cases = [
        ("www.youtube.com", {"sec-fetch-dest": "empty", "sec-fetch-site": "same-origin", "origin": "https://www.youtube.com"}),
        ("gemini.google.com", {"sec-fetch-dest": "empty", "sec-fetch-site": "same-origin"}),  # no Origin/Referer
        ("claude.ai", {"sec-fetch-dest": "serviceworker", "sec-fetch-site": "same-origin"}),
        ("rr3---sn-abc.googlevideo.com", {"sec-fetch-dest": "empty", "sec-fetch-site": "cross-site", "origin": "https://www.youtube.com"}),
    ]
    for host, headers in cases:
        f = _flow(host=host, headers=headers)
        addon.requestheaders(f)
        assert f.response is not None and f.response.status_code == 403, host


def test_class_mode_cross_site_without_initiator_passes(fixture_policy, tmp_path):
    addon, tctx = _make_addon(_class_policy(fixture_policy, tmp_path))
    f = _flow(host="fonts.gstatic.com", headers={"sec-fetch-dest": "font", "sec-fetch-site": "cross-site"})
    addon.requestheaders(f)
    assert f.response is None


def test_class_mode_embed_from_allowed_page_can_load_its_own_resources(fixture_policy, tmp_path):
    addon, tctx = _make_addon(_class_policy(fixture_policy, tmp_path))
    frame = _flow(host="player.vimeo.com", headers={
        "sec-fetch-dest": "iframe", "sec-fetch-mode": "navigate", "sec-fetch-site": "cross-site",
        "referer": "https://courseworks2.columbia.edu/courses/1"})
    addon.requestheaders(frame)
    assert frame.response is None
    inner = _flow(host="player.vimeo.com", headers={
        "sec-fetch-dest": "script", "sec-fetch-site": "same-origin", "referer": "https://player.vimeo.com/video/1"})
    addon.requestheaders(inner)
    assert inner.response is None
    # ...but a frame opened by a blocked page is blocked.
    bad = _flow(host="embed.example.net", headers={"sec-fetch-dest": "iframe", "referer": "https://example.org/"})
    addon.requestheaders(bad)
    assert bad.response is not None and bad.response.status_code == 403


def test_class_mode_leaves_non_browser_clients_alone(fixture_policy, tmp_path):
    addon, tctx = _make_addon(_class_policy(fixture_policy, tmp_path))
    f = _flow(host="example.com", headers={"user-agent": "git/2.50"})
    addon.requestheaders(f)
    assert f.response is None


def test_class_mode_canvas_frames_navigating_onward_pass(fixture_policy, tmp_path):
    # Found live: Canvas's chat/canvadocs frames navigate onward inside the
    # frame (Referer = the previous frame), and were flagged C-class.
    addon, tctx = _make_addon(_class_policy(fixture_policy, tmp_path))
    for host, ref in (("chat.instructure.com", "https://courseworks2.columbia.edu/courses/1"),
                      ("chat.instructure.com", "https://chat.instructure.com/lti"),
                      ("canvadocs.instructure.com", "https://courseworks2.columbia.edu/files/2")):
        f = _flow(host=host, headers={"sec-fetch-dest": "iframe", "sec-fetch-mode": "navigate", "referer": ref})
        addon.requestheaders(f)
        assert f.response is None, (host, ref)


def test_class_mode_allows_canvas_hosts_as_pages(fixture_policy, tmp_path):
    addon, tctx = _make_addon(_class_policy(fixture_policy, tmp_path))
    for host in ("sso.canvaslms.com", "canvadocs.instructure.com"):
        f = _nav(host)
        addon.requestheaders(f)
        assert f.response is None, host


def test_class_mode_off_outside_window(fixture_policy, tmp_path):
    addon, tctx = _make_addon(_class_policy(fixture_policy, tmp_path, now_in_window=False))
    f = _nav("example.com")
    addon.requestheaders(f)
    assert f.response is None


def test_class_mode_shadow_logs_would_block(fixture_policy, tmp_path):
    log = tmp_path / "dec.jsonl"
    addon, tctx = _make_addon(_class_policy(fixture_policy, tmp_path, enforce=False), guard_log=str(log))
    addon.running()
    f = _nav("example.com")
    addon.requestheaders(f)
    assert f.response is None
    assert '"would_block"' in log.read_text() and '"C-class"' in log.read_text()


def test_class_mode_temp_allow_lifts_it(fixture_policy, tmp_path):
    import time
    p = _class_policy(fixture_policy, tmp_path)
    raw = json.loads(open(p).read())
    raw["temp_allows"] = [{"host": "example.com", "expires_at": time.time() + 600}]
    open(p, "w").write(json.dumps(raw))
    addon, tctx = _make_addon(p)
    f = _nav("example.com")
    addon.requestheaders(f)
    assert f.response is None


def test_class_mode_intercepts_passthrough_hosts_it_must_gate(fixture_policy, tmp_path):
    # claude.ai is passthrough by default; during class it must be
    # intercepted so the navigation gate can block it.
    from mitmproxy.test import tflow as _tf
    from mitmproxy.tls import ClientHelloData

    class Hello:
        def __init__(self, sni):
            self.sni = sni

    def hello(addon, sni):
        ctx_ = type("C", (), {})()
        ctx_.client = _tf.tclient_conn()
        ctx_.server = type("S", (), {"address": ("203.0.113.9", 443)})()
        data = ClientHelloData(ctx_, Hello(sni))
        addon.tls_clienthello(data)
        return data.ignore_connection

    addon, tctx = _make_addon(_class_policy(fixture_policy, tmp_path))
    assert hello(addon, "claude.ai") is False  # intercepted during class
    assert hello(addon, "passthru-example.com") is False
    # ...and outside class too: a connection opened before class would
    # otherwise stay undecrypted straight through it.
    addon2, _ = _make_addon(_class_policy(fixture_policy, tmp_path, now_in_window=False))
    assert hello(addon2, "claude.ai") is False


def test_class_allowed_passthrough_host_is_never_decrypted(fixture_policy, tmp_path):
    from mitmproxy.test import tflow as _tf
    from mitmproxy.tls import ClientHelloData
    p = _class_policy(fixture_policy, tmp_path)
    raw = json.loads(open(p).read())
    raw["passthrough"].append("github.com")  # class-allowed
    open(p, "w").write(json.dumps(raw))
    addon, tctx = _make_addon(p)
    ctx_ = type("C", (), {})()
    ctx_.client = _tf.tclient_conn()
    ctx_.server = type("S", (), {"address": ("203.0.113.9", 443)})()
    data = ClientHelloData(ctx_, type("H", (), {"sni": "github.com"})())
    addon.tls_clienthello(data)
    assert data.ignore_connection is True


def test_decrypted_passthrough_host_is_never_scanned(fixture_policy, tmp_path):
    # claude.ai outside class: decrypted (for the class gate) but trusted,
    # so a term in its page title must not block it and nothing buffers.
    addon, tctx = _make_addon(_class_policy(fixture_policy, tmp_path, now_in_window=False))
    f = _nav("claude.ai")
    addon.requestheaders(f)
    assert f.response is None and f.metadata.get("dg_allow") is True
    f.response = _resp(b"<html><head><title>all about zorblax</title></head></html>", {"content-type": "text/html"})
    addon.responseheaders(f)
    assert f.response.stream is True
    addon.response(f)
    assert f.response.status_code == 200


def test_ordinary_json_api_responses_stream_unbuffered(fixture_policy):
    # Only YouTube's JSON is scanned; buffering every other API response
    # (Canvas is almost all API calls) just delayed it.
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="courseworks2.columbia.edu", path="/api/v1/courses", headers={"accept": "application/json"})
    addon.requestheaders(f)
    f.response = _resp(b"[]", {"content-type": "application/json"})
    addon.responseheaders(f)
    assert f.response.stream is True


def test_html_pages_are_still_buffered_for_scanning(fixture_policy):
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="example.com", headers={"sec-fetch-dest": "document"})
    addon.requestheaders(f)
    f.response = _resp(b"<html></html>", {"content-type": "text/html"})
    addon.responseheaders(f)
    assert not f.response.stream


def _hello(addon, sni):
    from mitmproxy.test import tflow as _tf
    from mitmproxy.tls import ClientHelloData
    ctx_ = type("C", (), {})()
    ctx_.client = _tf.tclient_conn()
    ctx_.server = type("S", (), {"address": ("160.79.104.10", 443)})()
    data = ClientHelloData(ctx_, type("H", (), {"sni": sni})())
    addon.tls_clienthello(data)
    return data.ignore_connection


def test_claude_code_api_never_decrypted_even_in_class(fixture_policy, tmp_path):
    addon, tctx = _make_addon(_class_policy(fixture_policy, tmp_path))
    assert _hello(addon, "api.anthropic.com") is True


def test_claude_ai_on_the_same_ip_is_class_gated(fixture_policy, tmp_path):
    # Found live: claude.ai shares 160.79.104.10 with api.anthropic.com,
    # so the old IP-level exemption let it skip class mode entirely.
    addon, tctx = _make_addon(_class_policy(fixture_policy, tmp_path))
    assert _hello(addon, "claude.ai") is False
    f = _nav("claude.ai")
    addon.requestheaders(f)
    assert f.response is not None and b"C-class" in f.response.content


def test_class_mode_lti_launch_from_courseworks_is_trusted(fixture_policy, tmp_path):
    # Found live: columbia.evaluationkit.com, launched from Canvas, was
    # blocked along with the Canvas files its page loads. Canvas launches
    # tools by form POST with Origin = Courseworks.
    addon, tctx = _make_addon(_class_policy(fixture_policy, tmp_path))
    launch = _flow(host="tool.example-lti.com", method="POST", headers={
        "sec-fetch-dest": "document", "sec-fetch-mode": "navigate", "sec-fetch-site": "cross-site",
        "origin": "https://courseworks2.columbia.edu"})
    addon.requestheaders(launch)
    assert launch.response is None
    # The tool's own later pages and resources pass for a while...
    nxt = _nav("tool.example-lti.com", **{"referer": "https://tool.example-lti.com/start"})
    addon.requestheaders(nxt)
    assert nxt.response is None
    res = _flow(host="du11hjcvx0uqb.cloudfront.net", headers={"sec-fetch-dest": "script", "referer": "https://tool.example-lti.com/start"})
    addon.requestheaders(res)
    assert res.response is None


def test_class_mode_plain_link_from_courseworks_stays_blocked(fixture_policy, tmp_path):
    addon, tctx = _make_addon(_class_policy(fixture_policy, tmp_path))
    f = _nav("www.youtube.com", **{"referer": "https://courseworks2.columbia.edu/courses/1", "sec-fetch-site": "cross-site"})
    addon.requestheaders(f)
    assert f.response is not None and f.response.status_code == 403
    post_elsewhere = _flow(host="tool.example-lti.com", method="POST", headers={
        "sec-fetch-dest": "document", "origin": "https://example.org"})
    addon.requestheaders(post_elsewhere)
    assert post_elsewhere.response is not None


def test_class_mode_evaluationkit_allowed(fixture_policy, tmp_path):
    addon, tctx = _make_addon(_class_policy(fixture_policy, tmp_path))
    f = _nav("columbia.evaluationkit.com")
    addon.requestheaders(f)
    assert f.response is None


def test_class_mode_browser_internal_requests_pass(fixture_policy, tmp_path):
    # Found live: Firefox's push service was blocked C-class.
    addon, tctx = _make_addon(_class_policy(fixture_policy, tmp_path))
    f = _flow(host="push.services.mozilla.com", headers={"sec-fetch-dest": "websocket", "sec-fetch-site": "none"})
    addon.requestheaders(f)
    assert f.response is None


def test_class_block_logs_the_request_kind(fixture_policy, tmp_path):
    log = tmp_path / "dec.jsonl"
    addon, tctx = _make_addon(_class_policy(fixture_policy, tmp_path), guard_log=str(log))
    addon.running()
    addon.requestheaders(_nav("example.com"))
    entry = json.loads(log.read_text().splitlines()[-1])
    assert entry["rule"] == "C-class" and entry["detail"] == "document"


# --- daily block (bookmarks' life folder, 9am-10pm) ---------------------------

def _daily_policy(fixture_policy, tmp_path, *, in_hours=True, with_class=False):
    import datetime as dt
    p = _class_policy(fixture_policy, tmp_path, now_in_window=with_class)
    raw = json.loads(open(p).read())
    now = dt.datetime.now()
    t = now.hour * 60 + now.minute
    start, end = (max(t - 60, 0), min(t + 60, 1439)) if in_hours else ((t + 60) % 1440, (t + 120) % 1440)
    if not in_hours and end <= start:
        start, end = 0, 1
    fmt = lambda m: f"{m // 60:02d}:{m % 60:02d}"  # noqa: E731
    raw["class_mode"]["daily_block"] = {"start": fmt(start), "end": fmt(end),
                                        "hosts": ["youtube.com", "amazon.com", "netflix.com"], "exempt": ["aws.amazon.com"]}
    open(p, "w").write(json.dumps(raw))
    return p


def test_daily_block_blocks_every_request_in_hours(fixture_policy, tmp_path):
    addon, tctx = _make_addon(_daily_policy(fixture_policy, tmp_path))
    for host, headers in (("www.netflix.com", {"sec-fetch-dest": "document"}),
                          ("www.amazon.com", {"sec-fetch-dest": "empty", "sec-fetch-site": "same-origin"}),
                          ("www.netflix.com", {})):  # non-browser client too
        f = _flow(host=host, headers=headers)
        addon.requestheaders(f)
        assert f.response is not None and f.response.status_code == 403, host


def test_daily_block_off_outside_hours_and_for_exempt(fixture_policy, tmp_path):
    addon, tctx = _make_addon(_daily_policy(fixture_policy, tmp_path, in_hours=False))
    f = _nav("www.netflix.com")
    addon.requestheaders(f)
    assert f.response is None
    addon2, _ = _make_addon(_daily_policy(fixture_policy, tmp_path))
    g = _nav("console.aws.amazon.com")
    addon2.requestheaders(g)
    assert g.response is None


def test_daily_block_lets_videos_embedded_in_courseworks_play(fixture_policy, tmp_path):
    addon, tctx = _make_addon(_daily_policy(fixture_policy, tmp_path))
    frame = _flow(host="www.youtube.com", path="/embed/abc", headers={
        "sec-fetch-dest": "iframe", "referer": "https://courseworks2.columbia.edu/courses/1"})
    addon.requestheaders(frame)
    assert frame.response is None
    inner = _flow(host="www.youtube.com", path="/s/player/x.js", headers={
        "sec-fetch-dest": "script", "sec-fetch-site": "same-origin", "referer": "https://www.youtube.com/embed/abc"})
    addon.requestheaders(inner)
    assert inner.response is None
    # ...while opening YouTube directly is still blocked.
    direct = _nav("www.youtube.com")
    addon.requestheaders(direct)
    assert direct.response is not None and direct.response.status_code == 403


def test_daily_block_logged_with_host(fixture_policy, tmp_path):
    log = tmp_path / "dec.jsonl"
    addon, tctx = _make_addon(_daily_policy(fixture_policy, tmp_path), guard_log=str(log))
    addon.running()
    addon.requestheaders(_nav("www.netflix.com"))
    entry = json.loads(log.read_text().splitlines()[-1])
    assert entry["rule"] == "D-daily" and entry["host"] == "www.netflix.com"


def test_youtube_search_api_response_has_shorts_stripped(fixture_policy):
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="www.youtube.com", path="/youtubei/v1/search", method="POST",
              headers={"content-type": "application/json", "sec-fetch-dest": "empty", "sec-fetch-site": "same-origin"})
    f.request.content = json.dumps({"query": "cooking"}).encode()
    addon.requestheaders(f)
    assert f.response is None
    body = {"contents": [{"videoRenderer": {"videoId": "a"}}, {"reelShelfRenderer": {"items": []}}]}
    f.response = _resp(json.dumps(body).encode(), {"content-type": "application/json"})
    addon.responseheaders(f)
    assert not f.response.stream
    addon.response(f)
    assert json.loads(f.response.content) == {"contents": [{"videoRenderer": {"videoId": "a"}}]}


def test_youtube_shorts_stripping_skipped_in_shadow_mode(fixture_policy, tmp_path):
    raw = json.loads(open(fixture_policy).read()); raw["enforce"] = False
    p = tmp_path / "shadow.json"; p.write_text(json.dumps(raw))
    addon, tctx = _make_addon(str(p))
    f = _flow(host="www.youtube.com", path="/youtubei/v1/browse", method="POST", headers={"sec-fetch-dest": "empty"})
    f.request.content = json.dumps({"browseId": "UCabc"}).encode()
    addon.requestheaders(f)
    body = json.dumps({"contents": [{"reelShelfRenderer": {}}]}).encode()
    f.response = _resp(body, {"content-type": "application/json"})
    addon.responseheaders(f)
    addon.response(f)
    assert f.response.content == body


def test_youtube_player_json_is_actually_scanned(fixture_policy):
    # Regression: the generic scan-kind assignment overwrote YouTube's
    # "yt-json", so player responses streamed through unscanned.
    addon, tctx = _make_addon(fixture_policy)
    f = _flow(host="www.youtube.com", path="/youtubei/v1/player", method="POST", headers={"sec-fetch-dest": "empty"})
    f.request.content = json.dumps({"videoId": "abc"}).encode()
    addon.requestheaders(f)
    assert f.metadata.get("dg_scan") == "yt-json"
    f.response = _resp(b"{}", {"content-type": "application/json"})
    addon.responseheaders(f)
    assert not f.response.stream


def test_youtube_restrict_header_follows_policy(fixture_policy, tmp_path):
    for level, header in (("strict", "Strict"), ("moderate", "Moderate")):
        raw = json.loads(open(fixture_policy).read()); raw["youtube_restrict"] = level
        p = tmp_path / f"{level}.json"; p.write_text(json.dumps(raw))
        addon, tctx = _make_addon(str(p))
        f = _flow(host="www.youtube.com", path="/results", headers={"sec-fetch-dest": "document"})
        addon.requestheaders(f)
        assert f.request.headers.get("YouTube-Restrict") == header


# --- night block (everything offline) -------------------------------------------

def _night_policy(fixture_policy, tmp_path, *, active=True, enforce=True):
    import datetime as dt
    raw = json.loads(open(fixture_policy).read())
    raw["enforce"] = enforce
    t = dt.datetime.now().hour * 60 + dt.datetime.now().minute
    a, b = ((t - 30) % 1440, (t + 30) % 1440) if active else ((t + 60) % 1440, (t + 120) % 1440)
    fmt = lambda m: f"{m // 60:02d}:{m % 60:02d}"  # noqa: E731
    raw["passthrough"] = ["passthru-example.com"]
    raw["class_mode"] = {"pad_minutes": 0, "windows": [], "allow": [], "night_block": {"start": fmt(a), "end": fmt(b)}}
    p = tmp_path / f"night-{active}-{enforce}.json"
    p.write_text(json.dumps(raw))
    return str(p)


def _connect(addon, host_ip, sni, monkeypatch):
    class FakeConn:
        def __init__(self, address=None, sni=None, error=None):
            self.address, self.sni, self.error = address, sni, error
    class FakeLoop:
        async def getaddrinfo(self, host, port, type=None):
            return [(2, 1, 6, "", ("10.10.10.10", port))]
    monkeypatch.setattr(asyncio, "get_running_loop", lambda: FakeLoop())
    data = type("D", (), {})()
    data.server = FakeConn(address=(host_ip, 443))
    data.client = FakeConn(sni=sni)
    asyncio.run(addon.server_connect(data))
    return data.server


def test_night_block_blocks_pages_with_marker_header(fixture_policy, tmp_path):
    addon, tctx = _make_addon(_night_policy(fixture_policy, tmp_path))
    f = _nav("en.wikipedia.org")
    addon.requestheaders(f)
    assert f.response.status_code == 403
    assert f.response.headers.get("X-Distraction-Guard") == "N-night"
    assert b"N-night" in f.response.content


def test_night_block_cuts_passthrough_and_never_decrypt_connections(fixture_policy, tmp_path, monkeypatch):
    addon, tctx = _make_addon(_night_policy(fixture_policy, tmp_path))
    assert _connect(addon, "160.79.104.10", "api.anthropic.com", monkeypatch).error == "dg: night"
    assert _connect(addon, "93.184.216.34", "passthru-example.com", monkeypatch).error == "dg: night"
    assert _connect(addon, "192.168.1.1", "router.lan", monkeypatch).error is None  # home network stays up


def test_night_block_off_outside_hours_and_in_shadow(fixture_policy, tmp_path, monkeypatch):
    addon, tctx = _make_addon(_night_policy(fixture_policy, tmp_path, active=False))
    f = _nav("en.wikipedia.org")
    addon.requestheaders(f)
    assert f.response is None
    assert _connect(addon, "93.184.216.34", "example.com", monkeypatch).error is None
    shadow, _ = _make_addon(_night_policy(fixture_policy, tmp_path, enforce=False))
    assert _connect(shadow, "93.184.216.34", "example.com", monkeypatch).error is None
