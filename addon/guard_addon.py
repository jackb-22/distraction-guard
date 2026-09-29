"""mitmproxy addon: the always-on content wall.

Every hook is wrapped so an exception blocks/kills *only the current flow*
and logs a rate-limited G-error -- it never lets the mitmdump process die.
That was v1's failure mode (an addon-load exception crash-looped the whole
proxy, which nftables had unconditionally redirected all traffic through).

Deployed at /usr/local/lib/distraction-guard/addon/guard_addon.py, with
dg_policy importable from its parent directory (../dg_policy). For local
dev/tests the repo layout is identical (addon/ and dg_policy/ are siblings
under the repo root), so the same relative insert works unmodified.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

logger = logging.getLogger(__name__)

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from mitmproxy import ctx, http  # noqa: E402
from mitmproxy.tls import ClientHelloData  # noqa: E402

from dg_policy import content, rules, search, youtube  # noqa: E402
from dg_policy.hosts import HostKind, is_ip_literal, is_lan, normalize_host  # noqa: E402
from dg_policy.log import DecisionLog  # noqa: E402
from dg_policy.model import PolicyStore  # noqa: E402
from dg_policy.text import tokens  # noqa: E402

MAX_SCAN_BYTES = 2_000_000
# Which content types each scan kind actually reads in response(). Only
# these get buffered; everything else streams straight through. Buffering
# ALL json (as this used to) held every API response -- Canvas loads nearly
# everything that way -- until complete, for a scan that never happened:
# only YouTube's player/next JSON is ever read.
SCANNED_CONTENT_TYPES = {"html": ("text/html",), "yt-json": ("application/json",), "yt-strip": ("application/json",)}

# Set on every block response. Lets guardctl's install/emergency-on probe
# tell "the proxy blocked it" (traffic path works -- e.g. during the night
# block) from "the network is broken".
BLOCK_HEADER = "X-Distraction-Guard"

# How long a host embedded by an allowed page (iframe) may itself load
# resources during class.
EMBED_TTL = 3600.0

_ERROR_LOG_MIN_INTERVAL = 5.0  # seconds between repeated G-error log lines


class Guard:
    def __init__(self):
        self.store: PolicyStore | None = None
        self.dlog: DecisionLog | None = None
        self._no_sni_conns: set[int] = set()
        self._raw_conns: set[int] = set()
        self._last_error_log: float = 0.0
        self._proxy_ports: set[int] = set()
        # Class mode: hosts embedded (iframe) by an allowed page -> expiry.
        self._class_embedded: dict[str, float] = {}

    # --- lifecycle -----------------------------------------------------

    def load(self, loader):
        loader.add_option("guard_policy", str, "/var/lib/distraction-guard/compiled/policy.json", "Compiled policy path")
        loader.add_option("guard_log", str, "/var/log/distraction-guard/proxy/decisions.jsonl", "Decision log path")
        loader.add_option("guard_pin_upstream", bool, True, "Resolve SNI/Host to its own IP instead of trusting original dst")
        loader.add_option("guard_regular_open", bool, False, "Dev/selftest only: allow the regular-mode listener for non-health requests")
        loader.add_option("guard_proxy_ports", str, "8080,8081", "Comma-separated ports this proxy itself listens on (loop guard)")

    def running(self):
        self.store = PolicyStore(ctx.options.guard_policy, on_error=self._log_load_error)
        self.dlog = DecisionLog(ctx.options.guard_log)
        self.store.refresh(force=True)
        self._proxy_ports = {int(p) for p in ctx.options.guard_proxy_ports.split(",") if p.strip()}

    def configure(self, updated):
        if self.store is not None and "guard_policy" in updated:
            self.store.path = ctx.options.guard_policy
            self.store.refresh(force=True)

    def client_disconnected(self, client):
        self._no_sni_conns.discard(id(client))
        self._raw_conns.discard(id(client))

    # --- error containment ----------------------------------------------

    def _log_load_error(self, msg: str) -> None:
        now = time.time()
        if now - self._last_error_log >= _ERROR_LOG_MIN_INTERVAL:
            logger.warning("policy load error (keeping last-good policy): %s", msg)
            self._last_error_log = now

    def _log_hook_error(self, hook_name: str, exc: Exception) -> None:
        now = time.time()
        if now - self._last_error_log >= _ERROR_LOG_MIN_INTERVAL:
            logger.warning("%s error (flow blocked, proxy continues): %s", hook_name, exc)
            logger.debug("traceback for %s error", hook_name, exc_info=exc)
            self._last_error_log = now
        if self.dlog is not None:
            self.dlog.write(action="error", rule="G-error")

    def _current_policy(self):
        if self.store is not None:
            self.store.refresh()
        return self.store.policy if self.store else None

    # --- TLS interception decision ---------------------------------------

    def tls_clienthello(self, data: ClientHelloData) -> None:
        try:
            self._tls_clienthello(data)
        except Exception as e:  # noqa: BLE001
            self._log_hook_error("tls_clienthello", e)
            # Fail closed: intercept (don't set ignore_connection), so the
            # connection falls through to requestheaders' block-by-default.

    def _tls_clienthello(self, data: ClientHelloData) -> None:
        sni = data.client_hello.sni
        orig_dst = data.context.server.address

        if not sni or is_ip_literal(sni):
            dst_host = orig_dst[0] if orig_dst else None
            if dst_host and is_lan(dst_host):
                data.ignore_connection = True
                return
            # Non-LAN with no usable SNI: never allow a raw/IP-pinned TLS
            # connection through. Mark it so server_connect kills it once
            # the connection actually tries to reach upstream.
            self._no_sni_conns.add(id(data.context.client))
            return

        policy = self._current_policy()
        host = normalize_host(sni)
        if policy is None:
            return  # no policy loaded yet -> intercept, requestheaders fails closed
        if policy.never_decrypt.match(host) is not None:
            data.ignore_connection = True  # e.g. Claude Code's API: never touched
            return
        decision = policy.classify(host)
        if decision.kind == HostKind.PASSTHROUGH:
            # With class mode set up, a passthrough host that class mode
            # must be able to block (claude.ai, slack, ...) is decrypted --
            # never scanned (requestheaders marks it dg_allow), but its
            # page loads stay visible to the class gate. Always, not just
            # during a window: browsers keep connections open for minutes,
            # so a tab opened at 1:05 would otherwise ride an undecrypted
            # connection straight through a 1:10 class. Class-allowed
            # passthrough hosts are never decrypted at all.
            if policy.class_windows and not policy.class_allows(host):
                return
            data.ignore_connection = True

    # --- next_layer: reject non-TLS on 443 / non-HTTP on 80 --------------

    def next_layer(self, nextlayer) -> None:
        try:
            self._next_layer(nextlayer)
        except Exception as e:  # noqa: BLE001
            self._log_hook_error("next_layer", e)

    def _next_layer(self, nextlayer) -> None:
        if nextlayer.layer is not None:
            return  # another addon already decided
        from mitmproxy.proxy import layers

        # Only judge a connection's FIRST bytes, never what's inside TLS.
        # Script addons run before mitmproxy's built-in NextLayer, so this
        # hook also sees the decision for the decrypted stream -- where the
        # first bytes are "GET ..." or the HTTP/2 preface, not 0x16. Treating
        # that as a raw tunnel is what silently relayed every decrypted
        # connection byte-for-byte: uninspected, and broken outright when
        # the client spoke HTTP/2 to an HTTP/1.1-only server (Columbia CAS,
        # Microsoft login). Inside TLS, the built-in picks HTTP/1 vs HTTP/2
        # from the negotiated ALPN, which is exactly right.
        if any(isinstance(l, layers.ClientTLSLayer) for l in nextlayer.context.layers):
            return

        client_data = nextlayer.data_client()
        server_port = None
        if nextlayer.context.server.address:
            server_port = nextlayer.context.server.address[1]

        if server_port == 443:
            if not client_data:
                return  # need more data before we can tell
            if client_data[0:1] != b"\x16":
                self._reject_raw(nextlayer)
        elif server_port == 80:
            if not client_data:
                return
            if not _looks_like_http_request(client_data):
                self._reject_raw(nextlayer)

    def _reject_raw(self, nextlayer) -> None:
        # A TCPLayer relays regardless of flow.kill() in tcp_start (its
        # start() never checks for it), so the kill has to happen where it
        # actually takes effect: the upstream connect, via server_connect.
        from mitmproxy.proxy import layers
        self._raw_conns.add(id(nextlayer.context.client))
        nextlayer.layer = layers.TCPLayer(nextlayer.context, ignore=False)
        if self.dlog is not None:
            self.dlog.write(action="kill", rule="G-raw-tunnel")

    # --- server_connect: kill loops/no-SNI/blocked passthrough, pin upstream

    async def server_connect(self, data) -> None:
        try:
            await self._server_connect(data)
        except Exception as e:  # noqa: BLE001
            self._log_hook_error("server_connect", e)
            data.server.error = "dg: internal error"

    async def _server_connect(self, data) -> None:
        addr = data.server.address
        if not addr:
            return
        host, port = addr[0], addr[1]

        # Loop/self-connect guard must run BEFORE the general LAN bypass --
        # loopback is technically "LAN" per is_lan(), but connecting back to
        # ourselves (or any loopback destination reaching this hook at all,
        # which nftables' `ip daddr 127.0.0.0/8 return` should normally have
        # prevented) is never something to relay.
        if is_ip_literal(host) and host in ("127.0.0.1", "::1"):
            data.server.error = "dg: loop"
            return
        if port in self._proxy_ports and host in ("127.0.0.1", "::1", "0.0.0.0"):
            data.server.error = "dg: loop"
            return

        if is_lan(host):
            return  # never touch other LAN destinations

        # Night block: every upstream connection is refused -- including
        # passthrough and never-decrypt hosts, which never reach
        # requestheaders. This hook fires for all of them.
        night_policy = self._current_policy()
        if night_policy is not None and night_policy.enforce and night_policy.night_active():
            data.server.error = "dg: night"
            if self.dlog is not None:
                self.dlog.write(action="block", rule="N-night", host=host)
            return

        if id(data.client) in self._raw_conns:
            data.server.error = "dg: raw tunnel"
            return

        if id(data.client) in self._no_sni_conns:
            data.server.error = "dg: no sni"
            return

        sni = data.client.sni if hasattr(data.client, "sni") else None
        if not sni:
            return  # nothing to pin against; leave the original dst alone

        policy = self._current_policy()
        if policy is None:
            data.server.error = "dg: no policy"
            return

        target_host = normalize_host(sni)
        decision = policy.classify(target_host)
        if decision.kind == HostKind.BLOCK and policy.enforce:
            # Shadow mode lets it connect: requestheaders then classifies
            # the same host and logs it as would_block. Killing it here
            # blocked for real in shadow mode, and logged nothing.
            data.server.error = "dg: blocked"
            return

        if not ctx.options.guard_pin_upstream or is_ip_literal(target_host):
            return
        # Only pin when the upstream address is still the client's raw
        # original destination IP. HTTP flows already connect by hostname
        # (requestheaders sets flow.request.host from the classified host),
        # so mitmproxy resolves them itself and there's nothing to pin.
        # Rewriting a hostname address to an IP was actively harmful: an
        # HTTP/2 connection is only reused for later requests while its
        # address still matches theirs, so every request opened its own
        # upstream connection, and mitmproxy caps those at 5 per
        # destination (held for the connection's lifetime). Request 6+
        # waited forever -- Courseworks stuck on "Waiting for
        # du11hjcvx0uqb.cloudfront.net".
        if not is_ip_literal(host):
            return

        try:
            loop = asyncio.get_running_loop()
            infos = await loop.getaddrinfo(target_host, port, type=socket.SOCK_STREAM)
        except (socket.gaierror, OSError):
            data.server.error = "dg: dns failed"
            return
        if not infos:
            data.server.error = "dg: dns failed"
            return
        resolved_ip = infos[0][4][0]
        data.server.address = (resolved_ip, port)

    # --- requestheaders: host/path rules, search terms, SafeSearch -------

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        try:
            self._requestheaders(flow)
        except Exception as e:  # noqa: BLE001
            self._log_hook_error("requestheaders", e)
            self._block(flow, "G-error")

    def _requestheaders(self, flow: http.HTTPFlow) -> None:
        mode = flow.client_conn.proxy_mode.type_name if flow.client_conn.proxy_mode else ""

        if mode == "regular":
            self._handle_regular_mode(flow)
            return

        if flow.request.method == "CONNECT":
            self._block(flow, "G-connect-blocked")
            return

        policy = self._current_policy()
        if policy is None:
            self._block(flow, "G-no-policy")
            return

        raw_host = flow.request.pretty_host
        host = normalize_host(raw_host)
        path = flow.request.path.split("?", 1)[0] if flow.request.path else "/"

        if ctx.options.guard_pin_upstream and not is_lan(flow.server_conn.address[0] if flow.server_conn.address else ""):
            flow.request.host = host

        if policy.night_active():
            self._block(flow, "N-night")
            return

        if policy.daily_blocks(host) and not self._daily_block_exempt(flow, host, policy):
            self._block(flow, "D-daily", detail=flow.request.headers.get("sec-fetch-dest") or None)
            return

        window = policy.class_window()
        if window is not None and self._class_blocks(flow, host, policy):
            self._block(flow, "C-class", detail=flow.request.headers.get("sec-fetch-dest") or None)
            return

        decision = rules.classify_with_workarounds(
            host, path,
            block_sets=policy.block_sets, exceptions=policy.exceptions,
            passthrough=policy.passthrough, temp_allows=policy.temp_allows,
        )
        if decision.kind == HostKind.BLOCK:
            self._block(flow, decision.rule_id or "G-blocked")
            return
        if decision.kind == HostKind.PASSTHROUGH:
            # Trusted but decrypted (see _tls_clienthello): never scanned,
            # never buffered.
            flow.metadata["dg_allow"] = True
            return
        if decision.kind == HostKind.ALLOW_TEMP:
            flow.metadata["dg_allow"] = True
        else:
            # Generic host+path-glob rules (guardctl `block-path`), e.g.
            # blocking one subreddit path on an otherwise-allowed host.
            # (PASSTHROUGH hosts returned above; they're never inspected.)
            path_rule_id = policy.match_path_rule(host, path)
            if path_rule_id is not None:
                self._block(flow, path_rule_id)
                return

        if youtube.is_youtube_host(host):
            self._handle_youtube_request(flow, host, path, policy)
            if flow.response is not None:
                return

        full_url = flow.request.pretty_url
        result = search.evaluate(full_url, flow.request.method)
        if result is not None:
            if result.query_tokens_source and not flow.metadata.get("dg_allow"):
                qtoks = tokens(result.query_tokens_source)
                v = policy.term_index.judge_query(qtoks, vertical=result.vertical)
                if v.block:
                    self._block(flow, v.rule_id or "G-term")
                    return
            if result.vertical == "images" and result.engine == "google" and not flow.metadata.get("dg_allow"):
                pass  # image verticals are content-checked at response time too; query-level pass here
            if result.rewrite_query:
                self._rewrite_query_param(flow, result.rewrite_query["param"], result.rewrite_query["value"])

        if search.bing_path_vertical_blocked(path) and normalize_host(raw_host) == "www.bing.com":
            self._block(flow, "S-bing-vertical")
            return
        if search.duckduckgo_path_vertical_blocked(path) and "duckduckgo.com" in host:
            self._block(flow, "S-ddg-vertical")
            return

        # setdefault, not assignment: _handle_youtube_request may already have
        # chosen a YouTube-specific scan kind. Plain assignment here used to
        # overwrite it with "html", so YouTube's player/next JSON checks
        # (not-family-safe, terms in video titles) never actually ran.
        flow.metadata.setdefault("dg_scan", self._scan_kind(host, path))

    def _class_blocks(self, flow: http.HTTPFlow, host: str, policy) -> bool:
        """Class mode, for browser requests (Sec-Fetch-Dest present;
        non-browser clients keep normal filtering):

        - A top-level page (dest=document) opens only on an allowed host.
        - Every other request is judged by the page that MADE it (Origin,
          else Referer, else -- for same-site requests -- the host itself),
          not by the host it goes to. So Courseworks can load from
          cloudfront, but a blocked site can't talk to anything.

        The second rule is what stops sites that never ask the network for
        a page at all: found live, YouTube/Gemini/Claude kept working in
        class because their service workers serve the page shell from the
        browser's own storage, and only their API calls go out.

        An iframe opened by an allowed page makes its host an allowed
        initiator for EMBED_TTL, so an embedded lecture video (or Canvas's
        chat/canvadocs frames, which navigate onward inside the frame) can
        load its own resources."""
        dest = flow.request.headers.get("sec-fetch-dest", "")
        if not dest:
            return False
        if policy.classify(host).kind == HostKind.ALLOW_TEMP:
            return False  # a friend-approved allow-temp lifts class mode
        now = time.time()
        if dest == "document":
            if policy.class_allows(host) or self._class_embedded.get(host, 0) > now:
                return False
            # A tool launched FROM an allowed page: Canvas opens external
            # tools (LTI) by submitting a form, so it arrives as a POST whose
            # Origin is Courseworks. Trust that host like an embed. A plain
            # link from Courseworks (a GET) to anywhere else stays blocked.
            origin = normalize_host(urlsplit(flow.request.headers.get("origin", "")).netloc)
            if flow.request.method == "POST" and origin and policy.class_allows(origin):
                self._trust_embed(host, now)
                return False
            return True

        initiator = self._initiator(flow, host)
        if initiator is None:
            return False  # cross-site with no Origin/Referer: can't tell, let it through
        ok = (
            policy.class_allows(initiator)
            or self._class_embedded.get(initiator, 0) > now
            or policy.classify(initiator).kind == HostKind.ALLOW_TEMP
        )
        if ok and dest in ("iframe", "frame", "embed", "object"):
            self._trust_embed(host, now)
        return not ok

    def _trust_embed(self, host: str, now: float) -> None:
        self._class_embedded[host] = now + EMBED_TTL
        if len(self._class_embedded) > 1024:
            self._class_embedded = {h: t for h, t in self._class_embedded.items() if t > now}

    def _daily_block_exempt(self, flow: http.HTTPFlow, host: str, policy) -> bool:
        """The daily block covers every request to its hosts, from any
        client -- except a friend-approved allow-temp, and videos embedded
        in a class-allowed page (a YouTube lecture video in Courseworks):
        the frame itself, then everything that frame loads."""
        if policy.classify(host).kind == HostKind.ALLOW_TEMP:
            return True
        dest = flow.request.headers.get("sec-fetch-dest", "")
        now = time.time()
        if dest in ("iframe", "frame", "embed", "object"):
            referer = normalize_host(urlsplit(flow.request.headers.get("referer", "")).netloc)
            if referer and (policy.class_allows(referer) or self._class_embedded.get(referer, 0) > now):
                self._trust_embed(host, now)
                return True
            return False
        if not dest:
            return False
        initiator = self._initiator(flow, host)
        return initiator is not None and self._class_embedded.get(initiator, 0) > now

    @staticmethod
    def _initiator(flow: http.HTTPFlow, host: str) -> str | None:
        for header in ("origin", "referer"):
            value = flow.request.headers.get(header, "")
            if value and value != "null":
                h = normalize_host(urlsplit(value).netloc)
                if h:
                    return h
        site = flow.request.headers.get("sec-fetch-site", "")
        if site in ("same-origin", "same-site"):
            return host
        # "none" = the browser's own request, not made by any page (found
        # live: Firefox's push service, push.services.mozilla.com). Pages
        # you open are gated before this; these aren't a page's doing.
        return None

    def _handle_regular_mode(self, flow: http.HTTPFlow) -> None:
        host = normalize_host(flow.request.pretty_host)
        if host == "guard.health":
            token = flow.request.headers.get("X-DG-Token", "")
            policy = self._current_policy()
            if policy is not None and token and token == policy.health_token:
                body = f"ok {policy.hash} enforce={policy.enforce}".encode()
                flow.response = http.Response.make(200, body, {"Content-Type": "text/plain"})
            else:
                flow.response = http.Response.make(503 if policy is None else 403, b"", {})
            return
        if not ctx.options.guard_regular_open:
            flow.response = http.Response.make(403, b"", {})

    def _handle_youtube_request(self, flow: http.HTTPFlow, host: str, path: str, policy) -> None:
        body_json = None
        if flow.request.method == "POST" and flow.request.content:
            try:
                import json
                body_json = json.loads(flow.request.content)
            except (ValueError, UnicodeDecodeError):
                body_json = None

        yt = youtube.evaluate_request(path, body_json)
        if yt.block:
            self._block(flow, yt.rule_id or "Y-blocked")
            return

        level = policy.raw.get("youtube_restrict", "strict")
        flow.request.headers["YouTube-Restrict"] = "Moderate" if level == "moderate" else "Strict"

        qs = parse_qs(urlsplit(flow.request.pretty_url).query)
        query = youtube.extract_search_query(path, qs, body_json)
        if query and not flow.metadata.get("dg_allow"):
            v = policy.term_index.judge_query(tokens(query))
            if v.block:
                self._block(flow, v.rule_id or "Y-term")
                return

        if path.startswith("/youtubei/v1/player") or path.startswith("/youtubei/v1/next"):
            flow.metadata["dg_scan"] = "yt-json"
        elif path.startswith(("/youtubei/v1/browse", "/youtubei/v1/search", "/youtubei/v1/guide")):
            flow.metadata["dg_scan"] = "yt-strip"  # only to strip Shorts shelves
        elif path in ("/watch", "/results") or path.startswith(("/@", "/channel/", "/c/", "/user/")):
            flow.metadata["dg_scan"] = "html"

    def _scan_kind(self, host: str, path: str) -> str | None:
        if youtube.is_youtube_media_host(host):
            return None
        return "html"

    def _rewrite_query_param(self, flow: http.HTTPFlow, param: str, value: str) -> None:
        flow.request.query[param] = value

    # --- responseheaders: stream everything not worth scanning -----------

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        try:
            self._responseheaders(flow)
        except Exception as e:  # noqa: BLE001
            self._log_hook_error("responseheaders", e)
            if flow.response is not None:
                flow.response.stream = True

    def _responseheaders(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        scan_kind = flow.metadata.get("dg_scan")
        if not scan_kind or flow.metadata.get("dg_allow"):
            flow.response.stream = True
            return
        content_type = flow.response.headers.get("content-type", "")
        content_length = flow.response.headers.get("content-length")
        too_big = content_length is not None and content_length.isdigit() and int(content_length) > MAX_SCAN_BYTES
        wanted = any(t in content_type for t in SCANNED_CONTENT_TYPES.get(scan_kind, ()))
        if not wanted or too_big:
            flow.response.stream = True

    # --- response: content scoring ---------------------------------------

    def response(self, flow: http.HTTPFlow) -> None:
        try:
            self._response(flow)
        except Exception as e:  # noqa: BLE001
            self._log_hook_error("response", e)
            self._block(flow, "G-error")

    def _response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None or flow.response.stream:
            return
        if flow.metadata.get("dg_allow"):
            return
        scan_kind = flow.metadata.get("dg_scan")
        if not scan_kind:
            return

        policy = self._current_policy()
        if policy is None:
            self._block(flow, "G-no-policy")
            return

        host = normalize_host(flow.request.pretty_host)
        path = flow.request.path.split("?", 1)[0] if flow.request.path else "/"

        if scan_kind in ("yt-json", "yt-strip"):
            try:
                body = flow.response.content
            except ValueError:
                return
            if scan_kind == "yt-json":
                v = youtube.evaluate_player_json(body, policy.term_index)
                self._apply_verdict(flow, v)
                if v.block:
                    return
            if policy.enforce:
                stripped = youtube.strip_shorts_json(body)
                if stripped is not None:
                    flow.response.content = stripped
            return

        content_type = flow.response.headers.get("content-type", "")
        if "text/html" not in content_type:
            return
        try:
            html_text = flow.response.text
        except ValueError:
            return
        if not html_text:
            return

        if youtube.is_youtube_host(host) and path == "/watch":
            v = youtube.evaluate_watch_html(html_text, policy.term_index)
        else:
            v = content.evaluate_html(html_text, path, policy.term_index)
        self._apply_verdict(flow, v)

        if youtube.is_youtube_host(host) and not v.block and policy.enforce:
            stripped = youtube.strip_shorts_html(html_text)
            if stripped is not None:
                flow.response.text = stripped

    def _apply_verdict(self, flow: http.HTTPFlow, v) -> None:
        if v.block:
            self._block(flow, v.rule_id or "G-content", score=v.score)
        elif v.near_miss and self.dlog is not None:
            self.dlog.write(action="near_miss", rule=v.rule_id, host=flow.request.pretty_host, path=flow.request.path, score=v.score)

    # --- blocking ----------------------------------------------------------

    def _block(self, flow: http.HTTPFlow, rule_id: str, *, score: int | None = None, detail: str | None = None) -> None:
        policy = self.store.policy if self.store else None
        enforce = policy.enforce if policy is not None else True

        if self.dlog is not None:
            self.dlog.write(
                action="block" if enforce else "would_block",
                rule=rule_id,
                host=flow.request.pretty_host,
                path=flow.request.path,
                score=score,
                detail=detail,
            )

        if not enforce:
            return  # shadow mode: log only, let the flow proceed

        accept = flow.request.headers.get("accept", "")
        is_doc = flow.request.headers.get("sec-fetch-dest") == "document" or "text/html" in accept
        if is_doc:
            flow.response = http.Response.make(
                403, _block_page(rule_id), {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", BLOCK_HEADER: rule_id}
            )
        elif "application/json" in accept:
            import json
            flow.response = http.Response.make(
                403, json.dumps({"error": "blocked", "rule": rule_id}).encode(), {"Content-Type": "application/json", BLOCK_HEADER: rule_id}
            )
        else:
            flow.response = http.Response.make(403, b"", {"Cache-Control": "no-store", BLOCK_HEADER: rule_id})


_HTTP_METHOD_RE = re.compile(rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) [^\r\n]+ HTTP/\d\.\d\r?\n")


def _looks_like_http_request(data: bytes) -> bool:
    return bool(_HTTP_METHOD_RE.match(data))


def _block_page(rule_id: str) -> bytes:
    try:
        with open("/etc/distraction-guard/block_page.html", encoding="utf-8") as f:
            template = f.read()
        return template.replace("{{RULE_ID}}", rule_id).encode("utf-8")
    except OSError:
        return (
            "<!doctype html><html><head><title>Blocked</title></head>"
            "<body><h1>This page matched a blocked rule.</h1>"
            f"<p>Rule: {rule_id}</p></body></html>"
        ).encode("utf-8")


addons = [Guard()]
