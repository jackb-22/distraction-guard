import shutil
import subprocess

import pytest

from guardctl.nftgen import NftConfig, NftRenderError, render

HAVE_UNSHARE_NFT = shutil.which("unshare") and shutil.which("nft")


def _check_syntax(text: str, tmp_path):
    p = tmp_path / "guard.nft"
    p.write_text(text)
    result = subprocess.run(
        ["unshare", "-rn", "nft", "-c", "-f", str(p)],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr


def test_normal_mode_basic_render():
    text = render(NftConfig(mode="normal"))
    assert "redirect to :8080" in text
    assert "meta skuid 1000" in text


def test_degraded_mode_basic_render():
    text = render(NftConfig(mode="degraded"))
    assert "redirect to" not in text
    assert "accept" in text


@pytest.mark.skipif(not HAVE_UNSHARE_NFT, reason="needs unshare+nft")
def test_normal_mode_valid_nft_syntax(tmp_path):
    text = render(NftConfig(mode="normal"))
    _check_syntax(text, tmp_path)


@pytest.mark.skipif(not HAVE_UNSHARE_NFT, reason="needs unshare+nft")
def test_degraded_mode_valid_nft_syntax(tmp_path):
    text = render(NftConfig(mode="degraded"))
    _check_syntax(text, tmp_path)


@pytest.mark.skipif(not HAVE_UNSHARE_NFT, reason="needs unshare+nft")
def test_with_ssh_allow_and_lan_ports_valid_syntax(tmp_path):
    cfg = NftConfig(
        mode="normal",
        ssh_allow_ipv4=["140.82.112.3", "140.82.113.0/24"],
        ssh_allow_ipv6=["2606:50c0::/32"],
        lan_tcp_ports=[22, 445, 8384],
    )
    text = render(cfg)
    assert "140.82.112.3" in text
    _check_syntax(text, tmp_path)


@pytest.mark.skipif(not HAVE_UNSHARE_NFT, reason="needs unshare+nft")
def test_empty_sets_valid_syntax(tmp_path):
    text = render(NftConfig(mode="normal", ssh_allow_ipv4=[], ssh_allow_ipv6=[], lan_tcp_ports=[]))
    _check_syntax(text, tmp_path)


def test_bad_mode_rejected():
    with pytest.raises(NftRenderError):
        render(NftConfig(mode="bogus"))


def test_bad_port_rejected():
    with pytest.raises(NftRenderError):
        render(NftConfig(lan_tcp_ports=[70000]))


def test_mismatched_ip_version_rejected():
    with pytest.raises(NftRenderError):
        render(NftConfig(ssh_allow_ipv4=["::1"]))


def test_no_unfilled_placeholders_ever():
    text = render(NftConfig())
    assert "@@" not in text


def test_critical_direct_exempted_from_redirect_and_allowed_in_filter():
    text = render(NftConfig(critical_direct_ipv4=["160.79.104.10"], critical_direct_ipv6=["2607:6bc0::10"]))
    assert "160.79.104.10" in text
    assert "2607:6bc0::10" in text
    # must appear as a `return` in the NAT chain (before the redirect --
    # skip it entirely) AND as an `accept` in the filter chain (otherwise
    # it falls through to the reject-everything-else catch-all, since
    # skipping the redirect means it never takes the oif "lo" accept path).
    assert "ip daddr @critical_direct4 return" in text
    assert "ip6 daddr @critical_direct6 return" in text
    assert "ip daddr @critical_direct4 accept" in text
    assert "ip6 daddr @critical_direct6 accept" in text


def test_critical_direct_return_precedes_web_nat_jump():
    text = render(NftConfig(critical_direct_ipv4=["160.79.104.10"]))
    nat_chain = text.split("chain jack_nat {")[1].split("chain web_nat {")[0]
    assert nat_chain.index("critical_direct4") < nat_chain.index("jump web_nat")


@pytest.mark.skipif(not HAVE_UNSHARE_NFT, reason="needs unshare+nft")
def test_critical_direct_valid_nft_syntax(tmp_path):
    cfg = NftConfig(
        mode="normal",
        critical_direct_ipv4=["160.79.104.10", "34.107.243.93"],
        critical_direct_ipv6=["2607:6bc0::10"],
    )
    text = render(cfg)
    _check_syntax(text, tmp_path)


def test_critical_direct_mismatched_ip_version_rejected():
    with pytest.raises(NftRenderError):
        render(NftConfig(critical_direct_ipv4=["2607:6bc0::10"]))


def test_dns_is_always_allowed():
    # Regression test for a real outage: the filter chain had no rule at
    # all for DNS (UDP/TCP 53), so applying this table blocked every fresh
    # hostname lookup while already-established connections kept running --
    # "nothing loads" for anything needing a new DNS query. Unconditional,
    # not scoped to lan4, since a resolver outside RFC1918 space would
    # reproduce the same bug.
    text = render(NftConfig())
    jack_out = text.split("chain jack_out {")[1].split("chain web_filter {")[0]
    assert "udp dport 53 accept" in jack_out
    assert "tcp dport 53 accept" in jack_out
    # must come before the catch-all reject at the end of the chain
    assert jack_out.index("dport 53") < jack_out.index("reject with icmpx")


@pytest.mark.skipif(not HAVE_UNSHARE_NFT, reason="needs unshare+nft")
def test_dns_allow_rules_valid_syntax(tmp_path):
    _check_syntax(render(NftConfig()), tmp_path)


# --- end-to-end redirect, in a throwaway network namespace -------------
# Regression test for the outage behind every failed live install: the
# kernel log showed `dg-reject OUT=wlo1 DST=127.0.0.1 DPT=8080` -- every
# connection jack_nat redirected to the proxy was then rejected by
# jack_out. The syntax checks above all passed; only loading the NAT and
# filter chains TOGETHER and pushing a real connection through them
# reproduces it. A dummy interface as the default route stands in for
# wlo1 (so the pre-NAT oif isn't lo), and a stub listener on :8080 stands
# in for mitmproxy, reporting the SO_ORIGINAL_DST it sees.

_NETNS_PROBE = r'''
import socket, struct, subprocess, sys, threading
def sh(*a): subprocess.run(a, check=True)
sh("ip", "link", "set", "lo", "up")
sh("ip", "link", "add", "d0", "type", "dummy")
sh("ip", "addr", "add", "192.0.2.2/24", "dev", "d0")
sh("ip", "addr", "add", "2001:db8:1::2/64", "dev", "d0", "nodad")
sh("ip", "link", "set", "d0", "up")
sh("ip", "route", "add", "default", "via", "192.0.2.1")
sh("ip", "-6", "route", "add", "default", "via", "2001:db8:1::1")
subprocess.run(["nft", "-f", "-"], input=sys.stdin.read(), text=True, check=True)

seen = {}
def serve(family, addr):
    s = socket.socket(family)
    if family == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, 8080)); s.listen()
    def loop():
        while True:
            c, _ = s.accept()
            if family == socket.AF_INET:
                d = c.getsockopt(socket.SOL_IP, 80, 16)
                seen[(socket.inet_ntop(socket.AF_INET, d[4:8]), struct.unpack(">H", d[2:4])[0])] = True
            else:
                d = c.getsockopt(socket.IPPROTO_IPV6, 80, 28)
                seen[(socket.inet_ntop(socket.AF_INET6, d[8:24]), struct.unpack(">H", d[2:4])[0])] = True
            c.close()
    threading.Thread(target=loop, daemon=True).start()
serve(socket.AF_INET, "127.0.0.1")
serve(socket.AF_INET6, "::1")

import json, time
out = {}
for host, port in json.loads(sys.argv[1]):
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    c = socket.socket(fam); c.settimeout(2)
    try:
        c.connect((host, port)); time.sleep(0.2)
        out[f"{host}:{port}"] = "proxied" if (host, port) in seen else "connected-elsewhere"
    except OSError as e:
        out[f"{host}:{port}"] = f"failed: {e}"
print(json.dumps(out))
'''


def _netns_connect(table: str, dests: list[tuple[str, int]]) -> dict[str, str]:
    import json
    import sys

    # Inside `unshare -r` our sockets are owned by uid 0, and render()
    # refuses uid 0 on purpose, so render for uid 1 and retarget.
    table = table.replace("meta skuid 1 ", "meta skuid 0 ")
    result = subprocess.run(
        ["unshare", "-rn", sys.executable, "-c", _NETNS_PROBE, json.dumps(dests)],
        input=table, capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        pytest.skip(f"netns setup unavailable here: {result.stderr.strip()[-200:]}")
    return json.loads(result.stdout)


@pytest.mark.skipif(not HAVE_UNSHARE_NFT, reason="needs unshare+nft")
def test_redirected_web_traffic_actually_reaches_the_proxy():
    out = _netns_connect(
        render(NftConfig(mode="normal", guard_uid=1)),
        [("203.0.113.5", 443), ("203.0.113.5", 80), ("2001:db8::5", 443)],
    )
    assert out == {
        "203.0.113.5:443": "proxied",
        "203.0.113.5:80": "proxied",
        "2001:db8::5:443": "proxied",
    }


@pytest.mark.skipif(not HAVE_UNSHARE_NFT, reason="needs unshare+nft")
def test_non_web_traffic_is_still_rejected():
    # The fix for the above must not turn into "accept everything".
    out = _netns_connect(
        render(NftConfig(mode="normal", guard_uid=1)),
        [("203.0.113.5", 25), ("2001:db8::5", 25)],
    )
    assert all(v.startswith("failed") for v in out.values()), out


# --- Google Meet media ----------------------------------------------------------
# Found live: Meet calls connected with no audio/video, because the media
# (UDP 3478/19302-19309, TCP 19305 or TLS-on-443) was hitting the catch-all
# reject. Inside the namespace nothing answers, so an ALLOWED connection
# times out while a REJECTED one fails immediately.

@pytest.mark.skipif(not HAVE_UNSHARE_NFT, reason="needs unshare+nft")
def test_meet_media_allowed_only_to_meet_ranges():
    out = _netns_connect(
        render(NftConfig(mode="normal", guard_uid=1)),
        [("74.125.250.9", 19305), ("74.125.250.9", 443), ("203.0.113.5", 19305)],
    )
    assert "timed out" in out["74.125.250.9:19305"], out
    assert "timed out" in out["74.125.250.9:443"], out  # not redirected to the proxy
    assert out["203.0.113.5:19305"].startswith("failed") and "timed out" not in out["203.0.113.5:19305"], out


def test_meet_media_udp_ports_render():
    text = render(NftConfig())
    jack_out = text.split("chain jack_out {")[1].split("chain web_filter {")[0]
    assert "ip daddr @meet_media4 udp dport { 3478, 19302-19309 } accept" in jack_out
    assert jack_out.index("meet_media4 udp") < jack_out.index("reject with icmpx")
