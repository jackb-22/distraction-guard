"""End-to-end: a network with real (global) IPv6, like Jack's home wifi.

Found live: at home, nothing loaded at all; at Columbia (IPv4-only)
everything was fine. Browsers prefer IPv6 when the network offers it, and
nftables' redirect keeps the connection's source address -- the laptop's
own GLOBAL IPv6 address. mitmproxy's block_global option (on by default,
meant to stop a proxy being used as an open relay from the internet) saw a
"global" client and killed every connection:

    Client connection from 2603:...:66bb killed by block_global option.

The watchdog never noticed: its health check goes over IPv4 loopback.

This test gives the namespace a global IPv6 address and default route,
redirects IPv6 web traffic to the proxy's [::1]:8080 listener, and runs
mitmdump with the --set options parsed from the REAL systemd unit, so a
production option that breaks IPv6 fails here.
"""
import os
import re
import shutil
import subprocess
import sys

import pytest

from conftest import ADDON_DIR, REPO_ROOT
from test_e2e_transparent import ORIGIN

MITMDUMP = shutil.which("mitmdump")
pytestmark = pytest.mark.skipif(
    not (MITMDUMP and shutil.which("unshare") and shutil.which("nft") and shutil.which("openssl") and shutil.which("curl")),
    reason="needs mitmdump, unshare, nft, openssl, curl",
)

UNIT = REPO_ROOT / "systemd" / "distraction-guard.service"
# Paths that only make sense on the real machine; the test supplies its own.
_MACHINE_SPECIFIC = {"confdir", "guard_policy", "guard_log", "ssl_verify_upstream_trusted_ca"}


def production_set_args() -> list[str]:
    exec_start = UNIT.read_text().split("ExecStart=", 1)[1].split("\nRestart", 1)[0]
    args = []
    for key, value in re.findall(r"--set\s+([a-z_]+)=(\S+)", exec_start):
        if key not in _MACHINE_SPECIFIC:
            args += ["--set", f"{key}={value}"]
    return args


SCENARIO = r'''
set -e
trap 'kill $(jobs -p) 2>/dev/null' EXIT
mount --bind "$W/hosts" /etc/hosts
ip link set lo up
ip addr add 127.0.0.2/8 dev lo 2>/dev/null || true
ip link add d0 type dummy
ip addr add 2600:1f18::2/64 dev d0 nodad   # a GLOBAL address, like a home ISP's
ip link set d0 up
ip -6 route add default via 2600:1f18::1
echo 'table inet t { chain o { type nat hook output priority dstnat; ip6 daddr 2606:4700::9 tcp dport 443 redirect to :8080; }; }' | nft -f -
"$PY" "$W/origin.py" "$W/srv.pem" "$W/srv.key" > /dev/null 2>&1 &
PYTHONUNBUFFERED=1 PYTHONPATH="$REPO" "$MITMDUMP" --mode transparent@127.0.0.1:8080 --mode "transparent@::1:8080" \
  --set confdir="$W/mitm" --set ssl_insecure=true $PROD_ARGS \
  --set guard_policy="$POLICY" --set guard_log="$W/decisions.jsonl" -s "$ADDON" > "$W/mitm.log" 2>&1 &
for i in $(seq 1 50); do (exec 3<>/dev/tcp/127.0.0.1/8080) 2>/dev/null && break; sleep 0.2; done
sleep 0.3
curl -s -k -m 8 -o /dev/null -w '%{http_code}' --resolve 'h1only.test:443:[2606:4700::9]' https://h1only.test/ || true
echo
grep -c "block_global" "$W/mitm.log" || true
'''


def test_global_ipv6_client_is_proxied_not_killed(tmp_path, fixture_policy):
    (tmp_path / "origin.py").write_text(ORIGIN)
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-keyout", tmp_path / "srv.key", "-out", tmp_path / "srv.pem",
         "-subj", "/CN=h1only.test", "-addext", "subjectAltName=DNS:h1only.test"],
        check=True, capture_output=True,
    )
    (tmp_path / "hosts").write_text("127.0.0.1 localhost\n127.0.0.2 h1only.test\n")
    (tmp_path / "mitm").mkdir()
    env = {
        "PATH": os.environ["PATH"], "W": str(tmp_path), "PY": sys.executable, "MITMDUMP": MITMDUMP,
        "REPO": str(REPO_ROOT), "POLICY": fixture_policy, "ADDON": str(ADDON_DIR / "guard_addon.py"),
        "PROD_ARGS": " ".join(production_set_args()),
    }
    r = subprocess.run(["unshare", "-rnm", "bash", "-c", SCENARIO], env=env, capture_output=True, text=True, timeout=90)
    lines = r.stdout.strip().splitlines()
    if r.returncode != 0 or len(lines) < 2:
        pytest.skip(f"namespace scenario unavailable here: {r.stderr.strip()[-300:]}")
    status, kills = lines[0], lines[1]
    assert kills == "0", f"mitmproxy killed the IPv6 client via block_global ({kills}x)"
    assert status == "200", status


def test_production_args_are_parsed():
    args = production_set_args()
    assert "connection_strategy=lazy" in args
    assert not any(a.startswith(("confdir=", "guard_policy=")) for a in args)
