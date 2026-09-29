"""End-to-end: real mitmdump + the real addon in transparent mode, inside a
throwaway user+net+mount namespace, with an nft redirect exactly like
production's. Nothing else in the suite runs traffic through the proxy,
which is how the addon's next_layer hook shipped relaying every decrypted
connection as raw bytes -- uninspected, and broken outright for HTTP/2
clients talking to HTTP/1.1-only servers (Columbia CAS, Microsoft login).

The fake origin is HTTP/1.1-only on purpose. It's reached via a
TEST-NET-3 address (203.0.113.9, redirected to the proxy by nft), and the
proxy's upstream pin resolves its SNI through a bind-mounted /etc/hosts to
127.0.0.2, where the origin actually listens.

DG_ADDON overrides which addon file is loaded, to confirm this fails
against an old version.
"""
import json
import os
import shutil
import subprocess
import sys
import textwrap

import pytest

from conftest import ADDON_DIR, REPO_ROOT

MITMDUMP = shutil.which("mitmdump")
pytestmark = pytest.mark.skipif(
    not (MITMDUMP and shutil.which("unshare") and shutil.which("nft") and shutil.which("openssl") and shutil.which("curl")),
    reason="needs mitmdump, unshare, nft, openssl, curl",
)

ORIGIN = textwrap.dedent('''
    import http.server, ssl, sys
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(sys.argv[1], sys.argv[2])
    ctx.set_alpn_protocols(["http/1.1"])  # HTTP/1.1-only, like cas.columbia.edu
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def do_GET(self):
            b = (b"<html><head><title>all about zorblax</title></head><body>x</body></html>"
                 if self.path == "/term" else b"<html><head><title>fine</title></head><body>ok</body></html>")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
        def log_message(self, *a): pass
    s = http.server.ThreadingHTTPServer(("127.0.0.2", 443), H)
    s.socket = ctx.wrap_socket(s.socket, server_side=True)
    s.serve_forever()
''')

SCENARIO = r'''
set -e
# Background jobs would otherwise hold stdout open and hang subprocess.run.
trap 'kill $(jobs -p) 2>/dev/null' EXIT
mount --bind "$W/hosts" /etc/hosts
ip link set lo up
ip addr add 127.0.0.2/8 dev lo 2>/dev/null || true
ip link add d0 type dummy; ip addr add 192.0.2.2/24 dev d0; ip link set d0 up
ip route add default via 192.0.2.1
echo 'table inet t { chain o { type nat hook output priority dstnat; ip daddr 203.0.113.9 tcp dport 443 redirect to :8080; }; }' | nft -f -
"$PY" "$W/origin.py" "$W/srv.pem" "$W/srv.key" > /dev/null 2>&1 &
PYTHONPATH="$REPO" "$MITMDUMP" -q --mode transparent@127.0.0.1:8080 \
  --set confdir="$W/mitm" --set connection_strategy=lazy --set ssl_insecure=true \
  --set guard_policy="$POLICY" --set guard_log="$W/decisions.jsonl" -s "$ADDON" > "$W/mitm.log" 2>&1 &
for i in $(seq 1 50); do (exec 3<>/dev/tcp/127.0.0.1/8080) 2>/dev/null && break; sleep 0.2; done
C="curl -s -k --resolve h1only.test:443:203.0.113.9 -m 8"
h2=$($C -w '%{http_code} %{http_version}' -o /dev/null https://h1only.test/ || true)
h1=$($C --http1.1 -w '%{http_code}' -o /dev/null https://h1only.test/ || true)
term=$($C -H 'Accept: text/html' -w '%{http_code}' -o /dev/null https://h1only.test/term || true)
raw=$("$PY" -c "
import socket
s = socket.create_connection(('203.0.113.9', 443), timeout=5)
s.sendall(b'GET / HTTP/1.1\r\nHost: h1only.test\r\n\r\n')
try: d = s.recv(200)
except OSError: d = b''
print('reached-origin' if b'fine' in d else 'closed')
")
printf '{"h2": "%s", "h1": "%s", "term": "%s", "raw": "%s"}\n' "$h2" "$h1" "$term" "$raw"
'''


def _run(tmp_path, fixture_policy, *, enforce: bool) -> tuple[dict, list[dict]]:
    policy = json.loads(open(fixture_policy).read())
    policy["enforce"] = enforce
    policy_path = tmp_path / "policy-e2e.json"
    policy_path.write_text(json.dumps(policy))

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
        "REPO": str(REPO_ROOT), "POLICY": str(policy_path),
        "ADDON": os.environ.get("DG_ADDON", str(ADDON_DIR / "guard_addon.py")),
    }
    r = subprocess.run(["unshare", "-rnm", "bash", "-c", SCENARIO], env=env, capture_output=True, text=True, timeout=90)
    if r.returncode != 0 or not r.stdout.strip():
        pytest.skip(f"namespace scenario unavailable here: {r.stderr.strip()[-300:]}")
    decisions_path = tmp_path / "decisions.jsonl"
    decisions = [json.loads(l) for l in decisions_path.read_text().splitlines()] if decisions_path.exists() else []
    return json.loads(r.stdout.strip().splitlines()[-1]), decisions


def test_e2e_enforcing(tmp_path, fixture_policy):
    out, decisions = _run(tmp_path, fixture_policy, enforce=True)
    # HTTP/2 client -> HTTP/1.1-only origin: the Courseworks/CAS failure.
    assert out["h2"] == "200 2", out
    assert out["h1"] == "200", out
    # Decrypted traffic is actually inspected: the term page is blocked.
    assert out["term"] == "403", out
    assert any(d["action"] == "block" and d["rule"] == "T-1" for d in decisions), decisions
    # Plaintext on :443 never reaches the origin.
    assert out["raw"] == "closed", out
    # Only the one genuinely raw connection may be classed as a raw tunnel
    # -- the old bug tagged every decrypted connection this way.
    assert sum(d["rule"] == "G-raw-tunnel" for d in decisions) == 1, decisions


def test_e2e_shadow_logs_but_does_not_block(tmp_path, fixture_policy):
    out, decisions = _run(tmp_path, fixture_policy, enforce=False)
    assert out["term"] == "200", out
    assert any(d["action"] == "would_block" and d["rule"] == "T-1" for d in decisions), decisions
