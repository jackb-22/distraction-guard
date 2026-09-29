"""End-to-end: many parallel HTTP/2 requests through the transparent proxy.

Found live: Courseworks (Canvas) never finished loading -- Firefox sat on
"Waiting for du11hjcvx0uqb.cloudfront.net" -- because Canvas fires dozens
of script requests at once, multiplexed over one HTTP/2 connection, and
through the proxy a large share of those streams stalled forever. The same
requests over HTTP/1.1, or one at a time, were fine. It reproduces with
bare mitmproxy 12.2.3 in connection_strategy=lazy (no addon involved), so
this test runs the production option set against a local HTTP/2-only
origin, inside a throwaway user+net+mount namespace like
test_e2e_transparent.py.

DG_H2_ADDON / DG_H2_ARGS let a run swap the addon or mitmdump options,
for bisecting.
"""
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

# HTTP/2-only TLS origin, like a CDN edge: every GET returns SIZE bytes.
ORIGIN = textwrap.dedent('''
    import asyncio, ssl, sys
    import h2.config, h2.connection, h2.events
    BODY = b"x" * int(sys.argv[3])

    async def handle(reader, writer):
        conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False))
        conn.initiate_connection()
        writer.write(conn.data_to_send())
        pending = {}

        def pump():
            for sid in list(pending):
                data = pending[sid]
                n = min(len(data), conn.local_flow_control_window(sid), conn.max_outbound_frame_size)
                while n > 0:
                    conn.send_data(sid, data[:n], end_stream=(n == len(data)))
                    data = data[n:]
                    n = min(len(data), conn.local_flow_control_window(sid), conn.max_outbound_frame_size) if data else 0
                if data:
                    pending[sid] = data
                else:
                    del pending[sid]

        while True:
            d = await reader.read(65536)
            if not d:
                break
            for ev in conn.receive_data(d):
                if isinstance(ev, h2.events.RequestReceived):
                    conn.send_headers(ev.stream_id, [
                        (":status", "200"), ("content-type", "application/javascript"),
                        ("content-length", str(len(BODY))),
                    ])
                    pending[ev.stream_id] = BODY
            pump()
            writer.write(conn.data_to_send())
            await writer.drain()
        writer.close()

    async def main():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(sys.argv[1], sys.argv[2])
        ctx.set_alpn_protocols(["h2"])
        srv = await asyncio.start_server(handle, "127.0.0.2", 443, ssl=ctx)
        async with srv:
            await srv.serve_forever()

    asyncio.run(main())
''')

# Production's mitmdump options that matter here (systemd/distraction-guard.service).
PROD_ARGS = "--set connection_strategy=lazy --set stream_large_bodies=2m --set http3=false --set flow_detail=0 --set termlog_verbosity=warn"

SCENARIO = r'''
set -e
trap 'kill $(jobs -p) 2>/dev/null' EXIT
mount --bind "$W/hosts" /etc/hosts
ip link set lo up
ip addr add 127.0.0.2/8 dev lo 2>/dev/null || true
ip link add d0 type dummy; ip addr add 192.0.2.2/24 dev d0; ip link set d0 up
ip route add default via 192.0.2.1
echo 'table inet t { chain o { type nat hook output priority dstnat; ip daddr 203.0.113.9 tcp dport 443 redirect to :8080; }; }' | nft -f -
"$PY" "$W/origin.py" "$W/srv.pem" "$W/srv.key" "$SIZE" > "$W/origin.log" 2>&1 &
PYTHONPATH="$REPO" "$MITMDUMP" --mode transparent@127.0.0.1:8080 \
  --set confdir="$W/mitm" --set ssl_insecure=true $ARGS \
  --set guard_policy="$POLICY" --set guard_log="$W/decisions.jsonl" -s "$ADDON" > "$W/mitm.log" 2>&1 &
for i in $(seq 1 50); do (exec 3<>/dev/tcp/127.0.0.1/8080) 2>/dev/null && break; sleep 0.2; done
sleep 0.3
args=(); for i in $(seq 1 "$N"); do args+=(-o /dev/null "https://cdn.test/chunk-$i.js"); done
curl -s -k --http2 --parallel --parallel-max 50 -m 10 --resolve cdn.test:443:203.0.113.9 \
  -w '%{http_code}\n' "${args[@]}" | sort | uniq -c
'''


def run_h2(tmp_path, policy_path, *, n=60, size=200_000, addon=None, args=None) -> dict[str, int]:
    """Returns {status_code: count} for n parallel HTTP/2 requests."""
    (tmp_path / "origin.py").write_text(ORIGIN)
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-keyout", tmp_path / "srv.key", "-out", tmp_path / "srv.pem",
         "-subj", "/CN=cdn.test", "-addext", "subjectAltName=DNS:cdn.test"],
        check=True, capture_output=True,
    )
    (tmp_path / "hosts").write_text("127.0.0.1 localhost\n127.0.0.2 cdn.test\n")
    (tmp_path / "mitm").mkdir(exist_ok=True)
    env = {
        "PATH": os.environ["PATH"], "W": str(tmp_path), "PY": sys.executable, "MITMDUMP": MITMDUMP,
        "REPO": str(REPO_ROOT), "POLICY": policy_path, "N": str(n), "SIZE": str(size),
        "ADDON": addon or os.environ.get("DG_H2_ADDON", str(ADDON_DIR / "guard_addon.py")),
        "ARGS": args if args is not None else os.environ.get("DG_H2_ARGS", PROD_ARGS),
    }
    r = subprocess.run(["unshare", "-rnm", "bash", "-c", SCENARIO], env=env, capture_output=True, text=True, timeout=120)
    if r.returncode != 0 or not r.stdout.strip():
        pytest.skip(f"namespace scenario unavailable here: {r.stderr.strip()[-300:]}")
    counts = {}
    for line in r.stdout.split("\n"):
        if line.strip():
            c, code = line.split()
            counts[code] = int(c)
    return counts


@pytest.mark.parametrize("size", [2_000, 200_000])
def test_parallel_h2_streams_all_complete(tmp_path, fixture_policy, size):
    counts = run_h2(tmp_path, fixture_policy, size=size)
    assert counts == {"200": 60}, counts
