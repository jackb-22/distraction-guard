#!/usr/bin/env bash
# Runs the full test suite in two passes:
#  1. dg_policy + guardctl unit tests, plain Python 3.13, zero third-party
#     deps -- this mirrors how guardctl actually runs in production (a
#     plain root script, no venv).
#  2. addon tests, which need the pinned mitmproxy version.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

export UV_NATIVE_TLS=1  # uv must trust the local CA once the guard is installed
echo "==> unit tests (stdlib only, Python 3.13)"
uv run --python 3.13 --with pytest pytest -q --ignore=tests/addon

echo
echo "==> addon tests (mitmproxy 12.2.3, Python 3.14)"
uv run --python 3.14 --with mitmproxy==12.2.3 --with pytest pytest -q tests/addon
