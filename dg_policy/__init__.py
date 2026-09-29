"""dg_policy: pure-stdlib decision engine for Distraction Guard.

No third-party imports anywhere in this package (checked by
tests/unit/test_no_deps.py, which runs `python3 -I -c "import dg_policy"`).
This lets both the mitmproxy addon and guardctl (a plain root script) share
the exact same blocking logic without dragging mitmproxy into guardctl.
"""
