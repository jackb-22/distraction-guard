"""The watchdog's decision logic: when to flip between normal and degraded
mode based on a stream of health checks. Kept separate from the actual
polling loop (bin/dg-watchdog) so the state machine is unit-testable
without a real proxy, real nft, or real time passing.
"""
from __future__ import annotations

import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

CHECK_INTERVAL_SECONDS = 10
RESTART_BACKOFF_SECONDS = 60
DEGRADE_HEALTHY_STREAK_TO_RESTORE = 12  # 12 * 10s = 2 minutes healthy


class Mode:
    NORMAL = "normal"
    DEGRADED = "degraded"


@dataclass
class WatchdogState:
    mode: str = Mode.NORMAL
    unhealthy_since: float | None = None
    healthy_streak: int = 0
    last_restart: float = 0.0


@dataclass
class Tick:
    """What the watchdog should do this cycle, decided by step()."""
    restart_proxy: bool = False
    set_mode: str | None = None  # Mode.NORMAL | Mode.DEGRADED | None (no change)
    notify: str | None = None


def step(state: WatchdogState, *, healthy: bool, now: float, degrade_after_seconds: int) -> Tick:
    """Pure state transition: given the current state and one health check
    result, returns what to do and mutates `state` in place (mirrors how
    the real loop will call this every CHECK_INTERVAL_SECONDS)."""
    tick = Tick()

    if healthy:
        state.unhealthy_since = None
        state.healthy_streak += 1
        if state.mode == Mode.DEGRADED and state.healthy_streak >= DEGRADE_HEALTHY_STREAK_TO_RESTORE:
            state.mode = Mode.NORMAL
            tick.set_mode = Mode.NORMAL
            tick.notify = "Distraction Guard: proxy healthy again, back to normal mode."
        return tick

    state.healthy_streak = 0
    if state.unhealthy_since is None:
        state.unhealthy_since = now

    if now - state.last_restart >= RESTART_BACKOFF_SECONDS:
        tick.restart_proxy = True
        state.last_restart = now

    if state.mode == Mode.NORMAL and (now - state.unhealthy_since) >= degrade_after_seconds:
        state.mode = Mode.DEGRADED
        tick.set_mode = Mode.DEGRADED
        tick.notify = (
            f"Distraction Guard: proxy has been down for {degrade_after_seconds}s. "
            "Switched to DEGRADED mode (DNS sinkhole + Firefox blocklist only; "
            "keyword/content checks are paused until it recovers)."
        )

    return tick


# --- real health probe (not unit tested against a live proxy; exercised by
# guardctl's selftest instead, which spins up a real mitmdump) -----------

def check_health(*, host: str = "127.0.0.1", admin_port: int = 8081, transparent_ports: tuple[int, ...] = (8080,), token: str = "", expected_hash: str = "", timeout: float = 5.0) -> bool:
    """Two checks, both required: the regular-mode admin endpoint answers
    with the right token/policy hash (proves the addon and policy are
    loaded correctly), AND every transparent-mode port actually accepts a
    TCP connection (proves the listener mitmdump's --mode transparent@...
    flags create is genuinely up).

    These are two DIFFERENT listeners on the same mitmdump process --
    found by tracing through a real failed install that the regular-mode
    check alone can pass while the transparent listener (the one that
    actually relays your traffic once nftables redirects to it) is down,
    which would show "healthy" and let nftables get applied anyway. A raw
    connect-and-close doesn't exercise the full SO_ORIGINAL_DST/relay path
    (that needs an actual NAT redirect in place, which is what we're
    gating), but it does catch "that listener isn't up at all," which is
    the failure mode this addresses."""
    if not _check_admin_endpoint(host, admin_port, token, expected_hash, timeout):
        return False
    return all(_check_port_open(host, p, timeout) for p in transparent_ports)


def _check_admin_endpoint(host: str, port: int, token: str, expected_hash: str, timeout: float) -> bool:
    url = f"http://{host}:{port}/"
    req = urllib.request.Request(url, headers={"Host": "guard.health", "X-DG-Token": token})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return False
            body = resp.read(200).decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError):
        return False
    if not expected_hash:
        return True
    return expected_hash in body


def _check_port_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def restart_proxy() -> None:
    subprocess.run(["systemctl", "restart", "distraction-guard.service"], check=False, timeout=30)


STARTUP_GRACE_SECONDS = 30


def wait_for_startup(check, *, grace: float = STARTUP_GRACE_SECONDS, sleep=time.sleep, clock=time.monotonic) -> bool:
    """Poll `check()` until it's healthy or `grace` seconds pass. Found
    live: at boot the watchdog judged the proxy 0.03s after it started,
    called it unhealthy and restarted it mid-startup. Returns whether it
    came up healthy within the grace period."""
    deadline = clock() + grace
    while True:
        if check():
            return True
        if clock() >= deadline:
            return False
        sleep(1)
