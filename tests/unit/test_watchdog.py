from guardctl.watchdog import (
    DEGRADE_HEALTHY_STREAK_TO_RESTORE,
    RESTART_BACKOFF_SECONDS,
    Mode,
    WatchdogState,
    step,
)

DEGRADE_AFTER = 300


def test_healthy_stays_normal_no_action():
    s = WatchdogState()
    tick = step(s, healthy=True, now=1000.0, degrade_after_seconds=DEGRADE_AFTER)
    assert not tick.restart_proxy
    assert tick.set_mode is None
    assert s.mode == Mode.NORMAL


def test_brief_unhealthy_blip_does_not_degrade():
    s = WatchdogState()
    now = 1000.0
    tick = step(s, healthy=False, now=now, degrade_after_seconds=DEGRADE_AFTER)
    assert tick.restart_proxy  # first failure always tries a restart
    assert tick.set_mode is None
    assert s.mode == Mode.NORMAL


def test_restart_has_backoff():
    s = WatchdogState()
    now = 1000.0
    tick1 = step(s, healthy=False, now=now, degrade_after_seconds=DEGRADE_AFTER)
    assert tick1.restart_proxy
    tick2 = step(s, healthy=False, now=now + 10, degrade_after_seconds=DEGRADE_AFTER)
    assert not tick2.restart_proxy  # too soon since last restart
    tick3 = step(s, healthy=False, now=now + RESTART_BACKOFF_SECONDS + 1, degrade_after_seconds=DEGRADE_AFTER)
    assert tick3.restart_proxy


def test_degrades_after_threshold():
    s = WatchdogState()
    now = 1000.0
    step(s, healthy=False, now=now, degrade_after_seconds=DEGRADE_AFTER)
    tick = step(s, healthy=False, now=now + DEGRADE_AFTER, degrade_after_seconds=DEGRADE_AFTER)
    assert s.mode == Mode.DEGRADED
    assert tick.set_mode == Mode.DEGRADED
    assert tick.notify is not None


def test_does_not_degrade_before_threshold():
    s = WatchdogState()
    now = 1000.0
    step(s, healthy=False, now=now, degrade_after_seconds=DEGRADE_AFTER)
    tick = step(s, healthy=False, now=now + DEGRADE_AFTER - 1, degrade_after_seconds=DEGRADE_AFTER)
    assert s.mode == Mode.NORMAL
    assert tick.set_mode is None


def test_restores_after_sustained_healthy_streak():
    s = WatchdogState(mode=Mode.DEGRADED)
    now = 1000.0
    tick = None
    for i in range(DEGRADE_HEALTHY_STREAK_TO_RESTORE):
        tick = step(s, healthy=True, now=now + i * 10, degrade_after_seconds=DEGRADE_AFTER)
    assert s.mode == Mode.NORMAL
    assert tick.set_mode == Mode.NORMAL
    assert tick.notify is not None


def test_does_not_restore_on_short_healthy_streak():
    s = WatchdogState(mode=Mode.DEGRADED)
    now = 1000.0
    for i in range(DEGRADE_HEALTHY_STREAK_TO_RESTORE - 1):
        step(s, healthy=True, now=now + i * 10, degrade_after_seconds=DEGRADE_AFTER)
    assert s.mode == Mode.DEGRADED


def test_single_unhealthy_check_resets_healthy_streak():
    s = WatchdogState(mode=Mode.DEGRADED)
    now = 1000.0
    for i in range(DEGRADE_HEALTHY_STREAK_TO_RESTORE - 1):
        step(s, healthy=True, now=now + i * 10, degrade_after_seconds=DEGRADE_AFTER)
    step(s, healthy=False, now=now + 100, degrade_after_seconds=DEGRADE_AFTER)
    assert s.healthy_streak == 0
    assert s.mode == Mode.DEGRADED  # still degraded, streak had to restart


def test_full_cycle_normal_to_degraded_and_back():
    s = WatchdogState()
    now = 1000.0
    # go unhealthy long enough to degrade
    step(s, healthy=False, now=now, degrade_after_seconds=DEGRADE_AFTER)
    step(s, healthy=False, now=now + DEGRADE_AFTER, degrade_after_seconds=DEGRADE_AFTER)
    assert s.mode == Mode.DEGRADED
    # recover
    base = now + DEGRADE_AFTER + 10
    for i in range(DEGRADE_HEALTHY_STREAK_TO_RESTORE):
        step(s, healthy=True, now=base + i * 10, degrade_after_seconds=DEGRADE_AFTER)
    assert s.mode == Mode.NORMAL


def test_wait_for_startup_returns_once_healthy():
    from guardctl.watchdog import wait_for_startup
    results = iter([False, False, True])
    t = [0.0]
    assert wait_for_startup(lambda: next(results), grace=30, sleep=lambda s: t.__setitem__(0, t[0] + s), clock=lambda: t[0]) is True
    assert t[0] == 2


def test_wait_for_startup_gives_up_after_grace():
    from guardctl.watchdog import wait_for_startup
    t = [0.0]
    assert wait_for_startup(lambda: False, grace=5, sleep=lambda s: t.__setitem__(0, t[0] + s), clock=lambda: t[0]) is False
    assert t[0] >= 5
