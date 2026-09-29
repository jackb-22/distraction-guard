import datetime as dt

import pytest

from dg_policy.schedule import ScheduleError, Window, active_window, parse_calcurse, removed_time

TODAY = dt.date(2026, 9, 21)  # a Monday

APTS = """\
09/21/2026 @ 08:00 -> 09/21/2026 @ 08:10 {1W -> 12/23/2026 w1} |Wake, bathroom
09/21/2026 @ 13:10 -> 09/21/2026 @ 14:25 {1W -> 12/23/2026 w1} |Class: Parallel Functional Programming
09/21/2026 @ 19:00 -> 09/21/2026 @ 21:30 {1W -> 12/23/2026 w1} >99f3ecfb0100b1537d365c7c70abedfd32e9b0c2 |Class: Competitive Programming
09/22/2026 @ 08:40 -> 09/22/2026 @ 09:55 {1W -> 12/23/2026 w2} |Class: Engineering SaaS
09/14/2026 @ 13:10 -> 09/14/2026 @ 14:25|Class: Parallel Functional Programming
10/02/2026 @ 09:00 -> 10/02/2026 @ 10:00|Class: Makeup lecture
"""


def test_parses_weekly_classes_only():
    ws = parse_calcurse(APTS, today=TODAY)
    titles = [(w.weekday, w.start, w.end, w.title) for w in ws]
    assert (0, "13:10", "14:25", "Class: Parallel Functional Programming") in titles
    assert (0, "19:00", "21:30", "Class: Competitive Programming") in titles  # note marker ">..." handled
    assert (1, "08:40", "09:55", "Class: Engineering SaaS") in titles
    assert not any("Wake" in t for *_, t in titles)


def test_past_one_off_dropped_future_one_off_kept():
    ws = parse_calcurse(APTS, today=TODAY)
    one_offs = [w for w in ws if w.start_date == w.until]
    assert [w.title for w in one_offs] == ["Class: Makeup lecture"]
    assert one_offs[0].start_date == "2026-10-02"


def test_skipped_dates_parsed():
    ws = parse_calcurse("09/21/2026 @ 13:10 -> 09/21/2026 @ 14:25 {1W -> 12/23/2026 !10/12/2026} |Class: X\n", today=TODAY)
    assert ws[0].skip == ("2026-10-12",)


def test_non_weekly_class_recurrence_is_an_error_not_silently_skipped():
    with pytest.raises(ScheduleError, match="only weekly"):
        parse_calcurse("09/21/2026 @ 13:10 -> 09/21/2026 @ 14:25 {1D -> 12/23/2026} |Class: X\n", today=TODAY)


def test_unparseable_class_line_is_an_error():
    with pytest.raises(ScheduleError, match="can't parse"):
        parse_calcurse("09/21/2026 [1] Class: all-day thing\n", today=TODAY)


def test_crossing_midnight_is_an_error():
    with pytest.raises(ScheduleError, match="midnight"):
        parse_calcurse("09/21/2026 @ 23:00 -> 09/22/2026 @ 01:00 |Class: Late\n", today=TODAY)


def _w(weekday=0, start="13:10", end="14:25", start_date="2026-09-21", until="2026-12-23", skip=()):
    return Window("Class: X", weekday, start, end, start_date, until, tuple(skip))


def test_active_window_with_padding():
    ws = [_w()]
    assert active_window(ws, dt.datetime(2026, 9, 21, 13, 5), pad_minutes=5) is not None
    assert active_window(ws, dt.datetime(2026, 9, 21, 13, 4), pad_minutes=5) is None
    assert active_window(ws, dt.datetime(2026, 9, 21, 14, 29), pad_minutes=5) is not None
    assert active_window(ws, dt.datetime(2026, 9, 21, 14, 30), pad_minutes=5) is None


def test_active_window_respects_weekday_dates_and_skips():
    ws = [_w(skip=["2026-10-05"])]
    assert active_window(ws, dt.datetime(2026, 9, 22, 13, 30)) is None  # Tuesday
    assert active_window(ws, dt.datetime(2026, 9, 14, 13, 30)) is None  # before start_date
    assert active_window(ws, dt.datetime(2026, 12, 28, 13, 30)) is None  # after until
    assert active_window(ws, dt.datetime(2026, 10, 5, 13, 30)) is None  # skipped
    assert active_window(ws, dt.datetime(2026, 10, 12, 13, 30)) is not None


def test_removed_time_empty_when_only_adding():
    old = [_w()]
    new = [_w(), _w(weekday=2)]
    assert removed_time(old, new, today=TODAY) == []


def test_removed_time_detects_dropped_shortened_and_skipped():
    old = [_w()]
    assert removed_time(old, [], today=TODAY) == old
    assert removed_time(old, [_w(end="14:00")], today=TODAY) == old
    assert removed_time(old, [_w(skip=["2026-10-05"])], today=TODAY) == old
    assert removed_time(old, [_w(until="2026-11-01")], today=TODAY) == old


def test_removed_time_ignores_windows_already_over():
    old = [_w(until="2026-09-01")]
    assert removed_time(old, [], today=TODAY) == []


def test_window_json_round_trip_and_validation():
    w = _w(skip=["2026-10-05"])
    assert Window.from_json(w.to_json()) == w
    with pytest.raises(ScheduleError):
        Window.from_json({**w.to_json(), "end": "13:00"})
