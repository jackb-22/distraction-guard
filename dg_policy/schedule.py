"""Class-mode schedule: time windows during which browser navigation is
limited to an allowlist (see dg_policy.model.CompiledPolicy.class_window).

Windows come from calcurse's `apts` file (entries whose title starts with
a prefix, "Class:" by default), snapshotted by `guardctl schedule-sync`
into root-owned config -- the calcurse file itself is jack's to edit, so it
is never read live by the proxy.

A window is one weekly slot: weekday + start/end time, active between
`start_date` and `until` (inclusive), minus `skip` dates. A one-off
calcurse appointment becomes a window with start_date == until.
"""
from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field

# 09/21/2026 @ 13:10 -> 09/21/2026 @ 14:25 {1W -> 12/23/2026 w1} >note |Title
_APT_RE = re.compile(
    r"^(?P<d0>\d\d/\d\d/\d{4}) @ (?P<t0>\d\d:\d\d) -> (?P<d1>\d\d/\d\d/\d{4}) @ (?P<t1>\d\d:\d\d)"
    r"\s*(?:\{(?P<rec>[^}]*)\})?\s*(?:>\S+\s*)?\|(?P<title>.*)$"
)
# 1W | 1W -> 12/23/2026 | 1W -> 12/23/2026 w1 | ... !10/12/2026 (skipped dates)
_REC_RE = re.compile(r"^\s*(?P<n>\d+)(?P<unit>[DWMY])(?:\s*->\s*(?P<until>\d\d/\d\d/\d{4}))?(?P<rest>.*)$")


# Sign-in and support hosts an allowed site redirects through. Without
# these, "open Courseworks" bounces to CAS/Duo or Google sign-in and gets
# the block page. Always allowed during class, not taken from bookmarks.
SUPPORT_HOSTS = (
    "columbia.edu",  # CAS, Courseworks, Vergil, course pages under cs.columbia.edu
    "instructure.com",  # Canvas (= Courseworks): canvadocs, chat, file previews
    "canvaslms.com",  # Canvas SSO hops (sso.canvaslms.com)
    "evaluationkit.com",  # Columbia course evaluations, launched from Canvas
    "duosecurity.com",
    "accounts.google.com",
    "login.microsoftonline.com",
)


class ScheduleError(ValueError):
    pass


@dataclass(frozen=True)
class Window:
    title: str
    weekday: int  # 0 = Monday, like datetime.weekday()
    start: str  # "HH:MM"
    end: str  # "HH:MM", same day, after start
    start_date: str  # "YYYY-MM-DD"
    until: str | None  # "YYYY-MM-DD" inclusive; None = no end
    skip: tuple[str, ...] = field(default_factory=tuple)

    def to_json(self) -> dict:
        return {
            "title": self.title, "weekday": self.weekday, "start": self.start, "end": self.end,
            "start_date": self.start_date, "until": self.until, "skip": list(self.skip),
        }

    @staticmethod
    def from_json(d: dict) -> "Window":
        w = Window(
            title=str(d.get("title", "")), weekday=int(d["weekday"]), start=d["start"], end=d["end"],
            start_date=d["start_date"], until=d.get("until"), skip=tuple(d.get("skip", [])),
        )
        _validate(w)
        return w


def _minutes(hhmm: str) -> int:
    h, m = hhmm.split(":")
    h, m = int(h), int(m)
    if not (0 <= h < 24 and 0 <= m < 60):
        raise ScheduleError(f"bad time {hhmm!r}")
    return h * 60 + m


def _validate(w: Window) -> None:
    if not 0 <= w.weekday <= 6:
        raise ScheduleError(f"{w.title}: bad weekday {w.weekday}")
    if _minutes(w.end) <= _minutes(w.start):
        raise ScheduleError(f"{w.title}: ends ({w.end}) before it starts ({w.start})")
    dt.date.fromisoformat(w.start_date)
    if w.until is not None:
        dt.date.fromisoformat(w.until)
    for s in w.skip:
        dt.date.fromisoformat(s)


def _mdy(s: str) -> dt.date:
    return dt.datetime.strptime(s, "%m/%d/%Y").date()


def parse_calcurse(text: str, *, prefix: str = "Class:", today: dt.date | None = None) -> list[Window]:
    """Windows for every calcurse appointment whose title starts with
    `prefix`. Entries that have fully ended before `today` are dropped.
    Anything matching the prefix that can't be represented (non-weekly
    recurrence, crossing midnight, unparseable line) raises ScheduleError
    rather than being silently skipped -- a class quietly missing from the
    schedule is exactly the failure this must not have."""
    today = today or dt.date.today()
    out: list[Window] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        m = _APT_RE.match(line)
        if not m:
            if prefix in line:
                raise ScheduleError(f"line {lineno}: can't parse class entry: {line!r}")
            continue
        title = m["title"].strip()
        if not title.startswith(prefix):
            continue
        d0, d1 = _mdy(m["d0"]), _mdy(m["d1"])
        if d0 != d1:
            raise ScheduleError(f"line {lineno}: {title!r} crosses midnight, not supported")

        until: dt.date | None = d0
        skip: list[str] = []
        if m["rec"] is not None:
            r = _REC_RE.match(m["rec"])
            if not r or r["unit"] != "W" or r["n"] != "1":
                raise ScheduleError(f"line {lineno}: {title!r} repeats as {{{m['rec']}}}; only weekly (1W) is supported")
            until = _mdy(r["until"]) if r["until"] else None
            skip = [_mdy(s).isoformat() for s in re.findall(r"!(\d\d/\d\d/\d{4})", r["rest"])]

        if until is not None and until < today:
            continue
        w = Window(
            title=title, weekday=d0.weekday(), start=m["t0"], end=m["t1"],
            start_date=d0.isoformat(), until=until.isoformat() if until else None, skip=tuple(skip),
        )
        _validate(w)
        out.append(w)
    return sorted(set(out), key=lambda w: (w.weekday, w.start, w.start_date, w.title))


def active_window(windows: list[Window], now: dt.datetime, *, pad_minutes: int = 0) -> Window | None:
    """The window `now` falls in (padded on both sides), or None."""
    d = now.date()
    t = now.hour * 60 + now.minute
    iso = d.isoformat()
    for w in windows:
        if d.weekday() != w.weekday or iso < w.start_date or (w.until is not None and iso > w.until) or iso in w.skip:
            continue
        if _minutes(w.start) - pad_minutes <= t < _minutes(w.end) + pad_minutes:
            return w
    return None


def removed_time(old: list[Window], new: list[Window], *, today: dt.date) -> list[Window]:
    """Old windows (still current or upcoming) that no single new window
    fully covers -- i.e. class time a sync would take away. Empty means the
    change only adds or keeps time, so it's a pure tightening. Deliberately
    conservative: a window split across two new ones counts as removed, and
    therefore needs a friend code, rather than risk misjudging a loosening
    as safe."""
    t_iso = today.isoformat()
    removed = []
    for o in old:
        if o.until is not None and o.until < t_iso:
            continue  # already over; dropping it removes nothing
        o_from = max(o.start_date, t_iso)
        if not any(_covers(n, o, o_from) for n in new):
            removed.append(o)
    return removed


def _covers(n: Window, o: Window, o_from: str) -> bool:
    return (
        n.weekday == o.weekday
        and _minutes(n.start) <= _minutes(o.start)
        and _minutes(n.end) >= _minutes(o.end)
        and n.start_date <= o_from
        and (n.until is None or (o.until is not None and n.until >= o.until))
        and set(n.skip) <= set(o.skip)
    )
