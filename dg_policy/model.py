"""The compiled policy: on-disk JSON schema, loader with mtime-based reload,
and the PolicyStore that ties hosts/terms/rules together into one object the
addon and guardctl both use.

A load failure (missing file, bad JSON, referenced file missing) NEVER
raises out of PolicyStore.refresh() -- it logs and keeps whatever policy
was loaded before. This is what stops a bad `guardctl` edit from crashing
the proxy the way v1's unreadable exempt-hosts.txt did.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field

from dg_policy.hosts import DomainSet, HostDecision, HostKind, classify_host
from dg_policy.rules import PathRule
from dg_policy.schedule import SUPPORT_HOSTS, Window, active_window
from dg_policy.terms import Term, TermIndex, TermType


# Hosts the proxy never decrypts, whatever else applies (passthrough,
# class mode). Matched on SNI, unlike nftables' IP-based critical_direct,
# so api.anthropic.com (Claude Code) stays untouched while claude.ai, on
# the very same IP, goes through class mode like any other site.
NEVER_DECRYPT_DEFAULT = ("api.anthropic.com",)


class PolicyLoadError(Exception):
    """Raised only by load_strict(); refresh() catches everything itself."""


@dataclass
class CompiledPolicy:
    version: int
    hash: str
    enforce: bool
    block_sets: list[DomainSet]
    exceptions: DomainSet
    passthrough: DomainSet
    temp_allows: dict[str, float]
    path_rules: list[PathRule]
    search_cfg: dict
    youtube_cfg: dict
    content_cfg: dict
    term_index: TermIndex
    health_token: str
    raw: dict = field(repr=False, default_factory=dict)
    class_windows: list[Window] = field(default_factory=list)
    class_allow: DomainSet = field(default_factory=DomainSet)
    class_pad_minutes: int = 0
    never_decrypt: DomainSet = field(default_factory=DomainSet)
    daily_hosts: DomainSet = field(default_factory=DomainSet)
    daily_exempt: DomainSet = field(default_factory=DomainSet)
    daily_start: int = 0  # minutes after midnight
    daily_end: int = 0
    night_start: int = 0  # minutes after midnight; equal to night_end = off
    night_end: int = 0

    def night_active(self, now=None) -> bool:
        """True during the night block (all traffic cut). Wraps midnight."""
        import datetime as dt
        if self.night_start == self.night_end:
            return False
        now = now or dt.datetime.now()
        t = now.hour * 60 + now.minute
        if self.night_start < self.night_end:
            return self.night_start <= t < self.night_end
        return t >= self.night_start or t < self.night_end

    def daily_blocks(self, host: str, now=None) -> bool:
        """True if `host` is under the daily block right now."""
        import datetime as dt
        if not self.daily_hosts or self.daily_hosts.match(host) is None or self.daily_exempt.match(host) is not None:
            return False
        now = now or dt.datetime.now()
        t = now.hour * 60 + now.minute
        return self.daily_start <= t < self.daily_end

    def class_window(self, now=None) -> Window | None:
        """The class-mode window in effect right now, if any."""
        import datetime as dt
        if not self.class_windows:
            return None
        return active_window(self.class_windows, now or dt.datetime.now(), pad_minutes=self.class_pad_minutes)

    def class_allows(self, host: str) -> bool:
        return self.class_allow.match(host) is not None

    def classify(self, host: str, *, now: float | None = None) -> HostDecision:
        return classify_host(
            host,
            block_sets=self.block_sets,
            exceptions=self.exceptions,
            passthrough=self.passthrough,
            temp_allows=self.temp_allows,
            now=now,
        )

    def match_path_rule(self, host: str, path: str) -> str | None:
        """Generic host+path-glob block rules (guardctl `block-path`), e.g.
        blocking one subreddit path on an otherwise-allowed host suffix."""
        from dg_policy.rules import path_rule_match

        return path_rule_match(self.path_rules, host, path)


_TERM_TYPES = {"strict": TermType.STRICT, "contextual": TermType.CONTEXTUAL, "combo": TermType.COMBO}


def _load_domain_list_file(path: str, *, required: bool = True) -> list[str]:
    """Load a newline-delimited domain list. If `required` is False, a
    missing file degrades to "this one list is empty" instead of failing
    the whole policy -- used for downloaded block_lists, which can
    legitimately not exist yet (first install, before the refresh timer's
    first successful download) without that being a reason to run with NO
    policy at all. `required=True` (the default) is for files that are
    supposed to always exist once referenced, e.g. by load_strict callers
    that want a hard error on a genuinely broken reference."""
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    out.append(line)
    except OSError:
        if required:
            raise
    return out


# Loaded block-list DomainSets, keyed by (path, rule), reused across policy
# reloads while the file is unchanged. A reload happens on every policy
# change (schedule-sync, set, add-term, the refresh timer); rebuilding ~1.5M
# domains each time froze the proxy for many seconds.
_LIST_CACHE: dict[tuple[str, str], tuple[tuple[float, int], DomainSet]] = {}


def _cached_list_set(path: str, rule: str) -> DomainSet:
    try:
        st = os.stat(path)
        sig = (st.st_mtime, st.st_size)
    except OSError:
        sig = (0.0, -1)  # missing file -> empty set (required=False semantics)
    hit = _LIST_CACHE.get((path, rule))
    if hit is not None and hit[0] == sig:
        return hit[1]
    ds = DomainSet()
    ds.add_many(_load_domain_list_file(path, required=False), rule)
    _LIST_CACHE[(path, rule)] = (sig, ds)
    return ds


def _load_terms(terms_path: str) -> list[Term]:
    if not os.path.exists(terms_path):
        return []
    with open(terms_path, encoding="utf-8") as f:
        raw = json.load(f)
    terms = []
    for entry in raw:
        ttype = _TERM_TYPES[entry["type"]]
        parts = tuple(tuple(p) for p in entry["parts"])
        terms.append(Term(entry["id"], ttype, parts))
    return terms


def _load_lexicon(paths: list[str]) -> set[str]:
    """Load context words and normalize each one through the same
    tokenize() pipeline as scanned text. Without this, an unstemmed entry
    (e.g. "running" in the file vs. the "run" token scanned text
    produces) would silently never match -- found while testing the
    shipped lexicon/context.txt. A multi-word entry contributes nothing
    (tokens() would split it), which is intentional: context_words is
    single-token only, see lexicon/context.txt's own comment on this."""
    from dg_policy.text import tokens as _tokenize

    words = set()
    for p in paths:
        if not os.path.exists(p):
            continue
        if p.endswith(".json"):
            with open(p, encoding="utf-8") as f:
                raw_words = json.load(f)
        else:
            raw_words = _load_domain_list_file(p, required=False)
        for w in raw_words:
            words.update(_tokenize(w))
    return words


def build_policy(raw: dict) -> CompiledPolicy:
    """Build a CompiledPolicy from parsed policy.json + its referenced files.
    Raises on any problem -- callers that want fail-open-to-old-policy
    behavior should use PolicyStore, not this directly."""
    block_sets: list[DomainSet] = []

    for entry in raw.get("block_lists", []):
        block_sets.append(_cached_list_set(entry["path"], entry["rule"]))

    for rule_id, domains in raw.get("block_domains", {}).items():
        ds = DomainSet()
        ds.add_many(domains, rule_id)
        block_sets.append(ds)

    exceptions = DomainSet()
    for host in raw.get("exceptions", []):
        exceptions.add(host, "X-user")

    passthrough = DomainSet()
    for entry in raw.get("passthrough", []):
        if isinstance(entry, str):
            passthrough.add(entry, "P-passthrough")
        else:
            passthrough.add(entry["host"], entry.get("rule", "P-passthrough"))

    temp_allows: dict[str, float] = {}
    for entry in raw.get("temp_allows", []):
        temp_allows[entry["host"]] = float(entry["expires_at"])

    path_rules_raw = raw.get("path_rules", [])
    if not isinstance(path_rules_raw, list):
        raise ValueError(f"path_rules must be a list, got {type(path_rules_raw).__name__}")
    path_rules = [
        PathRule(id=entry["id"], host_suffix=entry["host_suffix"], path_glob=entry["path_glob"])
        for entry in path_rules_raw
    ]

    terms = _load_terms(raw["terms_path"])
    lexicon = _load_lexicon(raw.get("lexicon_paths", []))
    content_cfg = raw.get("content", {})
    term_index = TermIndex(
        terms,
        lexicon,
        threshold=content_cfg.get("threshold", 8),
        window=content_cfg.get("window", 12),
    )

    class_raw = raw.get("class_mode") or {}
    class_windows = [Window.from_json(w) for w in class_raw.get("windows", [])]
    class_allow = DomainSet()
    if class_windows:
        class_allow.add_many(class_raw.get("allow", []), "C-allow")
        class_allow.add_many(SUPPORT_HOSTS, "C-support")

    daily_raw = class_raw.get("daily_block") or {}
    daily_hosts, daily_exempt = DomainSet(), DomainSet()
    daily_hosts.add_many(daily_raw.get("hosts", []), "D-daily")
    daily_exempt.add_many(daily_raw.get("exempt", []), "D-exempt")
    daily_start = daily_end = 0
    if daily_hosts:
        from dg_policy.schedule import _minutes
        daily_start, daily_end = _minutes(daily_raw["start"]), _minutes(daily_raw["end"])

    night_raw = class_raw.get("night_block") or {}
    night_start = night_end = 0
    if night_raw.get("start") and night_raw.get("end"):
        from dg_policy.schedule import _minutes
        night_start, night_end = _minutes(night_raw["start"]), _minutes(night_raw["end"])

    never_decrypt = DomainSet()
    never_decrypt.add_many([*NEVER_DECRYPT_DEFAULT, *raw.get("never_decrypt", [])], "P-never-decrypt")

    health_token = ""
    tok_path = raw.get("health_token_path")
    if tok_path and os.path.exists(tok_path):
        with open(tok_path, encoding="utf-8") as f:
            health_token = f.read().strip()

    return CompiledPolicy(
        version=raw.get("version", 1),
        hash=raw.get("hash", ""),
        enforce=bool(raw.get("enforce", False)),
        block_sets=block_sets,
        exceptions=exceptions,
        passthrough=passthrough,
        temp_allows=temp_allows,
        path_rules=path_rules,
        search_cfg=raw.get("search", {}),
        youtube_cfg=raw.get("youtube", {}),
        content_cfg=content_cfg,
        term_index=term_index,
        health_token=health_token,
        raw=raw,
        class_windows=class_windows,
        class_allow=class_allow,
        class_pad_minutes=int(class_raw.get("pad_minutes", 0)),
        never_decrypt=never_decrypt,
        daily_hosts=daily_hosts,
        daily_exempt=daily_exempt,
        daily_start=daily_start,
        daily_end=daily_end,
        night_start=night_start,
        night_end=night_end,
    )


class PolicyStore:
    """Watches a compiled policy.json file and reloads it on change.

    A failed reload (bad JSON, missing referenced file, etc.) is logged and
    the previous good CompiledPolicy is kept -- state stays "stale" rather
    than the process crashing or every flow force-blocking. If NO policy has
    ever loaded successfully, `.policy` is None and callers must fail closed.
    """

    def __init__(self, path: str, *, min_check_interval: float = 2.0, on_error=None):
        self.path = path
        self.min_check_interval = min_check_interval
        self._on_error = on_error or (lambda msg: None)
        self.policy: CompiledPolicy | None = None
        self._mtime: float = -1.0
        self._last_check: float = 0.0
        self.load_error: str | None = None

    def refresh(self, *, force: bool = False) -> bool:
        """Reload if the file's mtime changed. `force` only bypasses the
        min_check_interval throttle (checks right now instead of waiting) --
        it does NOT skip the "mtime genuinely unchanged" no-op. Returns True
        if the in-use policy changed. Never raises."""
        now = time.time()
        if not force and (now - self._last_check) < self.min_check_interval:
            return False
        self._last_check = now
        try:
            mtime = os.path.getmtime(self.path)
        except OSError as e:
            self.load_error = f"stat failed: {e}"
            self._on_error(self.load_error)
            return False
        if mtime == self._mtime:
            return False
        try:
            with open(self.path, encoding="utf-8") as f:
                raw = json.load(f)
            new_policy = build_policy(raw)
        except Exception as e:  # noqa: BLE001 - deliberately broad, see class docstring
            self.load_error = f"{type(e).__name__}: {e}"
            self._on_error(self.load_error)
            return False
        self.policy = new_policy
        self._mtime = mtime
        self.load_error = None
        return True

    def load_strict(self) -> CompiledPolicy:
        """Used by `guardctl compile` to validate before publishing. Raises
        PolicyLoadError with a readable message instead of swallowing it."""
        try:
            with open(self.path, encoding="utf-8") as f:
                raw = json.load(f)
            return build_policy(raw)
        except Exception as e:  # noqa: BLE001
            raise PolicyLoadError(f"{type(e).__name__}: {e}") from e
