"""Decision log writer: JSON lines, size-based rotation, and strict
redaction -- query strings and term text must never reach this log. Only
rule ids, a coarse host, and the first path segment are ever written."""
from __future__ import annotations

import json
import logging
import os
import time
from urllib.parse import urlsplit

MAX_BYTES = 10 * 1024 * 1024
BACKUP_COUNT = 5
# One loading page can trigger dozens of identical decisions (every image,
# script and poll on a blocked host) -- found live, where one visit to
# reddit filled a 20-line log view with redd.it thumbnails. Repeat
# (action, rule, host) entries within this window are dropped.
DEDUPE_SECONDS = 60

# Rules whose *host* is safe to log in the clear -- everything else gets the
# host redacted to just its rule id, because the block/list category itself
# (e.g. "matched the NSFW list") can be sensitive.
_HOST_SAFE_PREFIXES = ("S-", "Y-", "P-", "G-", "C-", "D-", "B-user", "W-workaround", "L-bypass")


def path_head(path: str) -> str:
    """First path segment only, no query string -- e.g. '/watch' not
    '/watch?v=xyz&list=...'."""
    p = urlsplit(path).path if "://" in path else path.split("?", 1)[0]
    parts = [seg for seg in p.split("/") if seg]
    return "/" + parts[0] if parts else "/"


def _safe_host(host: str, rule: str | None) -> str | None:
    if rule is None:
        return None
    if any(rule.startswith(p) for p in _HOST_SAFE_PREFIXES):
        return host
    return None


class DecisionLog:
    def __init__(self, path: str, *, max_bytes: int = MAX_BYTES, backup_count: int = BACKUP_COUNT,
                 dedupe_seconds: float = DEDUPE_SECONDS):
        self.dedupe_seconds = dedupe_seconds
        self._last_seen: dict[tuple, float] = {}
        self.path = path
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self._warned = False

    def _rotate_if_needed(self) -> None:
        try:
            if os.path.getsize(self.path) < self.max_bytes:
                return
        except OSError:
            return
        for i in range(self.backup_count - 1, 0, -1):
            src = f"{self.path}.{i}"
            dst = f"{self.path}.{i + 1}"
            if os.path.exists(src):
                os.replace(src, dst)
        os.replace(self.path, f"{self.path}.1")

    def write(
        self,
        *,
        action: str,  # block | would_block | near_miss | kill | error
        rule: str | None = None,
        host: str | None = None,
        path: str | None = None,
        score: int | None = None,
        mode: str = "enforce",
        detail: str | None = None,  # e.g. the Sec-Fetch-Dest of a C-class block
    ) -> None:
        safe = _safe_host(host, rule) if host else None
        key = (action, rule, safe)
        now = time.monotonic()
        last = self._last_seen.get(key)
        if last is not None and now - last < self.dedupe_seconds:
            return
        self._last_seen[key] = now
        if len(self._last_seen) > 4096:  # bound memory on a long-running proxy
            cutoff = now - self.dedupe_seconds
            self._last_seen = {k: v for k, v in self._last_seen.items() if v >= cutoff}
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
            "mode": mode,
            "action": action,
            "rule": rule,
            "host": safe,
            "path_head": path_head(path) if path else None,
            "score": score,
        }
        if detail:
            entry["detail"] = detail
        try:
            self._rotate_if_needed()
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, separators=(",", ":")) + "\n")
        except OSError as e:
            # Logging must never take down the proxy -- but it must not fail
            # invisibly either: a permissions bug once meant zero entries
            # were ever written, with nothing saying why. Warn once.
            if not self._warned:
                self._warned = True
                logging.getLogger(__name__).warning("decision log %s not writable: %s", self.path, e)
