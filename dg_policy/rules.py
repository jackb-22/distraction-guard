"""Generic path-glob rules, and resolving the translate.goog / archive.org
workarounds down to a real classify_host() call on the embedded host."""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass

from dg_policy.hosts import DomainSet, HostDecision, HostKind, classify_host, normalize_host
from dg_policy.search import decode_archive_org, decode_translate_goog


@dataclass(frozen=True)
class PathRule:
    id: str
    host_suffix: str
    path_glob: str


def path_rule_match(rules: list[PathRule], host: str, path: str) -> str | None:
    h = normalize_host(host)
    for r in rules:
        suffix = normalize_host(r.host_suffix)
        if h == suffix or h.endswith("." + suffix):
            if fnmatch.fnmatchcase(path, r.path_glob):
                return r.id
    return None


def resolve_workaround_host(host: str, path: str) -> str | None:
    """If `host`/`path` is a known workaround wrapper (translate.goog,
    archive.org) around another URL, return the embedded target host so it
    can be classified normally. Returns None if this isn't a workaround
    wrapper (caller should classify `host` itself as usual)."""
    decoded = decode_translate_goog(host)
    if decoded is not None:
        return decoded
    decoded = decode_archive_org(host, path)
    if decoded is not None:
        return decoded
    return None


def classify_with_workarounds(
    host: str,
    path: str,
    *,
    block_sets: list[DomainSet],
    exceptions: DomainSet,
    passthrough: DomainSet,
    temp_allows: dict,
    now: float | None = None,
) -> HostDecision:
    """classify_host(), but first unwraps translate.goog/archive.org so a
    blocked site can't be reached by proxying it through those hosts. If the
    *wrapper* host itself would otherwise be BLOCK/INSPECT that still applies
    -- we only ever make the decision *stricter* by checking the embedded
    host, never looser."""
    embedded = resolve_workaround_host(host, path)
    if embedded is None:
        return classify_host(
            host, block_sets=block_sets, exceptions=exceptions,
            passthrough=passthrough, temp_allows=temp_allows, now=now,
        )
    embedded_decision = classify_host(
        embedded, block_sets=block_sets, exceptions=exceptions,
        passthrough=passthrough, temp_allows=temp_allows, now=now,
    )
    if embedded_decision.kind == HostKind.BLOCK:
        return embedded_decision
    # Wrapper hosts (translate.goog, archive.org) are themselves inspected,
    # never treated as passthrough, regardless of the embedded host's status.
    return HostDecision(HostKind.INSPECT, None)
