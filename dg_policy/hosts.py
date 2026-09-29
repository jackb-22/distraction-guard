"""Host normalization, domain-suffix matching, and block/passthrough precedence.

Pure stdlib. No mitmproxy import here -- this module is unit-tested standalone
and reused by both the mitmproxy addon and guardctl.
"""
from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass
from enum import Enum


def normalize_host(raw: str) -> str:
    """Lowercase, strip port/brackets/trailing dot, IDNA-encode.

    Returns "" for anything that can't be turned into a sane hostname --
    callers should treat that as "no usable host" (e.g. block or pass to a
    stricter check), never as an empty-string wildcard match.
    """
    if not raw:
        return ""
    h = raw.strip()
    # Strip IPv6 brackets, e.g. "[::1]:8080" -> "::1"
    if h.startswith("["):
        end = h.find("]")
        if end == -1:
            return ""
        host_part = h[1:end]
        try:
            ipaddress.ip_address(host_part)
            return host_part.lower()
        except ValueError:
            return ""
    # IPv4/hostname with optional :port
    if h.count(":") == 1:
        host_part, _, port = h.partition(":")
        if port and not port.isdigit():
            return ""
        h = host_part
    elif h.count(":") > 1:
        # bare (unbracketed) IPv6 literal, no port possible
        try:
            ipaddress.ip_address(h)
            return h.lower()
        except ValueError:
            return ""
    h = h.rstrip(".").lower()
    if not h:
        return ""
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        pass
    try:
        encoded = h.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        # Already ASCII (e.g. mixed valid/invalid label) or IDNA rejected it --
        # fall back to the lowercased ASCII form rather than dropping the host.
        encoded = h
    return encoded


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


_LAN_V4 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8")]
_LAN_V6 = [ipaddress.ip_network(n) for n in ("fc00::/7", "fe80::/10", "::1/128")]


def is_lan(host: str) -> bool:
    """True if host is an IP literal inside a private/link-local/loopback range."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    nets = _LAN_V6 if ip.version == 6 else _LAN_V4
    return any(ip in n for n in nets)


# Lowercase ASCII hostname with at least one dot, no leading/trailing dot or
# hyphen issues worth normalizing. Entries ending in a digit (possible IPv4
# literals) always take the slow path.
_PLAIN_DOMAIN_RE = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+")


def suffix_chain(host: str):
    """Yield host, then each parent domain, down to (but excluding) the bare TLD.

    "a.b.reddit.com" -> "a.b.reddit.com", "b.reddit.com", "reddit.com"
    Never yields a single-label host (a bare TLD or unqualified name), since
    that would make every domain under it match by accident.
    """
    if is_ip_literal(host):
        yield host
        return
    labels = host.split(".")
    for i in range(len(labels) - 1):
        yield ".".join(labels[i:])


class DomainSet:
    """A set of blocked/allowed domains with suffix matching and rule-id lookup."""

    __slots__ = ("_rule_of",)

    def __init__(self):
        self._rule_of: dict[str, str] = {}

    def add(self, domain: str, rule_id: str) -> None:
        d = normalize_host(domain)
        if d and "." in d and not is_ip_literal(d):
            self._rule_of.setdefault(d, rule_id)
        elif d and is_ip_literal(d):
            self._rule_of.setdefault(d, rule_id)

    def add_many(self, domains, rule_id: str) -> None:
        # Fast path for the common case -- block-list files are already
        # plain lowercase ASCII domains, and full normalize_host() (IP
        # parsing + IDNA) on each of ~1M entries took seconds, during which
        # the proxy served no traffic. Anything unusual takes the slow path.
        rule_of = self._rule_of
        plain = _PLAIN_DOMAIN_RE.fullmatch
        for d in domains:
            if plain(d) and not d[-1].isdigit():
                if d not in rule_of:
                    rule_of[d] = rule_id
            else:
                self.add(d, rule_id)

    def match(self, host: str) -> str | None:
        """Return the rule_id of the most specific match, or None."""
        h = normalize_host(host)
        if not h:
            return None
        for candidate in suffix_chain(h):
            rid = self._rule_of.get(candidate)
            if rid is not None:
                return rid
        return None

    def __len__(self) -> int:
        return len(self._rule_of)

    def __bool__(self) -> bool:
        return bool(self._rule_of)


class HostKind(Enum):
    BLOCK = "block"
    PASSTHROUGH = "passthrough"
    ALLOW_TEMP = "allow_temp"
    INSPECT = "inspect"


@dataclass(frozen=True)
class HostDecision:
    kind: HostKind
    rule_id: str | None = None
    temp_expires_at: float | None = None


def classify_host(
    host: str,
    *,
    block_sets: list[DomainSet],
    exceptions: DomainSet,
    passthrough: DomainSet,
    temp_allows: dict[str, float],
    now: float | None = None,
) -> HostDecision:
    """Classify a host per the precedence order:

    1. unexpired temp_allows (host or suffix parent) -> ALLOW_TEMP
    2. exceptions (friend-approved unblocks)          -> skip block sets entirely
    3. block_sets (lists + rules.d + local blocks)    -> BLOCK
    4. passthrough                                    -> PASSTHROUGH
    5. otherwise                                       -> INSPECT

    A passthrough entry never overrides a block: block_sets are always
    checked before passthrough, unless an exception says otherwise.
    """
    now = now if now is not None else time.time()
    h = normalize_host(host)
    if not h:
        return HostDecision(HostKind.BLOCK, "G-bad-host")

    for candidate in suffix_chain(h):
        expires = temp_allows.get(candidate)
        if expires is not None and expires > now:
            return HostDecision(HostKind.ALLOW_TEMP, None, expires)

    if exceptions.match(h) is not None:
        pt_rule = passthrough.match(h)
        return HostDecision(HostKind.PASSTHROUGH if pt_rule else HostKind.INSPECT, pt_rule)

    for bs in block_sets:
        rid = bs.match(h)
        if rid is not None:
            return HostDecision(HostKind.BLOCK, rid)

    pt_rule = passthrough.match(h)
    if pt_rule is not None:
        return HostDecision(HostKind.PASSTHROUGH, pt_rule)

    return HostDecision(HostKind.INSPECT, None)
