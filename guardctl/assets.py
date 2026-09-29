"""Everything guardctl produces besides policy.json: the nftables table,
the two dnsmasq conf files, and the merged Firefox policy. Kept separate
from compile.py (which stays focused on the policy.json the proxy actually
reads) because these need resolved IPs, which means real DNS lookups --
injectable here so the assembly logic stays unit-testable.

Applying these to the live system (nft -f, nmcli reload, restarting
services) is deliberately NOT done here -- that's install.sh's job for the
initial apply and dg-watchdog's job for ongoing mode switches. This module
only ever writes files.
"""
from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field

DNSMASQ_SINKHOLE_LIVE_PATH = "/etc/NetworkManager/dnsmasq.d/distraction-guard-sinkhole.conf"

from guardctl.dnsmasqgen import DnsmasqConfig, SafeSearchPin, render_always_on, render_sinkhole
from guardctl.firefox import merge as firefox_merge
from guardctl.nftgen import NftConfig, render as render_nft

# Deliberately empty. critical_direct exempts hosts by resolved IP, at the
# network level, and IPs are shared: api.anthropic.com and claude.ai both
# resolve to 160.79.104.10, so exempting the API (as this used to) let
# browser traffic to claude.ai skip the proxy entirely -- found live, when
# class mode never saw claude.ai at all. Claude Code is protected instead
# by the proxy's never-decrypt list (dg_policy.model NEVER_DECRYPT_DEFAULT),
# which works on SNI and so can tell the two apart.
DEFAULT_CRITICAL_DIRECT_HOSTS: list[str] = []

# hostname -> the pinned hostname(s) that should resolve to it, used for
# SafeSearch enforcement at the DNS layer (defense in depth alongside the
# proxy's own query-parameter rewriting).
SAFE_SEARCH_TARGETS = {
    "forcesafesearch.google.com": ["www.google.com"],
    "restrict.youtube.com": ["www.youtube.com", "m.youtube.com", "youtubei.googleapis.com", "youtube.googleapis.com"],
    "safe.duckduckgo.com": ["duckduckgo.com"],
    "strict.bing.com": ["www.bing.com"],
}


def default_resolver(hostname: str) -> tuple[list[str], list[str]]:
    """Real DNS resolution: returns (ipv4_addrs, ipv6_addrs)."""
    v4, v6 = [], []
    try:
        for family, _, _, _, addr in socket.getaddrinfo(hostname, None):
            if family == socket.AF_INET and addr[0] not in v4:
                v4.append(addr[0])
            elif family == socket.AF_INET6 and addr[0] not in v6:
                v6.append(addr[0])
    except socket.gaierror:
        pass
    return v4, v6


def resolve_hostnames(hostnames: list[str], *, resolver=default_resolver) -> tuple[list[str], list[str]]:
    """Resolve a list of hostnames to a deduped, sorted (ipv4, ipv6) pair.
    Shared by the SSH allowlist and the critical_direct (never-redirect-
    even-if-the-proxy-is-dead) exemption -- both are "these hostnames need
    real IPs baked into an nft set" the same way."""
    v4_all, v6_all = [], []
    for h in hostnames:
        v4, v6 = resolver(h)
        v4_all.extend(v4)
        v6_all.extend(v6)
    return sorted(set(v4_all)), sorted(set(v6_all))


def resolve_ssh_allow(hostnames: list[str], *, resolver=default_resolver) -> dict:
    v4, v6 = resolve_hostnames(hostnames, resolver=resolver)
    return {"ssh_allow_ipv4": v4, "ssh_allow_ipv6": v6}


# YouTube Restricted Mode level -> the DNS endpoint that enforces it.
YOUTUBE_RESTRICT_HOSTS = {"strict": "restrict.youtube.com", "moderate": "restrictmoderate.youtube.com"}


def resolve_safe_search_pins(*, resolver=default_resolver, youtube_restrict: str = "strict") -> list[SafeSearchPin]:
    pins = []
    targets_by_host = dict(SAFE_SEARCH_TARGETS)
    yt_hosts = targets_by_host.pop("restrict.youtube.com")
    targets_by_host[YOUTUBE_RESTRICT_HOSTS.get(youtube_restrict, "restrict.youtube.com")] = yt_hosts
    for pinned_host, targets in targets_by_host.items():
        v4, v6 = resolver(pinned_host)
        if not v4 and not v6:
            continue
        pins.append(SafeSearchPin(hosts=targets, ipv4=v4[0] if v4 else None, ipv6=v6[0] if v6 else None))
    return pins


def sinkhole_domains(raw_policy: dict, list_catalog: list[dict]) -> dict[str, str]:
    """Combine curated block_domains with any downloaded list whose catalog
    entry has dns_sinkhole=true, reading that list's already-downloaded
    file. Returns {domain: rule_id}, used only for the (inert until
    degraded mode) dnsmasq sinkhole file -- the proxy's own block_sets do
    the real work when it's healthy."""
    out: dict[str, str] = {}
    for rule_id, domains in raw_policy.get("block_domains", {}).items():
        for d in domains:
            out[d] = rule_id

    sinkhole_rules = {e["rule"] for e in list_catalog if e.get("dns_sinkhole")}
    for entry in raw_policy.get("block_lists", []):
        if entry["rule"] not in sinkhole_rules:
            continue
        try:
            with open(entry["path"], encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        out.setdefault(line, entry["rule"])
        except OSError:
            continue  # list not downloaded yet -- degraded mode just won't sinkhole it
    return out


@dataclass
class AssetPaths:
    nft_path: str = "/var/lib/distraction-guard/compiled/guard.nft"
    dnsmasq_always_on_path: str = "/etc/NetworkManager/dnsmasq.d/distraction-guard.conf"
    # Staged OUTSIDE dnsmasq.d on purpose: NetworkManager starts dnsmasq with
    # --conf-dir=/etc/NetworkManager/dnsmasq.d, which loads every file there
    # regardless of suffix -- the old ".conf.off" copy was silently live,
    # sinkholing ~90k domains (reddit.com included) even in shadow mode.
    # dg-watchdog copies it into dnsmasq.d only while degraded.
    dnsmasq_sinkhole_off_path: str = "/var/lib/distraction-guard/compiled/dnsmasq-sinkhole.conf"
    firefox_base_policy_path: str = "/usr/lib/firefox/distribution/policies.json"
    firefox_policy_path: str = "/etc/firefox/policies/policies.json"
    ca_path: str = "/etc/distraction-guard/ca.pem"
    resolved_cache_path: str = "/var/lib/distraction-guard/state/resolved.json"


def write_assets(
    raw_policy: dict,
    list_catalog: list[dict],
    *,
    paths: AssetPaths,
    ssh_allow_hostnames: list[str],
    lan_tcp_ports: list[int],
    critical_direct_hostnames: list[str] = (),
    resolver=default_resolver,
    existing_firefox_json: str | None = None,
) -> dict:
    """Resolves what needs resolving, renders every asset, and writes them
    all. Returns a summary dict for logging. Firefox merge is skipped
    (returns firefox_written=False) if no existing policies.json text is
    given (tests can pass a synthetic one; install.sh reads the real file)."""
    import json
    import os

    resolved = resolve_ssh_allow(ssh_allow_hostnames, resolver=resolver)
    critical_hosts = sorted(set(DEFAULT_CRITICAL_DIRECT_HOSTS) | set(critical_direct_hostnames))
    critical4, critical6 = resolve_hostnames(critical_hosts, resolver=resolver)
    resolved["critical_direct_ipv4"] = critical4
    resolved["critical_direct_ipv6"] = critical6
    os.makedirs(os.path.dirname(paths.resolved_cache_path), exist_ok=True)
    _atomic_write(paths.resolved_cache_path, json.dumps(resolved, indent=2))

    nft_cfg = NftConfig(
        mode="normal",
        ssh_allow_ipv4=resolved["ssh_allow_ipv4"],
        ssh_allow_ipv6=resolved["ssh_allow_ipv6"],
        critical_direct_ipv4=critical4,
        critical_direct_ipv6=critical6,
        lan_tcp_ports=lan_tcp_ports,
    )
    nft_text = render_nft(nft_cfg)
    os.makedirs(os.path.dirname(paths.nft_path), exist_ok=True)
    _atomic_write(paths.nft_path, nft_text)

    pins = resolve_safe_search_pins(resolver=resolver, youtube_restrict=raw_policy.get("youtube_restrict", "strict"))
    dns_cfg = DnsmasqConfig(safe_search_pins=pins, sinkhole_domains=sinkhole_domains(raw_policy, list_catalog))
    os.makedirs(os.path.dirname(paths.dnsmasq_always_on_path), exist_ok=True)
    _atomic_write(paths.dnsmasq_always_on_path, render_always_on(dns_cfg))
    _atomic_write(paths.dnsmasq_sinkhole_off_path, render_sinkhole(dns_cfg))
    # Already degraded? Keep the live copy current too.
    if os.path.exists(DNSMASQ_SINKHOLE_LIVE_PATH):
        _atomic_write(DNSMASQ_SINKHOLE_LIVE_PATH, render_sinkhole(dns_cfg))

    firefox_written = False
    if existing_firefox_json is not None:
        block_patterns = _firefox_block_patterns(raw_policy)
        merged = firefox_merge(existing_firefox_json, ca_path=paths.ca_path, block_patterns=block_patterns)
        os.makedirs(os.path.dirname(paths.firefox_policy_path), exist_ok=True)
        _atomic_write(paths.firefox_policy_path, merged)
        firefox_written = True

    return {
        "ssh_allow_ipv4": len(resolved["ssh_allow_ipv4"]),
        "ssh_allow_ipv6": len(resolved["ssh_allow_ipv6"]),
        "critical_direct_ipv4": len(critical4),
        "critical_direct_ipv6": len(critical6),
        "safe_search_pins": len(pins),
        "sinkhole_domains": len(dns_cfg.sinkhole_domains),
        "firefox_written": firefox_written,
    }


def _firefox_block_patterns(raw_policy: dict) -> list[str]:
    """Only S-* rule domains (social feeds, S-social; mirror/frontend
    workarounds, S-workaround) -- never the NSFW lists, the image-board or
    fiction-archive categories, or anything term-derived -- since
    WebsiteFilter.Block is plain text in a config file a person could open
    and read, and those categories say more about what's being avoided
    than "reddit.com" does."""
    if not raw_policy.get("enforce", False):
        return []  # shadow mode blocks nothing, in Firefox too
    safe_rule_prefixes = ("S-",)
    patterns = []
    for rule_id, domains in raw_policy.get("block_domains", {}).items():
        if not any(rule_id.startswith(p) for p in safe_rule_prefixes):
            continue
        for d in domains:
            patterns.append(f"*://*.{d}/*")
    return patterns


def _atomic_write(path: str, content: str) -> None:
    import os

    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)
