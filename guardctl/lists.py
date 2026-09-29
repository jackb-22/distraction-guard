"""Downloads and normalizes third-party block lists into the plain
newline-delimited domain format dg_policy.model expects, regardless of the
source's native format (plain domains, wildcard, hosts file, Adblock Plus).

Verified against real samples from each source as of 2026-09-17:
  - HaGeZi wildcard/*-onlydomains.txt  -> format="domains" (already plain)
  - OISD */domainswild               -> format="wildcard" ("*.example.com")
  - StevenBlack hosts files           -> format="hosts" ("0.0.0.0 example.com")
  - Adblock Plus lists (oisd default) -> format="adblock" ("||example.com^")
"""
from __future__ import annotations

import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass

from dg_policy.hosts import normalize_host

MAX_DOWNLOAD_BYTES = 60 * 1024 * 1024
REQUEST_TIMEOUT = 30


class ListDownloadError(Exception):
    pass


@dataclass
class ListSpec:
    name: str
    url: str
    format: str  # "domains" | "wildcard" | "hosts" | "adblock"
    rule: str
    category: str = ""
    min_entries: int = 100
    dns_sinkhole: bool = False
    enabled: bool = True


_ADBLOCK_DOMAIN_RE = re.compile(r"^\|\|([a-z0-9.-]+)\^")
_HOSTS_LINE_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-z0-9.-]+)")


def parse_domains(text: str) -> list[str]:
    return _parse_plain(text, strip_wildcard=False)


def parse_wildcard(text: str) -> list[str]:
    return _parse_plain(text, strip_wildcard=True)


def _parse_plain(text: str, *, strip_wildcard: bool) -> list[str]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if strip_wildcard and line.startswith("*."):
            line = line[2:]
        h = normalize_host(line)
        if h and "." in h:
            out.append(h)
    return out


def parse_hosts(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _HOSTS_LINE_RE.match(line)
        if not m:
            continue
        h = normalize_host(m.group(1))
        if h and h not in ("localhost", "local"):
            out.append(h)
    return out


def parse_adblock(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("!") or line.startswith("@@"):
            continue  # comments and exception rules
        m = _ADBLOCK_DOMAIN_RE.match(line)
        if not m:
            continue
        h = normalize_host(m.group(1))
        if h and "." in h:
            out.append(h)
    return out


_PARSERS = {
    "domains": parse_domains,
    "wildcard": parse_wildcard,
    "hosts": parse_hosts,
    "adblock": parse_adblock,
}


def parse(text: str, format: str) -> list[str]:
    parser = _PARSERS.get(format)
    if parser is None:
        raise ListDownloadError(f"unknown list format: {format!r}")
    return parser(text)


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "distraction-guard/2.0"})
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            data = resp.read(MAX_DOWNLOAD_BYTES + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise ListDownloadError(f"download failed: {e}") from e
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise ListDownloadError(f"list exceeds {MAX_DOWNLOAD_BYTES} bytes, refusing")
    return data.decode("utf-8", errors="replace")


def update_one(spec: ListSpec, lists_dir: str) -> tuple[bool, str]:
    """Download, parse, and atomically write one list. Returns (ok, message).
    On any failure, the existing file (if any) is left untouched -- a list
    server being down for a day shouldn't remove that category's blocking."""
    dest = os.path.join(lists_dir, f"{spec.name}.txt")
    try:
        text = fetch(spec.url)
        domains = parse(text, spec.format)
    except ListDownloadError as e:
        return False, str(e)

    if len(domains) < spec.min_entries:
        return False, f"only {len(domains)} entries parsed (need >= {spec.min_entries}) -- source format may have changed"

    os.makedirs(lists_dir, exist_ok=True)
    tmp = dest + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(f"# {spec.name} -- fetched from {spec.url}\n")
        f.write(f"# {len(domains)} entries\n")
        for d in sorted(set(domains)):
            f.write(d + "\n")
    os.chmod(tmp, 0o640)
    os.replace(tmp, dest)
    return True, f"{len(domains)} entries"


def update_all(specs: list[ListSpec], lists_dir: str) -> dict[str, tuple[bool, str]]:
    results = {}
    for spec in specs:
        if not spec.enabled:
            continue
        results[spec.name] = update_one(spec, lists_dir)
    return results
