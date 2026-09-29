"""Search-engine recognition, vertical (image/video) detection, SafeSearch
enforcement, and decoders for the two main "view a blocked site through a
different host" workarounds: Google Translate proxy and the Wayback Machine.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

from dg_policy.hosts import normalize_host

# --- engine table -----------------------------------------------------------
# Each entry: host regex, query param(s) holding the search text, path(s) that
# count as "a search", vertical detection, and the SafeSearch rewrite to apply.

_GOOGLE_HOST_RE = re.compile(r"^(www\.)?google\.[a-z.]{2,6}$")
_GOOGLE_SEARCH_PATHS = {"/search", "/complete/search"}
_GOOGLE_IMAGE_HOSTS = {"images.google.com", "lens.google.com"}


@dataclass(frozen=True)
class SearchResult:
    engine: str
    query_tokens_source: str  # raw query text, tokenize with dg_policy.text.tokens
    vertical: str | None  # "images" | "videos" | None
    rewrite_query: dict | None  # {"param": "safe", "value": "active"} etc, or None
    add_headers: dict  # extra headers to set on the outgoing request


# Whole-host-blocked search engines (no first-party SafeSearch control we can
# enforce reliably, or not worth the complexity) -- these show up in
# rules.d/search.toml as a plain block list, not here. This module only
# handles engines we actively rewrite/inspect.


def _is_google(host: str) -> bool:
    return bool(_GOOGLE_HOST_RE.match(host))


def evaluate(url: str, method: str) -> SearchResult | None:
    """Return a SearchResult if `url` is a recognized search-engine request,
    else None (caller falls through to ordinary host/path rules)."""
    parts = urlsplit(url)
    host = normalize_host(parts.hostname or "")
    path = parts.path or "/"
    qs = parse_qs(parts.query)

    if _is_google(host) or host in _GOOGLE_IMAGE_HOSTS:
        return _google(host, path, qs)
    if host == "www.bing.com":
        return _bing(path, qs)
    if host in ("duckduckgo.com", "html.duckduckgo.com", "links.duckduckgo.com"):
        return _duckduckgo(path, qs)
    return None


def _first(qs: dict, key: str) -> str:
    v = qs.get(key)
    return v[0] if v else ""


def _google(host: str, path: str, qs: dict) -> SearchResult | None:
    if host in _GOOGLE_IMAGE_HOSTS:
        return SearchResult("google", _first(qs, "q"), "images", None, {})
    if path not in _GOOGLE_SEARCH_PATHS:
        return None
    udm = _first(qs, "udm")
    tbm = _first(qs, "tbm")
    vertical = None
    if udm == "2" or tbm == "isch":
        vertical = "images"
    elif udm == "7" or tbm == "vid":
        vertical = "videos"
    safe = _first(qs, "safe")
    rewrite = None if safe == "active" else {"param": "safe", "value": "active"}
    return SearchResult("google", _first(qs, "q") or _first(qs, "oq"), vertical, rewrite, {})


def _bing(path: str, qs: dict) -> SearchResult | None:
    if path not in ("/search", "/AS/Suggestions"):
        return None
    vertical = "images" if path.startswith("/images") else "videos" if path.startswith("/videos") else None
    adlt = _first(qs, "adlt")
    rewrite = None if adlt == "strict" else {"param": "adlt", "value": "strict"}
    return SearchResult("bing", _first(qs, "q"), vertical, rewrite, {})


def _duckduckgo(path: str, qs: dict) -> SearchResult | None:
    if path not in ("/", "/html/", "/html", "/i.js", "/v.js"):
        return None
    ia = _first(qs, "ia")
    iax = _first(qs, "iax")
    vertical = "images" if "image" in ia or "image" in iax or path == "/i.js" else \
        "videos" if "video" in ia or "video" in iax or path == "/v.js" else None
    kp = _first(qs, "kp")
    rewrite = None if kp == "1" else {"param": "kp", "value": "1"}
    return SearchResult("duckduckgo", _first(qs, "q"), vertical, rewrite, {})


def bing_path_vertical_blocked(path: str) -> bool:
    return path.startswith("/images") or path.startswith("/videos")


def duckduckgo_path_vertical_blocked(path: str) -> bool:
    return path in ("/i.js", "/v.js")


# --- workaround decoders -----------------------------------------------------

_TRANSLATE_GOOG_RE = re.compile(r"^(?P<label>[a-z0-9-]+)--([a-z0-9-]+)\.translate\.goog$")
# translate.goog encodes the origin host as a single label with '.' -> '-' and
# literal '-' escaped as '--'. We only need the common case: split off the
# trailing "-<2-letter-ish-tld-block>" is unreliable, so instead decode by
# replacing '--' with a placeholder, splitting on '-', then rejoining with '.'.
_PLACEHOLDER = "\x00"


def decode_translate_goog(host: str) -> str | None:
    """'www-reddit-com.translate.goog' -> 'www.reddit.com'. Returns None if
    `host` isn't a translate.goog host."""
    host = normalize_host(host)
    if not host.endswith(".translate.goog"):
        return None
    label = host[: -len(".translate.goog")]
    label = label.replace("--", _PLACEHOLDER)
    parts = label.split("-")
    decoded = ".".join(p.replace(_PLACEHOLDER, "-") for p in parts)
    return decoded or None


_ARCHIVE_HOSTS = {"web.archive.org"}
_ARCHIVE_PATH_RE = re.compile(r"^/web/(?:\d{1,14}[a-z_]*)/(?P<url>https?://.+)$", re.IGNORECASE)


def decode_archive_org(host: str, path: str) -> str | None:
    """Extract the embedded target URL's host from a Wayback Machine URL,
    e.g. '/web/20240101000000/https://www.reddit.com/r/x' -> 'www.reddit.com'."""
    if normalize_host(host) not in _ARCHIVE_HOSTS:
        return None
    m = _ARCHIVE_PATH_RE.match(path)
    if not m:
        return None
    embedded = urlsplit(m.group("url"))
    return normalize_host(embedded.hostname or "") or None
