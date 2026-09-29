"""YouTube-specific rules: feed/Shorts/trending blocked, search and /watch
allowed, Restricted Mode forced, and non-family-safe or term-matching videos
blocked based on the player/next JSON responses.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from dg_policy.hosts import normalize_host
from dg_policy.terms import TermIndex, Verdict

YT_HOSTS = {
    "youtube.com",
    "www.youtube.com",
    "m.youtube.com",
    "music.youtube.com",
    "youtube-nocookie.com",
    "www.youtube-nocookie.com",
    "youtubei.googleapis.com",
    "youtube.googleapis.com",
}

# Passthrough media/CDN hosts -- never HTML/JSON-scanned, gated only by
# whether the referring /watch or player request was allowed.
YT_MEDIA_PASSTHROUGH_SUFFIXES = ("googlevideo.com", "ytimg.com")

_BLOCKED_PATHS = {"/", "/feed/trending", "/feed/explore"}
_BLOCKED_PATH_PREFIXES = ("/shorts/", "/hashtag/")
_BLOCKED_BROWSE_IDS = {"FEwhat_to_watch", "FEtrending", "FEexplore", "FEshorts"}

_ALLOWED_PATHS_ALWAYS = {"/watch", "/results"}


def is_youtube_host(host: str) -> bool:
    return normalize_host(host) in YT_HOSTS


def is_youtube_media_host(host: str) -> bool:
    h = normalize_host(host)
    return any(h == s or h.endswith("." + s) for s in YT_MEDIA_PASSTHROUGH_SUFFIXES)


@dataclass(frozen=True)
class YtDecision:
    block: bool
    rule_id: str | None = None


def evaluate_request(path: str, body_json: dict | None) -> YtDecision:
    """Feed/Shorts/trending/browse-id block for a YouTube page or API request."""
    if path in _BLOCKED_PATHS:
        return YtDecision(True, "Y-feed")
    if any(path.startswith(p) for p in _BLOCKED_PATH_PREFIXES):
        return YtDecision(True, "Y-shorts")
    if path in _ALLOWED_PATHS_ALWAYS:
        return YtDecision(False)
    if path.startswith("/youtubei/v1/browse") and body_json:
        browse_id = body_json.get("browseId", "")
        if browse_id in _BLOCKED_BROWSE_IDS:
            return YtDecision(True, "Y-feed")
    if path.startswith("/youtubei/v1/reel/"):
        return YtDecision(True, "Y-shorts")
    return YtDecision(False)


def extract_search_query(path: str, qs: dict, body_json: dict | None) -> str | None:
    if path == "/results":
        v = qs.get("search_query")
        return v[0] if v else None
    if path.startswith("/youtubei/v1/search") and body_json:
        return body_json.get("query")
    return None


_IS_FAMILY_SAFE_FALSE_RE = re.compile(r'"isFamilySafe"\s*:\s*false')


def evaluate_watch_html(html_text: str, term_index: TermIndex) -> Verdict:
    """Scan a /watch page's embedded player data for isFamilySafe + title/keywords."""
    if _IS_FAMILY_SAFE_FALSE_RE.search(html_text):
        return Verdict(True, "Y-not-family-safe")
    title, keywords = _extract_watch_title_keywords(html_text)
    zones = {"title": title, "meta": " ".join(keywords)}
    return term_index.judge_zones(zones)


_TITLE_JSON_RE = re.compile(r'"title"\s*:\s*"((?:[^"\\]|\\.)*)"')
_KEYWORDS_JSON_RE = re.compile(r'"keywords"\s*:\s*\[((?:[^\]])*)\]')


def _extract_watch_title_keywords(html_text: str) -> tuple[str, list[str]]:
    title = ""
    m = _TITLE_JSON_RE.search(html_text)
    if m:
        try:
            title = json.loads(f'"{m.group(1)}"')
        except (json.JSONDecodeError, UnicodeDecodeError):
            title = m.group(1)
    keywords: list[str] = []
    km = _KEYWORDS_JSON_RE.search(html_text)
    if km:
        for part in re.findall(r'"((?:[^"\\]|\\.)*)"', km.group(1)):
            try:
                keywords.append(json.loads(f'"{part}"'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                keywords.append(part)
    return title, keywords


def evaluate_player_json(body: bytes, term_index: TermIndex) -> Verdict:
    """Scan a youtubei/v1/player or /next JSON response body."""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return Verdict(False, None)

    microformat = data.get("microformat", {}).get("playerMicroformatRenderer", {})
    if microformat.get("isFamilySafe") is False:
        return Verdict(True, "Y-not-family-safe")

    details = data.get("videoDetails", {})
    title = details.get("title", "")
    keywords = details.get("keywords", [])
    zones = {"title": title, "meta": " ".join(keywords) if isinstance(keywords, list) else ""}
    return term_index.judge_zones(zones)


# --- Shorts stripping --------------------------------------------------------
# Blocking /shorts/ and the reel API stops Shorts from PLAYING, but YouTube
# still mixes Shorts shelves into search results, the watch-page sidebar,
# channel pages and the guide menu -- found live: with the home feed
# blocked, those leftover shelves were most of what YouTube showed. These
# functions remove the smallest list item that contains a Short, so the
# normal videos beside it stay.

_SHORTS_KEYS = frozenset({
    "reelShelfRenderer", "reelItemRenderer", "shortsLockupViewModel",
    "reelWatchEndpoint", "reelPlayerOverlayRenderer",
})
_SHORTS_BROWSE_IDS = frozenset({"FEshorts"})


def _is_shorts_item(node) -> bool:
    """True if `node` contains a Shorts marker without passing through a
    nested list -- i.e. this item itself is (or wraps exactly) a Short,
    rather than being a section that merely contains one somewhere."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k in _SHORTS_KEYS:
                return True
            if k == "browseId" and v in _SHORTS_BROWSE_IDS:
                return True
            if k == "url" and isinstance(v, str) and v.startswith("/shorts/"):
                return True
            if isinstance(v, dict) and _is_shorts_item(v):
                return True
    return False


def strip_shorts(node) -> tuple[object, int]:
    """Return (node without Shorts items, number removed)."""
    removed = 0
    if isinstance(node, list):
        out = []
        for item in node:
            if _is_shorts_item(item):
                removed += 1
                continue
            item, n = strip_shorts(item)
            removed += n
            out.append(item)
        return out, removed
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            v, n = strip_shorts(v)
            removed += n
            out[k] = v
        return out, removed
    return node, 0


def strip_shorts_json(body: bytes) -> bytes | None:
    """Shorts-free JSON body, or None if nothing changed / not parseable
    (callers then leave the response untouched)."""
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None
    data, n = strip_shorts(data)
    if not n:
        return None
    return json.dumps(data, separators=(",", ":")).encode()


_INITIAL_DATA_RE = re.compile(r"(var ytInitialData\s*=\s*)(\{.*?\})(;\s*</script>)", re.DOTALL)


def strip_shorts_html(html_text: str) -> str | None:
    """Same, for the ytInitialData blob inlined in full page loads
    (/results, /watch, channel pages). None if unchanged or unparseable."""
    m = _INITIAL_DATA_RE.search(html_text)
    if not m:
        return None
    try:
        data = json.loads(m.group(2))
    except ValueError:
        return None
    data, n = strip_shorts(data)
    if not n:
        return None
    return html_text[: m.start(2)] + json.dumps(data, separators=(",", ":")) + html_text[m.end(2):]
