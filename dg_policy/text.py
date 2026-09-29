"""Text normalization, tokenization, and HTML zone extraction.

Applied identically to stored terms, the context lexicon, and scanned page
text/queries, so a term written once matches consistently everywhere.
"""
from __future__ import annotations

import html
import re
import unicodedata

_LEET = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
    "@": "a", "$": "s", "!": "i",
})

_WORD_RE = re.compile(r"[a-z]+")
_REPEAT_RE = re.compile(r"([a-z])\1+")

_STEM_SUFFIXES = ("ings", "ing", "ies", "es", "ed", "s")


def _stem(word: str) -> str:
    """Conservative, symmetric suffix stripping -- not a real stemmer, just
    enough to fold plurals/gerunds so "term" and "terms"/"terming" match."""
    for suf in _STEM_SUFFIXES:
        if word.endswith(suf) and len(word) - len(suf) >= 3:
            if suf == "ies":
                return word[: -len(suf)] + "y"
            return word[: -len(suf)]
    return word


def tokens(s: str) -> list[str]:
    """Normalize and tokenize text into stemmed, casefolded ASCII words.

    Pipeline: HTML-unescape -> NFKD + strip combining marks (diacritics) ->
    casefold -> leetspeak fold -> split on anything non a-z (punctuation,
    digits, underscores, hyphens, whitespace all act as separators, which
    catches "word_word" / "word-word" evasions) -> stem each token.
    """
    if not s:
        return []
    s = html.unescape(s)
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    s = s.casefold()
    s = s.translate(_LEET)
    # Collapse repeated letters ("teerrmm" -> "term"), applied to terms and
    # scanned text alike so it stays symmetric. Search engines fold these
    # back to the real word, so the filter must too.
    return [_stem(_REPEAT_RE.sub(r"\1", t)) for t in _WORD_RE.findall(s) if t]


def joined(phrase_tokens: list[str]) -> str:
    """Concatenation of a phrase's tokens, to catch "wordword" run-together
    evasions of a multi-word term/phrase."""
    return "".join(phrase_tokens)


_SCRIPT_STYLE_RE = re.compile(r"<(script|style)\b[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_META_RE = re.compile(
    r'<meta\s+[^>]*?(?:name|property)\s*=\s*["\']?'
    r"(description|keywords|og:title|og:description|twitter:title|rating)"
    r'["\']?[^>]*?content\s*=\s*["\']([^"\']*)["\']',
    re.IGNORECASE,
)
_META_RE_REV = re.compile(
    r'<meta\s+[^>]*?content\s*=\s*["\']([^"\']*)["\'][^>]*?(?:name|property)\s*=\s*["\']?'
    r"(description|keywords|og:title|og:description|twitter:title|rating)"
    r'["\']?',
    re.IGNORECASE,
)
_HEADING_RE = re.compile(r"<h[1-3][^>]*>(.*?)</h[1-3]>", re.IGNORECASE | re.DOTALL)


def strip_html(html_text: str, limit: int = 300_000) -> str:
    """Remove script/style/comments/tags, collapse whitespace, cap length."""
    if not html_text:
        return ""
    t = html_text[: limit * 4]  # cheap pre-cap before the more expensive regex work
    t = _SCRIPT_STYLE_RE.sub(" ", t)
    t = _COMMENT_RE.sub(" ", t)
    t = _TAG_RE.sub(" ", t)
    t = html.unescape(t)
    t = _WS_RE.sub(" ", t).strip()
    return t[:limit]


def extract_zones(html_text: str, *, limit: int = 300_000) -> dict[str, str]:
    """Pull title / meta+og tags / h1-h3 headings / body text out of an HTML
    document. Each zone's text has tags stripped but is otherwise raw
    (tokenize separately per zone with `tokens()`)."""
    if not html_text:
        return {"title": "", "meta": "", "headings": "", "body": ""}

    head = html_text[: max(limit, 60_000)]

    title_m = _TITLE_RE.search(head)
    title = html.unescape(_TAG_RE.sub(" ", title_m.group(1))).strip() if title_m else ""

    meta_parts = []
    for m in _META_RE.finditer(head):
        meta_parts.append(m.group(2))
    for m in _META_RE_REV.finditer(head):
        meta_parts.append(m.group(1))
    meta = html.unescape(" ".join(meta_parts)).strip()

    headings = " ".join(
        html.unescape(_TAG_RE.sub(" ", m.group(1))).strip() for m in _HEADING_RE.finditer(html_text[:limit])
    )

    body = strip_html(html_text, limit=limit)

    return {"title": title, "meta": meta, "headings": headings, "body": body}
