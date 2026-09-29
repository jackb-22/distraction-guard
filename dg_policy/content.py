"""Whole-page content evaluation: adult self-labeling (RTA / rating meta tags)
plus the zone-weighted term scoring from dg_policy.terms.
"""
from __future__ import annotations

import re

from dg_policy.terms import TermIndex, Verdict
from dg_policy.text import extract_zones

RTA_LABEL = "RTA-5042-1996-1400-1577-RTA"

_RATING_META_RE = re.compile(
    r'<meta\s+[^>]*?name\s*=\s*["\']rating["\'][^>]*?content\s*=\s*["\']([^"\']*)["\']',
    re.IGNORECASE,
)
_PICS_LABEL_RE = re.compile(r'<meta\s+[^>]*?http-equiv\s*=\s*["\']pics-label["\']', re.IGNORECASE)
_ADULT_RATING_VALUES = {"adult", "mature", "rta-5042-1996-1400-1577-rta", "restricted"}


def adult_label(html_text: str, *, scan_limit: int = 65536) -> bool:
    """True if the page self-labels as adult content via the RTA convention
    or a <meta name="rating"> / PICS label. Checked separately from the term
    scanner because these are unambiguous, site-declared signals -- almost
    every adult site sets at least one of them, which covers sites whose
    text alone wouldn't otherwise trip the scanner."""
    head = html_text[:scan_limit]
    if RTA_LABEL in head:
        return True
    m = _RATING_META_RE.search(head)
    if m and m.group(1).strip().lower() in _ADULT_RATING_VALUES:
        return True
    if _PICS_LABEL_RE.search(head):
        return True
    return False


def evaluate_html(html_text: str, url_path: str, term_index: TermIndex) -> Verdict:
    """Full content decision for an HTML response body."""
    labeled = adult_label(html_text)
    if labeled:
        # Still run zone scoring so the caller gets a term-based rule_id
        # when one exists, but the label alone is sufficient to block.
        zones = extract_zones(html_text)
        zones["url_path"] = url_path
        v = term_index.judge_zones(zones, adult_labeled=True)
        if v.block:
            return v
        return Verdict(True, "A-label", score=v.score)

    zones = extract_zones(html_text)
    zones["url_path"] = url_path
    return term_index.judge_zones(zones, adult_labeled=False)
