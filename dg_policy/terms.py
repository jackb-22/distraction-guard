"""Term storage and matching: strict / contextual / combo terms, and the
context lexicon that gates contextual/combo terms in ordinary body text.

Terms are never printed back out by anything that touches this module --
callers (guardctl, the addon) must only ever report rule_id / term_id, never
the term text itself. See guardctl/cli.py add-term for the write-only flow.
"""
from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from enum import Enum

from dg_policy.text import joined, tokens


class TermType(Enum):
    STRICT = "strict"
    CONTEXTUAL = "contextual"
    COMBO = "combo"


@dataclass(frozen=True)
class Term:
    id: str
    type: TermType
    parts: tuple[tuple[str, ...], ...]  # 1 part for strict/contextual, 2 for combo


@dataclass(frozen=True)
class Hit:
    term_id: str
    part_idx: int
    pos: int  # token index where this part's first token matched


@dataclass(frozen=True)
class Verdict:
    block: bool
    rule_id: str | None
    score: int = 0
    near_miss: bool = False


DEFAULT_THRESHOLD = 8
DEFAULT_WINDOW = 12

_ZONE_WEIGHTS = {"title": 5, "meta": 4, "headings": 3, "url_path": 3, "body": 1}
_MAX_COUNT_PER_ZONE = 3


class TermIndex:
    """Fast lookup structure over a list of Terms plus a context lexicon."""

    def __init__(self, terms: list[Term], context_words: set[str], *, threshold: int = DEFAULT_THRESHOLD, window: int = DEFAULT_WINDOW):
        self.terms = {t.id: t for t in terms}
        self.context_words = context_words
        self.threshold = threshold
        self.window = window
        # first_token -> list of (term, part_idx, part_tokens)
        self._by_first_token: dict[str, list[tuple[Term, int, tuple[str, ...]]]] = {}
        # joined-phrase concatenation -> list of (term, part_idx)
        self._by_joined: dict[str, list[tuple[Term, int]]] = {}
        for t in terms:
            for pi, part in enumerate(t.parts):
                if not part:
                    continue
                self._by_first_token.setdefault(part[0], []).append((t, pi, part))
                if len(part) > 1:
                    self._by_joined.setdefault(joined(list(part)), []).append((t, pi))

    def _find_part_at(self, toks: list[str], i: int, part: tuple[str, ...]) -> bool:
        if i + len(part) > len(toks):
            return False
        return tuple(toks[i : i + len(part)]) == part

    def scan(self, toks: list[str]) -> list[Hit]:
        """Find every (term, part) occurrence in a token sequence, matching
        whole tokens/phrases only (never substrings of a longer token)."""
        hits: list[Hit] = []
        n = len(toks)
        for i in range(n):
            tok = toks[i]
            for term, part_idx, part in self._by_first_token.get(tok, ()):
                if self._find_part_at(toks, i, part):
                    hits.append(Hit(term.id, part_idx, i))
            # Joined-phrase evasion: a multi-word phrase typed run together
            # (e.g. "wordword" tokenizing to a single token that equals the
            # concatenation of a stored multi-word term's tokens).
            for term, part_idx in self._by_joined.get(tok, ()):
                hits.append(Hit(term.id, part_idx, i))
        return hits

    def _term_type(self, term_id: str) -> TermType:
        return self.terms[term_id].type

    def scan_query(self, toks: list[str]) -> list[Hit]:
        """scan() plus the evasions a search engine silently corrects, which
        is why they're safe to be aggressive about here but NOT in page
        text: fragments rejoined ("te-rm", "t-e-r-m" -> "term") and
        near-misses of single-word terms (one extra or swapped letter; two
        extra for long terms). Dropped letters are deliberately not
        matched, so a shorter real word ("plane") never trips a longer
        term ("planet")."""
        hits = self.scan(toks)
        singles = [(t, pi, part[0]) for t in self.terms.values() for pi, part in enumerate(t.parts) if len(part) == 1]
        max_len = max((len(w) for *_, w in singles), default=0) + 2
        seen = {(h.term_id, h.part_idx) for h in hits}
        for i in range(len(toks)):
            candidates = [toks[i]]
            cat = toks[i]
            for j in range(i + 1, min(i + 10, len(toks))):  # length-capped below
                cat += toks[j]
                if len(cat) > max_len:
                    break
                candidates.append(cat)
                for term, pi in self._by_joined.get(cat, ()):  # multi-word terms typed in fragments
                    if (term.id, pi) not in seen:
                        seen.add((term.id, pi))
                        hits.append(Hit(term.id, pi, i))
            for cand in candidates:
                for term, pi, word in singles:
                    if (term.id, pi) not in seen and (cand == word or _near_miss(cand, word)):
                        seen.add((term.id, pi))
                        hits.append(Hit(term.id, pi, i))
        return hits

    def judge_query(self, toks: list[str], vertical: str | None = None) -> Verdict:
        """Evaluate a search query's tokens. `vertical` is "images"/"videos"/None."""
        hits = self.scan_query(toks)
        if not hits:
            return Verdict(False, None)

        by_term: dict[str, set[int]] = {}
        for h in hits:
            by_term.setdefault(h.term_id, set()).add(h.part_idx)

        has_context = vertical in ("images", "videos") or any(t in self.context_words for t in toks)

        for term_id, parts_hit in by_term.items():
            term = self.terms[term_id]
            if term.type == TermType.STRICT:
                return Verdict(True, term_id)
            if term.type == TermType.COMBO:
                if len(parts_hit) >= len(term.parts):
                    return Verdict(True, term_id)
            elif term.type == TermType.CONTEXTUAL:
                if has_context:
                    return Verdict(True, term_id)
        return Verdict(False, None)

    def judge_zones(self, zones: dict[str, str], *, adult_labeled: bool = False) -> Verdict:
        """Evaluate extracted page zones (title/meta/headings/url_path/body)."""
        zone_tokens: dict[str, list[str]] = {z: tokens(text) for z, text in zones.items()}

        # Immediate block: a strict term appearing in a high-confidence zone.
        for zone in ("title", "meta", "url_path"):
            toks = zone_tokens.get(zone, [])
            if not toks:
                continue
            for h in self.scan(toks):
                if self._term_type(h.term_id) == TermType.STRICT:
                    return Verdict(True, h.term_id, score=self.threshold)

        score = 0
        hit_rule: str | None = None
        near_rule: str | None = None

        for zone, weight in _ZONE_WEIGHTS.items():
            toks = zone_tokens.get(zone, [])
            if not toks:
                continue
            hits = self.scan(toks)
            if not hits:
                continue
            zone_context = adult_labeled and zone in ("title", "meta", "headings")
            zone_has_ctx_word = any(t in self.context_words for t in toks)
            context_positions = sorted(i for i, t in enumerate(toks) if t in self.context_words)

            counted: dict[str, int] = {}
            # term_id -> part_idx -> list of token positions where that part matched
            combo_positions: dict[str, dict[int, list[int]]] = {}

            for h in hits:
                term = self.terms[h.term_id]
                counted.setdefault(h.term_id, 0)

                if term.type == TermType.COMBO:
                    combo_positions.setdefault(h.term_id, {}).setdefault(h.part_idx, []).append(h.pos)
                    continue

                if counted[h.term_id] >= _MAX_COUNT_PER_ZONE:
                    continue
                if term.type == TermType.STRICT:
                    score += weight
                    counted[h.term_id] += 1
                    hit_rule = hit_rule or h.term_id
                elif term.type == TermType.CONTEXTUAL:
                    if zone == "body":
                        if context_positions and self._within_window(h.pos, context_positions):
                            score += 1
                            counted[h.term_id] += 1
                            hit_rule = hit_rule or h.term_id
                    else:
                        if zone_context or zone_has_ctx_word:
                            score += weight
                            counted[h.term_id] += 1
                            hit_rule = hit_rule or h.term_id

            # Combo: both parts present in the same zone (title/meta/headings),
            # or some occurrence of each part within `window` tokens of each
            # other in body.
            for term_id, parts_seen in combo_positions.items():
                term = self.terms[term_id]
                if len(parts_seen) < len(term.parts):
                    continue
                if zone == "body":
                    if self._parts_within_window(list(parts_seen.values())):
                        score += 1
                        hit_rule = hit_rule or term_id
                else:
                    score += weight
                    hit_rule = hit_rule or term_id

            if score >= self.threshold and near_rule is None:
                near_rule = hit_rule

        if score >= self.threshold:
            return Verdict(True, hit_rule, score=score)
        if score >= self.threshold / 2:
            return Verdict(False, None, score=score, near_miss=True)
        return Verdict(False, None, score=score)

    def _within_window(self, pos: int, sorted_positions: list[int]) -> bool:
        i = bisect.bisect_left(sorted_positions, pos)
        for j in (i - 1, i):
            if 0 <= j < len(sorted_positions) and abs(sorted_positions[j] - pos) <= self.window:
                return True
        return False

    def _parts_within_window(self, position_lists: list[list[int]]) -> bool:
        """True if there's at least one position from each part-list such
        that all chosen positions fall within `window` of each other.
        Only ever called with exactly 2 lists (combo terms have 2 parts)."""
        if len(position_lists) != 2:
            return False
        a_positions, b_positions = position_lists
        for a in a_positions:
            for b in b_positions:
                if abs(a - b) <= self.window:
                    return True
        return False


def _near_miss(cand: str, word: str) -> bool:
    """cand is word with one letter swapped (len >= 6), or with one extra
    letter inserted (len >= 5), or two extra (len >= 8). Same first letter
    required, to keep unrelated words out."""
    if len(word) < 5 or not cand or cand[0] != word[0]:
        return False
    extra = len(cand) - len(word)
    if extra == 0:
        return len(word) >= 6 and sum(a != b for a, b in zip(cand, word)) == 1
    if extra == 1 or (extra == 2 and len(word) >= 8):
        it = iter(cand)
        return all(ch in it for ch in word)  # word is a subsequence of cand
    return False
