"""Guards the shipped lexicon/context.txt against two bugs found while
authoring it:
  1. An unstemmed entry (e.g. "running") never matching the stemmed
     token that scanned text actually produces -- fixed by
     having _load_lexicon() tokenize every entry on load.
  2. A multi-word entry silently meaning something different than
     intended: dg_policy.model._load_lexicon() now splits any line into
     its individual tokens (so "adult content" would add "adult" and
     "content" as two independent, less-specific gates, not a phrase
     match) -- the file's own convention is one word per line, kept as a
     regression guard here rather than a hard requirement.
"""
from pathlib import Path

from dg_policy.model import _load_lexicon
from dg_policy.text import tokens as tokenize

import pytest

# Personal, so it lives in the git-ignored private/ folder. These checks run
# only where it exists (the author's machine), and skip in a public clone.
LEXICON_PATH = Path(__file__).resolve().parents[2] / "private" / "lexicon" / "context.txt"
pytestmark = pytest.mark.skipif(not LEXICON_PATH.exists(), reason="no private lexicon in this checkout")


def test_lexicon_file_exists_and_nonempty():
    assert LEXICON_PATH.exists()
    words = _load_lexicon([str(LEXICON_PATH)])
    assert len(words) > 20


def test_every_lexicon_entry_is_a_single_matchable_token():
    raw_lines = [
        line.strip()
        for line in LEXICON_PATH.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert raw_lines, "lexicon file has no entries to check"
    for line in raw_lines:
        toks = tokenize(line)
        assert len(toks) == 1, (
            f"lexicon entry {line!r} tokenizes to {toks!r} (expected exactly "
            "1 token) -- a multi-word or non-alpha entry never matches "
            "anything in TermIndex's context_words check"
        )


def test_lexicon_loaded_words_are_all_stemmed_tokens():
    words = _load_lexicon([str(LEXICON_PATH)])
    for w in words:
        assert tokenize(w) == [w], f"{w!r} is not already in normalized/stemmed form"
