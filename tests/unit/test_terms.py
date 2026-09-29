"""Term-matching tests use only synthetic nonsense words (zorblax, quimble,
ctxword...) -- never real terms. Real terms live only in the user's private,
root-owned terms.json, added via `guardctl add-term`, and are never written
to this repo or seen by any test."""
from dg_policy.terms import Term, TermIndex, TermType
from dg_policy.text import extract_zones, tokens


def _strict(id_, phrase):
    return Term(id_, TermType.STRICT, ((tuple(tokens(phrase)),)))


def _contextual(id_, phrase):
    return Term(id_, TermType.CONTEXTUAL, ((tuple(tokens(phrase)),)))


def _combo(id_, a, b):
    return Term(id_, TermType.COMBO, (tuple(tokens(a)), tuple(tokens(b))))


def test_strict_term_blocks_query_with_no_context():
    idx = TermIndex([_strict("T-1", "zorblax")], set())
    v = idx.judge_query(tokens("what is zorblax"))
    assert v.block and v.rule_id == "T-1"


def test_strict_term_no_match_leaves_query_alone():
    idx = TermIndex([_strict("T-1", "zorblax")], set())
    v = idx.judge_query(tokens("what is quimble"))
    assert not v.block


def test_strict_term_matches_stemmed_plural():
    idx = TermIndex([_strict("T-1", "zorblax")], set())
    v = idx.judge_query(tokens("zorblaxes are common"))
    assert v.block


def test_contextual_term_alone_in_query_allowed():
    idx = TermIndex([_contextual("T-2", "widget")], {"ctxword"})
    v = idx.judge_query(tokens("buy a widget online"))
    assert not v.block


def test_contextual_term_with_context_word_blocks():
    idx = TermIndex([_contextual("T-2", "widget")], {"ctxword"})
    v = idx.judge_query(tokens("widget ctxword compilation"))
    assert v.block and v.rule_id == "T-2"


def test_contextual_term_on_image_vertical_blocks_even_without_context_word():
    idx = TermIndex([_contextual("T-2", "widget")], {"ctxword"})
    v = idx.judge_query(tokens("widget"), vertical="images")
    assert v.block


def test_contextual_term_on_plain_search_not_blocked():
    idx = TermIndex([_contextual("T-2", "widget")], {"ctxword"})
    v = idx.judge_query(tokens("widget"), vertical=None)
    assert not v.block


def test_combo_needs_both_parts():
    idx = TermIndex([_combo("T-3", "alpha", "beta")], set())
    assert not idx.judge_query(tokens("alpha only")).block
    assert not idx.judge_query(tokens("beta only")).block
    assert idx.judge_query(tokens("alpha and beta together")).block


def test_word_boundary_no_substring_match():
    # "zorblax" must not match inside "zorblaxxian" as a substring --
    # tokenization treats it as a different token entirely.
    idx = TermIndex([_strict("T-1", "zorblax")], set())
    v = idx.judge_query(tokens("zorblaxxian empire"))
    assert not v.block


def test_leet_evasion_caught():
    idx = TermIndex([_strict("T-1", "zorblax")], set())
    v = idx.judge_query(tokens("z0rbl4x"))
    assert v.block


def test_joined_phrase_evasion_caught():
    idx = TermIndex([_strict("T-4", "foo bar")], set())
    # "foobar" as a single run-together token should still match the
    # two-word phrase "foo bar".
    v = idx.judge_query(tokens("foobar"))
    assert v.block


# --- page-zone scoring ---

def _html(title="", meta_desc="", h1="", body=""):
    return f"""<html><head><title>{title}</title>
    <meta name="description" content="{meta_desc}"></head>
    <body><h1>{h1}</h1><p>{body}</p></body></html>"""


def test_strict_term_in_title_blocks_immediately():
    idx = TermIndex([_strict("T-1", "zorblax")], set(), threshold=100)
    zones = extract_zones(_html(title="All about zorblax", body="unrelated text " * 50))
    v = idx.judge_zones(zones)
    assert v.block and v.rule_id == "T-1"


def test_contextual_term_in_body_needs_nearby_context_word():
    # Body-zone contextual hits score +1 each (weakest signal, weight 1) --
    # use threshold=1 so a single near-context hit is enough to block, and
    # confirm a far-away context word does *not* count.
    idx = TermIndex([_contextual("T-2", "widget")], {"ctxword"}, threshold=1, window=12)
    far = "widget " + ("filler " * 30) + "ctxword"
    zones = extract_zones(_html(body=far))
    v = idx.judge_zones(zones)
    assert not v.block

    near = "widget filler filler ctxword"
    zones2 = extract_zones(_html(body=near))
    v2 = idx.judge_zones(zones2)
    assert v2.block


def test_contextual_term_alone_in_normal_article_not_blocked():
    idx = TermIndex([_contextual("T-2", "widget")], {"ctxword"}, threshold=8)
    zones = extract_zones(_html(title="Widget Reviews", body="This widget is great. " * 5))
    v = idx.judge_zones(zones)
    assert not v.block


def test_rta_label_style_adult_flag_via_context():
    idx = TermIndex([_contextual("T-2", "widget")], set(), threshold=1)
    zones = extract_zones(_html(title="widget"))
    v = idx.judge_zones(zones, adult_labeled=True)
    assert v.block


def test_combo_term_in_body_within_window():
    idx = TermIndex([_combo("T-3", "alpha", "beta")], set(), threshold=1, window=12)
    zones = extract_zones(_html(body="alpha stuff beta"))
    v = idx.judge_zones(zones)
    assert v.block


def test_combo_term_in_body_far_apart_not_blocked():
    idx = TermIndex([_combo("T-3", "alpha", "beta")], set(), threshold=100, window=5)
    filler = " word" * 30
    zones = extract_zones(_html(body=f"alpha{filler} beta"))
    v = idx.judge_zones(zones)
    assert not v.block


def test_near_miss_reported_below_threshold():
    # score=1 from the single body hit; threshold=2 makes half-threshold
    # exactly 1, so this should surface as a near-miss without blocking.
    idx = TermIndex([_contextual("T-2", "widget")], {"ctxword"}, threshold=2, window=12)
    zones = extract_zones(_html(body="widget ctxword"))
    v = idx.judge_zones(zones)
    assert not v.block
    assert v.near_miss


# --- search-query evasions (found live: extra letters/symbols in a search
# got Google results for the real word, but passed the filter) ----------

from dg_policy.terms import Term as _T, TermIndex as _TI, TermType as _TT
from dg_policy.text import tokens as _tok


def _qidx(*words):
    return _TI([_T(f"T-{i}", _TT.STRICT, (tuple(_tok(w)),)) for i, w in enumerate(words)], set())


def _q(idx, q):
    return idx.judge_query(_tok(q)).block


def test_query_repeated_letters():
    idx = _qidx("zebra")
    assert _q(idx, "zeebra") and _q(idx, "zebraaa") and _q(idx, "zzebbra facts")


def test_query_fragments_rejoined():
    idx = _qidx("zebra")
    assert _q(idx, "ze bra") and _q(idx, "z-e-b-r-a") and _q(idx, "z.eb.ra pics")


def test_query_near_misses():
    idx = _qidx("planet", "zebra")
    assert _q(idx, "planett") and _q(idx, "plamet") and _q(idx, "zebrax")


def test_query_no_false_positives_on_nearby_real_words():
    idx = _qidx("planet", "zebra")
    for q in ("plane ticket", "algebra homework", "zebu", "planning", "plant"):
        assert not _q(idx, q), q


def test_repeated_letter_collapse_is_symmetric_for_page_text():
    assert _tok("Bookkeeping") == _tok("bokeping")
