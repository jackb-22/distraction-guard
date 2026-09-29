import json

from dg_policy.content import RTA_LABEL, adult_label, evaluate_html
from dg_policy.terms import Term, TermIndex, TermType


def test_rta_label_detected():
    html = f"<html><head><meta name='rating' content='{RTA_LABEL}'></head></html>"
    assert adult_label(html)


def test_rating_adult_meta_detected():
    html = "<html><head><meta name='rating' content='adult'></head></html>"
    assert adult_label(html)


def test_rating_general_not_flagged():
    html = "<html><head><meta name='rating' content='general'></head></html>"
    assert not adult_label(html)


def test_pics_label_detected():
    html = "<html><head><meta http-equiv='PICS-Label' content='...'></head></html>"
    assert adult_label(html)


def test_no_label_plain_page():
    html = "<html><head><title>Cats</title></head><body>hello</body></html>"
    assert not adult_label(html)


def test_evaluate_html_blocks_on_label_even_with_no_term_hits():
    idx = TermIndex([Term("T-1", TermType.STRICT, ((tuple(["zorblax"]),)))], set())
    html = f"<html><head><meta name='rating' content='adult'><title>Cats</title></head></html>"
    v = evaluate_html(html, "/page", idx)
    assert v.block and v.rule_id == "A-label"


def test_evaluate_html_prefers_term_rule_id_when_both_fire():
    idx = TermIndex([Term("T-1", TermType.STRICT, ((tuple(["zorblax"]),)))], set())
    html = "<html><head><meta name='rating' content='adult'><title>zorblax</title></head></html>"
    v = evaluate_html(html, "/page", idx)
    assert v.block and v.rule_id == "T-1"


def test_evaluate_html_no_label_no_terms_passes():
    idx = TermIndex([Term("T-1", TermType.STRICT, ((tuple(["zorblax"]),)))], set())
    html = "<html><head><title>Cats</title></head><body>hello world</body></html>"
    v = evaluate_html(html, "/page", idx)
    assert not v.block
