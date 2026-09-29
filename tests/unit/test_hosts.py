import time

import pytest

from dg_policy.hosts import (
    DomainSet,
    HostKind,
    classify_host,
    is_lan,
    normalize_host,
    suffix_chain,
)


def test_normalize_lowercases_and_strips_port():
    assert normalize_host("Example.COM:443") == "example.com"


def test_normalize_strips_trailing_dot():
    assert normalize_host("example.com.") == "example.com"


def test_normalize_ipv6_brackets():
    assert normalize_host("[::1]:8080") == "::1"


def test_normalize_bare_ipv6():
    assert normalize_host("2607:6bc0::10") == "2607:6bc0::10"


def test_normalize_empty():
    assert normalize_host("") == ""


def test_suffix_chain_never_yields_bare_tld():
    chain = list(suffix_chain("a.b.reddit.com"))
    assert chain == ["a.b.reddit.com", "b.reddit.com", "reddit.com"]
    assert "com" not in chain


def test_suffix_chain_single_label_yields_nothing():
    assert list(suffix_chain("localhost")) == []


def test_domainset_suffix_match():
    ds = DomainSet()
    ds.add("reddit.com", "S-social")
    assert ds.match("www.reddit.com") == "S-social"
    assert ds.match("old.reddit.com") == "S-social"
    assert ds.match("reddit.com") == "S-social"


def test_domainset_lookalike_not_matched():
    ds = DomainSet()
    ds.add("reddit.com", "S-social")
    assert ds.match("notreddit.com") is None
    assert ds.match("reddit.com.evil.com") is None  # evil.com is the real suffix


def test_domainset_case_insensitive():
    ds = DomainSet()
    ds.add("Reddit.COM", "S-social")
    assert ds.match("WWW.REDDIT.COM") == "S-social"


def test_is_lan():
    assert is_lan("192.168.1.1")
    assert is_lan("10.0.0.5")
    assert is_lan("127.0.0.1")
    assert is_lan("fe80::1")
    assert not is_lan("8.8.8.8")
    assert not is_lan("not-an-ip")


def _empty_sets():
    return {
        "block_sets": [],
        "exceptions": DomainSet(),
        "passthrough": DomainSet(),
        "temp_allows": {},
    }


def test_classify_default_inspect():
    d = classify_host("example.com", **_empty_sets())
    assert d.kind == HostKind.INSPECT


def test_classify_block():
    block = DomainSet()
    block.add("reddit.com", "S-social")
    kwargs = _empty_sets()
    kwargs["block_sets"] = [block]
    d = classify_host("www.reddit.com", **kwargs)
    assert d.kind == HostKind.BLOCK
    assert d.rule_id == "S-social"


def test_classify_passthrough_never_overrides_block():
    block = DomainSet()
    block.add("reddit.com", "S-social")
    passthrough = DomainSet()
    passthrough.add("reddit.com", "P-user")
    kwargs = _empty_sets()
    kwargs["block_sets"] = [block]
    kwargs["passthrough"] = passthrough
    d = classify_host("reddit.com", **kwargs)
    assert d.kind == HostKind.BLOCK


def test_classify_exception_skips_block():
    block = DomainSet()
    block.add("reddit.com", "S-social")
    exceptions = DomainSet()
    exceptions.add("reddit.com", "X-user")
    kwargs = _empty_sets()
    kwargs["block_sets"] = [block]
    kwargs["exceptions"] = exceptions
    d = classify_host("reddit.com", **kwargs)
    assert d.kind == HostKind.INSPECT


def test_classify_temp_allow_active():
    kwargs = _empty_sets()
    kwargs["temp_allows"] = {"example.com": time.time() + 60}
    block = DomainSet()
    block.add("example.com", "B-user")
    kwargs["block_sets"] = [block]
    d = classify_host("example.com", **kwargs)
    assert d.kind == HostKind.ALLOW_TEMP


def test_classify_temp_allow_expired_falls_through_to_block():
    kwargs = _empty_sets()
    kwargs["temp_allows"] = {"example.com": time.time() - 1}
    block = DomainSet()
    block.add("example.com", "B-user")
    kwargs["block_sets"] = [block]
    d = classify_host("example.com", **kwargs)
    assert d.kind == HostKind.BLOCK


def test_classify_bad_host_blocks():
    d = classify_host("", **_empty_sets())
    assert d.kind == HostKind.BLOCK
    assert d.rule_id == "G-bad-host"


def test_add_many_fast_path_matches_slow_path():
    from dg_policy.hosts import DomainSet
    domains = ["example.com", "Sub.Example.COM", "xn--bcher-kva.example", "bücher.example",
               "1.2.3.4", "trailing.dot.", "nodot", "a-b.c-d.org", "  spaced.com  ", "*.wild.com", ""]
    fast = DomainSet(); fast.add_many(domains, "R")
    slow = DomainSet()
    for d in domains:
        slow.add(d, "R")
    assert fast._rule_of == slow._rule_of
