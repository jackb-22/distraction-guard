from dg_policy.hosts import DomainSet, HostKind
from dg_policy.rules import PathRule, classify_with_workarounds, path_rule_match


def test_path_rule_match():
    rules = [PathRule("R-1", "example.com", "/blocked/*")]
    assert path_rule_match(rules, "www.example.com", "/blocked/x") == "R-1"
    assert path_rule_match(rules, "www.example.com", "/allowed/x") is None
    assert path_rule_match(rules, "other.com", "/blocked/x") is None


def _sets():
    block = DomainSet()
    block.add("reddit.com", "S-social")
    return dict(block_sets=[block], exceptions=DomainSet(), passthrough=DomainSet(), temp_allows={})


def test_translate_goog_wrapper_around_blocked_host_blocks():
    d = classify_with_workarounds("www-reddit-com.translate.goog", "/r/x", **_sets())
    assert d.kind == HostKind.BLOCK
    assert d.rule_id == "S-social"


def test_translate_goog_wrapper_around_allowed_host_inspects_not_passthrough():
    d = classify_with_workarounds("www-example-com.translate.goog", "/page", **_sets())
    assert d.kind == HostKind.INSPECT


def test_archive_org_wrapper_around_blocked_host_blocks():
    d = classify_with_workarounds(
        "web.archive.org", "/web/20240101000000/https://www.reddit.com/r/x", **_sets()
    )
    assert d.kind == HostKind.BLOCK


def test_non_wrapper_host_classified_normally():
    d = classify_with_workarounds("www.reddit.com", "/r/x", **_sets())
    assert d.kind == HostKind.BLOCK


def test_wrapper_host_itself_never_passthrough():
    kwargs = _sets()
    kwargs["passthrough"].add("translate.goog", "P-oops")
    d = classify_with_workarounds("www-example-com.translate.goog", "/page", **kwargs)
    assert d.kind == HostKind.INSPECT
