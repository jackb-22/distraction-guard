import json

from dg_policy.log import DecisionLog, path_head


def test_path_head_strips_query():
    assert path_head("/watch?v=xyz&list=abc") == "/watch"


def test_path_head_root():
    assert path_head("/") == "/"


def test_path_head_full_url():
    assert path_head("https://example.com/foo/bar?x=1") == "/foo"


def test_write_never_includes_query_or_terms(tmp_path):
    log = DecisionLog(str(tmp_path / "decisions.jsonl"))
    log.write(action="block", rule="T-0042", host="example.com", path="/search?q=secretterm")
    content = (tmp_path / "decisions.jsonl").read_text()
    assert "secretterm" not in content
    assert "q=" not in content
    entry = json.loads(content.strip())
    assert entry["rule"] == "T-0042"
    assert entry["path_head"] == "/search"


def test_sensitive_rule_host_redacted():
    import tempfile
    import os
    d = tempfile.mkdtemp()
    log = DecisionLog(os.path.join(d, "decisions.jsonl"))
    log.write(action="block", rule="L-nsfw-hagezi", host="some-adult-site.example", path="/")
    content = open(os.path.join(d, "decisions.jsonl")).read()
    assert "some-adult-site.example" not in content


def test_safe_rule_host_kept():
    import tempfile
    import os
    d = tempfile.mkdtemp()
    log = DecisionLog(os.path.join(d, "decisions.jsonl"))
    log.write(action="block", rule="S-social", host="www.reddit.com", path="/")
    content = open(os.path.join(d, "decisions.jsonl")).read()
    assert "www.reddit.com" in content


def test_write_never_raises_on_bad_path():
    log = DecisionLog("/nonexistent-root-dir-xyz/nope/decisions.jsonl")
    log.write(action="block", rule="T-1")  # must not raise


def test_unwritable_log_warns_once_instead_of_failing_silently(tmp_path, caplog):
    # Regression: a root-only parent directory made every write fail with
    # EACCES and nothing ever said so.
    import logging
    blocked = tmp_path / "nope"
    blocked.write_text("a file, so nope/decisions.jsonl can't be created")
    log = DecisionLog(str(blocked / "decisions.jsonl"))
    with caplog.at_level(logging.WARNING):
        log.write(action="block", rule="S-social")
        log.write(action="block", rule="S-social")
    warnings = [r for r in caplog.records if "not writable" in r.getMessage()]
    assert len(warnings) == 1


def test_repeat_decisions_are_deduplicated(tmp_path):
    import json
    path = tmp_path / "d.jsonl"
    log = DecisionLog(str(path))
    for _ in range(10):
        log.write(action="would_block", rule="S-social", host="www.reddit.com", path="/svc")
    log.write(action="would_block", rule="S-social", host="i.redd.it", path="/x")
    log.write(action="block", rule="S-social", host="www.reddit.com", path="/")
    entries = [json.loads(l) for l in path.read_text().splitlines()]
    assert [(e["action"], e["host"]) for e in entries] == [
        ("would_block", "www.reddit.com"), ("would_block", "i.redd.it"), ("block", "www.reddit.com")]


def test_dedupe_can_be_disabled(tmp_path):
    path = tmp_path / "d.jsonl"
    log = DecisionLog(str(path), dedupe_seconds=0)
    log.write(action="block", rule="S-social", host="www.reddit.com")
    log.write(action="block", rule="S-social", host="www.reddit.com")
    assert len(path.read_text().splitlines()) == 2
