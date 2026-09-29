import json
import os

import pytest

from dg_policy.hosts import HostKind
from dg_policy.model import PolicyLoadError, PolicyStore, build_policy


@pytest.fixture
def policy_dir(tmp_path):
    lists_dir = tmp_path / "lists"
    lists_dir.mkdir()
    (lists_dir / "social.txt").write_text("reddit.com\n# comment\nx.com\n")

    terms_path = tmp_path / "terms.json"
    terms_path.write_text(json.dumps([
        {"id": "T-1", "type": "strict", "parts": [["zorblax"]]},
    ]))

    token_path = tmp_path / "health.token"
    token_path.write_text("secrettoken123\n")

    raw = {
        "version": 1,
        "hash": "abc123",
        "enforce": True,
        "block_lists": [{"rule": "S-social", "path": str(lists_dir / "social.txt")}],
        "block_domains": {"B-user": ["example-blocked.com"]},
        "exceptions": [],
        "passthrough": ["anthropic.com"],
        "temp_allows": [],
        "path_rules": [],
        "search": {},
        "youtube": {},
        "content": {"threshold": 8, "window": 12},
        "terms_path": str(terms_path),
        "lexicon_paths": [],
        "health_token_path": str(token_path),
    }
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(raw))
    return str(policy_path)


def test_build_policy_classifies_correctly(policy_dir):
    with open(policy_dir) as f:
        raw = json.load(f)
    policy = build_policy(raw)
    assert policy.enforce is True
    assert policy.classify("www.reddit.com").kind == HostKind.BLOCK
    assert policy.classify("example-blocked.com").kind == HostKind.BLOCK
    assert policy.classify("anthropic.com").kind == HostKind.PASSTHROUGH
    assert policy.classify("unrelated.com").kind == HostKind.INSPECT
    assert policy.health_token == "secrettoken123"
    v = policy.term_index.judge_query(["zorblax"])
    assert v.block


def test_policy_store_loads_and_reloads(policy_dir):
    store = PolicyStore(policy_dir, min_check_interval=0)
    changed = store.refresh(force=True)
    assert changed
    assert store.policy is not None
    assert store.policy.classify("www.reddit.com").kind == HostKind.BLOCK

    # No change -> refresh() returns False and keeps the same object
    changed2 = store.refresh(force=True)
    assert not changed2


def test_policy_store_keeps_old_policy_on_bad_reload(policy_dir):
    store = PolicyStore(policy_dir, min_check_interval=0)
    store.refresh(force=True)
    good_policy = store.policy

    with open(policy_dir, "w") as f:
        f.write("{not valid json")

    changed = store.refresh(force=True)
    assert not changed
    assert store.policy is good_policy  # unchanged, not crashed
    assert store.load_error is not None


def test_policy_store_never_raises_when_file_missing(tmp_path):
    store = PolicyStore(str(tmp_path / "nope.json"), min_check_interval=0)
    store.refresh(force=True)  # must not raise
    assert store.policy is None


def test_missing_block_list_file_degrades_not_crashes(policy_dir):
    with open(policy_dir) as f:
        raw = json.load(f)
    raw["block_lists"].append({"rule": "L-not-downloaded-yet", "path": "/tmp/does-not-exist-xyz.txt"})
    policy = build_policy(raw)  # must not raise
    # The list that IS present still works.
    assert policy.classify("www.reddit.com").kind == HostKind.BLOCK
    # The missing list just contributes zero domains, not a crash.
    assert policy.classify("some-domain-only-on-the-missing-list.com").kind == HostKind.INSPECT


def test_path_rules_parsed_and_matchable(policy_dir):
    with open(policy_dir) as f:
        raw = json.load(f)
    raw["path_rules"] = [{"id": "R-1", "host_suffix": "example.com", "path_glob": "/blocked/*"}]
    policy = build_policy(raw)
    assert policy.match_path_rule("www.example.com", "/blocked/x") == "R-1"
    assert policy.match_path_rule("www.example.com", "/ok") is None


def test_malformed_path_rules_type_raises(policy_dir):
    with open(policy_dir) as f:
        raw = json.load(f)
    raw["path_rules"] = "not-a-list"
    with pytest.raises(ValueError):
        build_policy(raw)


def test_path_rule_missing_field_raises(policy_dir):
    with open(policy_dir) as f:
        raw = json.load(f)
    raw["path_rules"] = [{"id": "R-1", "host_suffix": "example.com"}]  # no path_glob
    with pytest.raises(KeyError):
        build_policy(raw)


def test_load_strict_raises_readable_error(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not valid")
    store = PolicyStore(str(p))
    with pytest.raises(PolicyLoadError):
        store.load_strict()


def test_block_lists_cached_across_reloads_until_file_changes(tmp_path):
    import json, os, time
    from dg_policy import model
    lst = tmp_path / "l.txt"
    lst.write_text("a.example\n")
    terms = tmp_path / "t.json"; terms.write_text("[]")
    raw = {"block_lists": [{"rule": "L-x", "path": str(lst)}], "terms_path": str(terms)}
    p1 = model.build_policy(raw)
    p2 = model.build_policy({**raw, "enforce": True})  # policy change, same list file
    assert p1.block_sets[0] is p2.block_sets[0]  # reused, not rebuilt
    lst.write_text("a.example\nb.example\n")
    os.utime(lst, (time.time() + 5, time.time() + 5))
    p3 = model.build_policy(raw)
    assert p3.block_sets[0] is not p1.block_sets[0]
    assert p3.block_sets[0].match("b.example") == "L-x"
