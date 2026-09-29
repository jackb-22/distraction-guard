import json

import pytest

from guardctl.compile import (
    CompileError,
    Sources,
    build,
    compile_policy,
    compute_hash,
    load_sources_from_disk,
    validate,
    write_atomic,
)


def _sources(**overrides):
    defaults = dict(
        policy_toml={"enforce": True, "content": {"threshold": 8, "window": 12}},
        lists_catalog=[{"name": "test-list", "rule": "L-test"}],
        rules={"S-social": ["reddit.com"]},
        lists_dir="/tmp/does-not-need-to-exist",
        terms_path="/tmp/does-not-exist-terms.json",
        health_token_path="/tmp/does-not-exist-token",
        lexicon_path="/tmp/does-not-exist-lexicon.txt",
    )
    defaults.update(overrides)
    return Sources(**defaults)


def test_build_basic_structure():
    raw = build(_sources())
    assert raw["enforce"] is True
    assert raw["block_domains"]["S-social"] == ["reddit.com"]
    assert raw["block_lists"] == [{"rule": "L-test", "path": "/tmp/does-not-need-to-exist/test-list.txt"}]
    assert "hash" in raw


def test_build_disabled_list_excluded():
    raw = build(_sources(disabled_lists={"test-list"}))
    assert raw["block_lists"] == []


def test_build_merges_static_and_local_passthrough():
    raw = build(_sources(
        policy_toml={"enforce": True, "passthrough": ["anthropic.com", "googlevideo.com"]},
        local_passthrough=["my-bank.example"],
    ))
    assert raw["passthrough"] == ["anthropic.com", "googlevideo.com", "my-bank.example"]


def test_build_passthrough_dedups():
    raw = build(_sources(
        policy_toml={"enforce": True, "passthrough": ["anthropic.com"]},
        local_passthrough=["anthropic.com"],
    ))
    assert raw["passthrough"] == ["anthropic.com"]


def test_build_local_blocks_become_b_user_rule():
    raw = build(_sources(local_blocks=["example-blocked.com"]))
    assert raw["block_domains"]["B-user"] == ["example-blocked.com"]


def test_build_missing_rule_key_raises():
    with pytest.raises(CompileError):
        build(_sources(lists_catalog=[{"name": "x"}]))  # no 'rule'


def test_build_temp_allow_missing_field_raises():
    with pytest.raises(CompileError):
        build(_sources(local_temp_allows=[{"host": "x.com"}]))  # no expires_at


def test_build_path_rule_missing_field_raises():
    with pytest.raises(CompileError):
        build(_sources(local_paths=[{"id": "R-1", "host_suffix": "x.com"}]))  # no path_glob


def test_hash_stable_for_same_input():
    raw1 = build(_sources())
    raw2 = build(_sources())
    assert raw1["hash"] == raw2["hash"]


def test_hash_changes_when_content_changes():
    raw1 = build(_sources())
    raw2 = build(_sources(local_blocks=["different.com"]))
    assert raw1["hash"] != raw2["hash"]


def test_validate_passes_for_well_formed_policy():
    raw = build(_sources())
    validate(raw)  # must not raise


def test_validate_catches_bad_path_rules_structure(tmp_path):
    raw = build(_sources())
    raw["path_rules"] = "not-a-list"  # deliberately malformed
    with pytest.raises(CompileError):
        validate(raw)


def test_compile_policy_writes_file(tmp_path):
    dest = tmp_path / "policy.json"
    raw = compile_policy(_sources(), str(dest))
    assert dest.exists()
    on_disk = json.loads(dest.read_text())
    assert on_disk["hash"] == raw["hash"]


def test_compile_policy_leaves_old_file_on_validation_failure(tmp_path):
    dest = tmp_path / "policy.json"
    compile_policy(_sources(), str(dest))
    original = dest.read_text()

    bad = _sources()
    bad.local_paths = [{"id": "R-1", "host_suffix": "x.com"}]  # missing path_glob -> CompileError
    with pytest.raises(CompileError):
        compile_policy(bad, str(dest))
    assert dest.read_text() == original


def test_write_atomic_no_tmp_file_left(tmp_path):
    dest = tmp_path / "policy.json"
    write_atomic({"a": 1}, str(dest))
    assert not (tmp_path / "policy.json.tmp").exists()


# --- load_sources_from_disk integration ---

def _write(p, content):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


def test_load_sources_from_disk_full_layout(tmp_path):
    etc = tmp_path / "etc"
    _write(etc / "policy.toml", 'enforce = true\n\n[content]\nthreshold = 8\nwindow = 12\n')
    _write(etc / "lists.toml", '[[list]]\nname = "test-list"\nrule = "L-test"\n')
    _write(etc / "rules.d" / "social.toml", 'rule = "S-social"\ndomains = ["reddit.com", "x.com"]\n')
    local = etc / "local"
    _write(local / "blocks.json", json.dumps(["blocked-example.com"]))
    _write(local / "exceptions.json", json.dumps(["reddit.com"]))

    sources = load_sources_from_disk(etc_dir=str(etc), lists_dir=str(tmp_path / "lists"))
    assert sources.policy_toml["enforce"] is True
    assert sources.rules["S-social"] == ["reddit.com", "x.com"]
    assert sources.local_blocks == ["blocked-example.com"]
    assert sources.local_exceptions == ["reddit.com"]

    raw = build(sources)
    validate(raw)  # must not raise


def test_load_sources_missing_files_defaults_empty(tmp_path):
    etc = tmp_path / "etc-empty"
    sources = load_sources_from_disk(etc_dir=str(etc))
    assert sources.policy_toml == {}
    assert sources.lists_catalog == []
    assert sources.rules == {}
    assert sources.local_blocks == []


def test_load_sources_bad_toml_raises(tmp_path):
    etc = tmp_path / "etc-bad"
    _write(etc / "policy.toml", "not = valid = toml =")
    with pytest.raises(CompileError):
        load_sources_from_disk(etc_dir=str(etc))


def test_load_sources_bad_json_local_file_raises(tmp_path):
    etc = tmp_path / "etc-bad-json"
    _write(etc / "local" / "blocks.json", "{not a list}")
    with pytest.raises(CompileError):
        load_sources_from_disk(etc_dir=str(etc))
