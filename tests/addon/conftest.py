import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
ADDON_DIR = REPO_ROOT / "addon"
if str(ADDON_DIR) not in sys.path:
    sys.path.insert(0, str(ADDON_DIR))


@pytest.fixture
def fixture_policy(tmp_path):
    """Writes a small compiled policy.json (synthetic terms only) and
    returns its path. block_sets: reddit.com under S-social."""
    lists_dir = tmp_path / "lists"
    lists_dir.mkdir()
    (lists_dir / "social.txt").write_text("reddit.com\n")

    terms_path = tmp_path / "terms.json"
    terms_path.write_text(json.dumps([
        {"id": "T-1", "type": "strict", "parts": [["zorblax"]]},
        {"id": "T-2", "type": "contextual", "parts": [["widget"]]},
    ]))

    lexicon_path = tmp_path / "lexicon.json"
    lexicon_path.write_text(json.dumps(["ctxword"]))

    token_path = tmp_path / "health.token"
    token_path.write_text("secrettoken123")

    raw = {
        "version": 1,
        "hash": "fixturehash",
        "enforce": True,
        "block_lists": [{"rule": "S-social", "path": str(lists_dir / "social.txt")}],
        "block_domains": {"B-user": ["blocked-example.com"]},
        "exceptions": [],
        "passthrough": ["passthru-example.com"],
        "temp_allows": [],
        "path_rules": [{"id": "R-1", "host_suffix": "example.com", "path_glob": "/blocked/*"}],
        "search": {},
        "youtube": {},
        "content": {"threshold": 8, "window": 12},
        "terms_path": str(terms_path),
        "lexicon_paths": [str(lexicon_path)],
        "health_token_path": str(token_path),
    }
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(raw))
    return str(policy_path)
