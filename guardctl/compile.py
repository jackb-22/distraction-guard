"""Builds the compiled policy.json from etc/policy.toml, etc/lists.toml,
etc/rules.d/*.toml, and the guardctl-written local/*.json overlays, then
validates it (via dg_policy.model.PolicyStore.load_strict) before it's ever
published. This is what stands between a typo in a config file and a
crashed proxy.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from dg_policy.model import PolicyLoadError, PolicyStore

SCHEMA_VERSION = 1


class CompileError(Exception):
    pass


@dataclass
class Sources:
    """Already-parsed config, so compile logic can be unit tested without
    touching the filesystem. load_from_disk() below does the real reading."""
    policy_toml: dict
    lists_catalog: list[dict]  # entries from etc/lists.toml's [[list]] tables
    rules: dict[str, list[str]]  # rule_id -> domains, from rules.d/*.toml
    local_blocks: list[str] = field(default_factory=list)
    local_paths: list[dict] = field(default_factory=list)
    local_exceptions: list[str] = field(default_factory=list)
    local_passthrough: list[str] = field(default_factory=list)
    local_temp_allows: list[dict] = field(default_factory=list)
    disabled_lists: set[str] = field(default_factory=set)
    local_context_words: list[str] = field(default_factory=list)
    local_class_mode: dict = field(default_factory=dict)  # local/class_mode.json, from `guardctl schedule-sync`
    lists_dir: str = "/var/lib/distraction-guard/lists"
    terms_path: str = "/etc/distraction-guard/private/terms.json"
    lexicon_path: str = "/usr/local/lib/distraction-guard/lexicon/context.txt"
    local_context_path: str = "/etc/distraction-guard/local/context.json"
    health_token_path: str = "/etc/distraction-guard/private/health.token"


def load_sources_from_disk(
    *,
    etc_dir: str = "/etc/distraction-guard",
    local_dir: str | None = None,
    lists_dir: str = "/var/lib/distraction-guard/lists",
    terms_path: str = "/etc/distraction-guard/private/terms.json",
    lexicon_path: str = "/usr/local/lib/distraction-guard/lexicon/context.txt",
    health_token_path: str = "/etc/distraction-guard/private/health.token",
) -> Sources:
    etc = Path(etc_dir)
    local_dir = local_dir or str(etc / "local")
    local = Path(local_dir)

    policy_toml = _read_toml(etc / "policy.toml")

    lists_catalog: list[dict] = []
    lists_toml_path = etc / "lists.toml"
    if lists_toml_path.exists():
        data = _read_toml(lists_toml_path)
        lists_catalog = data.get("list", [])

    rules: dict[str, list[str]] = {}
    for p in sorted(glob.glob(str(etc / "rules.d" / "*.toml"))):
        data = _read_toml(Path(p))
        rule_id = data.get("rule")
        domains = data.get("domains", [])
        if not rule_id:
            raise CompileError(f"{p}: missing 'rule' key")
        rules.setdefault(rule_id, []).extend(domains)

    return Sources(
        policy_toml=policy_toml,
        lists_catalog=lists_catalog,
        rules=rules,
        local_blocks=_read_json_list(local / "blocks.json"),
        local_paths=_read_json_list(local / "paths.json"),
        local_exceptions=_read_json_list(local / "exceptions.json"),
        local_passthrough=_read_json_list(local / "passthrough.json"),
        local_temp_allows=_read_json_list(local / "temp_allows.json"),
        disabled_lists=set(_read_json_list(local / "disabled_lists.json")),
        local_context_words=_read_json_list(local / "context.json"),
        local_class_mode=_read_json_dict(local / "class_mode.json"),
        lists_dir=lists_dir,
        terms_path=terms_path,
        lexicon_path=lexicon_path,
        local_context_path=str(local / "context.json"),
        health_token_path=health_token_path,
    )


def _read_toml(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise CompileError(f"{path}: {e}") from e


def _read_json_list(path: Path) -> list:
    if not path.exists():
        return []
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        raise CompileError(f"{path}: {e}") from e
    if not isinstance(data, list):
        raise CompileError(f"{path}: expected a JSON list, got {type(data).__name__}")
    return data


def _read_json_dict(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        raise CompileError(f"{path}: {e}") from e
    if not isinstance(data, dict):
        raise CompileError(f"{path}: expected a JSON object, got {type(data).__name__}")
    return data


def build(sources: Sources) -> dict:
    """Build the raw policy.json dict (dg_policy.model.build_policy's input
    schema) from Sources. Deterministic given the same input, so its hash
    is stable across recompiles that change nothing."""
    p = sources.policy_toml

    block_lists = []
    for entry in sources.lists_catalog:
        name = entry.get("name")
        if not name:
            raise CompileError("lists.toml entry missing 'name'")
        if name in sources.disabled_lists:
            continue
        rule = entry.get("rule")
        if not rule:
            raise CompileError(f"lists.toml entry {name!r} missing 'rule'")
        block_lists.append({
            "rule": rule,
            "path": os.path.join(sources.lists_dir, f"{name}.txt"),
        })

    block_domains = dict(sources.rules)
    if sources.local_blocks:
        block_domains["B-user"] = list(sources.local_blocks)

    path_rules = []
    for entry in sources.local_paths:
        for k in ("id", "host_suffix", "path_glob"):
            if k not in entry:
                raise CompileError(f"paths.json entry missing {k!r}: {entry}")
        path_rules.append(entry)

    for allow in sources.local_temp_allows:
        for k in ("host", "expires_at"):
            if k not in allow:
                raise CompileError(f"temp_allows.json entry missing {k!r}: {allow}")

    content_cfg = p.get("content", {"threshold": 8, "window": 12, "max_scan_chars": 300_000})

    lexicon_paths = [sources.lexicon_path]
    if sources.local_context_words:
        lexicon_paths.append(sources.local_context_path)

    raw = {
        "version": SCHEMA_VERSION,
        "enforce": bool(p.get("enforce", False)),
        "block_lists": block_lists,
        "block_domains": block_domains,
        "exceptions": list(sources.local_exceptions),
        "passthrough": list(dict.fromkeys([
            *p.get("passthrough", []), *sources.local_passthrough,
            *sources.local_class_mode.get("passthrough", []),  # trusted bookmark folders
        ])),
        "temp_allows": list(sources.local_temp_allows),
        "path_rules": path_rules,
        "search": p.get("search", {}),
        "youtube": p.get("youtube", {}),
        "content": content_cfg,
        "terms_path": sources.terms_path,
        "lexicon_paths": lexicon_paths,
        "health_token_path": sources.health_token_path,
        "never_decrypt": list(p.get("never_decrypt", [])),
        "youtube_restrict": _youtube_restrict(p),
        "class_mode": {
            "pad_minutes": int(sources.local_class_mode.get("pad_minutes", 0)),
            "windows": list(sources.local_class_mode.get("windows", [])),
            "allow": list(sources.local_class_mode.get("allow", [])),
            "daily_block": dict(sources.local_class_mode.get("daily_block") or {}),
            "night_block": dict(sources.local_class_mode.get("night_block") or {}),
        },
    }
    raw["hash"] = compute_hash(raw)
    return raw


def _youtube_restrict(p: dict) -> str:
    level = p.get("youtube_restrict", "strict")
    if level not in ("strict", "moderate"):
        raise CompileError(f"youtube_restrict must be \"strict\" or \"moderate\", got {level!r}")
    return level


def compute_hash(raw: dict) -> str:
    """Hash over everything except the hash field itself, so it's stable
    and can be used by the addon's health endpoint / doctor to confirm the
    running proxy actually picked up a given compile."""
    stripped = {k: v for k, v in raw.items() if k != "hash"}
    canonical = json.dumps(stripped, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def validate(raw: dict) -> None:
    """Raises CompileError with a readable message if `raw` wouldn't load.
    Writes it to a throwaway temp file because PolicyStore reads from disk
    (keeps one code path for both real loads and validation)."""
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(raw, f)
        tmp_path = f.name
    try:
        PolicyStore(tmp_path).load_strict()
    except PolicyLoadError as e:
        raise CompileError(f"compiled policy failed validation: {e}") from e
    finally:
        os.unlink(tmp_path)


def write_atomic(raw: dict, dest_path: str) -> None:
    tmp = dest_path + ".tmp"
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(raw, f, indent=2)
    os.chmod(tmp, 0o640)
    os.replace(tmp, dest_path)


def compile_policy(sources: Sources, dest_path: str) -> dict:
    """Full pipeline: build -> validate -> write. Raises CompileError and
    writes nothing if validation fails -- the previous policy.json (and
    therefore the running proxy's last-good policy) is untouched."""
    raw = build(sources)
    validate(raw)
    write_atomic(raw, dest_path)
    return raw
