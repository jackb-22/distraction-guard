"""Deep-merges the Distraction Guard policy keys into Firefox's enterprise
policies.json, preserving whatever was already there (uBlock force-install,
homepage, telemetry settings, etc). Never overwrites unrelated keys.
"""
from __future__ import annotations

import copy
import json


class FirefoxPolicyError(Exception):
    pass


def guard_keys(*, ca_path: str, block_patterns: list[str]) -> dict:
    """The keys guardctl owns. WebsiteFilter.Block is a backstop for
    degraded mode / non-proxy-aware traffic; it carries only patterns for
    rules we're comfortable a person could see in a config file (social +
    workaround domains) -- never the NSFW lists or anything term-derived."""
    return {
        "DNSOverHTTPS": {"Enabled": False, "Locked": True},
        "Proxy": {"Mode": "none", "Locked": True},
        "Certificates": {
            "ImportEnterpriseRoots": True,
            "Install": [ca_path],
        },
        "Preferences": {
            "network.http.http3.enable": {"Value": False, "Status": "locked"},
            "network.dns.echconfig.enabled": {"Value": False, "Status": "locked"},
            "network.dns.http3_echconfig.enabled": {"Value": False, "Status": "locked"},
        },
        "WebsiteFilter": {"Block": list(block_patterns)},
    }


def _deep_merge(base: dict, overlay: dict) -> dict:
    """Merge overlay into base. Dict values merge recursively; anything else
    (lists, scalars) in overlay replaces the base value outright, and keys
    only in base are left untouched."""
    out = copy.deepcopy(base)
    for key, value in overlay.items():
        if key in out and isinstance(out[key], dict) and isinstance(value, dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def merge(existing_json_text: str, *, ca_path: str, block_patterns: list[str]) -> str:
    try:
        data = json.loads(existing_json_text)
    except json.JSONDecodeError as e:
        raise FirefoxPolicyError(f"existing policies.json is not valid JSON: {e}") from e

    if "policies" not in data or not isinstance(data["policies"], dict):
        raise FirefoxPolicyError("existing policies.json has no top-level 'policies' object")

    # Certificates.Install is a list we want to *extend*, not replace, in
    # case something else already lists a CA there.
    existing_certs = data["policies"].get("Certificates", {})
    existing_installs = existing_certs.get("Install", []) if isinstance(existing_certs, dict) else []
    installs = list(existing_installs)
    if ca_path not in installs:
        installs.append(ca_path)

    overlay = guard_keys(ca_path=ca_path, block_patterns=block_patterns)
    overlay["Certificates"]["Install"] = installs

    data["policies"] = _deep_merge(data["policies"], overlay)

    out = json.dumps(data, indent=2)
    # Round-trip validation: never write something we can't parse back.
    json.loads(out)
    return out + "\n"


GUARD_OWNED_KEYS = ("DNSOverHTTPS", "Proxy", "Certificates", "Preferences", "WebsiteFilter")


def strip_guard_keys(json_text: str) -> str:
    """The policy with every guard-owned key removed -- what to restore on
    uninstall/emergency-off, and what a pre-install backup must look like.

    Whole keys, not just our sub-entries: found live, an uninstall that
    never restored Firefox left these keys in place, so the next install's
    "original" backup already contained them. Jack's own policy has none of
    these five keys, so removing them wholesale recovers it exactly (checked
    against his clean copy)."""
    try:
        data = json.loads(json_text)
    except json.JSONDecodeError as e:
        raise FirefoxPolicyError(f"policies.json is not valid JSON: {e}") from e
    policies = data.get("policies")
    if not isinstance(policies, dict):
        raise FirefoxPolicyError("policies.json has no top-level 'policies' object")
    data["policies"] = {k: v for k, v in policies.items() if k not in GUARD_OWNED_KEYS}
    return json.dumps(data, indent=2) + "\n"


def restore_original(backup_path: str, policy_path: str) -> bool:
    """Write the (guard-key-free) backup back as Firefox's policy. Returns
    False if there's no backup to restore from."""
    import os
    if not os.path.exists(backup_path):
        return False
    text = strip_guard_keys(open(backup_path, encoding="utf-8").read())
    tmp = policy_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, policy_path)
    return True
