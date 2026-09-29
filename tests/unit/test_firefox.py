import json

import pytest

from guardctl.firefox import FirefoxPolicyError, merge

EXISTING = json.dumps({
    "policies": {
        "DisableTelemetry": True,
        "Homepage": {"URL": "file:///home/jack/.config/startpage/index.html", "StartPage": "homepage", "Locked": True},
        "ExtensionSettings": {
            "uBlock0@raymondhill.net": {"installation_mode": "force_installed", "install_url": "x", "private_browsing": True}
        },
    }
})


def test_merge_preserves_existing_unrelated_keys():
    out = json.loads(merge(EXISTING, ca_path="/etc/distraction-guard/ca.pem", block_patterns=["*://*.reddit.com/*"]))
    assert out["policies"]["DisableTelemetry"] is True
    assert out["policies"]["Homepage"]["URL"].endswith("index.html")
    assert "uBlock0@raymondhill.net" in out["policies"]["ExtensionSettings"]


def test_merge_adds_guard_keys():
    out = json.loads(merge(EXISTING, ca_path="/etc/distraction-guard/ca.pem", block_patterns=["*://*.reddit.com/*"]))
    assert out["policies"]["Proxy"] == {"Mode": "none", "Locked": True}
    assert out["policies"]["DNSOverHTTPS"]["Enabled"] is False
    assert "/etc/distraction-guard/ca.pem" in out["policies"]["Certificates"]["Install"]
    assert out["policies"]["WebsiteFilter"]["Block"] == ["*://*.reddit.com/*"]


def test_merge_extends_existing_certificate_installs_not_replaces():
    existing = json.dumps({"policies": {"Certificates": {"Install": ["/etc/some-other-ca.pem"]}}})
    out = json.loads(merge(existing, ca_path="/etc/distraction-guard/ca.pem", block_patterns=[]))
    installs = out["policies"]["Certificates"]["Install"]
    assert "/etc/some-other-ca.pem" in installs
    assert "/etc/distraction-guard/ca.pem" in installs


def test_merge_idempotent_does_not_duplicate_ca():
    once = merge(EXISTING, ca_path="/etc/distraction-guard/ca.pem", block_patterns=[])
    twice = merge(once, ca_path="/etc/distraction-guard/ca.pem", block_patterns=[])
    installs = json.loads(twice)["policies"]["Certificates"]["Install"]
    assert installs.count("/etc/distraction-guard/ca.pem") == 1


def test_merge_rejects_invalid_json():
    with pytest.raises(FirefoxPolicyError):
        merge("{not valid", ca_path="/x", block_patterns=[])


def test_merge_rejects_missing_policies_key():
    with pytest.raises(FirefoxPolicyError):
        merge(json.dumps({"notpolicies": {}}), ca_path="/x", block_patterns=[])


def test_merge_output_is_valid_json():
    out = merge(EXISTING, ca_path="/x", block_patterns=["*://a.example/*"])
    json.loads(out)  # must not raise


def test_strip_guard_keys_recovers_original_from_contaminated_backup():
    # Found live: an uninstall that never restored Firefox left guard keys
    # in place, so the next install's "original" backup contained them.
    import json
    from guardctl.firefox import merge, strip_guard_keys
    original = {"policies": {"Homepage": {"URL": "file:///start.html"}, "DisableTelemetry": True}}
    contaminated = merge(json.dumps(original), ca_path="/etc/distraction-guard/ca.pem", block_patterns=["*://*.reddit.com/*"])
    assert json.loads(strip_guard_keys(contaminated)) == original
    assert json.loads(strip_guard_keys(strip_guard_keys(contaminated))) == original  # idempotent


def test_restore_original_writes_guard_free_policy(tmp_path):
    import json
    from guardctl.firefox import merge, restore_original
    original = {"policies": {"DisablePocket": True}}
    backup = tmp_path / "orig.json"
    backup.write_text(merge(json.dumps(original), ca_path="/x.pem", block_patterns=[]))
    live = tmp_path / "policies.json"
    live.write_text("{}")
    assert restore_original(str(backup), str(live)) is True
    assert json.loads(live.read_text()) == original
    assert restore_original(str(tmp_path / "missing.json"), str(live)) is False
