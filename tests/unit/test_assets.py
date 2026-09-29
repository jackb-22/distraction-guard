import json

import pytest

from guardctl.assets import (
    DEFAULT_CRITICAL_DIRECT_HOSTS,
    AssetPaths,
    _firefox_block_patterns,
    resolve_hostnames,
    resolve_safe_search_pins,
    resolve_ssh_allow,
    sinkhole_domains,
    write_assets,
)


def fake_resolver(hostname: str):
    table = {
        "github.com": (["140.82.112.3"], []),
        "gitlab.com": (["172.65.251.78"], ["2606:4700:90:0:f22e:fbec:5bed:a9b9"]),
        "forcesafesearch.google.com": (["216.239.38.120"], []),
        "restrict.youtube.com": (["216.239.38.119"], ["2001:4860:4802::119"]),
        "safe.duckduckgo.com": (["40.90.4.12"], []),
        "strict.bing.com": (["204.79.197.220"], []),
        "does-not-resolve.invalid": ([], []),
        "api.anthropic.com": (["160.79.104.10"], ["2607:6bc0::10"]),
        "extra-critical.example": (["9.9.9.9"], []),
    }
    return table.get(hostname, ([], []))


def test_resolve_ssh_allow_dedups_and_sorts():
    result = resolve_ssh_allow(["github.com", "gitlab.com"], resolver=fake_resolver)
    assert result["ssh_allow_ipv4"] == sorted(["140.82.112.3", "172.65.251.78"])
    assert result["ssh_allow_ipv6"] == ["2606:4700:90:0:f22e:fbec:5bed:a9b9"]


def test_resolve_ssh_allow_skips_unresolvable():
    result = resolve_ssh_allow(["does-not-resolve.invalid"], resolver=fake_resolver)
    assert result == {"ssh_allow_ipv4": [], "ssh_allow_ipv6": []}


def test_resolve_hostnames_dedups_and_sorts():
    v4, v6 = resolve_hostnames(["github.com", "gitlab.com"], resolver=fake_resolver)
    assert v4 == sorted(["140.82.112.3", "172.65.251.78"])
    assert v6 == ["2606:4700:90:0:f22e:fbec:5bed:a9b9"]


def test_default_critical_direct_hosts_is_empty():
    # Regression: api.anthropic.com shares its IP with claude.ai, so an
    # IP-level exemption for the API let claude.ai skip the proxy (and
    # class mode) entirely. Claude Code is protected by NEVER_DECRYPT now.
    assert DEFAULT_CRITICAL_DIRECT_HOSTS == []


def test_resolve_safe_search_pins():
    pins = resolve_safe_search_pins(resolver=fake_resolver)
    by_host = {tuple(p.hosts): p for p in pins}
    assert by_host[("www.google.com",)].ipv4 == "216.239.38.120"
    yt = by_host[("www.youtube.com", "m.youtube.com", "youtubei.googleapis.com", "youtube.googleapis.com")]
    assert yt.ipv4 == "216.239.38.119"
    assert yt.ipv6 == "2001:4860:4802::119"


def test_sinkhole_domains_combines_curated_and_list_files(tmp_path):
    list_file = tmp_path / "hagezi-nsfw.txt"
    list_file.write_text("# header\nsome-nsfw-domain.example\nanother.example\n")
    raw_policy = {
        "block_domains": {"S-social": ["reddit.com"]},
        "block_lists": [{"rule": "L-nsfw-hagezi", "path": str(list_file)}],
    }
    catalog = [{"name": "hagezi-nsfw", "rule": "L-nsfw-hagezi", "dns_sinkhole": True}]
    domains = sinkhole_domains(raw_policy, catalog)
    assert domains["reddit.com"] == "S-social"
    assert domains["some-nsfw-domain.example"] == "L-nsfw-hagezi"


def test_sinkhole_domains_excludes_non_sinkhole_lists(tmp_path):
    list_file = tmp_path / "oisd-nsfw.txt"
    list_file.write_text("some-domain.example\n")
    raw_policy = {"block_domains": {}, "block_lists": [{"rule": "L-nsfw-oisd", "path": str(list_file)}]}
    catalog = [{"name": "oisd-nsfw", "rule": "L-nsfw-oisd", "dns_sinkhole": False}]
    domains = sinkhole_domains(raw_policy, catalog)
    assert domains == {}


def test_sinkhole_domains_missing_list_file_degrades_gracefully(tmp_path):
    raw_policy = {"block_domains": {}, "block_lists": [{"rule": "L-x", "path": str(tmp_path / "nope.txt")}]}
    catalog = [{"name": "x", "rule": "L-x", "dns_sinkhole": True}]
    domains = sinkhole_domains(raw_policy, catalog)  # must not raise
    assert domains == {}


def test_firefox_block_patterns_only_social_and_workaround():
    raw_policy = {"enforce": True, "block_domains": {
        "S-social": ["reddit.com"],
        "S-workaround": ["nitter.net"],
        "U-images": ["images.example"],
        "W-stories": ["stories.example"],
        "L-nsfw": ["some-adult-site.example"],
    }}
    patterns = _firefox_block_patterns(raw_policy)
    assert "*://*.reddit.com/*" in patterns
    assert "*://*.nitter.net/*" in patterns
    assert not any("images.example" in p for p in patterns)
    assert not any("stories.example" in p for p in patterns)
    assert not any("adult-site" in p for p in patterns)


def test_firefox_block_patterns_empty_in_shadow_mode():
    # Shadow mode blocks nothing -- found live: Firefox's WebsiteFilter was
    # already blocking reddit.com etc. during the "log only" install.
    raw_policy = {"enforce": False, "block_domains": {"S-social": ["reddit.com"]}}
    assert _firefox_block_patterns(raw_policy) == []


def test_write_assets_end_to_end(tmp_path):
    raw_policy = {"enforce": True, "block_domains": {"S-social": ["reddit.com"], "S-workaround": ["nitter.net"]}, "block_lists": []}
    paths = AssetPaths(
        nft_path=str(tmp_path / "guard.nft"),
        dnsmasq_always_on_path=str(tmp_path / "dnsmasq" / "always-on.conf"),
        dnsmasq_sinkhole_off_path=str(tmp_path / "dnsmasq" / "sinkhole.conf.off"),
        firefox_policy_path=str(tmp_path / "firefox" / "policies.json"),
        ca_path="/etc/distraction-guard/ca.pem",
        resolved_cache_path=str(tmp_path / "state" / "resolved.json"),
    )
    existing_firefox = json.dumps({"policies": {"DisableTelemetry": True}})

    summary = write_assets(
        raw_policy, [],
        paths=paths,
        ssh_allow_hostnames=["github.com"],
        lan_tcp_ports=[22],
        critical_direct_hostnames=["extra-critical.example"],
        resolver=fake_resolver,
        existing_firefox_json=existing_firefox,
    )

    assert summary["firefox_written"] is True
    assert summary["ssh_allow_ipv4"] == 1
    assert "140.82.112.3" in open(paths.nft_path).read()
    # critical_direct comes only from policy.toml now (default is empty).
    nft_text = open(paths.nft_path).read()
    assert "160.79.104.10" not in nft_text  # api.anthropic.com: not IP-exempted
    assert "9.9.9.9" in nft_text  # extra-critical.example, from policy.toml
    assert "host-record=www.google.com" in open(paths.dnsmasq_always_on_path).read()
    assert "address=/reddit.com/" in open(paths.dnsmasq_sinkhole_off_path).read()
    ff = json.loads(open(paths.firefox_policy_path).read())
    assert ff["policies"]["DisableTelemetry"] is True
    assert "*://*.reddit.com/*" in ff["policies"]["WebsiteFilter"]["Block"]
    resolved = json.loads(open(paths.resolved_cache_path).read())
    assert resolved["ssh_allow_ipv4"] == ["140.82.112.3"]
    assert resolved["critical_direct_ipv4"] == ["9.9.9.9"]
    assert resolved["critical_direct_ipv6"] == []


def test_write_assets_no_ip_exemptions_without_policy_toml_list(tmp_path):
    # Nothing is IP-exempted by default any more: an IP exemption for the
    # Anthropic API also exempted claude.ai (same IP) from all filtering.
    paths = AssetPaths(
        nft_path=str(tmp_path / "guard.nft"),
        dnsmasq_always_on_path=str(tmp_path / "a.conf"),
        dnsmasq_sinkhole_off_path=str(tmp_path / "b.conf.off"),
        firefox_policy_path=str(tmp_path / "policies.json"),
        resolved_cache_path=str(tmp_path / "state" / "resolved.json"),
    )
    write_assets({"block_domains": {}}, [], paths=paths, ssh_allow_hostnames=[], lan_tcp_ports=[], resolver=fake_resolver)
    assert "160.79.104.10" not in open(paths.nft_path).read()


def test_write_assets_skips_firefox_when_not_given(tmp_path):
    paths = AssetPaths(
        nft_path=str(tmp_path / "guard.nft"),
        dnsmasq_always_on_path=str(tmp_path / "a.conf"),
        dnsmasq_sinkhole_off_path=str(tmp_path / "b.conf.off"),
        firefox_policy_path=str(tmp_path / "policies.json"),
        resolved_cache_path=str(tmp_path / "state" / "resolved.json"),
    )
    summary = write_assets({"block_domains": {}}, [], paths=paths, ssh_allow_hostnames=[], lan_tcp_ports=[], resolver=fake_resolver)
    assert summary["firefox_written"] is False
    assert not (tmp_path / "policies.json").exists()


def test_staged_sinkhole_is_outside_dnsmasq_conf_dir():
    # Regression: NetworkManager runs dnsmasq with
    # --conf-dir=/etc/NetworkManager/dnsmasq.d, which loads every file in
    # it regardless of suffix. The degraded-mode sinkhole was staged there
    # as *.conf.off and so was always live: ~90k domains, reddit.com
    # included, NXDOMAIN'd even in shadow mode (and never reached the
    # proxy, so nothing was logged).
    from pathlib import Path
    staged = Path(AssetPaths(nft_path="x").dnsmasq_sinkhole_off_path)
    assert Path("/etc/NetworkManager/dnsmasq.d") not in staged.parents


def test_watchdog_stages_sinkhole_outside_dnsmasq_conf_dir():
    import re
    from pathlib import Path
    src = (Path(__file__).resolve().parents[2] / "bin" / "dg-watchdog").read_text()
    off = re.search(r'DNSMASQ_SINKHOLE_OFF = Path\("([^"]+)"\)', src).group(1)
    assert not off.startswith("/etc/NetworkManager/dnsmasq.d/")
    assert "DNSMASQ_SINKHOLE_OFF.rename" not in src  # copy in / delete, never move the staged file


def test_youtube_restrict_level_picks_dns_pin():
    seen = []
    def resolver(h):
        seen.append(h)
        return (["1.2.3.4"], [])
    resolve_safe_search_pins(resolver=resolver, youtube_restrict="moderate")
    assert "restrictmoderate.youtube.com" in seen and "restrict.youtube.com" not in seen
