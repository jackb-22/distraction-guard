"""Parser tests use real (small) samples captured from each source on
2026-09-17, so a format change upstream would show up as a test failure
here before it silently produced an empty/garbage list in production."""
import pytest

from guardctl.lists import (
    ListDownloadError,
    parse,
    parse_adblock,
    parse_domains,
    parse_hosts,
    parse_wildcard,
    update_one,
    ListSpec,
)

HAGEZI_ONLYDOMAINS_SAMPLE = """\
# Title: HaGeZi's NSFW - blocks adult content!
# Homepage: https://github.com/hagezi/dns-blocklists

xhamstersexvideo.com.123freedownload.com
so.252035.xyz
erotaganime.blog.2nt.com
"""

OISD_DOMAINSWILD_SAMPLE = """\
# oisd nsfw domainswild

*.0-0.asia
*.0-3353djb.garden
*.0-57.com
"""

STEVENBLACK_HOSTS_SAMPLE = """\
# StevenBlack hosts
0.0.0.0 0310love.com
0.0.0.0 1001truyen.blogspot.com
127.0.0.1 localhost
0.0.0.0 local
"""

OISD_ADBLOCK_SAMPLE = """\
[Adblock Plus]
! Title: oisd nsfw
||0-0.asia^
||example.com^$important
@@||exception.example.com^
! comment line
"""


def test_parse_domains_hagezi_sample():
    domains = parse_domains(HAGEZI_ONLYDOMAINS_SAMPLE)
    assert "so.252035.xyz" in domains
    assert "xhamstersexvideo.com.123freedownload.com" in domains
    assert len(domains) == 3


def test_parse_wildcard_oisd_sample_strips_star_dot():
    domains = parse_wildcard(OISD_DOMAINSWILD_SAMPLE)
    assert domains == ["0-0.asia", "0-3353djb.garden", "0-57.com"]


def test_parse_hosts_stevenblack_sample():
    domains = parse_hosts(STEVENBLACK_HOSTS_SAMPLE)
    assert "0310love.com" in domains
    assert "1001truyen.blogspot.com" in domains
    assert "localhost" not in domains
    assert "local" not in domains


def test_parse_adblock_sample():
    domains = parse_adblock(OISD_ADBLOCK_SAMPLE)
    assert "0-0.asia" in domains
    assert "example.com" in domains
    assert "exception.example.com" not in domains  # @@ exception rules skipped


def test_parse_unknown_format_raises():
    with pytest.raises(ListDownloadError):
        parse("x", "bogus-format")


def test_update_one_writes_normalized_file(tmp_path, monkeypatch):
    import guardctl.lists as lists_mod
    monkeypatch.setattr(lists_mod, "fetch", lambda url: HAGEZI_ONLYDOMAINS_SAMPLE)
    spec = ListSpec(name="test-nsfw", url="https://example.com/x", format="domains", rule="L-test", min_entries=1)
    ok, msg = update_one(spec, str(tmp_path))
    assert ok
    content = (tmp_path / "test-nsfw.txt").read_text()
    assert "so.252035.xyz" in content
    assert "3 entries" in msg


def test_update_one_below_min_entries_fails_without_writing(tmp_path, monkeypatch):
    import guardctl.lists as lists_mod
    monkeypatch.setattr(lists_mod, "fetch", lambda url: HAGEZI_ONLYDOMAINS_SAMPLE)
    spec = ListSpec(name="test-nsfw", url="https://example.com/x", format="domains", rule="L-test", min_entries=1000)
    ok, msg = update_one(spec, str(tmp_path))
    assert not ok
    assert not (tmp_path / "test-nsfw.txt").exists()


def test_update_one_keeps_old_file_on_download_failure(tmp_path, monkeypatch):
    import guardctl.lists as lists_mod
    spec = ListSpec(name="test-nsfw", url="https://example.com/x", format="domains", rule="L-test", min_entries=1)

    monkeypatch.setattr(lists_mod, "fetch", lambda url: HAGEZI_ONLYDOMAINS_SAMPLE)
    update_one(spec, str(tmp_path))
    original = (tmp_path / "test-nsfw.txt").read_text()

    def boom(url):
        raise ListDownloadError("network down")
    monkeypatch.setattr(lists_mod, "fetch", boom)
    ok, msg = update_one(spec, str(tmp_path))
    assert not ok
    assert (tmp_path / "test-nsfw.txt").read_text() == original


def test_parse_domains_rejects_bare_words():
    # A line with no dot isn't a domain -- must not silently produce a
    # bare-TLD-style entry that would match everything.
    assert parse_domains("notadomain\nreddit.com\n") == ["reddit.com"]


def test_shipped_catalog_includes_blocklistproject_and_rules_include_altsearch():
    import tomllib
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    names = [e["name"] for e in tomllib.load(open(root / "etc" / "lists.toml", "rb"))["list"]]
    assert "blocklistproject-porn" in names
    alt = tomllib.load(open(root / "etc" / "rules.d" / "altsearch.toml", "rb"))
    assert alt["rule"] == "S-altsearch" and "search.brave.com" in alt["domains"]
