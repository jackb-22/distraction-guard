import json

from dg_policy.terms import Term, TermIndex, TermType
from dg_policy.youtube import (
    evaluate_player_json,
    evaluate_request,
    evaluate_watch_html,
    extract_search_query,
    is_youtube_host,
    is_youtube_media_host,
)


def test_home_feed_blocked():
    assert evaluate_request("/", None).block


def test_shorts_blocked():
    assert evaluate_request("/shorts/abc123", None).block


def test_trending_blocked():
    assert evaluate_request("/feed/trending", None).block


def test_watch_allowed():
    assert not evaluate_request("/watch", None).block


def test_results_allowed():
    assert not evaluate_request("/results", None).block


def test_browse_feed_id_blocked():
    body = {"browseId": "FEwhat_to_watch"}
    assert evaluate_request("/youtubei/v1/browse", body).block


def test_browse_other_id_allowed():
    body = {"browseId": "UCsomeChannel"}
    assert not evaluate_request("/youtubei/v1/browse", body).block


def test_reel_endpoint_blocked():
    assert evaluate_request("/youtubei/v1/reel/reel_watch_sequence", None).block


def test_is_youtube_host():
    assert is_youtube_host("www.youtube.com")
    assert is_youtube_host("m.youtube.com")
    assert not is_youtube_host("notyoutube.com")


def test_is_youtube_media_host():
    assert is_youtube_media_host("rr3---sn-abcd.googlevideo.com")
    assert is_youtube_media_host("i.ytimg.com")
    assert not is_youtube_media_host("example.com")


def test_extract_search_query_from_results_page():
    q = extract_search_query("/results", {"search_query": ["lecture on cats"]}, None)
    assert q == "lecture on cats"


def test_extract_search_query_from_api_body():
    q = extract_search_query("/youtubei/v1/search", {}, {"query": "lecture"})
    assert q == "lecture"


def test_watch_html_not_family_safe_blocked():
    idx = TermIndex([], set())
    html = '<script>var x = {"isFamilySafe":false,"title":"whatever"};</script>'
    v = evaluate_watch_html(html, idx)
    assert v.block and v.rule_id == "Y-not-family-safe"


def test_watch_html_family_safe_true_passes_term_check():
    idx = TermIndex([], set())
    html = '<script>var x = {"isFamilySafe":true,"title":"Cats 101"};</script>'
    v = evaluate_watch_html(html, idx)
    assert not v.block


def test_watch_html_title_term_match():
    idx = TermIndex([Term("T-1", TermType.STRICT, ((("zorblax",),)))], set())
    html = '<script>var x = {"isFamilySafe":true,"title":"all about zorblax"};</script>'
    v = evaluate_watch_html(html, idx)
    assert v.block and v.rule_id == "T-1"


def test_player_json_not_family_safe():
    idx = TermIndex([], set())
    body = json.dumps({
        "microformat": {"playerMicroformatRenderer": {"isFamilySafe": False}},
        "videoDetails": {"title": "x", "keywords": []},
    }).encode()
    v = evaluate_player_json(body, idx)
    assert v.block and v.rule_id == "Y-not-family-safe"


def test_player_json_family_safe_passes():
    idx = TermIndex([], set())
    body = json.dumps({
        "microformat": {"playerMicroformatRenderer": {"isFamilySafe": True}},
        "videoDetails": {"title": "Cats 101", "keywords": ["cats", "cute"]},
    }).encode()
    v = evaluate_player_json(body, idx)
    assert not v.block


def test_player_json_keyword_term_match():
    idx = TermIndex([Term("T-1", TermType.STRICT, ((("zorblax",),)))], set())
    body = json.dumps({
        "microformat": {"playerMicroformatRenderer": {"isFamilySafe": True}},
        "videoDetails": {"title": "Cats 101", "keywords": ["cats", "zorblax"]},
    }).encode()
    v = evaluate_player_json(body, idx)
    assert v.block and v.rule_id == "T-1"


def test_player_json_malformed_body_does_not_raise():
    idx = TermIndex([], set())
    v = evaluate_player_json(b"not json at all {{{", idx)
    assert not v.block


# --- Shorts stripping ---------------------------------------------------------

from dg_policy.youtube import strip_shorts, strip_shorts_html, strip_shorts_json


def _video(vid):
    return {"videoRenderer": {"videoId": vid, "navigationEndpoint": {"commandMetadata": {"webCommandMetadata": {"url": f"/watch?v={vid}"}}}}}


def test_strip_shorts_removes_shelf_but_keeps_videos():
    data = {"contents": {"sectionListRenderer": {"contents": [{"itemSectionRenderer": {"contents": [
        _video("a"),
        {"reelShelfRenderer": {"items": [{"reelItemRenderer": {"videoId": "s1"}}]}},
        _video("b"),
        {"richItemRenderer": {"content": {"shortsLockupViewModel": {"entityId": "s2"}}}},
    ]}}]}}}
    out, n = strip_shorts(data)
    items = out["contents"]["sectionListRenderer"]["contents"][0]["itemSectionRenderer"]["contents"]
    assert n == 2
    assert [i["videoRenderer"]["videoId"] for i in items] == ["a", "b"]


def test_strip_shorts_removes_guide_entry_and_shorts_links():
    data = {"items": [
        {"guideEntryRenderer": {"navigationEndpoint": {"browseEndpoint": {"browseId": "FEwhat_to_watch"}}}},
        {"guideEntryRenderer": {"navigationEndpoint": {"browseEndpoint": {"browseId": "FEshorts"}}}},
        {"compactVideoRenderer": {"navigationEndpoint": {"commandMetadata": {"webCommandMetadata": {"url": "/shorts/xyz"}}}}},
    ]}
    out, n = strip_shorts(data)
    assert n == 2 and len(out["items"]) == 1


def test_strip_shorts_json_unchanged_or_bad_returns_none():
    import json
    assert strip_shorts_json(json.dumps({"items": [_video("a")]}).encode()) is None
    assert strip_shorts_json(b"not json") is None
    changed = strip_shorts_json(json.dumps({"items": [_video("a"), {"reelItemRenderer": {}}]}).encode())
    assert json.loads(changed) == {"items": [_video("a")]}


def test_strip_shorts_html_rewrites_initial_data_only():
    import json
    data = {"items": [_video("a"), {"reelShelfRenderer": {}}]}
    page = f'<html><script>var ytInitialData = {json.dumps(data)};</script><p>keep me</p></html>'
    out = strip_shorts_html(page)
    assert "reelShelfRenderer" not in out and "keep me" in out and '"a"' in out
    assert strip_shorts_html("<html>no data</html>") is None
