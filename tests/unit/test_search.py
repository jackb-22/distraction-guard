from dg_policy.search import decode_archive_org, decode_translate_goog, evaluate


def test_google_plain_search_no_vertical():
    r = evaluate("https://www.google.com/search?q=cats", "GET")
    assert r.engine == "google"
    assert r.vertical is None
    assert r.query_tokens_source == "cats"


def test_google_image_vertical_udm2():
    r = evaluate("https://www.google.com/search?q=cats&udm=2", "GET")
    assert r.vertical == "images"


def test_google_image_vertical_tbm_isch():
    r = evaluate("https://www.google.com/search?q=cats&tbm=isch", "GET")
    assert r.vertical == "images"


def test_google_video_vertical():
    r = evaluate("https://www.google.com/search?q=cats&udm=7", "GET")
    assert r.vertical == "videos"


def test_google_images_subdomain_is_images_vertical():
    r = evaluate("https://images.google.com/search?q=cats", "GET")
    assert r.vertical == "images"


def test_google_safe_off_gets_rewritten():
    r = evaluate("https://www.google.com/search?q=cats&safe=off", "GET")
    assert r.rewrite_query == {"param": "safe", "value": "active"}


def test_google_safe_already_active_no_rewrite():
    r = evaluate("https://www.google.com/search?q=cats&safe=active", "GET")
    assert r.rewrite_query is None


def test_google_cctld_matches():
    r = evaluate("https://www.google.co.uk/search?q=cats", "GET")
    assert r is not None and r.engine == "google"


def test_non_search_google_path_not_matched():
    assert evaluate("https://www.google.com/maps", "GET") is None


def test_bing_search():
    r = evaluate("https://www.bing.com/search?q=cats", "GET")
    assert r.engine == "bing"
    assert r.rewrite_query == {"param": "adlt", "value": "strict"}


def test_bing_images_path_vertical():
    r = evaluate("https://www.bing.com/search?q=cats", "GET")
    assert r is not None
    from dg_policy.search import bing_path_vertical_blocked
    assert bing_path_vertical_blocked("/images/search")
    assert not bing_path_vertical_blocked("/search")


def test_duckduckgo_search():
    r = evaluate("https://duckduckgo.com/?q=cats", "GET")
    assert r.engine == "duckduckgo"
    assert r.rewrite_query == {"param": "kp", "value": "1"}


def test_duckduckgo_kp_already_set():
    r = evaluate("https://duckduckgo.com/?q=cats&kp=1", "GET")
    assert r.rewrite_query is None


def test_unrelated_host_returns_none():
    assert evaluate("https://example.com/search?q=cats", "GET") is None


# --- workaround decoders ---

def test_translate_goog_simple():
    assert decode_translate_goog("www-reddit-com.translate.goog") == "www.reddit.com"


def test_translate_goog_with_escaped_hyphen():
    assert decode_translate_goog("www-some--site-com.translate.goog") == "www.some-site.com"


def test_translate_goog_non_match_returns_none():
    assert decode_translate_goog("www.reddit.com") is None


def test_archive_org_decode():
    host = decode_archive_org(
        "web.archive.org", "/web/20240101000000/https://www.reddit.com/r/x"
    )
    assert host == "www.reddit.com"


def test_archive_org_decode_star_timestamp():
    host = decode_archive_org("web.archive.org", "/web/20240101000000if_/https://www.reddit.com/")
    assert host == "www.reddit.com"


def test_archive_org_non_match():
    assert decode_archive_org("example.com", "/web/123/https://reddit.com/") is None
    assert decode_archive_org("web.archive.org", "/not-a-web-path") is None
