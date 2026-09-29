import pytest

from guardctl.classmode import BookmarkError, allow_hosts, parse_bookmarks

JS = """const BOOKMARKS = {
    classes: [
        ['cw', 'courseworks', 'https://courseworks2.columbia.edu'],
        ['cd', 'comp slides', 'https://drive.google.com/drive/folders/abc'],
    ],
    coms: [
        ['g', 'lionmail', 'https://mail.google.com/a/columbia.edu'],
        ['z', 'zoom', 'https://www.zoom.com'],
    ],
    dev: [
        ['gh', 'github', 'https://github.com'],
        ['cl', 'claude', 'https://claude.ai'],
        ['ge', 'gemini', 'https://gemini.google.com'],
    ],
};"""


def _allow(**kw):
    args = dict(include_folders=["classes", "dev"], include_labels=["zoom"], exclude_labels=["claude", "gemini"], extra_hosts=[])
    args.update(kw)
    return allow_hosts(parse_bookmarks(JS), **args)


def test_folders_parsed():
    f = parse_bookmarks(JS)
    assert set(f) == {"classes", "coms", "dev"}
    assert ("github", "https://github.com") in f["dev"]


def test_allowlist_folders_plus_labels_minus_exclusions():
    hosts = _allow()
    assert hosts == ["courseworks2.columbia.edu", "drive.google.com", "github.com", "zoom.com"]


def test_exact_host_never_widened_to_parent():
    # drive.google.com must not open up gemini.google.com or mail.google.com
    hosts = _allow()
    assert "google.com" not in hosts


def test_missing_folder_or_label_is_an_error():
    with pytest.raises(BookmarkError, match="folder"):
        _allow(include_folders=["classes", "nope"])
    with pytest.raises(BookmarkError, match="not found"):
        _allow(include_labels=["zoomz"])
