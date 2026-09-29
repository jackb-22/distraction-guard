"""Builds class mode's config (local/class_mode.json) from jack's own
files: the calcurse schedule and the startpage bookmarks
(~/.config/startpage/bookmarks.js). Both are jack-editable, so they're
only ever read here, by `guardctl schedule-sync`, and snapshotted into
root-owned config -- never read live by the proxy.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from dg_policy.hosts import normalize_host
from dg_policy.schedule import SUPPORT_HOSTS  # noqa: F401 - re-exported for guardctl callers

# `name: [` opens a folder; `['key', 'label', 'https://...']` is an entry.
_FOLDER_RE = re.compile(r"^\s*([A-Za-z_][\w-]*)\s*:\s*\[", re.M)
_ENTRY_RE = re.compile(r"\[\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*\]")


class BookmarkError(ValueError):
    pass


def parse_bookmarks(text: str) -> dict[str, list[tuple[str, str]]]:
    """{folder: [(label, url), ...]} from bookmarks.js."""
    folders: dict[str, list[tuple[str, str]]] = {}
    starts = [(m.start(), m.group(1)) for m in _FOLDER_RE.finditer(text) if m.group(1) != "BOOKMARKS"]
    for i, (pos, name) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(text)
        folders[name] = [(label, url) for _k, label, url in _ENTRY_RE.findall(text[pos:end])]
    if not folders:
        raise BookmarkError("no bookmark folders found")
    return folders


def allow_hosts(
    folders: dict[str, list[tuple[str, str]]],
    *,
    include_folders: list[str],
    include_labels: list[str],
    exclude_labels: list[str],
    extra_hosts: list[str],
) -> list[str]:
    """Hostnames allowed as navigation targets during class. Each
    bookmark contributes its exact host (and, via DomainSet suffix
    matching, its subdomains) -- never a broader parent: drive.google.com
    must not open up gemini.google.com."""
    missing = [f for f in include_folders if f not in folders]
    if missing:
        raise BookmarkError(f"bookmark folder(s) not found: {', '.join(missing)}")
    exclude = {l.lower() for l in exclude_labels}
    wanted = {l.lower() for l in include_labels}
    found_labels = set()

    hosts: list[str] = []
    for folder, entries in folders.items():
        for label, url in entries:
            lab = label.lower()
            if lab in exclude:
                continue
            if folder in include_folders or lab in wanted:
                found_labels.add(lab)
                host = normalize_host(urlsplit(url).hostname or "")
                if host.startswith("www."):
                    host = host[4:]
                if host:
                    hosts.append(host)
    not_found = wanted - found_labels
    if not_found:
        raise BookmarkError(f"bookmark(s) not found: {', '.join(sorted(not_found))}")
    hosts.extend(normalize_host(h) for h in extra_hosts)
    return sorted(set(h for h in hosts if h))
