# Distraction Guard

A content-aware, system-wide distraction filter for Linux. It blocks by **topic**, not just by website, and hands its off switch to someone you trust.

Website blockers fail in a predictable way. The problem is rarely a site; it's a topic, and topics show up everywhere, including on sites you need. Distraction Guard sits in the network path of your user account. It reads what's actually on a page, applies time-based rules from your own calendar, and makes loosening any rule require a code from a friend's authenticator app.

## How it works

```
your apps (uid 1000) ──nftables redirect──▶ mitmproxy (sandboxed service) ──▶ internet
                                               │
                                     guard addon + compiled policy
```

- **Interception.** nftables redirects the user's TCP 80/443 to a transparent [mitmproxy](https://mitmproxy.org) instance running as its own unprivileged, systemd-sandboxed user. TLS is decrypted with a local CA trusted system-wide (and pinned into Firefox by policy). QUIC is rejected so browsers fall back to inspectable TCP.
- **Classification.** Pages are scored by where terms appear (title, meta, headings, URL, body), with context gating for ambiguous words. Search queries are matched through the evasions search engines silently correct: repeated letters, split fragments, near-miss spellings and leetspeak. There are about 1.5M domains from public blocklists, pages that label themselves adult are blocked, and SafeSearch and YouTube Restricted Mode are forced through DNS pinning plus request headers.
- **Response rewriting.** YouTube Shorts are stripped out of API responses and inlined page data, so the rest of YouTube keeps working.
- **Schedules** come from files the user already maintains:
  - *Class mode* reads class times from a [calcurse](https://calcurse.org) calendar and allowed sites from a bookmarks file. It judges each browser request by the page that made it (`Sec-Fetch-*`, `Origin`, `Referer`), which also stops web apps that load from a service-worker cache.
  - A *daily block* for a folder of sites (e.g. streaming) during set hours.
  - A *night block* that cuts all traffic overnight.
- **Private terms.** Users enter terms at a no-echo prompt. They're stored root-only and never printed or logged, only referred to by ID.

## Tamper resistance

- **The ratchet.** Every `guardctl` command is classified as *tighten* (always free) or *loosen* (needs a friend's TOTP code once locked), with lockout and exponential backoff on wrong codes, and a notification to the friend for every loosening.
- **`guardctl lock`.** A transactional lock: it installs a narrow sudoers rule (only `guardctl` and a restricted pacman wrapper), removes the user from `wheel` and `docker`, disables the boot-menu editor, and makes the audit log append-only. It verifies the result with `sudo -l` and rolls every step back on any failure. `guardctl unlock` reverses it with a friend code.
- **Fail-safe operations.** Every deploy arms a 90-second systemd auto-revert timer and fetches a real page through the redirect before disarming it, so a bad rule can never leave the machine offline. A watchdog restarts the proxy, degrades to a DNS sinkhole if it stays down, and alerts the friend. A pacman hook re-applies anything a package update resets.

## Testing

About 460 tests (`scripts/test.sh`). Beyond unit tests, the end-to-end suites run the real mitmproxy and addon inside throwaway `unshare` user+network namespaces, with real nftables rules, fake origins and production service options. They reproduced, then guarded against, bugs found in live use:
- HTTP/2 multiplexed requests stalling behind a per-host connection cap
- `block_global` killing every connection on IPv6 networks
- decrypted traffic being relayed raw, uninspected

## Install (Arch Linux)

```sh
sudo bash install.sh --shadow     # installs in log-only mode
sudo guardctl doctor
sudo guardctl add-term --strict   # add your own terms privately
sudo guardctl set enforce true    # start blocking
```

Your personal lists (a context lexicon and extra `rules.d` files) go in the git-ignored `private/` directory. See [RECOVERY.md](RECOVERY.md) for the lock ceremony and the guide for the friend who holds the code.
