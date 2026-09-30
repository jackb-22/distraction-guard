# Distraction Guard

**A content-aware, system-wide distraction filter for Linux. It blocks by *topic*, not just by domain, and moves its off switch to someone you trust.**

A transparent TLS-intercepting proxy sits in the network path of a single Unix user. It classifies every page, search query and API response against the user's private terms and public blocklists, and enforces calendar-driven access windows. The ability to *loosen* any rule is gated behind a TOTP code held by a friend. Once locked, the user has no route to root: sudo is reduced to two audited binaries, and polkit, docker and boot-time escapes are closed.

~6,000 lines of Python · 467 test cases (~5,300 lines), including end-to-end suites running the real proxy inside throwaway kernel network namespaces · deployed and locked on the author's daily-driver Arch laptop.

```
                 uid 1000 sockets
 Firefox, CLI ──────────────┐
 tools, apps                ▼
                   ┌──────────────────┐  nat/output: tcp 80,443 → :8080 (redirect)
                   │ nftables  inet   │  filter/output: allow lo, DNAT'd, DNS, Meet media,
                   │ distraction_guard│  ssh-allowlist; reject everything else (logged)
                   └────────┬─────────┘
                            ▼
      ┌────────────────────────────────────────────────┐
      │ mitmdump --mode transparent (uid distraction-guard, systemd-sandboxed)
      │   guard_addon: tls_clienthello → next_layer → server_connect
      │               → requestheaders → responseheaders → response
      │   PolicyStore: compiled policy.json, mtime hot-reload, last-good fallback
      └───────────────────────┬────────────────────────┘
                              ▼  upstream re-pinned by SNI
                          internet
   guardctl (root CLI, TOTP ratchet) ── compiles ──▶ policy.json, guard.nft, dnsmasq, Firefox policy
   dg-watchdog ── health-checks both listeners ──▶ restart / degrade to DNS sinkhole / restore
```

## Highlights

- **Transparent interception without a system-wide blast radius.** The redirect is scoped with `meta skuid`, so root, package managers and system daemons never touch the proxy. IPv4 and IPv6 are handled in a single `inet` table. QUIC is rejected so browsers fall back to inspectable TCP. HTTPS/SVCB DNS records are filtered, and Firefox's DoH, HTTP/3 and ECH are locked off, so encrypted ClientHello can't hide the SNI.
- **Content classification, not URL lists.** Zone-weighted scoring (`title`×5, `meta`×4, `headings`/`url_path`×3, `body`×1, threshold 8, per-zone caps) with three term types: strict, contextual (gated by a context lexicon within a 12-token window) and combo. A symmetric normalization pipeline (NFKD, casefold, leetspeak fold, repeated-letter collapse, stemming) handles evasions. On top of that, search queries are matched against the corrections search engines apply silently: rejoined fragments (`t-e-r-m`) and edit-distance near-misses that are insertions only, so a shorter real word never trips a longer term.
- **Initiator-aware scheduling.** "Class mode" reads windows from a calcurse calendar and an allowlist from a bookmarks file. It judges every browser request by the page that *made* it (`Sec-Fetch-Dest`, `Origin`, `Referer`, `Sec-Fetch-Site`), which also stops sites whose service worker serves the shell from cache. LTI tool launches (form POSTs from an allowed origin) and embedded iframes inherit trust for a bounded TTL. Daily and overnight blocks are layered on top.
- **Response rewriting.** YouTube Shorts are removed structurally from `youtubei/v1/{browse,search,next,guide}` JSON and from the inlined `ytInitialData` blob. The smallest list item containing a Shorts marker is pruned, and everything around it is left intact.
- **A cryptographic ratchet.** Every CLI command is classified *tighten*, *loosen*, *neutral* or *internal*. Loosening requires an RFC 6238 TOTP code (±1 step, replay-protected, 5-strike lockout with exponential backoff to 24h that decays over clean weeks), and every use notifies the friend over ntfy.
- **A transactional lock.** `guardctl lock` installs a `visudo`-validated drop-in (NOPASSWD for `guardctl` and a restricted pacman wrapper only) *before* removing the user from `wheel` and `docker`. It then adds a polkit rule so the user can still join wifi, sets systemd-boot `editor no`, and makes the audit log `chattr +a`. It verifies the result with `sudo -l -U`, and a failure at any step unwinds every completed step in reverse. A pacman hook re-applies anything a package upgrade resets.
- **Operations that can't strand you offline.** Every deploy arms a 90s `systemd-run` auto-revert timer, then fetches a real page *as the filtered user*, through the redirect, before disarming it. A watchdog verifies both proxy listeners (plus a policy-hash health endpoint), restarts the proxy, degrades to a dnsmasq sinkhole after 5 minutes, and restores after 2 healthy minutes.

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Component-by-component internals: packet path, addon hook pipeline, classifier, scheduler, policy compiler, ratchet, lock, watchdog |
| [docs/ENGINEERING-LOG.md](docs/ENGINEERING-LOG.md) | Bugs found in live use, with root causes traced to kernel, proxy and protocol behavior, and the regression test that now pins each one |
| [RECOVERY.md](RECOVERY.md) | Guide for the key holder, and the lock ceremony |

## Install (Arch Linux)

```sh
sudo bash install.sh --shadow     # log-only mode: classifies and logs, blocks nothing
sudo guardctl doctor              # services, nft table, CA trust, proxy running the current policy hash
sudo guardctl add-term --strict   # no-echo prompt; stored root-only, never printed or logged
sudo guardctl set enforce true    # start blocking
sudo guardctl lock --dry-run      # review the lock's prechecks and steps
```

Personal lists (a context lexicon, extra `rules.d` categories) live in the git-ignored `private/` directory.

## Testing

```sh
scripts/test.sh    # stdlib-only unit suite (Python 3.13) + addon suite against pinned mitmproxy 12.2.3
```

The end-to-end suites use `unshare -rnm` to build a disposable user, network and mount namespace with a dummy default route, a bind-mounted `/etc/hosts`, real nftables rules rendered from the production template, a real `mitmdump` running the addon with options parsed from the production systemd unit, and purpose-built origins: an HTTP/1.1-only TLS server, and an HTTP/2-only server written against `h2`. They cover:
- a redirected connection actually reaching the proxy with the right `SO_ORIGINAL_DST` (IPv4 and IPv6)
- non-web ports still being rejected
- 60 multiplexed HTTP/2 streams all completing
- a client with a global IPv6 source being proxied rather than killed
- content blocking and shadow-mode logging, end to end
