# Architecture

Distraction Guard is five cooperating pieces:

1. **A per-user nftables table** that steers one Unix user's traffic.
2. **A sandboxed mitmproxy** running a policy addon.
3. **A root-owned policy compiler and CLI** (`guardctl`) that enforces a code-gated ratchet.
4. **A watchdog.**
5. **A lock** that removes the user's routes to root.

Everything that makes a decision lives in `dg_policy/`, which is pure Python with no third-party dependencies. It is shared by the addon (inside mitmproxy) and by `guardctl` (plain system Python, running as root).

```
dg_policy/   hosts, text, terms, content, search, youtube, rules, schedule, model, log
guardctl/    cli, registry, compile, assets, nftgen, dnsmasqgen, firefox, lists,
             auth, totp, notify, state, lock, watchdog, classmode
addon/       guard_addon.py (mitmproxy hooks)
bin/         guardctl, dg-watchdog, guard-pkg
templates/   guard.nft.in, sudoers.in, polkit.rules.in
systemd/     proxy, nft, watchdog, refresh/notify timers
```

---

## 1. Packet path (nftables)

`templates/guard.nft.in` renders one `inet distraction_guard` table, covering IPv4 and IPv6 together. Every rule is scoped with `meta skuid <uid>`. Root, system daemons and the proxy's own user (`distraction-guard`) never enter the user chains, so a proxy fault can't take the whole machine offline, and the proxy's upstream connections can't loop back into it.

| Chain | Hook | Behavior |
|---|---|---|
| `nat_out` → `jack_nat` | `nat output`, prio `dstnat` | loopback and the Meet media ranges `return`, then `tcp dport {80,443}` → `redirect to :8080` |
| `filter_out` → `jack_out` | `filter output` | accept `lo`, `ct status dnat` (see below), established, ICMP, DNS (53/udp+tcp to any resolver), Meet media (UDP 3478/19302-19309, TCP 443/19305 to Google's published relay ranges only), and ssh to a resolved allowlist; reject `udp dport 443` (forces TCP fallback from QUIC); rate-limited `log prefix "dg-reject"`, then `reject with icmpx admin-prohibited` |
| `in_guard` | `filter input` | drop any non-`lo` traffic to the proxy ports, so the proxy is never reachable from outside |

The `ct status dnat accept` rule is load-bearing. In the output hook, the NAT chain runs first and rewrites the destination to `127.0.0.1:8080`. The filter chain then sees the *post*-NAT port but the *pre*-NAT output interface (`wlo1`), so neither `oif "lo"` nor the 80/443 jump matches the redirected packet, and without this rule every proxied connection falls through to the reject. See the engineering log.

Rendering is done by `guardctl/nftgen.py`. Every IP, CIDR and port is validated, IP versions are checked per set, and unfilled placeholders are refused. The same renderer is used by the installer, by the refresh timer, and by the watchdog on degrade/restore, so no rule can be dropped by a mode switch.

## 2. The proxy

`mitmdump` runs in transparent mode on `127.0.0.1:8080` and `[::1]:8080`, plus a regular-mode admin listener on `127.0.0.1:8081` that serves only a token-authenticated health endpoint. It runs as the unprivileged `distraction-guard` user under a systemd sandbox:
- `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`
- `NoNewPrivileges`, an empty `CapabilityBoundingSet`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`
- `RestrictSUIDSGID`, `LockPersonality`, `MemoryMax=1500M`
- `ReadWritePaths` limited to its CA directory and log directory

The runtime is a pinned virtualenv (`mitmproxy==12.2.3`), built by `uv`. The local CA is generated with OpenSSL (RSA-2048, `CA:TRUE`, `keyCertSign,cRLSign`). Its private key never leaves the service user's 0700 directory. The certificate is trusted through p11-kit (`trust anchor --store`, which covers curl, git, NSS and Chromium) and pinned into Firefox with `Certificates.Install`. Node and uv are pointed at the system store with `NODE_USE_SYSTEM_CA=1` and `UV_NATIVE_TLS=1`.

Options that matter:
- `connection_strategy=lazy`
- `stream_large_bodies=2m`
- `http3=false`
- `block_global=false`, because the listeners are loopback-only and a laptop's own global IPv6 address must not be treated as a hostile client

### Addon hook pipeline (`addon/guard_addon.py`)

Every hook is wrapped so that an exception blocks *only the current flow*, and logs a rate-limited `G-error` instead of killing mitmdump.

1. **`tls_clienthello`**
   - No usable SNI to a non-LAN destination: the connection is marked, and killed at `server_connect`.
   - `never_decrypt` hosts (always including `api.anthropic.com`): passed through untouched. This is matched by SNI, deliberately *not* by IP, because the same IP also serves `claude.ai`.
   - `passthrough` hosts: passed through, *unless* class mode must be able to gate them. Those are decrypted but marked never-scanned, because a browser connection opened before a class window would otherwise carry on undecrypted through it.
2. **`next_layer`** judges only the *outer* layer. Non-TLS bytes on 443, or non-HTTP bytes on 80, are marked as a raw tunnel and killed at `server_connect`. `TCPLayer.start()` ignores `flow.kill()`, so killing at the upstream connect is the only reliable point. Once a `ClientTLSLayer` is on the stack, the hook defers to mitmproxy's built-in `NextLayer`, which picks HTTP/1 or HTTP/2 from the negotiated ALPN.
3. **`server_connect`** runs, in order:
   - a loop guard (connections to loopback or to the proxy's own ports)
   - the night block, which refuses every non-LAN upstream, including passthrough and never-decrypt hosts
   - the raw-tunnel and no-SNI kills
   - a block-list kill (enforce mode only)
   - upstream pinning, which re-resolves by SNI. It applies only when the upstream address is still the client's raw original-destination IP; rewriting hostname upstreams defeated HTTP/2 connection reuse, see the engineering log.
4. **`requestheaders`**, in precedence order:
   1. night block
   2. daily block (with an embed exemption)
   3. class-mode gate
   4. host classification: temp-allow › exception › block list › passthrough › inspect
   5. host+path-glob rules
   6. YouTube request rules
   7. search-engine query judgement and SafeSearch parameter rewriting
   8. scan-kind assignment
5. **`responseheaders`** buffers a response only if its content type is one its scan kind actually reads (`text/html` for pages; `application/json` for YouTube player and strip endpoints) and it's under 2 MB. Everything else streams, so API traffic is never held back.
6. **`response`** scores HTML, evaluates YouTube player/next JSON, and strips Shorts, which is done in enforce mode only.

**Block responses** are content-negotiated. Documents get an HTML block page, `Accept: application/json` gets a JSON 403 so apps fail cleanly, and anything else gets an empty 403. Every block carries `X-Distraction-Guard: <rule-id>`, which the deploy probe uses to tell "the proxy blocked it" from "the network is broken". In shadow mode (`enforce = false`) nothing is blocked, and each decision is logged as `would_block`.

## 3. Classification

### Host matching (`dg_policy/hosts.py`)

`normalize_host` handles IDNA, ports, IPv6 brackets and trailing dots. `DomainSet` does suffix-chain matching: `a.b.example.com` → `b.example.com` → `example.com`, never a bare TLD. It has a fast path for plain ASCII list entries, checked against the full normalizer by test.

Downloaded lists (HaGeZi, OISD, StevenBlack, Block List Project; about 1.5M domains, in four formats) are parsed by `guardctl/lists.py`, with a minimum-entry guard so a truncated download never replaces a good list. Loaded lists are cached per `(path, rule)` and keyed on `(mtime, size)`, so a policy reload that doesn't touch a list costs nothing. Before this, every policy change froze the proxy for about 6 seconds.

### Text pipeline (`dg_policy/text.py`)

Applied identically to stored terms, the context lexicon and scanned text:

```
html.unescape → NFKD + strip combining marks → casefold → leetspeak fold (0→o, 3→e, @→a, $→s…)
→ split on [^a-z] → collapse repeated letters → conservative suffix stemming
```

Zones (title, meta/OpenGraph, h1-h3, URL path, stripped body) are extracted separately.

### Term index (`dg_policy/terms.py`)

Three term types:
- **Strict:** always counts.
- **Contextual:** counts only near a context-lexicon word (within 12 body tokens), in a context-bearing zone, or on a page that labels itself adult (RTA and `rating` meta tags).
- **Combo:** two parts that must co-occur in the same zone, or within the window.

A strict term in the title, meta or URL path blocks immediately. Otherwise zone weights are summed against the threshold, with per-zone caps so one repeated word can't dominate. Multi-word terms also match run-together (`wordword`).

**Search queries** go through `scan_query`, which is intentionally more aggressive than page scanning because search engines "fix" these evasions for the user:
- adjacent fragments are rejoined, up to 10 tokens and length-bounded
- single-word terms match near-misses: one substitution (length ≥ 6), one insertion (length ≥ 5), or two insertions (length ≥ 8), with the same first letter

Deletions are excluded on purpose, so that a shorter real word never matches a longer term.

### Search and YouTube

- **Search engines** (`dg_policy/search.py`): Google `safe=active`, Bing `adlt=strict` (plus blocked image/video verticals) and DuckDuckGo. These parameter rewrites are paired with dnsmasq `host-record` pins to each engine's SafeSearch endpoint. Engines where SafeSearch can't be forced are blocked (`S-altsearch`). `translate.goog` and `web.archive.org` URLs are unwrapped, and the real target is re-classified.
- **YouTube** (`dg_policy/youtube.py`):
  - the home feed, trending and explore are blocked, including by `browseId` in `youtubei/v1/browse` POST bodies
  - `/shorts/` and `youtubei/v1/reel/*` are blocked
  - a `YouTube-Restrict: Strict|Moderate` header is added, paired with a DNS pin to `restrict[moderate].youtube.com`
  - player/next JSON is checked for `isFamilySafe` and for terms in titles and keywords
  - Shorts shelves are pruned from responses by `strip_shorts`, which removes the smallest list element containing a Shorts marker (`reelShelfRenderer`, `shortsLockupViewModel`, `reelWatchEndpoint`, `/shorts/` URLs, the `FEshorts` guide entry)

## 4. Scheduling (`dg_policy/schedule.py`, `guardctl/classmode.py`)

`guardctl schedule-sync` parses calcurse's `apts` format: weekly `{1W -> date}` recurrences with `!date` exceptions, plus one-off appointments. Any `Class:` entry it can't represent is an error rather than a silent skip. It also parses the startpage `bookmarks.js` into folders. The result is snapshotted into root-owned `local/class_mode.json`; the user-editable source files are never read live. Via sudo, the files are opened with `O_NOFOLLOW` and must be owned by the invoking user, so the command can't be used to make root read arbitrary files.

- **Class mode.** During a window (±5 minute padding), every browser request (anything with `Sec-Fetch-Dest`) is gated:
  - A top-level `document` opens only on an allowed host, or on sign-in hosts (Columbia CAS, Duo, Canvas/Instructure, Google and Microsoft SSO).
  - Every other request is judged by its **initiator**: `Origin`, else `Referer`, else the host itself when `Sec-Fetch-Site` is same-origin. This is what stops service-worker-cached web apps, whose shell never hits the network but whose API calls do.
  - An iframe opened by an allowed page, or a top-level form POST from an allowed origin (an LTI tool launch), makes its host a trusted initiator for one hour.
  - `Sec-Fetch-Site: none` requests (the browser's own, like push services) aren't gated. Clients without `Sec-Fetch-*` headers aren't class-gated at all.
- **Daily block.** A bookmark folder's hosts, blocked for every request from any client during set hours. Embeds inside class-allowed pages are exempt.
- **Night block.** Every upstream connection is refused at `server_connect` during a window that may wrap midnight.
- **Change detection.** `removed_time()` compares old and new windows conservatively: a window split across two new ones counts as removed. Removing time, shortening padding or hours, allowing or trusting a new site, or exempting a site is classified as a loosening and asks for a friend code before being written.

## 5. Policy compilation (`guardctl/compile.py`)

Sources are `policy.toml`, `lists.toml`, `rules.d/*.toml`, the `local/*.json` overlays written by `guardctl`, the private terms file, and lexicons. They are merged into a deterministic `policy.json` with a content hash, validated by loading it through the same `PolicyStore.load_strict()` the proxy uses, and published atomically.

The proxy's `PolicyStore` reloads on mtime change, throttled to once every 2s. A reload that fails for any reason (bad JSON, a missing or unreadable file) keeps the last-good policy and logs a warning. The health endpoint reports the hash actually loaded, and `guardctl doctor` compares it against the compiled hash to catch a proxy silently running stale policy.

`guardctl/assets.py` renders the side artifacts from the same policy:
- the nft table
- dnsmasq configuration: always-on SafeSearch pins and `filter-rr=HTTPS,SVCB`, plus a degraded-mode sinkhole staged *outside* NetworkManager's `dnsmasq.d`, because `--conf-dir` loads files regardless of suffix
- a Firefox policy merge: DoH and HTTP/3 disabled, ECH disabled, `Proxy: none` locked, the CA installed, and `WebsiteFilter` populated only in enforce mode and only with non-sensitive categories

The pre-install Firefox policy is backed up with guard-owned keys stripped, and it is restored by `uninstall` and `emergency-off`.

## 6. The ratchet (`guardctl/registry.py`, `cli.py`, `auth.py`, `totp.py`)

Each command is registered as `TIGHTEN`, `LOOSEN`, `NEUTRAL` or `INTERNAL`, and an unknown command defaults to `LOOSEN`. `INTERNAL` commands (timer and hook jobs) refuse to run whenever `SUDO_USER` is set. Once locked, `LOOSEN` requires a code:
- RFC 6238, SHA-1, 6 digits, 30s steps, ±1 step tolerance
- the last accepted counter is stored, so a code can't be replayed
- 5 consecutive failures trigger a 15-minute lockout, doubling up to 24h, with one escalation level decaying per clean week
- real root (the key holder via `su`) bypasses it

Some commands classify their own direction at runtime. `set enforce true` is free while `set enforce false` needs a code, and `schedule-sync` computes a diff and asks only when the diff loosens.

`totp-enroll` renders a QR code with `qrencode`, and commits the new secret only after a code from the new authenticator verifies. A failed confirmation restores the previous secret.

Every command is written to an append-only JSON-lines audit log. It is opened with `O_APPEND` and its mode is set only at creation, because `chmod` returns `EPERM` on a `chattr +a` file. Every non-neutral command also queues an ntfy notification. The queue is durable, flushes immediately, retries on a timer, keeps only the newest 20 entries, stops at the first failure, and records the last HTTP status. `guardctl notify-status --test` shows its state.

Terms are entered through `getpass`, stored root:distraction-guard 0640, and referenced only by ID (`find-term` resolves an ID without listing terms). They never appear in output or in the decision log. That log redacts query strings, keeps only the first path segment, hides hosts for sensitive categories, and deduplicates on `(action, rule, host)` within 60s.

## 7. The lock (`guardctl/lock.py`)

`guardctl lock` always requires a friend code, even though nothing is locked yet. Prechecks:
- enforce is on
- `doctor` is clean
- TOTP is enrolled and notifications are configured
- root has a password, changed within the last day (`passwd -S`), which proves the key holder set it at the ceremony

Steps, each recording an inverse:

1. Render `templates/sudoers.in` to a temp file, run `visudo -cf`, and install it 0440: `user ALL=(root) NOPASSWD: /usr/local/bin/guardctl, /usr/local/bin/guard-pkg`.
2. Install a polkit rule granting only `org.freedesktop.NetworkManager.settings.modify.system`, so the user can join wifi. This is safe because the redirect is per-UID on output, so no NetworkManager setting (DNS, routes, VPN) can route around it.
3. Set `editor no` in systemd-boot's `loader.conf`. It is written without `chmod`, because the ESP is FAT.
4. Disable rootful Docker (the `docker` group is root-equivalent). Containers move to rootless Podman, whose traffic is owned by the user and filtered normally.
5. `gpasswd -d` the user from `wheel` (sudo and polkit admin) and from `docker`.
6. Verify that `sudo -l -U` lists exactly the two commands. Anything else (such as a rule outside `wheel`) aborts and rolls back instead of editing `/etc/sudoers`.
7. `chattr +a` the audit log.
8. Mark the system locked.

What actually changed is saved as a lock record, and `unlock` (a friend code) restores exactly that. `doctor` checks the lock's invariants, and the pacman hook re-applies any that drift. `guard-pkg` allows `-Syu`, `-S --needed` of validated package names and `-Rns`, with no `-U`, custom config, dbpath or hook directories. It refuses to remove lock dependencies (sudo, polkit, pam, shadow, util-linux, e2fsprogs, nftables and others) and refuses to install NetworkManager VPN plugins.

## 8. Deploy safety and the watchdog

**`install.sh --shadow`** runs these steps in order:
1. Preflight checks.
2. A sandboxed service user and directories. Setgid group directories let the proxy read root-written policy.
3. The pinned runtime and the CA.
4. The NetworkManager switch to dnsmasq, followed by a check that DNS still resolves, with an automatic switch back if it doesn't.
5. Policy compilation.
6. Starting the proxy, then waiting until both the admin endpoint and the transparent port answer.
7. Only then, the nft table, applied through `_apply_nft_guarded`:
   - arm `systemd-run --on-active=90` to delete the table
   - apply it
   - `runuser` as the filtered user and `curl` a real HTTPS page over IPv4, plus IPv6 when routed
   - accept a 2xx/3xx, or any response carrying the proxy's block header
   - disarm the timer, or revert immediately and print the `dg-reject` kernel log
8. The watchdog, timers and pacman hook.

**`dg-watchdog`** allows a 30s startup grace. It then polls every 10s, requiring both the token-authenticated health endpoint (which also checks the policy hash) and a TCP connect to the transparent listener. It restarts the proxy with a 60s backoff. After 5 minutes unhealthy it degrades: the nft table is re-rendered without the redirect, the DNS sinkhole is armed, and the friend is notified. It restores after 2 minutes healthy.
