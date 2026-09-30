# Engineering log

Every entry below was found in live use on the author's machine, traced to a root cause, fixed, and then pinned by a regression test. Most of the interesting failures sat at the boundary between components: kernel and proxy, proxy and protocol, tool and filesystem. Unit tests on either side of those boundaries passed. That's why the end-to-end suites run the real proxy against real nftables rules inside network namespaces.

---

### The redirect was rejected by its own firewall
**Symptom:** every install cut the machine off the internet, and the health checks all passed.
**Root cause:** in the netfilter output path, the NAT chain (priority `dstnat`) rewrites the destination to `127.0.0.1:8080` before the filter chain runs. The filter chain sees the post-NAT destination port (8080), but the *pre-NAT* output interface (`wlo1`), so neither `oif "lo" accept` nor the `dport {80,443}` jump matched. Kernel log: `dg-reject OUT=wlo1 DST=127.0.0.1 DPT=8080`.
**Fix:** `ct status dnat accept`.
**Test:** loads the rendered table into an `unshare -rn` namespace with a dummy default route and a stub listener that reads `SO_ORIGINAL_DST` (`getsockopt(SOL_IP, 80)`, and `IP6T_SO_ORIGINAL_DST` for IPv6). It asserts that the IPv4 and IPv6 connections arrive with the right original destination, and that non-web ports are still rejected.

### Health checks that couldn't detect the failure
**Root cause:** the proxy's health check ran over its admin listener, a different listener from the one nftables redirects to. Installs also trusted that check alone.
**Fix:**
- Health now requires both the token-authenticated admin endpoint (which also checks the policy hash) and a TCP connect to the transparent port.
- Deploys are guarded like `netplan try`: a `systemd-run` timer deletes the table after 90s unless a real HTTPS fetch, made as the filtered user through the redirect, succeeds first.

### The DNS the rules forgot
**Root cause:** the per-user filter chain had no DNS rule, so connections that were already established survived while every new lookup failed.
**Fix:** unconditional DNS to any resolver. Scoping it to RFC 1918 ranges would break networks that use public resolvers. Allowing DNS doesn't bypass anything, because enforcement happens on the SNI and the Host header.

### Decrypted traffic relayed as raw bytes: no inspection, and broken SSO
**Symptom:** Columbia's CAS login failed only over HTTP/2, and the decision log stayed empty.
**Root cause:** mitmproxy runs script addons *before* its built-in `NextLayer`, so the addon's `next_layer` hook also fired for the stream inside TLS. There, the first bytes are `GET` or the HTTP/2 connection preface rather than a TLS record (`0x16`), so the hook installed a raw `TCPLayer`. Every HTTPS connection was relayed byte-for-byte, uninspected, and an HTTP/2 client talking to an HTTP/1.1-only Apache received `400 Bad Request` in reply to the h2 preface.
**Fix:** only judge the outermost layer; once a `ClientTLSLayer` is on the stack, the built-in picks the protocol from the negotiated ALPN. The raw-tunnel kill moved to `server_connect`, because `TCPLayer.start()` ignores `flow.kill()` from `tcp_start`.
**Test:** the real mitmdump runs in transparent mode inside a namespace, against an HTTP/1.1-only TLS origin. It checks that HTTP/2 to that origin works, that a page with a term is blocked (or logged, in shadow mode), and that plaintext on 443 never reaches the origin.

### HTTP/2 pages that never finished loading
**Symptom:** Canvas sat forever on "Waiting for du11hjcvx0uqb.cloudfront.net".
**Root cause:** the addon re-pinned every upstream address from hostname to resolved IP. mitmproxy reuses an HTTP/2 connection only while `connection_spec_matches`, so every multiplexed stream opened a new upstream connection. Those are capped by a per-destination `asyncio.Semaphore(5)` held for the connection's lifetime. The debug log showed 60 streams, 20 connections opened, and 5 ever established.
**Fix:** re-pin only when the upstream address is still the client's raw original-destination IP. HTTP flows already connect by the classified hostname.
**Test:** 60 parallel HTTP/2 streams through transparent mode to an `h2`-based HTTP/2-only origin, with the production options. It failed with 10 to 46 of the 60 stalled before the fix.

### IPv6 networks: every connection killed
**Symptom:** everything worked on campus (IPv4-only) and nothing loaded at home.
**Root cause:** `Client connection from 2603:…:66bb killed by block_global option`. Browsers prefer IPv6. The redirect preserves the source address, which on IPv6 is the laptop's own *global* address, and mitmproxy's open-relay protection kills clients with global addresses. The watchdog didn't notice, because it checked over IPv4.
**Fix:** `block_global=false`. The listeners are loopback-only, and inbound traffic to the guard ports is dropped.
**Test:** a namespace with a global IPv6 address and a default route. The `--set` options are parsed from the real systemd unit, so a production-only option can't slip past the suite.

### A disabled blocklist that was always enabled
**Root cause:** the degraded-mode DNS sinkhole (about 90k domains) was staged as `dnsmasq.d/…-sinkhole.conf.off`. NetworkManager starts dnsmasq with `--conf-dir`, which loads every file regardless of suffix. As a result, shadow mode really blocked sites, and those lookups never reached the proxy to be logged.
**Fix:** stage it outside the conf-dir, and copy it in only while degraded.

### Service workers walking through class mode
**Symptom:** the log showed `block C-class` for YouTube, and YouTube kept working anyway.
**Root cause:** the gate only judged top-level documents. PWAs serve their shell from a service-worker cache, so only their API and media calls reach the network.
**Fix:** judge every browser request by its initiator (`Origin` › `Referer` › same-site host). Embedded frames and LTI launches from allowed pages get a time-bounded trust grant.

### A shared IP exempted the wrong service
**Root cause:** to keep a terminal AI assistant alive during proxy outages, its API host was exempted from redirection by resolved IP. `claude.ai` resolves to the same address, so browser traffic to it bypassed the proxy completely.
**Fix:** the default IP-level exemptions were removed, and a `never_decrypt` list matched on SNI replaced them.

### New terms silently never enforced
**Root cause:** `write_terms` ended with `chmod(dir, 0o750)`, which clears setgid. Every later replacement file took root's group instead of `distraction-guard`, the proxy got `EACCES` on reload, and it kept its last-good policy without saying so.
**Fix:** proxy-read files are written with an explicit group and 0640, and directory modes are never touched. `doctor` now compares the policy hash the running proxy reports with the compiled hash.

### The lock would have bricked the CLI
**Root cause:** the audit logger `chmod`ed the log on every write, and `chmod` returns `EPERM` on a `chattr +a` file. Locking would therefore have made every later command crash.
**Fix:** open with `O_APPEND` and set the mode only at creation. Also, an unreadable lock flag now reads as *locked* (fail closed).

### A code prompt that couldn't accept codes
**Root cause:** `getpass(stream=open("/dev/tty"))` opened the terminal read-only, and writing the prompt raised `UnsupportedOperation: not writable`. Tests always injected the code reader, so this path was never exercised. It was found during the lock ceremony.
**Fix:** let `getpass` open `/dev/tty` itself. Verified on a real pty.

### Video calls with no audio or video
**Root cause:** Google Meet's media runs over UDP 3478 and 19302-19309, with TCP 19305 and TURN-over-TLS on 443 as fallbacks. All of it hit the per-user catch-all reject.
**Fix:** allow those ports, and skip the redirect, *only* toward Google's published Meet relay ranges. Opening the ports to any address would create a tunnel.
**Test:** a namespace probe using connect timing (an allowed connection times out, a rejected one fails immediately) confirms that Meet ranges are allowed and not proxied, while the same ports elsewhere stay rejected.

### Smaller ones
- **Scan kind overwritten.** A generic scan-kind assignment overwrote YouTube's, so player JSON (family-safe flags, video titles) was never scanned. It now uses `setdefault`.
- **Buffering for nothing.** Every JSON response was buffered for a scan that never ran, which stalled API-heavy apps. Buffering now follows each scan kind's actual content type.
- **Blocklist reloads froze the proxy.** Reloading about 1.5M domains took about 6s on every policy change. It now uses an ASCII fast path plus an `(mtime, size)`-keyed cache.
- **Shadow mode blocked for real.** Blocked hosts were killed at connect time even in shadow mode, and never logged.
- **The watchdog restarted the proxy mid-boot.** It checked 0.03s after start. There is now a 30s startup grace.
- **Contaminated Firefox backup.** An uninstall that never restored Firefox's policy meant the next install backed up a modified policy as the "original". Guard-owned keys are now stripped from the backup.
- **Notifications stuck behind a backlog.** A new notification queued behind old ones while ntfy's rate limit rejected sends. The queue is now capped, stops at the first failure, and records the last HTTP status.
