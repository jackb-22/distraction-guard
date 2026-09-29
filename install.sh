#!/usr/bin/env bash
# Distraction Guard v2 installer. Usage: sudo bash install.sh --shadow
#
# Phased on purpose:
#   --shadow  : install everything, but the proxy only LOGS what it would
#               block (enforce=false in policy.toml). Nothing blocks yet.
#               This is the only phase this script performs.
#   Afterwards, once you've verified real browsing still works and false
#   positives are tuned out (see the checklist this script prints at the
#   end), turn enforcement on yourself with:  sudo guardctl set enforce true
#   Locking (removing your own sudo) is `guardctl lock`, done separately
#   with your friend present -- this script never touches sudoers/wheel.
#
# Ordering matters and mirrors the actual bug that broke v1: nftables must
# NEVER redirect traffic to a proxy port before something is actually
# listening and healthy there. So: install the proxy, start it, WAIT for
# its health endpoint, and only THEN load the nftables table. If the proxy
# never becomes healthy, this script aborts before nftables ever touches
# your traffic.
set -Eeuo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR=/usr/local/lib/distraction-guard
BIN_DIR=/usr/local/bin
ETC_DIR=/etc/distraction-guard
VAR_LIB=/var/lib/distraction-guard
VAR_LOG=/var/log/distraction-guard
SVC_USER=distraction-guard
REAL_USER="${SUDO_USER:-jack}"
GUARD_UID="$(id -u "$REAL_USER" 2>/dev/null || echo 1000)"
HEALTH_TIMEOUT=20

step() { echo; echo "==> $*"; }
die() { echo "FATAL: $*" >&2; exit 1; }

trap 'echo; echo "==> Install failed at line $LINENO. Nothing further was applied."; echo "    Re-run is safe (steps are idempotent). See uninstall.sh to revert what did apply."' ERR

if [[ "${1:-}" != "--shadow" ]]; then
  die "usage: sudo bash install.sh --shadow"
fi
if [[ $EUID -ne 0 ]]; then
  die "run with sudo: sudo bash install.sh --shadow"
fi

step "Preflight checks"
command -v systemctl >/dev/null || die "systemd not found"
command -v nft >/dev/null || die "nftables not found (pacman -S nftables)"
command -v uv >/dev/null || die "uv not found (pacman -S uv)"
command -v dnsmasq >/dev/null || die "dnsmasq not found (pacman -S dnsmasq)"
command -v qrencode >/dev/null || die "qrencode not found (pacman -S qrencode)"
command -v openssl >/dev/null || die "openssl not found"
[[ "$GUARD_UID" == "1000" ]] || echo "WARNING: $REAL_USER's uid is $GUARD_UID, not 1000 -- the shipped nft template assumes 1000; edit templates/guard.nft.in's meta skuid if this is wrong for you."
if nft list tables 2>/dev/null | grep -q distraction_guard; then
  echo "  (an nft table from a previous install is already present -- re-install will replace it)"
fi
systemctl is-active --quiet NetworkManager || die "NetworkManager is not active"

step "Creating $SVC_USER system user"
if ! id "$SVC_USER" &>/dev/null; then
  useradd --system --home-dir "$VAR_LIB/mitm" --no-create-home --shell /usr/bin/nologin "$SVC_USER"
else
  echo "already exists, skipping"
fi

step "Creating directories"
install -d -o root -g root -m 755 "$LIB_DIR"
install -d -o root -g root -m 755 "$LIB_DIR/dg_policy" "$LIB_DIR/addon" "$LIB_DIR/guardctl" "$LIB_DIR/templates"
install -d -o root -g "$SVC_USER" -m 750 "$LIB_DIR/lexicon"
install -d -o root -g root -m 755 "$ETC_DIR"
install -d -o root -g "$SVC_USER" -m 750 "$ETC_DIR/rules.d" "$ETC_DIR/local"
install -d -o root -g "$SVC_USER" -m 750 "$ETC_DIR/private"
install -d -o "$SVC_USER" -g "$SVC_USER" -m 700 "$VAR_LIB/mitm"
install -d -o root -g "$SVC_USER" -m 750 "$VAR_LIB/lists" "$VAR_LIB/compiled"
install -d -o root -g root -m 700 "$VAR_LIB/state"
install -d -o "$SVC_USER" -g "$SVC_USER" -m 750 "$VAR_LOG/proxy"
# root:distraction-guard, not root:root: the proxy must be able to traverse
# this to reach proxy/. With root:root 750 every decision-log write failed
# with EACCES (silently -- see DecisionLog), so nothing was ever logged.
install -d -o root -g "$SVC_USER" -m 750 "$VAR_LOG"
# setgid: root-owned code (guardctl compile/_refresh) writes into these
# directories, and the proxy (running as distraction-guard:distraction-guard)
# needs group-read on what lands there. Without setgid, a file root creates
# takes root's primary group (root), not the directory's group, and the
# proxy would silently lose read access to its own compiled policy --
# found by tracing through this exact chain before it ever ran for real.
chmod g+s "$ETC_DIR/rules.d" "$ETC_DIR/local" "$ETC_DIR/private" "$VAR_LIB/lists" "$VAR_LIB/compiled"

step "Installing code to $LIB_DIR"
cp -a "$SRC_DIR/dg_policy/." "$LIB_DIR/dg_policy/"
cp -a "$SRC_DIR/addon/." "$LIB_DIR/addon/"
cp -a "$SRC_DIR/guardctl/." "$LIB_DIR/guardctl/"
cp -a "$SRC_DIR/templates/." "$LIB_DIR/templates/"
# The context lexicon and any extra rules.d files are personal, so they live
# in the git-ignored private/ folder, not the repo. Without a lexicon,
# contextual terms still work in image/video searches and on pages that
# label themselves adult; they just can't use context words.
if [[ -f "$SRC_DIR/private/lexicon/context.txt" ]]; then
  install -o root -g "$SVC_USER" -m 640 "$SRC_DIR/private/lexicon/context.txt" "$LIB_DIR/lexicon/context.txt"
else
  [[ -f "$LIB_DIR/lexicon/context.txt" ]] || install -o root -g "$SVC_USER" -m 640 /dev/null "$LIB_DIR/lexicon/context.txt"
fi
# cp -a picks up dev-tree __pycache__/.pytest_cache clutter too; drop it so
# the install is a clean copy of source, not a mix of source + stale bytecode.
find "$LIB_DIR/dg_policy" "$LIB_DIR/addon" "$LIB_DIR/guardctl" "$LIB_DIR/templates" \( -name '__pycache__' -o -name '.pytest_cache' \) -exec rm -rf {} +
chown -R root:root "$LIB_DIR/dg_policy" "$LIB_DIR/addon" "$LIB_DIR/guardctl" "$LIB_DIR/templates"
find "$LIB_DIR/dg_policy" "$LIB_DIR/addon" "$LIB_DIR/guardctl" "$LIB_DIR/templates" -type f -exec chmod 644 {} \;
find "$LIB_DIR/dg_policy" "$LIB_DIR/addon" "$LIB_DIR/guardctl" "$LIB_DIR/templates" -type d -exec chmod 755 {} \;

install -o root -g root -m 755 "$SRC_DIR/bin/guardctl" "$BIN_DIR/guardctl"
install -o root -g root -m 755 "$SRC_DIR/bin/guard-pkg" "$BIN_DIR/guard-pkg"
install -o root -g root -m 755 "$SRC_DIR/bin/dg-watchdog" "$BIN_DIR/dg-watchdog"

step "Seeding $ETC_DIR (only files not already present are touched)"
[[ -f "$ETC_DIR/policy.toml" ]] || install -o root -g root -m 644 "$SRC_DIR/etc/policy.toml" "$ETC_DIR/policy.toml"
if [[ -f "$ETC_DIR/lists.toml" ]]; then
  # Merge in lists added since this machine's copy was seeded -- adding a
  # block list only tightens. Existing entries (including ones disabled or
  # edited here) are never touched.
  python3 - "$SRC_DIR/etc/lists.toml" "$ETC_DIR/lists.toml" <<'PY'
import sys, tomllib
src, dst = sys.argv[1], sys.argv[2]
have = {e.get("name") for e in tomllib.load(open(dst, "rb")).get("list", [])}
blocks = open(src).read().split("[[list]]")
added = []
for block in blocks[1:]:
    entry = tomllib.loads(block)
    if entry.get("name") not in have:
        added.append(entry["name"])
        with open(dst, "a") as f:
            f.write("\n[[list]]" + block.split("\n\n#")[0].rstrip() + "\n")
tomllib.load(open(dst, "rb"))  # still valid TOML
print("  added lists: " + (", ".join(added) if added else "none"))
PY
else
  install -o root -g root -m 644 "$SRC_DIR/etc/lists.toml" "$ETC_DIR/lists.toml"
fi
for f in "$SRC_DIR"/etc/rules.d/*.toml "$SRC_DIR"/private/rules.d/*.toml; do
  [[ -f "$f" ]] || continue
  name="$(basename "$f")"
  [[ -f "$ETC_DIR/rules.d/$name" ]] || install -o root -g "$SVC_USER" -m 640 "$f" "$ETC_DIR/rules.d/$name"
done
[[ -f "$ETC_DIR/private/terms.json" ]] || echo "[]" > "$ETC_DIR/private/terms.json"
# Always (re)assert ownership: an earlier add-term bug cleared private/'s
# setgid and left terms.json group root, unreadable to the proxy.
chown root:"$SVC_USER" "$ETC_DIR/private/terms.json" "$ETC_DIR/private"/*.json "$ETC_DIR/local"/*.json 2>/dev/null || true
chmod 640 "$ETC_DIR/private/terms.json"
install -o root -g root -m 644 "$SRC_DIR/addon/block_page.html" "$ETC_DIR/block_page.html"

step "Health check secret"
if [[ ! -f "$ETC_DIR/private/health.token" ]]; then
  head -c 32 /dev/urandom | base64 > "$ETC_DIR/private/health.token"
  chown root:"$SVC_USER" "$ETC_DIR/private/health.token"
  chmod 640 "$ETC_DIR/private/health.token"
fi

step "Building the pinned mitmproxy runtime (this takes a minute)"
if [[ ! -x /opt/distraction-guard/venv/bin/mitmdump ]]; then
  UV_PYTHON_INSTALL_DIR=/opt/distraction-guard/python \
    uv venv --python 3.13 /opt/distraction-guard/venv-12.2.3
  uv pip install --python /opt/distraction-guard/venv-12.2.3/bin/python 'mitmproxy==12.2.3'
  ln -sfn venv-12.2.3 /opt/distraction-guard/venv
  chown -R root:root /opt/distraction-guard
  chmod -R go-w /opt/distraction-guard
else
  echo "already built, skipping"
fi

step "Generating the local CA (private key never leaves $VAR_LIB/mitm, 0600 $SVC_USER)"
if [[ ! -f "$VAR_LIB/mitm/mitmproxy-ca.pem" ]]; then
  TMP_KEY="$(mktemp)"
  TMP_CERT="$(mktemp)"
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$TMP_KEY" -out "$TMP_CERT" \
    -subj "/CN=Distraction Guard Local CA" \
    -addext basicConstraints=critical,CA:TRUE \
    -addext keyUsage=critical,keyCertSign,cRLSign
  cat "$TMP_KEY" "$TMP_CERT" > "$VAR_LIB/mitm/mitmproxy-ca.pem"
  cp "$TMP_CERT" "$VAR_LIB/mitm/mitmproxy-ca-cert.pem"
  cp "$TMP_CERT" "$ETC_DIR/ca.pem"
  shred -u "$TMP_KEY"; rm -f "$TMP_CERT"
  chown "$SVC_USER:$SVC_USER" "$VAR_LIB/mitm/mitmproxy-ca.pem" "$VAR_LIB/mitm/mitmproxy-ca-cert.pem"
  chmod 600 "$VAR_LIB/mitm/mitmproxy-ca.pem"
  chmod 644 "$VAR_LIB/mitm/mitmproxy-ca-cert.pem" "$ETC_DIR/ca.pem"
else
  echo "already generated, skipping"
fi

step "Trusting the CA system-wide (Firefox/Chromium/curl/git/node via p11-kit)"
trust anchor --store "$ETC_DIR/ca.pem"

step "System CA store for tools that ship their own (Node, uv)"
# Node-based apps (Claude Code, etc) and uv both bundle their own root
# lists and ignore p11-kit, so without these every HTTPS call they make
# fails against the proxy's certificates (seen live: uv's "invalid peer
# certificate: UnknownIssuer" on the first shadow install).
for kv in NODE_USE_SYSTEM_CA=1 UV_NATIVE_TLS=1; do
  grep -qx "$kv" /etc/environment 2>/dev/null || echo "$kv" >> /etc/environment
done

step "NetworkManager: route DNS through dnsmasq"
# Migration: earlier versions staged the degraded-mode sinkhole INSIDE
# dnsmasq.d as *.conf.off, which dnsmasq loads anyway (conf-dir ignores
# suffixes) -- it was always live. Remove it; it's staged elsewhere now.
rm -f /etc/NetworkManager/dnsmasq.d/distraction-guard-sinkhole.conf.off
install -d -m 755 /etc/NetworkManager/conf.d
cat > /etc/NetworkManager/conf.d/50-distraction-guard.conf <<'EOF'
[main]
dns=dnsmasq
EOF

step "Backing up your Firefox policy before it's ever modified"
FF_POLICY=/etc/firefox/policies/policies.json
FF_BACKUP="$ETC_DIR/firefox-policies.orig.json"
# Only if a backup doesn't already exist, so a re-run never overwrites it.
# uninstall.sh and emergency-off restore from it.
if [[ ! -f "$FF_BACKUP" ]]; then
  if [[ -f "$FF_POLICY" ]]; then
    cp "$FF_POLICY" "$FF_BACKUP"
  else
    echo '{"policies":{}}' > "$FF_BACKUP"
  fi
fi
# Always strip guard-owned keys from the backup (idempotent). Found live:
# an earlier uninstall never restored Firefox, so the next install backed up
# an already-guard-modified policy as the "original" -- restoring it would
# have kept the CA and block list in Firefox after uninstalling.
PYTHONPATH="$LIB_DIR" python3 -c '
import sys
from guardctl.firefox import strip_guard_keys
p = sys.argv[1]
clean = strip_guard_keys(open(p).read())
open(p, "w").write(clean)
' "$FF_BACKUP"
chmod 644 "$FF_BACKUP"

step "Compiling the policy and generating nft/dnsmasq/Firefox config"
# -u SUDO_USER: _refresh is an internal (systemd-only) command that refuses
# to run with SUDO_USER set, specifically so jack can't invoke it directly
# as a side door. This script runs as real root via sudo, so we drop that
# one variable for guardctl's own internal calls.
env -u SUDO_USER "$BIN_DIR/guardctl" compile
env -u SUDO_USER "$BIN_DIR/guardctl" _refresh || echo "  (list download/asset generation had issues -- check above; policy.json is still valid, continuing)"
# Class mode from calcurse + startpage bookmarks. Runs WITH SUDO_USER, so
# it reads $REAL_USER's own files. Not fatal: a calendar it can't parse
# just leaves class mode off, with the reason printed.
"$BIN_DIR/guardctl" schedule-sync || echo "  (class mode not set up -- fix the error above, then: sudo guardctl schedule-sync)"

step "Installing systemd units"
install -o root -g root -m 644 "$SRC_DIR"/systemd/*.service "$SRC_DIR"/systemd/*.timer /etc/systemd/system/
systemctl daemon-reload

step "Starting the proxy and waiting for it to become healthy"
systemctl enable distraction-guard.service
# restart, not start: on a re-run the proxy is already up with the OLD
# addon code, and a plain start would leave it running that.
systemctl restart distraction-guard.service
HEALTHY=0
TOKEN="$(cat "$ETC_DIR/private/health.token")"
# Two checks, both required: the admin endpoint (8081) confirms the addon
# and policy loaded correctly; a raw TCP connect to the TRANSPARENT port
# (8080) confirms that separate listener -- the one nftables will actually
# redirect your traffic to -- is genuinely up. These are two different
# listeners on the same mitmdump process; checking only the admin endpoint
# can report "healthy" while the transparent listener is down, which would
# let nftables get applied against a proxy that can't actually relay
# anything. (guardctl.watchdog.check_health does the same two-part check
# for the ongoing watchdog.)
port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && exec 3<&- 3>&-; }
for i in $(seq 1 "$HEALTH_TIMEOUT"); do
  # -f is load-bearing: without it, curl exits 0 on ANY response including
  # a 403 (wrong token) or 503 (no policy loaded) -- verified by hand
  # against the real addon before writing this, since a health check that
  # can't actually fail would defeat the entire point of gating nftables
  # on it.
  if curl -sf -o /dev/null -m 2 -H "Host: guard.health" -H "X-DG-Token: $TOKEN" "http://127.0.0.1:8081/" \
     && port_open 8080; then
    HEALTHY=1
    break
  fi
  sleep 1
done
if [[ "$HEALTHY" -ne 1 ]]; then
  systemctl status distraction-guard.service --no-pager || true
  journalctl -u distraction-guard --no-pager -n 40 || true
  die "proxy did not become healthy (admin endpoint or transparent port 8080) after ${HEALTH_TIMEOUT}s -- nftables was NOT applied, your internet is untouched. Fix the above and re-run."
fi
echo "  proxy is healthy."

step "Reloading NetworkManager's DNS"
# Before nftables, not after: the verified apply below then tests the
# final DNS setup too, not the one that's about to be replaced.
nmcli general reload dns-full || systemctl restart NetworkManager
DNS_OK=0
for i in $(seq 1 15); do
  if getent ahosts example.com >/dev/null; then DNS_OK=1; break; fi
  sleep 1
done
if [[ "$DNS_OK" -ne 1 ]]; then
  rm -f /etc/NetworkManager/conf.d/50-distraction-guard.conf
  nmcli general reload dns-full || systemctl restart NetworkManager
  die "DNS stopped resolving after switching NetworkManager to dnsmasq -- switched it back; nftables was NOT applied."
fi

step "Applying nftables (verified, with a 90s auto-revert)"
nft -c -f "$VAR_LIB/compiled/guard.nft"   # syntax check first
install -o root -g root -m 644 "$SRC_DIR/systemd/distraction-guard-nft.service" /etc/systemd/system/
systemctl daemon-reload
# Arms a revert timer, applies the table, fetches https://example.com as
# you (through the redirect), and only disarms the timer if that works.
# On failure it reverts immediately and prints the kernel reject log.
# Even if this script is killed mid-way, the timer removes the table.
env -u SUDO_USER "$BIN_DIR/guardctl" _apply-nft "$REAL_USER"

step "Starting the watchdog and timers"
systemctl enable --now distraction-guard-watchdog.service
systemctl enable --now distraction-guard-refresh.timer distraction-guard-notify.timer

step "Installing the pacman hook"
install -d -m 755 /etc/pacman.d/hooks
install -o root -g root -m 644 "$SRC_DIR/pacman/zz-distraction-guard.hook" /etc/pacman.d/hooks/

cat <<EOF

==> Shadow mode installed. Nothing is blocked yet (policy.toml: enforce = false).

Next steps, in order:

1. Restart Firefox (so it picks up the new trusted CA and policy), and log
   out and back in (so NODE_USE_SYSTEM_CA takes effect for apps like
   Claude Code).

2. Run the verification checklist:
     sudo guardctl doctor
     curl -sS -o /dev/null -w '%{http_code}\n' https://example.com   # expect 200
     curl -sS -o /dev/null -w '%{http_code}\n' https://www.reddit.com # expect 200 (shadow mode: page still loads)
     sudo guardctl log -n 20   # expect a would_block entry for reddit.com's rule (S-social)

3. Use the internet normally for a day or two. Watch for TLS failures
   (apps with their own trust store -- add them to policy.toml's
   passthrough list) and false positives in the log.

4. Check class mode (built from calcurse + your startpage bookmarks):
     sudo guardctl schedule
   In shadow mode it only logs C-class would_block entries. After editing
   calcurse or bookmarks.js:  sudo guardctl schedule-sync

5. Add your own terms privately (never shown, never logged):
     sudo guardctl add-term --strict
     sudo guardctl add-term --contextual
     sudo guardctl add-term --combo

6. When you're satisfied:  sudo guardctl set enforce true

7. When you're ready to lock it behind your friend's code (this is
   separate, deliberate, and done with them physically present):
     sudo guardctl notify-setup
     sudo guardctl totp-enroll
   then follow RECOVERY.md's lock ceremony.

Rollback at any point before locking: sudo bash uninstall.sh
EOF
