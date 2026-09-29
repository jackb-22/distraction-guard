#!/usr/bin/env bash
# Reverts everything install.sh did. Usage: sudo bash uninstall.sh
#
# Only works pre-lock (or as real root post-lock -- guardctl itself refuses
# `emergency-off` without a friend code once locked, and this script relies
# on plain sudo, which won't exist for jack anymore after locking anyway).
set -Eeuo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run this with sudo: sudo bash uninstall.sh" >&2
  exit 1
fi

step() { echo; echo "==> $*"; }

step "Stopping and disabling all Distraction Guard units"
for u in distraction-guard-watchdog.service distraction-guard.service \
         distraction-guard-nft.service distraction-guard-refresh.timer \
         distraction-guard-notify.timer distraction-guard-refresh.service \
         distraction-guard-notify.service; do
  systemctl disable --now "$u" 2>/dev/null || true
done
rm -f /etc/systemd/system/distraction-guard*.service /etc/systemd/system/distraction-guard*.timer
systemctl daemon-reload

step "Removing the nftables table"
nft delete table inet distraction_guard 2>/dev/null || true

step "Removing NetworkManager DNS override and dnsmasq config"
rm -f /etc/NetworkManager/conf.d/50-distraction-guard.conf
rm -f /etc/NetworkManager/dnsmasq.d/distraction-guard.conf
rm -f /etc/NetworkManager/dnsmasq.d/distraction-guard-sinkhole.conf
rm -f /etc/NetworkManager/dnsmasq.d/distraction-guard-sinkhole.conf.off
nmcli general reload dns-full 2>/dev/null || systemctl restart NetworkManager

step "Restoring your original Firefox policy"
if [[ -f /etc/distraction-guard/firefox-policies.orig.json ]]; then
  PYTHONPATH=/usr/local/lib/distraction-guard python3 -c '
from guardctl.firefox import restore_original
restore_original("/etc/distraction-guard/firefox-policies.orig.json", "/etc/firefox/policies/policies.json")
' && echo "  restored" || echo "  (could not restore -- remove the Certificates/WebsiteFilter/DNSOverHTTPS/Proxy/Preferences keys from /etc/firefox/policies/policies.json by hand)"
else
  echo "  (no backup found -- remove the Certificates/WebsiteFilter/DNSOverHTTPS/Proxy/Preferences keys from /etc/firefox/policies/policies.json by hand)"
fi

step "Removing the trusted CA"
CA_CERT=/etc/distraction-guard/ca.pem
if [[ -f "$CA_CERT" ]]; then
  trust anchor --remove "$CA_CERT" 2>/dev/null || echo "  (could not auto-remove -- check: trust list | grep -i 'distraction guard')"
fi

step "Removing the pacman hook"
rm -f /etc/pacman.d/hooks/zz-distraction-guard.hook

step "Removing NODE_USE_SYSTEM_CA/UV_NATIVE_TLS from /etc/environment"
sed -i -e '/^NODE_USE_SYSTEM_CA=1$/d' -e '/^UV_NATIVE_TLS=1$/d' /etc/environment 2>/dev/null || true

step "Removing code and runtime"
rm -rf /usr/local/lib/distraction-guard
rm -f /usr/local/bin/guardctl /usr/local/bin/guard-pkg /usr/local/bin/dg-watchdog
rm -rf /opt/distraction-guard
rm -rf /var/lib/distraction-guard /var/log/distraction-guard /run/distraction-guard

if [[ -d /etc/distraction-guard ]]; then
  echo
  read -r -p "Remove /etc/distraction-guard too? It contains your private terms and any custom rules. [y/N] " ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    rm -rf /etc/distraction-guard
  else
    echo "  left in place at /etc/distraction-guard"
  fi
fi

step "Removing the distraction-guard user"
userdel "distraction-guard" 2>/dev/null || true

echo
echo "==> Reverted. Restart Firefox for the CA/policy change to take effect."
