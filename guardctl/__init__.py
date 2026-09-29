"""guardctl: the root-side ratchet controller (policy compiler, TOTP auth,
firewall/DNS/Firefox config generation). Unlike dg_policy, this package may
depend on the system only (stdlib + subprocess calls to nft/dnsmasq/etc),
never on mitmproxy.
"""
