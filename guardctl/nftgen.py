"""Renders templates/guard.nft.in into the compiled nftables ruleset for
"normal" (redirect through the proxy) or "degraded" (direct, fail-open web
with DNS sinkhole doing the blocking instead) mode.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_TEMPLATE = Path(__file__).resolve().parent.parent / "templates" / "guard.nft.in"


class NftRenderError(Exception):
    pass


@dataclass
class NftConfig:
    guard_uid: int = 1000
    ssh_allow_ipv4: list[str] = field(default_factory=list)
    ssh_allow_ipv6: list[str] = field(default_factory=list)
    # Hosts exempted from the redirect at the network level, even when the
    # proxy is completely down -- not "passthrough" (proxy stays in the
    # loop, just skips TLS decryption). Populated from resolving
    # policy.toml's critical_direct hostnames (e.g. Anthropic's API), so a
    # dead proxy can't take a terminal AI assistant down along with it.
    critical_direct_ipv4: list[str] = field(default_factory=list)
    critical_direct_ipv6: list[str] = field(default_factory=list)
    lan_tcp_ports: list[int] = field(default_factory=list)
    guard_ports: list[int] = field(default_factory=lambda: [8080, 8081])
    mode: str = "normal"  # "normal" | "degraded"
    proxy_port: int = 8080


def _elements_block(values: list[str], indent: str = "    ") -> str:
    if not values:
        return ""
    return f"{indent}elements = {{ {', '.join(values)} }}"


def _validate_ips(values: list[str], version: int) -> list[str]:
    out = []
    for v in values:
        ip = ipaddress.ip_address(v) if "/" not in v else ipaddress.ip_network(v, strict=False)
        if ip.version != version:
            raise NftRenderError(f"expected IPv{version}, got {v}")
        out.append(str(ip))
    return out


def render(cfg: NftConfig, *, template_path: Path = DEFAULT_TEMPLATE) -> str:
    if cfg.mode not in ("normal", "degraded"):
        raise NftRenderError(f"unknown mode: {cfg.mode}")
    if not (1 <= cfg.guard_uid <= 2**32 - 1):
        raise NftRenderError(f"bad uid: {cfg.guard_uid}")

    ssh4 = _validate_ips(cfg.ssh_allow_ipv4, 4)
    ssh6 = _validate_ips(cfg.ssh_allow_ipv6, 6)
    critical4 = _validate_ips(cfg.critical_direct_ipv4, 4)
    critical6 = _validate_ips(cfg.critical_direct_ipv6, 6)
    for p in cfg.lan_tcp_ports + cfg.guard_ports:
        if not (1 <= p <= 65535):
            raise NftRenderError(f"bad port: {p}")

    if cfg.mode == "normal":
        web_nat = f"    tcp dport {{ 80, 443 }} redirect to :{cfg.proxy_port}"
        web_filter = ""
    else:
        web_nat = ""
        web_filter = "    accept"

    lan_ports = _elements_block([str(p) for p in cfg.lan_tcp_ports])

    substitutions = {
        "@@GUARD_UID@@": str(cfg.guard_uid),
        "@@CRITICAL_DIRECT4_ELEMENTS@@": _elements_block(critical4),
        "@@CRITICAL_DIRECT6_ELEMENTS@@": _elements_block(critical6),
        "@@SSH_ALLOW4_ELEMENTS@@": _elements_block(ssh4),
        "@@SSH_ALLOW6_ELEMENTS@@": _elements_block(ssh6),
        "@@LAN_TCP_PORTS_ELEMENTS@@": lan_ports,
        "@@WEB_NAT_RULES@@": web_nat,
        "@@WEB_FILTER_RULES@@": web_filter,
        "@@GUARD_PORTS@@": ", ".join(str(p) for p in cfg.guard_ports),
    }

    text = template_path.read_text()
    for placeholder, value in substitutions.items():
        text = text.replace(placeholder, value)

    remaining = re.findall(r"@@[A-Z0-9_]+@@", text)
    if remaining:
        raise NftRenderError(f"unfilled placeholders: {remaining}")

    # Collapse blank lines left by empty substitutions so the output stays
    # readable in `nft list ruleset` / audit review.
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text
