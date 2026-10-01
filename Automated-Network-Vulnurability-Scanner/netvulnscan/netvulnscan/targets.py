"""Target validation and scope guard.

Targets are passed to nmap as an argv list (never through a shell) and anything
that could be read as an nmap option is rejected.
"""
from __future__ import annotations

import ipaddress
import re
import socket

HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$")
RANGE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$")
PORTS_RE = re.compile(r"^\d{1,5}([,\-]\d{1,5})*$")


class TargetError(ValueError):
    pass


def _addresses_for(target: str) -> tuple[int, list[ipaddress._BaseAddress]]:
    """Return (host_count, sample addresses used for the public/private check)."""
    m = RANGE_RE.match(target)
    if m:
        prefix, lo, hi = m.group(1), int(m.group(2)), int(m.group(3))
        if not (0 <= lo <= hi <= 255):
            raise TargetError(f"Bad range: {target}")
        return hi - lo + 1, [ipaddress.ip_address(f"{prefix}.{lo}"), ipaddress.ip_address(f"{prefix}.{hi}")]
    try:
        return 1, [ipaddress.ip_address(target)]
    except ValueError:
        pass
    try:
        net = ipaddress.ip_network(target, strict=False)
        return net.num_addresses, [net.network_address, net.broadcast_address]
    except ValueError:
        pass
    if HOSTNAME_RE.match(target):
        try:
            infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            raise TargetError(f"Could not resolve host '{target}'.")
        return 1, [ipaddress.ip_address(i[4][0]) for i in infos]
    raise TargetError(f"Unrecognised target '{target}'. Use an IP, CIDR (10.0.0.0/24), a.b.c.d-e range, or hostname.")


def validate_targets(targets: list[str], max_hosts: int = 256, allow_public: bool = False) -> list[str]:
    if not targets:
        raise TargetError("No targets given.")
    total = 0
    for t in targets:
        if t.startswith("-"):
            raise TargetError(f"Target '{t}' looks like an option.")
        count, addrs = _addresses_for(t)
        total += count
        if not allow_public and any(a.is_global for a in addrs):
            raise TargetError(
                f"'{t}' is a public address. Scanning systems you do not own is illegal in most places. "
                "If you have written authorization, re-run with --allow-public.")
    if total > max_hosts:
        raise TargetError(f"{total} addresses exceeds the --max-hosts limit of {max_hosts}.")
    return targets


def validate_ports(spec: str) -> str:
    if not PORTS_RE.match(spec):
        raise TargetError("Ports must look like 22,80,443 or 1-1024.")
    for part in re.split(r"[,\-]", spec):
        if not 0 < int(part) <= 65535:
            raise TargetError(f"Port {part} out of range.")
    return spec
