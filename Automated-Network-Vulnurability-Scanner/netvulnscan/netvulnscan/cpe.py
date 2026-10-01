"""CPE helpers: convert nmap's CPE 2.2 URIs into the CPE 2.3 names NVD expects."""
from __future__ import annotations

import re
from urllib.parse import unquote

_OPENSSH_STYLE = re.compile(r"^(\d+(?:\.\d+)+)(p\d+)$", re.I)


def _escape(component: str) -> str:
    # CPE 2.3 formatted strings backslash-escape everything except [A-Za-z0-9_.-]
    return "".join(c if re.match(r"[A-Za-z0-9_.\-]", c) else "\\" + c for c in component)


def cpe22_to_cpe23(uri: str) -> str | None:
    """cpe:/a:openbsd:openssh:8.2p1 -> cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*

    Returns None for OS/hardware CPEs or CPEs without a version (they cannot be
    matched meaningfully to CVEs).
    """
    if not uri.startswith("cpe:/"):
        return None
    parts = [unquote(p) for p in uri[len("cpe:/"):].split(":")]
    if len(parts) < 4 or parts[0] != "a" or not parts[3]:
        return None
    part, vendor, product, version = parts[:4]
    rest = parts[4:8] + [""] * (4 - len(parts[4:8]))
    update = rest[0]
    # NVD records "OpenSSH 8.2p1" as version 8.2 + update p1
    m = _OPENSSH_STYLE.match(version)
    if m and not update:
        version, update = m.group(1), m.group(2).lower()
    fields = [part, vendor, product, version, update, rest[1], rest[2], "*", "*", "*", "*"]
    fields = ["*" if f in ("", "*") else _escape(f) for f in fields]
    # 11 fields after "cpe:2.3:" -> part vendor product version update edition language sw_edition target_sw target_hw other
    return "cpe:2.3:" + ":".join(fields[:11])
