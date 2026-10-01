from __future__ import annotations

import re

from .cpe import cpe22_to_cpe23
from .models import SEVERITY_RANK, HostResult, PortResult, ScanReport, Vuln
from .nvd import NVDClient, NVDError

BACKPORT_RE = re.compile(r"(ubuntu|debian|deb\d+u\d+|el\d+|\.el\d|rhel|centos|fedora|suse|alpine|raspbian)", re.I)


def _sort_key(v: Vuln):
    return (not v.kev, SEVERITY_RANK[v.severity], -(v.score or 0), v.cve_id)  # known-exploited first


def match_port(port: PortResult, nvd: NVDClient, keyword_fallback: bool, memo: dict) -> None:
    cpe23s = []
    for c in port.cpes:
        c23 = cpe22_to_cpe23(c)
        if c23 and c23 not in cpe23s:
            cpe23s.append(c23)

    found: dict[str, Vuln] = {}
    queries: list[tuple[str, str]] = [("cpe", c) for c in cpe23s]
    if not queries and keyword_fallback and port.product and port.version:
        queries = [("kw", f"{port.product} {port.version.split()[0]}")]
    if not queries:
        if port.product or port.version:
            port.notes.append("Version detected but nmap supplied no CPE to query NVD with. Try --keyword-fallback "
                              "(noisy, low confidence) or look the product up manually.")
        else:
            port.notes.append("No version fingerprint, so the service cannot be mapped to CVEs. "
                              "Re-scan with a higher --intensity or check the service manually.")
        return

    for kind, q in queries:
        if (kind, q) not in memo:  # same service on many hosts is queried once
            try:
                memo[(kind, q)] = nvd.cves_for_cpe(q) if kind == "cpe" else nvd.cves_for_keyword(q)
            except NVDError as exc:
                port.notes.append(f"NVD lookup failed for {q}: {exc}")
                memo[(kind, q)] = []
        for v in memo[(kind, q)]:
            found.setdefault(v.cve_id, v)
    port.vulns = sorted(found.values(), key=_sort_key)

    if port.vulns and BACKPORT_RE.search(f"{port.version} {port.extrainfo}"):
        port.notes.append("Distribution-packaged build: the vendor may have back-ported fixes without changing the "
                          "version string. Check the distro security tracker before treating these as confirmed.")


def map_vulnerabilities(report: ScanReport, nvd: NVDClient, keyword_fallback: bool = False,
                        min_severity: str | None = None, progress=lambda msg: None) -> None:
    memo: dict = {}
    for host in report.hosts:
        for port in host.ports:
            progress(f"{host.address}:{port.port} {port.banner or port.service}")
            match_port(port, nvd, keyword_fallback, memo)
            if min_severity:
                limit = SEVERITY_RANK[min_severity]
                port.vulns = [v for v in port.vulns if SEVERITY_RANK[v.severity] <= limit]
