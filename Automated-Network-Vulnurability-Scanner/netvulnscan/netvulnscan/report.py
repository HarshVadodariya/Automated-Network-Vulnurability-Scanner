from __future__ import annotations

import csv
import json

from .models import SEVERITY_ORDER, ScanReport


def write_json(report: ScanReport, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report.to_dict(), fh, indent=2)


def write_csv(report: ScanReport, path: str) -> None:
    cols = ["host", "hostname", "port", "protocol", "service", "product", "version", "cve_id", "cvss", "severity",
            "cvss_version", "kev", "confidence", "published", "url", "description"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for h in report.hosts:
            for p in h.ports:
                base = [h.address, h.hostname, p.port, p.protocol, p.service, p.product, p.version]
                if not p.vulns:
                    w.writerow(base + [""] * 9)
                for v in p.vulns:
                    w.writerow(base + [v.cve_id, v.score if v.score is not None else "", v.severity, v.cvss_version,
                                       "yes" if v.kev else "", v.confidence, v.published, v.url, v.description])


def print_console(report: ScanReport, out=print) -> None:
    out(f"\nScan: {', '.join(report.targets) or '(imported XML)'}  |  nmap {report.nmap_version}")
    for h in report.hosts:
        title = f"{h.address}" + (f" ({h.hostname})" if h.hostname else "") + (f"  [{h.os_guess}]" if h.os_guess else "")
        out(f"\n{title}")
        if not h.ports:
            out("  no open ports found in the scanned range")
        for p in h.ports:
            top = p.vulns[0].severity if p.vulns else "-"
            out(f"  {p.port:>5}/{p.protocol:<4} {p.service:<12} {p.banner or '(version not detected)':<38} "
                f"CVEs: {len(p.vulns):<4} worst: {top}")
            for v in p.vulns[:5]:
                score = f"{v.score:.1f}" if v.score is not None else " n/a"
                out(f"          {v.cve_id:<16} {score:>4} {v.severity:<9}{' KEV' if v.kev else ''}")
            if len(p.vulns) > 5:
                out(f"          ... +{len(p.vulns) - 5} more (see JSON/CSV/PDF)")
            for n in p.notes:
                out(f"          note: {n}")
    c = report.severity_counts()
    out("\nUnique CVEs by severity: " + "  ".join(f"{s}: {c[s]}" for s in SEVERITY_ORDER))
