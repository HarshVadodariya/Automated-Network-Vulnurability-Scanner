#!/usr/bin/env python3
"""Automated network vulnerability scanner: nmap -> CPE -> NVD CVEs -> reports.

Examples
  python cli.py 192.168.1.0/24 --i-am-authorized --pdf report.pdf --json report.json
  python cli.py scanme.lab.local -p 1-1024 --nvd-key $KEY --min-severity high --i-am-authorized
  nmap -sV -oX scan.xml 10.0.0.5 && python cli.py --from-xml scan.xml --pdf report.pdf
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

from netvulnscan.cpe import cpe22_to_cpe23
from netvulnscan.matcher import map_vulnerabilities
from netvulnscan.models import SEVERITY_ORDER
from netvulnscan.nmap_runner import NmapError, build_args, parse_nmap_xml, run_nmap
from netvulnscan.nvd import NVDClient
from netvulnscan.pdf_report import build_pdf
from netvulnscan.report import print_console, write_csv, write_json
from netvulnscan.targets import TargetError, validate_ports, validate_targets


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="*", help="IP, CIDR, a.b.c.d-e range or hostname")
    ap.add_argument("--i-am-authorized", action="store_true", help="confirm you have permission to scan the targets")
    ap.add_argument("--allow-public", action="store_true", help="allow public IP targets (written authorization required)")
    ap.add_argument("--max-hosts", type=int, default=256)
    ap.add_argument("-p", "--ports", help="e.g. 22,80,443 or 1-1024 (default: nmap top ports)")
    ap.add_argument("--top-ports", type=int, default=1000)
    ap.add_argument("--timing", type=int, choices=range(0, 6), default=3, help="nmap -T level (default 3)")
    ap.add_argument("--intensity", type=int, choices=range(0, 10), default=7, help="nmap --version-intensity")
    ap.add_argument("--no-ping", action="store_true", help="skip host discovery (-Pn)")
    ap.add_argument("--from-xml", metavar="FILE", help="analyse an existing nmap -oX file instead of scanning")
    ap.add_argument("--no-cve", action="store_true", help="skip NVD lookups (ports/services only)")
    ap.add_argument("--nvd-key", help="NVD API key (or set NVD_API_KEY); raises rate limit 5 -> 50 requests/30s")
    ap.add_argument("--keyword-fallback", action="store_true",
                    help="when nmap gives no CPE, search NVD by 'product version' (noisy, flagged low confidence)")
    ap.add_argument("--min-severity", choices=["critical", "high", "medium", "low"], help="hide CVEs below this severity")
    ap.add_argument("--cache-dir", default=".nvd_cache")
    ap.add_argument("--json"), ap.add_argument("--csv"), ap.add_argument("--pdf")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    a = parse_args(argv)
    log = lambda m: print(m, file=sys.stderr)  # noqa: E731
    try:
        if a.from_xml:
            with open(a.from_xml, encoding="utf-8") as fh:
                report = parse_nmap_xml(fh.read(), a.targets)
        else:
            if not a.i_am_authorized:
                log("Refusing to scan: pass --i-am-authorized to confirm you have permission to test these targets.")
                return 2
            targets = validate_targets(a.targets, a.max_hosts, a.allow_public)
            ports = validate_ports(a.ports) if a.ports else None
            if not 1 <= a.top_ports <= 65535:
                raise TargetError("--top-ports must be 1-65535")
            args = build_args(targets, ports, a.top_ports, a.timing, a.intensity, a.no_ping)
            log("Running: " + " ".join(args))
            report = parse_nmap_xml(run_nmap(args), targets)
    except (TargetError, NmapError, OSError) as exc:
        log(f"Error: {exc}")
        return 1

    if a.no_cve:
        report.cve_lookup = "skipped"
    else:
        nvd = NVDClient(api_key=a.nvd_key, cache_dir=a.cache_dir)
        cpes = {cpe22_to_cpe23(c) for h in report.hosts for p in h.ports for c in p.cpes} - {None}
        eta = int(len(cpes) * nvd.min_interval)
        log(f"Looking up {len(cpes)} unique service CPE(s) in NVD (~{eta}s uncached"
            + ("" if nvd.api_key else "; use --nvd-key to go ~9x faster") + ")")
        map_vulnerabilities(report, nvd, a.keyword_fallback, a.min_severity.title() if a.min_severity else None,
                            progress=lambda m: log(f"  {m}"))
    report.finished = report.finished or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    print_console(report)
    if a.json:
        write_json(report, a.json); log(f"JSON: {a.json}")
    if a.csv:
        write_csv(report, a.csv); log(f"CSV:  {a.csv}")
    if a.pdf:
        build_pdf(report, a.pdf); log(f"PDF:  {a.pdf}")
    c = report.severity_counts()
    return 3 if (c["Critical"] or c["High"]) else 0  # non-zero exit lets CI fail on serious findings


if __name__ == "__main__":
    sys.exit(main())
