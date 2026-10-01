from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from .models import HostResult, PortResult, ScanReport


class NmapError(RuntimeError):
    pass


def build_args(targets: list[str], ports: str | None, top_ports: int, timing: int,
               intensity: int, skip_discovery: bool) -> list[str]:
    args = ["nmap", "-sV", "--version-intensity", str(intensity), f"-T{timing}", "--open", "-oX", "-"]
    args += ["-p", ports] if ports else ["--top-ports", str(top_ports)]
    if skip_discovery:
        args.append("-Pn")
    # Version detection only: no NSE scripts, no exploitation, no OS fingerprinting.
    return args + ["--"] + targets


def run_nmap(args: list[str], timeout: int = 3600) -> str:
    if shutil.which(args[0]) is None:
        raise NmapError("nmap not found. Install it first (e.g. 'sudo apt install nmap' or https://nmap.org/download).")
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)  # no shell
    except subprocess.TimeoutExpired:
        raise NmapError(f"nmap exceeded the {timeout}s timeout.")
    if proc.returncode != 0:
        raise NmapError(f"nmap failed ({proc.returncode}): {proc.stderr.strip()[:300]}")
    return proc.stdout


def parse_nmap_xml(xml_text: str, targets: list[str] | None = None) -> ScanReport:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NmapError(f"Could not parse nmap XML: {exc}")
    report = ScanReport(
        targets=targets or [],
        started=datetime.fromtimestamp(int(root.get("start", "0") or 0), timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        nmap_version=root.get("version", ""),
        nmap_args=root.get("args", ""),
    )
    fin = root.find("runstats/finished")
    if fin is not None and fin.get("time"):
        report.finished = datetime.fromtimestamp(int(fin.get("time")), timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    for h in root.findall("host"):
        status = h.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addr = next((a.get("addr") for a in h.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), "")
        name_el = h.find("hostnames/hostname")
        host = HostResult(address=addr, hostname=name_el.get("name", "") if name_el is not None else "")
        os_el = h.find("os/osmatch")
        if os_el is not None:
            host.os_guess = os_el.get("name", "")
        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = p.find("service")
            pr = PortResult(port=int(p.get("portid")), protocol=p.get("protocol", "tcp"), state="open")
            if svc is not None:
                pr.service = svc.get("name", "")
                pr.product = svc.get("product", "")
                pr.version = svc.get("version", "")
                pr.extrainfo = svc.get("extrainfo", "")
                pr.cpes = [c.text.strip() for c in svc.findall("cpe") if c.text]
            host.ports.append(pr)
        host.ports.sort(key=lambda x: (x.protocol, x.port))
        report.hosts.append(host)
    return report
