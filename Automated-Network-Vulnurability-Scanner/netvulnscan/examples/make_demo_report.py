"""Builds examples/sample_report.pdf from a sample nmap XML and MOCK CVE data (no network needed).

Everything in the CVE descriptions is labelled SAMPLE DATA: this demonstrates the report layout only.
Run a real scan to get real NVD data.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, "tests")]

from test_netvulnscan import client, nvd_item, page, sample  # noqa: E402

from netvulnscan.matcher import map_vulnerabilities  # noqa: E402
from netvulnscan.pdf_report import build_pdf  # noqa: E402

TAG = "[SAMPLE DATA - not from NVD] "


def handler(p):
    cpe = p.get("cpeName", "")
    if "openssh" in cpe:
        return page([nvd_item("CVE-2023-38408", 9.8, "CRITICAL", desc=TAG + "Example critical issue in a forwarded agent component."),
                     nvd_item("CVE-2020-14145", 5.9, "MEDIUM", desc=TAG + "Example information disclosure during key exchange.")])
    if "http_server" in cpe:
        items = [nvd_item("CVE-2021-41773", 7.5, "HIGH", kev=True, desc=TAG + "Example path traversal. " * 4),
                 nvd_item("CVE-2021-42013", 9.8, "CRITICAL", kev=True, desc=TAG + "Example remote code execution.")]
        items += [nvd_item(f"CVE-2099-{1000 + i}", 4.3 + (i % 5), "MEDIUM" if i % 5 < 3 else "HIGH",
                           desc=TAG + "Filler entry to demonstrate the per-service cap.") for i in range(18)]
        return page(items)
    return page([])


report = sample(["10.0.0.5"])
c, _ = client(handler)
map_vulnerabilities(report, c)
out = os.path.join(ROOT, "examples", "sample_report.pdf")
build_pdf(report, out)
print("wrote", out)
