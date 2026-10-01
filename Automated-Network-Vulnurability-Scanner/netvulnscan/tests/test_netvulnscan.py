"""Run:  python -m unittest discover -s tests -v   (NVD is mocked; nmap test skips if nmap is absent)"""
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netvulnscan.cpe import cpe22_to_cpe23  # noqa: E402
from netvulnscan.matcher import map_vulnerabilities  # noqa: E402
from netvulnscan.nmap_runner import build_args, parse_nmap_xml  # noqa: E402
from netvulnscan.nvd import NVDClient, NVDError, parse_cve  # noqa: E402
from netvulnscan.pdf_report import build_pdf  # noqa: E402
from netvulnscan.report import write_csv, write_json  # noqa: E402
from netvulnscan.targets import TargetError, validate_ports, validate_targets  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def sample(targets=None):
    with open(os.path.join(HERE, "sample_nmap.xml"), encoding="utf-8") as fh:
        return parse_nmap_xml(fh.read(), targets)


def read(path):
    with open(path, "rb") as fh:
        return fh.read()


def nvd_item(cve_id, score, sev, kev=False, v="cvssMetricV31", desc="Test vulnerability \u2019s description <b>x</b>"):
    cve = {"id": cve_id, "published": "2021-10-05T09:15:00.000", "descriptions": [{"lang": "en", "value": desc}],
           "metrics": {v: [{"type": "Primary", "cvssData": {"baseScore": score, "baseSeverity": sev, "vectorString": "CVSS:3.1/AV:N"}}]}}
    if kev:
        cve["cisaExploitAdd"] = "2021-11-03"
    return {"cve": cve}


class FakeResp:
    def __init__(self, status=200, body=None, ctype="application/json", headers=None):
        self.status_code, self._body = status, body
        self.headers = {"Content-Type": ctype, **(headers or {})}

    def json(self):
        return self._body


class FakeSession:
    """Scripted responses; records query params."""
    def __init__(self, handler):
        self.handler, self.calls = handler, []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append(dict(params))
        return self.handler(params)


def page(items):
    return FakeResp(body={"resultsPerPage": 2000, "startIndex": 0, "totalResults": len(items), "vulnerabilities": items})


def client(handler, **kw):
    s = FakeSession(handler)
    return NVDClient(api_key="k", cache_dir=None, session=s, sleep=lambda _: None, **kw), s


class CpeTests(unittest.TestCase):
    def test_conversion(self):
        self.assertEqual(cpe22_to_cpe23("cpe:/a:openbsd:openssh:8.2p1"), "cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*")
        self.assertEqual(cpe22_to_cpe23("cpe:/a:apache:http_server:2.4.49"), "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
        self.assertEqual(cpe22_to_cpe23("cpe:/a:php:php:7.4.3%2b1"), "cpe:2.3:a:php:php:7.4.3\\+1:*:*:*:*:*:*:*")

    def test_unusable_cpes_are_dropped(self):
        self.assertIsNone(cpe22_to_cpe23("cpe:/o:linux:linux_kernel"))      # OS
        self.assertIsNone(cpe22_to_cpe23("cpe:/a:vendor:product"))          # no version


class TargetTests(unittest.TestCase):
    def test_private_ok_public_blocked(self):
        self.assertEqual(validate_targets(["192.168.1.0/25", "10.0.0.5", "127.0.0.1"]), ["192.168.1.0/25", "10.0.0.5", "127.0.0.1"])
        with self.assertRaises(TargetError):
            validate_targets(["8.8.8.8"])
        validate_targets(["8.8.8.8"], allow_public=True)

    def test_option_injection_and_garbage_rejected(self):
        for bad in ("--script=vuln", "-iL /etc/passwd", "10.0.0.1; rm -rf /", "10.0.0.1 -p-", ""):
            with self.assertRaises(TargetError, msg=bad):
                validate_targets([bad])

    def test_size_cap_and_ranges(self):
        with self.assertRaises(TargetError):
            validate_targets(["10.0.0.0/16"])
        validate_targets(["10.0.0.0/16"], max_hosts=70000)
        validate_targets(["10.0.0.0/24"])  # exactly 256 is allowed
        validate_targets(["192.168.1.10-20"])
        with self.assertRaises(TargetError):
            validate_targets(["192.168.1.20-10"])

    def test_ports(self):
        self.assertEqual(validate_ports("22,80,1-1024"), "22,80,1-1024")
        for bad in ("22;ls", "0", "70000", "-p-", "T:22"):
            with self.assertRaises(TargetError, msg=bad):
                validate_ports(bad)

    def test_nmap_args_use_separator_and_no_scripts(self):
        a = build_args(["10.0.0.5"], "22", 1000, 3, 7, False)
        self.assertEqual(a[-2:], ["--", "10.0.0.5"])
        self.assertNotIn("-A", a)
        self.assertFalse(any(x.startswith("--script") for x in a))


class ParseTests(unittest.TestCase):
    def setUp(self):
        self.report = sample(["10.0.0.5"])

    def test_hosts_and_ports(self):
        self.assertEqual(len(self.report.hosts), 1)  # down host skipped
        h = self.report.hosts[0]
        self.assertEqual((h.address, h.hostname, h.os_guess), ("10.0.0.5", "web01.lab.local", "Linux 5.4"))
        self.assertEqual([p.port for p in h.ports], [22, 80, 3306, 9999])  # closed port skipped
        self.assertEqual(h.ports[0].version, "8.2p1 Ubuntu 4ubuntu0.5")
        self.assertEqual(self.report.started[:4], "2026")


class NVDTests(unittest.TestCase):
    def test_parse_cvss_preference_and_kev(self):
        v = parse_cve(nvd_item("CVE-2021-41773", 7.5, "HIGH", kev=True), "Version match")
        self.assertEqual((v.severity, v.score, v.cvss_version, v.kev), ("High", 7.5, "3.1", True))
        old = parse_cve(nvd_item("CVE-2010-0001", 5.0, "MEDIUM", v="cvssMetricV2"), "x")
        self.assertEqual((old.severity, old.cvss_version), ("Medium", "2.0"))
        none = parse_cve({"cve": {"id": "CVE-2099-1", "descriptions": [], "metrics": {}}}, "x")
        self.assertEqual(none.severity, "Unscored")

    def test_cpe_query_uses_cpename_and_isvulnerable(self):
        c, s = client(lambda p: page([nvd_item("CVE-2021-41773", 7.5, "HIGH")]))
        out = c.cves_for_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
        self.assertEqual([v.cve_id for v in out], ["CVE-2021-41773"])
        self.assertIn("cpeName", s.calls[0]); self.assertIn("isVulnerable", s.calls[0])

    def test_falls_back_to_virtual_match_string_when_cpe_unknown(self):
        c, s = client(lambda p: FakeResp(404, headers={"message": "Invalid cpeName"}) if "cpeName" in p
                      else page([nvd_item("CVE-1", 9.8, "CRITICAL")]))
        out = c.cves_for_cpe("cpe:2.3:a:x:y:1:*:*:*:*:*:*:*")
        self.assertEqual(out[0].severity, "Critical")
        self.assertIn("virtualMatchString", s.calls[1])

    def test_retries_rate_limit_html_page(self):
        replies = [FakeResp(200, ctype="text/html"), FakeResp(403, ctype="text/html"), page([nvd_item("CVE-2", 5, "MEDIUM")])]
        c, s = client(lambda p: replies.pop(0))
        self.assertEqual(len(c.cves_for_cpe("cpe:2.3:a:x:y:1:*:*:*:*:*:*:*")), 1)
        self.assertEqual(len(s.calls), 3)

    def test_gives_up_with_clear_error(self):
        c, _ = client(lambda p: FakeResp(503, ctype="text/html"))
        with self.assertRaises(NVDError):
            c.cves_for_cpe("cpe:2.3:a:x:y:1:*:*:*:*:*:*:*")

    def test_disk_cache_avoids_second_call(self):
        d = tempfile.mkdtemp()
        s = FakeSession(lambda p: page([nvd_item("CVE-3", 4, "MEDIUM")]))
        c = NVDClient(api_key="k", cache_dir=d, session=s, sleep=lambda _: None)
        c.cves_for_cpe("cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"); c.cves_for_cpe("cpe:2.3:a:x:y:1:*:*:*:*:*:*:*")
        self.assertEqual(len(s.calls), 1)
        shutil.rmtree(d)

    def test_rate_interval_depends_on_key(self):
        self.assertGreater(NVDClient(cache_dir=None, api_key=None).min_interval, 6)
        self.assertLess(NVDClient(cache_dir=None, api_key="k").min_interval, 1)


def fake_nvd_handler(p):
    cpe = p.get("cpeName", "")
    if "openssh" in cpe:
        return page([nvd_item("CVE-2023-38408", 9.8, "CRITICAL"), nvd_item("CVE-2020-14145", 5.9, "MEDIUM")])
    if "http_server" in cpe:
        return page([nvd_item("CVE-2021-41773", 7.5, "HIGH", kev=True), nvd_item("CVE-2021-42013", 9.8, "CRITICAL", kev=True)])
    return page([])


class MatcherAndReportTests(unittest.TestCase):
    def setUp(self):
        self.report = sample(["10.0.0.5"])
        c, self.session = client(fake_nvd_handler)
        map_vulnerabilities(self.report, c)
        self.ports = {p.port: p for p in self.report.hosts[0].ports}

    def test_cves_mapped_sorted_by_severity_then_score(self):
        self.assertEqual([v.cve_id for v in self.ports[22].vulns], ["CVE-2023-38408", "CVE-2020-14145"])
        self.assertEqual([v.cve_id for v in self.ports[80].vulns], ["CVE-2021-42013", "CVE-2021-41773"])
        self.assertEqual(self.report.severity_counts(), {"Critical": 2, "High": 1, "Medium": 1, "Low": 0, "Unscored": 0})

    def test_backport_warning_only_on_distro_builds(self):
        self.assertTrue(any("back-ported" in n for n in self.ports[22].notes))   # Ubuntu build
        self.assertFalse(self.ports[80].notes)                                    # upstream Apache

    def test_unfingerprinted_services_are_flagged_not_guessed(self):
        self.assertTrue(any("No version fingerprint" in n for n in self.ports[9999].notes))
        self.assertTrue(any("supplied no CPE" in n for n in self.ports[3306].notes))  # version known, CPE missing
        self.assertEqual(self.ports[9999].vulns, [])

    def test_keyword_fallback_is_low_confidence(self):
        r = sample()
        c, s = client(lambda p: page([nvd_item("CVE-9", 5, "MEDIUM")]) if "keywordSearch" in p else page([]))
        map_vulnerabilities(r, c, keyword_fallback=True)
        v = [p for p in r.hosts[0].ports if p.port == 3306][0].vulns[0]
        self.assertTrue(v.confidence.startswith("Keyword"))

    def test_min_severity_filter(self):
        r = sample()
        c, _ = client(fake_nvd_handler)
        map_vulnerabilities(r, c, min_severity="High")
        self.assertEqual({v.severity for p in r.hosts[0].ports for v in p.vulns}, {"Critical", "High"})

    def test_identical_services_queried_once(self):
        r = sample()
        r.hosts.append(r.hosts[0].__class__(address="10.0.0.6", ports=[__import__("copy").deepcopy(p) for p in r.hosts[0].ports]))
        c, s = client(fake_nvd_handler)
        map_vulnerabilities(r, c)
        self.assertEqual(len(s.calls), 2)  # one openssh + one apache query for both hosts

    def test_pdf_json_csv_outputs(self):
        d = tempfile.mkdtemp()
        pdf, js, csvp = (os.path.join(d, n) for n in ("r.pdf", "r.json", "r.csv"))
        build_pdf(self.report, pdf); write_json(self.report, js); write_csv(self.report, csvp)
        self.assertEqual(read(pdf)[:5], b"%PDF-")
        self.assertIn(b"CVE-2023-38408", read(js))
        rows = read(csvp).decode("utf-8").splitlines()
        self.assertEqual(len(rows), 1 + 2 + 2 + 2)  # header + ssh(2) + http(2) + two ports with no CVEs
        shutil.rmtree(d)

    def test_pdf_survives_hostile_and_unicode_text(self):
        self.report.hosts[0].hostname = "<script>alert(1)</script> \u4e2d\u6587 & co"
        self.report.hosts[0].ports[0].vulns[0].description = "Bad <para> markup & \u201csmart quotes\u201d \u2014 \u2713 " * 20
        d = tempfile.mkdtemp()
        build_pdf(self.report, os.path.join(d, "x.pdf"))
        shutil.rmtree(d)

    def test_pdf_with_no_findings(self):
        empty = sample()
        empty.cve_lookup = "skipped"
        d = tempfile.mkdtemp()
        build_pdf(empty, os.path.join(d, "x.pdf"))
        shutil.rmtree(d)


@unittest.skipUnless(shutil.which("nmap"), "nmap not installed")
class RealNmapTest(unittest.TestCase):
    def test_scan_local_listener(self):
        import socket
        import threading
        from netvulnscan.nmap_runner import run_nmap
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5)
        port = srv.getsockname()[1]
        threading.Thread(target=lambda: [srv.accept() for _ in range(20)], daemon=True).start()
        xml = run_nmap(build_args(["127.0.0.1"], str(port), 1000, 4, 0, False), timeout=120)
        rep = parse_nmap_xml(xml, ["127.0.0.1"])
        self.assertEqual([p.port for p in rep.hosts[0].ports], [port])
        srv.close()


if __name__ == "__main__":
    unittest.main()
