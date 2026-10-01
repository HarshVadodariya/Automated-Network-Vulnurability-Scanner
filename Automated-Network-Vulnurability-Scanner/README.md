# netvulnscan - Automated Network Vulnerability Scanner

Scans a network you are authorized to test with **Nmap**, identifies open ports and service versions, maps those versions to
known CVEs using the **NVD CVE API 2.0**, and writes console, JSON, CSV and **PDF** reports.

## Setup

```bash
sudo apt install nmap            # or https://nmap.org/download (Windows/macOS)
pip install -r requirements.txt  # requests, reportlab
export NVD_API_KEY=...           # optional but recommended (free): https://nvd.nist.gov/developers/request-an-api-key
```

## Usage

```bash
# scan a lab subnet, write all report formats
python cli.py 192.168.1.0/24 --i-am-authorized --pdf report.pdf --json report.json --csv report.csv

# specific ports, only High/Critical CVEs
python cli.py 10.0.0.5 -p 1-1024 --min-severity high --i-am-authorized --pdf report.pdf

# re-use an existing nmap scan (no scanning, no authorization flag needed)
nmap -sV -oX scan.xml 10.0.0.5 && python cli.py --from-xml scan.xml --pdf report.pdf

# ports/services only, no NVD lookups
python cli.py 10.0.0.5 --i-am-authorized --no-cve
```

Exit code is `3` if any High/Critical CVE is found (handy for CI), `2` if authorization wasn't confirmed, `1` on errors.

Run the tests (NVD is mocked; the real-nmap test skips if nmap is missing):
`python -m unittest discover -s tests -v`

`python examples/make_demo_report.py` regenerates `examples/sample_report.pdf` from **mock** data to show the layout.

## How it works

```
targets -> validate -> nmap -sV (XML) -> parse ports/services/CPEs -> CPE 2.2 -> 2.3
        -> NVD: cpeName + isVulnerable (fallback: virtualMatchString) -> CVSS + KEV
        -> console / JSON / CSV / PDF
```

- Nmap's CPE for each service (e.g. `cpe:/a:openbsd:openssh:8.2p1`) is converted to the CPE 2.3 form NVD uses
  (`...openssh:8.2:p1...`) so NVD can match it against its version ranges.
- Severity is the CVSS base severity (v3.1, then v3.0, v4.0, v2). CVEs on CISA's **KEV** list are flagged and sorted first.
- Identical services across hosts are queried once; responses are cached on disk (`.nvd_cache`, 24 h).
- Rate limits (5 requests/30 s without a key, 50 with one) are respected, with backoff on 403/429/503.

## Reading the results honestly

Version-to-CVE mapping gives **leads, not confirmed vulnerabilities**:

- **False positives**: Linux distros back-port fixes without changing the version string. Distro builds are flagged in the report;
  check the vendor's security tracker.
- **False negatives**: hidden/altered banners, services without a CPE, and anything outside the scanned ports (UDP is not scanned).
- Services with no usable CPE are listed as such. `--keyword-fallback` tries an NVD keyword search, but it is noisy and marked low confidence.
- Misconfigurations and weak credentials are out of scope; this tool only matches software versions.

## Safety

- Requires `--i-am-authorized`; public IPs additionally require `--allow-public`; default cap of 256 hosts (`--max-hosts`).
- Version detection only: no NSE scripts, no exploitation. Nmap runs via an argv list (no shell); targets and ports are validated
  and anything resembling an option is rejected.
- Scanning systems you don't own or have written permission to test is illegal in many places.

## Layout

```
cli.py                      command-line entry point
netvulnscan/targets.py      target/port validation and scope guard
netvulnscan/nmap_runner.py  build/run nmap, parse XML
netvulnscan/cpe.py          CPE 2.2 -> 2.3
netvulnscan/nvd.py          NVD client (rate limit, retry, cache, CVSS parsing)
netvulnscan/matcher.py      services -> CVEs, dedupe, back-port warnings
netvulnscan/report.py       console / JSON / CSV
netvulnscan/pdf_report.py   PDF report (ReportLab)
tests/                      25 tests, sample nmap XML
```

## Ideas to extend

EPSS scores for prioritisation, scan diffing between runs, UDP top ports, a scope allow-list file, a Flask dashboard,
scheduled scans with email alerts, and Vulners/OSV as additional sources.
