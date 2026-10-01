from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Unscored"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


@dataclass
class Vuln:
    cve_id: str
    score: float | None
    severity: str  # Critical | High | Medium | Low | Unscored
    cvss_version: str = ""
    vector: str = ""
    description: str = ""
    published: str = ""
    kev: bool = False  # on CISA's Known Exploited Vulnerabilities list
    confidence: str = "Version match"  # or "Keyword match (low confidence)"

    @property
    def url(self) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpes: list[str] = field(default_factory=list)
    vulns: list[Vuln] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def banner(self) -> str:
        return " ".join(x for x in (self.product, self.version) if x).strip()


@dataclass
class HostResult:
    address: str
    hostname: str = ""
    os_guess: str = ""
    ports: list[PortResult] = field(default_factory=list)


@dataclass
class ScanReport:
    targets: list[str]
    started: str
    finished: str = ""
    nmap_version: str = ""
    nmap_args: str = ""
    hosts: list[HostResult] = field(default_factory=list)
    cve_lookup: str = "enabled"  # enabled | skipped
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        for h in d["hosts"]:
            for p in h["ports"]:
                for v in p["vulns"]:
                    v["url"] = f"https://nvd.nist.gov/vuln/detail/{v['cve_id']}"
        return d

    def severity_counts(self) -> dict[str, int]:
        """Unique CVEs per severity across the whole scan."""
        seen: dict[str, str] = {}
        for h in self.hosts:
            for p in h.ports:
                for v in p.vulns:
                    seen[v.cve_id] = v.severity
        counts = {s: 0 for s in SEVERITY_ORDER}
        for sev in seen.values():
            counts[sev] += 1
        return counts
