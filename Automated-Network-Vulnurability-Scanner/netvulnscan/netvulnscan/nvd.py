"""Small NVD CVE API 2.0 client: rate limiting, retries, paging and a disk cache.

NVD limits: 5 requests / 30 s without an API key, 50 / 30 s with one
(free key: https://nvd.nist.gov/developers/request-an-api-key).
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import requests

from .models import Vuln

BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE = 2000        # NVD maximum resultsPerPage
MAX_PAGES = 5      # safety bound per query


class NVDError(RuntimeError):
    pass


def _cvss(metrics: dict) -> tuple[float | None, str, str, str]:
    """Pick the best available CVSS block: v3.1, v3.0, v4.0, then v2."""
    for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV40", "4.0"), ("cvssMetricV2", "2.0")):
        arr = metrics.get(key) or []
        if not arr:
            continue
        m = next((x for x in arr if x.get("type") == "Primary"), arr[0])
        data = m.get("cvssData", {})
        sev = (data.get("baseSeverity") or m.get("baseSeverity") or "").title()
        score = data.get("baseScore")
        if sev not in ("Critical", "High", "Medium", "Low"):
            sev = "Unscored" if score is None else _bucket(score)
        return score, sev, data.get("vectorString", ""), ver
    return None, "Unscored", "", ""


def _bucket(score: float) -> str:
    return "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low"


def parse_cve(item: dict, confidence: str) -> Vuln:
    cve = item["cve"]
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    score, sev, vector, ver = _cvss(cve.get("metrics", {}))
    return Vuln(
        cve_id=cve["id"], score=score, severity=sev, cvss_version=ver, vector=vector,
        description=" ".join(desc.split())[:400], published=cve.get("published", "")[:10],
        kev=bool(cve.get("cisaExploitAdd")), confidence=confidence,
    )


class NVDClient:
    def __init__(self, api_key: str | None = None, cache_dir: str | None = ".nvd_cache", ttl: int = 86400,
                 session: requests.Session | None = None, sleep=time.sleep, timeout: int = 30):
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.session = session or requests.Session()
        self.sleep = sleep
        self.timeout = timeout
        self.ttl = ttl
        self.min_interval = 0.7 if self.api_key else 6.5
        self._last = 0.0
        self.cache = Path(cache_dir) if cache_dir else None
        if self.cache:
            self.cache.mkdir(parents=True, exist_ok=True)
        self.api_calls = 0

    # ---- low level -------------------------------------------------------
    def _cache_path(self, params: dict) -> Path | None:
        if not self.cache:
            return None
        key = hashlib.sha256(json.dumps(params, sort_keys=True).encode()).hexdigest()[:32]
        return self.cache / f"{key}.json"

    def _get(self, params: dict) -> dict:
        cp = self._cache_path(params)
        if cp and cp.exists() and time.time() - cp.stat().st_mtime < self.ttl:
            return json.loads(cp.read_text())
        headers = {"apiKey": self.api_key} if self.api_key else {}
        for attempt in range(5):
            wait = self.min_interval - (time.monotonic() - self._last)
            if wait > 0:
                self.sleep(wait)
            self._last = time.monotonic()
            self.api_calls += 1
            try:
                r = self.session.get(BASE, params=params, headers=headers, timeout=self.timeout)
            except requests.RequestException as exc:
                if attempt == 4:
                    raise NVDError(f"NVD request failed: {type(exc).__name__}")
                self.sleep(2 ** attempt * 3)
                continue
            if r.status_code in (400, 404):
                raise NVDError(f"HTTP {r.status_code}: {r.headers.get('message', 'bad request')}")
            ctype = r.headers.get("Content-Type", "")
            if r.status_code == 200 and "json" in ctype:
                data = r.json()
                if cp:
                    cp.write_text(json.dumps(data))
                return data
            # 403/429/503, or a rate-limit HTML page served with 200: back off and retry
            self.sleep(2 ** attempt * 6)
        raise NVDError("NVD kept rejecting requests (rate limited or unavailable). Use an API key or retry later.")

    def _paged(self, params: dict, confidence: str) -> list[Vuln]:
        out: list[Vuln] = []
        start = 0
        for _ in range(MAX_PAGES):
            data = self._get({**params, "resultsPerPage": PAGE, "startIndex": start, "noRejected": ""})
            out += [parse_cve(v, confidence) for v in data.get("vulnerabilities", [])]
            start += data.get("resultsPerPage", PAGE)
            if start >= data.get("totalResults", 0):
                break
        return out

    # ---- queries ---------------------------------------------------------
    def cves_for_cpe(self, cpe23: str) -> list[Vuln]:
        """CVEs whose NVD applicability statements match this CPE (ranges included).

        cpeName + isVulnerable is the precise query; if NVD rejects the name
        (not in the CPE dictionary) fall back to virtualMatchString.
        """
        try:
            return self._paged({"cpeName": cpe23, "isVulnerable": ""}, "Version match")
        except NVDError as exc:
            if not str(exc).startswith("HTTP"):
                raise
            return self._paged({"virtualMatchString": cpe23}, "Version match")

    def cves_for_keyword(self, text: str) -> list[Vuln]:
        return self._paged({"keywordSearch": text}, "Keyword match (low confidence)")
