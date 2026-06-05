"""
CVE correlation  (owner: E2).

Maps the targeted port -> software family -> known CVEs. Two sources, for both
ACCURACY and FRESHNESS (evaluation criterion #3):

  * LIVE  - queries the public NVD 2.0 API for the latest CVEs in real time.
  * CACHE - a local snapshot, used as a reliable fallback when NVD is
            unreachable / rate-limited (keeps the demo from ever breaking).

Default is cache (fast + deterministic for the demo). Pass use_live=True to
fetch fresh from NVD; it automatically falls back to cache on any failure.
Run the evaluator with --refresh-cve to rebuild the cache from a live NVD pull,
so the cached snapshot is genuinely NVD-sourced rather than hand-written.
"""
import json
import urllib.request
import urllib.parse
from functools import lru_cache
from datetime import datetime, timezone

import config

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def sev_rank(s):
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(s, 4)


# ----------------------------------------------------------------- live NVD pull
def _normalize_nvd(cve, software):
    """Map one NVD 2.0 'cve' object into our internal CVE shape."""
    cvss, severity = 0.0, "UNKNOWN"
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData", {})
            cvss = data.get("baseScore", 0.0)
            severity = arr[0].get("baseSeverity") or data.get("baseSeverity") or "UNKNOWN"
            break
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    return {
        "id": cve.get("id"),
        "software": software,
        "affected_versions": [],
        "cvss": cvss,
        "severity": str(severity).upper(),
        "published": cve.get("published", ""),
        "summary": desc[:200],
        "recommended_action": "Review the NVD advisory and patch the affected service.",
    }


def _rank_live(cves):
    """Order live NVD results so the BEST match is first — i.e. the freshest
    HIGH/CRITICAL CVE. A bare keyword search returns lots of noise (old
    catch-all CVEs with inflated scores); ranking by recency among severe CVEs
    keeps correlation both accurate AND fresh.
    """
    current_year = datetime.now(timezone.utc).year
    severe_recent = [c for c in cves
                     if c["cvss"] >= 7.0 and (c["published"][:4] or "0").isdigit()
                     and int(c["published"][:4] or 0) >= current_year - 6]
    pool = severe_recent or cves
    return sorted(pool, key=lambda c: c.get("published", ""), reverse=True)


def _nvd_get(params, timeout):
    qs = urllib.parse.urlencode(params)
    req = urllib.request.Request(f"{NVD_API}?{qs}", headers={"User-Agent": "ps3-evaluator"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


@lru_cache(maxsize=None)
def fetch_cves_live(software, limit=20, timeout=8):
    """Fetch the LATEST CVEs for a software keyword straight from NVD.

    NVD returns keyword matches oldest-first, so we read totalResults and pull
    the LAST page (startIndex = total - limit) to get the newest CVEs. Returns
    normalized CVE dicts, or [] on ANY failure (network, timeout, rate-limit)
    so the caller can fall back to the cache. Memoized: one pull per run.
    """
    try:
        total = _nvd_get({"keywordSearch": software, "resultsPerPage": 1},
                         timeout).get("totalResults", 0)
        start = max(0, total - limit)
        data = _nvd_get({"keywordSearch": software, "resultsPerPage": limit,
                         "startIndex": start}, timeout)
        return [_normalize_nvd(v["cve"], software) for v in data.get("vulnerabilities", [])]
    except Exception:
        return []


# ----------------------------------------------------------------- resolution
def resolve_cves(software, cache, use_live=False):
    """Return (cves, source_label) for a software family, BEST match first.
    Tries live NVD first when use_live is set; always falls back to cache."""
    if use_live:
        live = fetch_cves_live(software)
        if live:
            return _rank_live(live), "NVD (live)"
    cached = [c for c in cache if c.get("software", "").lower() == software.lower()]
    cached.sort(key=lambda c: c.get("cvss", 0), reverse=True)
    return cached, "cache"


def correlate(target_port, cache, use_live=False):
    """Map targeted port -> software family -> CVEs.
    Returns (software_or_None, [cve dicts], source_label_or_None)."""
    software = config.PORT_SOFTWARE.get(target_port)
    if not software:
        return None, [], None
    cves, source = resolve_cves(software, cache, use_live)
    return software, cves, source


# ----------------------------------------------------------------- cache refresh
def refresh_cache(path, softwares=None, limit=20):
    """Rebuild the on-disk CVE cache from a live NVD pull, so the cached
    snapshot is genuinely NVD-sourced. Returns (per-software counts, total)."""
    softwares = softwares or sorted(set(config.PORT_SOFTWARE.values()))
    fetch_cves_live.cache_clear()          # force a fresh pull, ignore memoized
    all_cves, counts = [], {}
    for sw in softwares:
        cves = fetch_cves_live(sw, limit=limit)
        counts[sw] = len(cves)
        all_cves.extend(cves)
    if all_cves:
        snapshot = {
            "_source": "NVD 2.0 API",
            "_fetched_at": datetime.now(timezone.utc).isoformat(),
            "cves": all_cves,
        }
        # store as a flat list for backward-compat, with provenance alongside
        json.dump(all_cves, open(path, "w"), indent=2)
        json.dump(snapshot, open(path.replace(".json", "_meta.json"), "w"), indent=2)
    return counts, len(all_cves)
