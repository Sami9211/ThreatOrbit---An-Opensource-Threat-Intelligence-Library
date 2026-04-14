# =============================================================================
# enrichment/virustotal.py — Enrich IOCs using VirusTotal API v3
# =============================================================================
# VirusTotal checks a given IOC (IP, URL, domain, hash) against 70+ antivirus
# engines and threat intelligence feeds. We extract:
#   - How many engines flagged it as malicious
#   - Total engines that scanned it
#   - A permalink to the full VT report
#   - Date of last analysis
#
# FREE tier limits: 4 requests/minute, 500 requests/day
# The code automatically waits between requests to stay within limits.
# =============================================================================

import requests
import time
from datetime import datetime, timezone
from typing import List
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import VIRUSTOTAL_API_KEY, VT_RATE_LIMIT_SECONDS
from models import IOC, EnrichedIOC

VT_BASE = "https://www.virustotal.com/api/v3"


def enrich_iocs(iocs: List[IOC], max_enrichments: int = 100) -> List[EnrichedIOC]:
    """
    Take a list of IOCs and enrich each one with VirusTotal data.

    Args:
        iocs:             List of IOC objects to enrich
        max_enrichments:  Max number to enrich (to stay within daily API limits)

    Returns:
        List of EnrichedIOC objects
    """
    if VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        print("[VirusTotal] API key not set — skipping enrichment.")
        return [_skip(ioc, "API key not configured") for ioc in iocs]

    enriched: List[EnrichedIOC] = []
    count = 0

    for ioc in iocs:
        if count >= max_enrichments:
            # Mark remaining as skipped (daily limit protection)
            enriched.append(_skip(ioc, "daily enrichment limit reached"))
            continue

        result = _enrich_single(ioc)
        enriched.append(result)
        count += 1

        if count < min(max_enrichments, len(iocs)):
            # Respect rate limit between requests
            time.sleep(VT_RATE_LIMIT_SECONDS)

    malicious = sum(1 for e in enriched if (e.vt_malicious_count or 0) > 0)
    print(f"[VirusTotal] Enriched {count} IOCs. {malicious} confirmed malicious.")
    return enriched


def _enrich_single(ioc: IOC) -> EnrichedIOC:
    """
    Query VirusTotal for a single IOC. Returns an EnrichedIOC.
    """
    base = EnrichedIOC(**ioc.model_dump())

    try:
        url, params = _build_request(ioc)
        if not url:
            return _skip(ioc, f"unsupported type: {ioc.ioc_type}")

        resp = requests.get(
            url,
            params=params,
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=20,
        )

        if resp.status_code == 404:
            base.enrichment_status = "done"
            base.vt_malicious_count = 0
            base.vt_total_engines = 0
            return base

        if resp.status_code == 429:
            return _skip(ioc, "VT rate limit hit — slow down or upgrade plan")

        resp.raise_for_status()
        data = resp.json()

        stats = (
            data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
        )

        last_analysis_ts = (
            data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_date")
        )

        base.vt_malicious_count = stats.get("malicious", 0)
        base.vt_total_engines   = sum(stats.values()) if stats else 0
        base.vt_permalink       = f"https://www.virustotal.com/gui/{_vt_gui_path(ioc)}"
        base.vt_last_analysis   = (
            datetime.fromtimestamp(last_analysis_ts, tz=timezone.utc)
            if last_analysis_ts else None
        )

        # Bump confidence if VT confirms malicious
        if base.vt_malicious_count and base.vt_malicious_count > 5:
            base.confidence = min(100, base.confidence + 20)

        base.enrichment_status = "done"
        print(
            f"  [VT] {ioc.ioc_type} {ioc.value[:50]!r} → "
            f"{base.vt_malicious_count}/{base.vt_total_engines} engines"
        )

    except requests.RequestException as e:
        base.enrichment_status = "error"
        base.enrichment_error  = str(e)

    return base


def _build_request(ioc: IOC) -> tuple[str | None, dict]:
    """
    Return the correct VT API endpoint for each IOC type.
    """
    import urllib.parse

    if ioc.ioc_type == "ip":
        return f"{VT_BASE}/ip_addresses/{ioc.value}", {}

    if ioc.ioc_type == "domain":
        return f"{VT_BASE}/domains/{ioc.value}", {}

    if ioc.ioc_type == "hash":
        return f"{VT_BASE}/files/{ioc.value}", {}

    if ioc.ioc_type == "url":
        # VT requires URL ID = base64url(url) without padding
        import base64
        url_id = base64.urlsafe_b64encode(ioc.value.encode()).decode().rstrip("=")
        return f"{VT_BASE}/urls/{url_id}", {}

    return None, {}


def _vt_gui_path(ioc: IOC) -> str:
    type_map = {"ip": "ip-address", "domain": "domain", "hash": "file", "url": "url"}
    t = type_map.get(ioc.ioc_type, "search")
    return f"{t}/{ioc.value}"


def _skip(ioc: IOC, reason: str) -> EnrichedIOC:
    e = EnrichedIOC(**ioc.model_dump())
    e.enrichment_status = "skipped"
    e.enrichment_error  = reason
    return e


if __name__ == "__main__":
    # Quick test with a known malicious hash
    test = IOC(
        ioc_type="hash",
        value="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        source="test",
        threat_type="malware",
    )
    results = enrich_iocs([test], max_enrichments=1)
    for r in results:
        print(f"Malicious: {r.vt_malicious_count}/{r.vt_total_engines}")
        print(f"Report: {r.vt_permalink}")
