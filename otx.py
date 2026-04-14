# =============================================================================
# fetchers/otx.py — Pull IOCs from AlienVault OTX
# =============================================================================
# AlienVault OTX (Open Threat Exchange) is a crowd-sourced threat intelligence
# platform. It organises IOCs into "pulses" — bundles of related indicators.
# We pull recent pulses and extract all their indicators.
# =============================================================================

import requests
from datetime import datetime, timedelta, timezone
from typing import List
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import OTX_API_KEY, OTX_DAYS_BACK
from models import IOC, FetchResult

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

# Maps OTX indicator types to our internal types
OTX_TYPE_MAP = {
    "IPv4":          "ip",
    "IPv6":          "ip",
    "domain":        "domain",
    "hostname":      "domain",
    "URL":           "url",
    "FileHash-MD5":  "hash",
    "FileHash-SHA1": "hash",
    "FileHash-SHA256": "hash",
}


def fetch_otx_iocs() -> FetchResult:
    """
    Fetch indicators from AlienVault OTX pulses updated in the last N days.
    Returns a FetchResult with all IOCs and any errors encountered.
    """
    errors = []
    iocs: List[IOC] = []

    if OTX_API_KEY == "YOUR_OTX_API_KEY_HERE":
        return FetchResult(
            source="AlienVault OTX",
            ioc_count=0,
            iocs=[],
            fetched_at=datetime.now(timezone.utc),
            errors=["OTX API key not set. Edit config.py and add your key."]
        )

    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    since = (datetime.now(timezone.utc) - timedelta(days=OTX_DAYS_BACK)).strftime(
        "%Y-%m-%dT%H:%M:%S"
    )

    print(f"[OTX] Fetching pulses modified since {since}...")

    page = 1
    while True:
        try:
            resp = requests.get(
                f"{OTX_BASE_URL}/pulses/subscribed",
                headers=headers,
                params={"modified_since": since, "page": page, "limit": 20},
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            errors.append(f"OTX request failed on page {page}: {str(e)}")
            break

        pulses = data.get("results", [])
        if not pulses:
            break

        for pulse in pulses:
            pulse_name   = pulse.get("name", "Unknown Pulse")
            pulse_tags   = pulse.get("tags", [])
            pulse_desc   = pulse.get("description", "")
            malware_fam  = pulse.get("malware_families", [])
            malware_name = malware_fam[0].get("display_name", None) if malware_fam else None

            for indicator in pulse.get("indicators", []):
                raw_type = indicator.get("type", "")
                ioc_type = OTX_TYPE_MAP.get(raw_type)

                if not ioc_type:
                    # Skip CVEs, emails, and other types we don't handle
                    continue

                # Parse dates safely
                created = _parse_date(indicator.get("created"))
                expiry  = _parse_date(indicator.get("expiration"))

                iocs.append(IOC(
                    ioc_type=ioc_type,
                    value=indicator.get("indicator", ""),
                    source="AlienVault OTX",
                    threat_type=_infer_threat_type(pulse_tags, pulse_name),
                    malware_family=malware_name,
                    tags=pulse_tags[:10],   # cap at 10 tags
                    first_seen=created,
                    last_seen=expiry,
                    description=f"[{pulse_name}] {pulse_desc}"[:300],
                    confidence=70,
                ))

        # OTX paginates — stop if there's no next page
        if not data.get("next"):
            break
        page += 1

    print(f"[OTX] Done. Collected {len(iocs)} indicators.")
    return FetchResult(
        source="AlienVault OTX",
        ioc_count=len(iocs),
        iocs=iocs,
        fetched_at=datetime.now(timezone.utc),
        errors=errors,
    )


def _parse_date(date_str: str | None) -> datetime | None:
    if not date_str:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    return None


def _infer_threat_type(tags: list, pulse_name: str) -> str:
    combined = " ".join(tags + [pulse_name]).lower()
    if any(w in combined for w in ["ransom"]):
        return "ransomware"
    if any(w in combined for w in ["phish", "credential"]):
        return "phishing"
    if any(w in combined for w in ["botnet", "c2", "c&c", "command"]):
        return "botnet"
    if any(w in combined for w in ["malware", "trojan", "rat", "stealer"]):
        return "malware"
    if any(w in combined for w in ["scan", "brute"]):
        return "scanning"
    return "malicious-activity"


if __name__ == "__main__":
    result = fetch_otx_iocs()
    print(f"Fetched {result.ioc_count} IOCs from {result.source}")
    if result.errors:
        print("Errors:", result.errors)
    for ioc in result.iocs[:5]:
        print(f"  [{ioc.ioc_type}] {ioc.value} — {ioc.threat_type}")
