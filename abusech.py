# =============================================================================
# fetchers/abusech.py — Pull IOCs from abuse.ch feeds (no API key needed)
# =============================================================================
# abuse.ch runs three free, public threat feeds:
#
#   URLhaus       — malicious URLs used to distribute malware
#   MalwareBazaar — malware sample hashes with family/tag info
#   Feodo Tracker — C2 IP addresses for banking trojans & botnets
#                   (Emotet, QakBot, TrickBot, etc.)
#
# No registration required. All feeds are open to the public.
# =============================================================================

import requests
from datetime import datetime, timezone
from typing import List
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import ABUSECH_URLHAUS_URL, ABUSECH_MALWARE_URL, ABUSECH_FEODO_URL
from models import IOC, FetchResult


def fetch_abusech_iocs() -> FetchResult:
    """
    Pull IOCs from all three abuse.ch feeds and merge them.
    """
    all_iocs: List[IOC] = []
    all_errors: List[str] = []

    print("[abuse.ch] Fetching URLhaus feed...")
    url_iocs, url_errors = _fetch_urlhaus()
    all_iocs.extend(url_iocs)
    all_errors.extend(url_errors)

    print("[abuse.ch] Fetching MalwareBazaar feed...")
    mb_iocs, mb_errors = _fetch_malwarebazaar()
    all_iocs.extend(mb_iocs)
    all_errors.extend(mb_errors)

    print("[abuse.ch] Fetching Feodo Tracker C2 feed...")
    feodo_iocs, feodo_errors = _fetch_feodo()
    all_iocs.extend(feodo_iocs)
    all_errors.extend(feodo_errors)

    print(f"[abuse.ch] Done. Collected {len(all_iocs)} indicators total.")
    return FetchResult(
        source="abuse.ch",
        ioc_count=len(all_iocs),
        iocs=all_iocs,
        fetched_at=datetime.now(timezone.utc),
        errors=all_errors,
    )


# ---------------------------------------------------------------------------
# URLhaus — malicious URLs
# ---------------------------------------------------------------------------

def _fetch_urlhaus() -> tuple[List[IOC], List[str]]:
    iocs: List[IOC] = []
    errors: List[str] = []

    try:
        resp = requests.post(
            ABUSECH_URLHAUS_URL,
            data={"limit": 200},  # last 200 URLs
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        errors.append(f"URLhaus fetch failed: {str(e)}")
        return iocs, errors

    for entry in data.get("urls", []):
        if entry.get("url_status") not in ("online", "unknown"):
            continue  # skip already-dead URLs

        tags = entry.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]

        iocs.append(IOC(
            ioc_type="url",
            value=entry.get("url", ""),
            source="abuse.ch / URLhaus",
            threat_type="malware-distribution",
            malware_family=entry.get("threat", None),
            tags=tags,
            first_seen=_parse_date(entry.get("date_added")),
            description=f"Malicious URL — threat: {entry.get('threat', 'unknown')}",
            confidence=85,
        ))

    return iocs, errors


# ---------------------------------------------------------------------------
# MalwareBazaar — malware file hashes
# ---------------------------------------------------------------------------

def _fetch_malwarebazaar() -> tuple[List[IOC], List[str]]:
    iocs: List[IOC] = []
    errors: List[str] = []

    try:
        resp = requests.post(
            ABUSECH_MALWARE_URL,
            data={"query": "get_recent", "selector": "time"},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        errors.append(f"MalwareBazaar fetch failed: {str(e)}")
        return iocs, errors

    if data.get("query_status") != "ok":
        errors.append(f"MalwareBazaar returned status: {data.get('query_status')}")
        return iocs, errors

    for sample in data.get("data", []):
        tags = sample.get("tags") or []
        sha256 = sample.get("sha256_hash", "")
        if not sha256:
            continue

        iocs.append(IOC(
            ioc_type="hash",
            value=sha256,
            source="abuse.ch / MalwareBazaar",
            threat_type="malware",
            malware_family=sample.get("signature", None),
            tags=tags if isinstance(tags, list) else [tags],
            first_seen=_parse_date(sample.get("first_seen")),
            description=(
                f"Malware hash — family: {sample.get('signature', 'unknown')}, "
                f"file type: {sample.get('file_type', 'unknown')}, "
                f"size: {sample.get('file_size', '?')} bytes"
            ),
            confidence=90,
        ))

    return iocs, errors


# ---------------------------------------------------------------------------
# Feodo Tracker — botnet C2 IPs
# ---------------------------------------------------------------------------

def _fetch_feodo() -> tuple[List[IOC], List[str]]:
    iocs: List[IOC] = []
    errors: List[str] = []

    try:
        resp = requests.get(ABUSECH_FEODO_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        errors.append(f"Feodo Tracker fetch failed: {str(e)}")
        return iocs, errors

    for entry in data:
        ip = entry.get("ip_address", "")
        if not ip:
            continue

        malware = entry.get("malware", "unknown")
        iocs.append(IOC(
            ioc_type="ip",
            value=ip,
            source="abuse.ch / Feodo Tracker",
            threat_type="botnet",
            malware_family=malware,
            tags=[malware, "c2", "botnet"],
            first_seen=_parse_date(entry.get("first_seen")),
            last_seen=_parse_date(entry.get("last_online")),
            description=(
                f"Botnet C2 server — malware: {malware}, "
                f"port: {entry.get('port', '?')}, "
                f"status: {entry.get('status', '?')}"
            ),
            confidence=95,
        ))

    return iocs, errors


def _parse_date(date_str) -> datetime | None:
    if not date_str:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    return None


if __name__ == "__main__":
    result = fetch_abusech_iocs()
    print(f"Fetched {result.ioc_count} IOCs from {result.source}")
    if result.errors:
        print("Errors:", result.errors)
    for ioc in result.iocs[:5]:
        print(f"  [{ioc.ioc_type}] {ioc.value[:80]} — {ioc.threat_type}")
