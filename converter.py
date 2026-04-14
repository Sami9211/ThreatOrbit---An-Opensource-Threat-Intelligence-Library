# =============================================================================
# stix_converter/converter.py — Convert enriched IOCs to STIX 2.1 format
# =============================================================================
# STIX (Structured Threat Information eXpression) is the standard format
# for sharing cyber threat intelligence. Version 2.1 is what OpenCTI,
# MISP, and most modern TI platforms consume.
#
# We produce two types of STIX objects:
#   - Indicator       : the IOC itself with a detection pattern
#   - Malware         : threat actor / malware family context (if known)
#   - Relationship    : links Indicator → Malware (if applicable)
#
# The output is a STIX Bundle — a single JSON object containing all of them.
# TAXII servers serve bundles, and OpenCTI imports them directly.
# =============================================================================

import json
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config import STIX_IDENTITY_NAME, STIX_IDENTITY_CLASS
from models import EnrichedIOC

# STIX 2.1 type URIs for indicator patterns
STIX_PATTERN_MAP = {
    "ip":     lambda v: f"[ipv4-addr:value = '{v}']",
    "domain": lambda v: f"[domain-name:value = '{v}']",
    "url":    lambda v: f"[url:value = '{v}']",
    "hash":   lambda v: f"[file:hashes.SHA-256 = '{v}']",
}

# Maps our threat_type strings to STIX indicator_types list
STIX_INDICATOR_TYPES = {
    "malware":               ["malicious-activity"],
    "botnet":                ["malicious-activity", "compromised"],
    "ransomware":            ["malicious-activity"],
    "phishing":              ["malicious-activity", "anonymization"],
    "malware-distribution":  ["malicious-activity"],
    "scanning":              ["anomalous-activity"],
    "malicious-activity":    ["malicious-activity"],
}


def convert_to_stix_bundle(iocs: List[EnrichedIOC]) -> Dict[str, Any]:
    """
    Convert a list of EnrichedIOCs into a STIX 2.1 Bundle dict.
    Ready to be serialised to JSON and sent to OpenCTI / a TAXII server.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Identity object — who produced this intelligence
    identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, STIX_IDENTITY_NAME)}"
    identity = {
        "type":             "identity",
        "spec_version":     "2.1",
        "id":               identity_id,
        "created":          now,
        "modified":         now,
        "name":             STIX_IDENTITY_NAME,
        "identity_class":   STIX_IDENTITY_CLASS,
    }

    stix_objects = [identity]
    malware_cache: Dict[str, str] = {}  # malware_family → stix id (dedup)

    for ioc in iocs:
        # --- Build the Indicator ---
        pattern_fn = STIX_PATTERN_MAP.get(ioc.ioc_type)
        if not pattern_fn:
            continue  # skip unsupported types

        indicator_id = f"indicator--{uuid.uuid4()}"
        indicator_types = STIX_INDICATOR_TYPES.get(
            ioc.threat_type or "malicious-activity",
            ["malicious-activity"]
        )

        # Confidence: STIX uses 0-100
        confidence = ioc.confidence

        # Bump confidence if VT confirmed it
        if ioc.vt_malicious_count and ioc.vt_malicious_count > 0:
            confidence = min(100, confidence + 10)

        indicator = {
            "type":              "indicator",
            "spec_version":      "2.1",
            "id":                indicator_id,
            "created":           _fmt_date(ioc.first_seen) or now,
            "modified":          now,
            "name":              f"{ioc.ioc_type.upper()}: {ioc.value[:100]}",
            "description":       _build_description(ioc),
            "indicator_types":   indicator_types,
            "pattern":           pattern_fn(ioc.value),
            "pattern_type":      "stix",
            "valid_from":        _fmt_date(ioc.first_seen) or now,
            "confidence":        confidence,
            "labels":            ioc.tags[:10],
            "created_by_ref":    identity_id,
            "external_references": _build_external_refs(ioc),
        }

        stix_objects.append(indicator)

        # --- Build Malware object (if family known, deduplicated) ---
        if ioc.malware_family:
            family = ioc.malware_family.lower().strip()
            if family not in malware_cache:
                malware_id = f"malware--{uuid.uuid5(uuid.NAMESPACE_DNS, family)}"
                malware_cache[family] = malware_id
                malware_obj = {
                    "type":          "malware",
                    "spec_version":  "2.1",
                    "id":            malware_id,
                    "created":       now,
                    "modified":      now,
                    "name":          ioc.malware_family,
                    "is_family":     True,
                    "malware_types": [_map_malware_type(ioc.threat_type)],
                    "created_by_ref": identity_id,
                }
                stix_objects.append(malware_obj)

            # Relationship: indicator → malware
            rel = {
                "type":              "relationship",
                "spec_version":      "2.1",
                "id":                f"relationship--{uuid.uuid4()}",
                "created":           now,
                "modified":          now,
                "relationship_type": "indicates",
                "source_ref":        indicator_id,
                "target_ref":        malware_cache[family],
                "created_by_ref":    identity_id,
            }
            stix_objects.append(rel)

    bundle = {
        "type":         "bundle",
        "id":           f"bundle--{uuid.uuid4()}",
        "objects":      stix_objects,
    }

    print(f"[STIX] Bundle created: {len(stix_objects)} objects "
          f"({len(iocs)} indicators, {len(malware_cache)} malware families)")
    return bundle


def save_bundle_to_file(bundle: Dict[str, Any], filepath: str) -> None:
    """Save a STIX bundle to a JSON file."""
    with open(filepath, "w") as f:
        json.dump(bundle, f, indent=2, default=str)
    print(f"[STIX] Bundle saved to {filepath}")


def _build_description(ioc: EnrichedIOC) -> str:
    parts = []
    if ioc.description:
        parts.append(ioc.description)
    if ioc.vt_malicious_count is not None:
        parts.append(
            f"VirusTotal: {ioc.vt_malicious_count}/{ioc.vt_total_engines} engines flagged as malicious."
        )
    if ioc.vt_permalink:
        parts.append(f"VT Report: {ioc.vt_permalink}")
    return " | ".join(parts) or "No description available."


def _build_external_refs(ioc: EnrichedIOC) -> list:
    refs = [{"source_name": ioc.source, "description": "Original feed source"}]
    if ioc.vt_permalink:
        refs.append({
            "source_name": "VirusTotal",
            "url": ioc.vt_permalink,
            "description": f"{ioc.vt_malicious_count}/{ioc.vt_total_engines} detections",
        })
    return refs


def _fmt_date(dt: datetime | None) -> str | None:
    if not dt:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _map_malware_type(threat_type: str | None) -> str:
    mapping = {
        "ransomware": "ransomware",
        "botnet":     "bot",
        "trojan":     "trojan",
        "phishing":   "spyware",
    }
    return mapping.get(threat_type or "", "malware")


if __name__ == "__main__":
    # Quick smoke test with a dummy IOC
    from models import IOC
    dummy = EnrichedIOC(
        ioc_type="ip",
        value="185.220.101.1",
        source="test",
        threat_type="botnet",
        malware_family="Emotet",
        tags=["emotet", "c2"],
        confidence=90,
        vt_malicious_count=55,
        vt_total_engines=90,
        vt_permalink="https://www.virustotal.com/gui/ip-address/185.220.101.1",
        enrichment_status="done",
    )
    bundle = convert_to_stix_bundle([dummy])
    print(json.dumps(bundle, indent=2, default=str)[:1000])
