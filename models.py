# =============================================================================
# models.py — Data models shared across the project
# =============================================================================

from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class IOC(BaseModel):
    """
    A single Indicator of Compromise.
    All fetchers return a list of these.
    """
    ioc_type: str               # "ip", "url", "domain", "hash"
    value: str                  # The actual IOC value
    source: str                 # Where it came from (e.g. "AlienVault OTX")
    threat_type: Optional[str]  # e.g. "malware", "botnet", "phishing"
    malware_family: Optional[str] = None
    tags: List[str] = []
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    description: Optional[str] = None
    confidence: int = 50        # 0–100, default medium


class EnrichedIOC(IOC):
    """
    An IOC after VirusTotal enrichment has been added.
    """
    vt_malicious_count: Optional[int] = None    # Engines flagging as malicious
    vt_total_engines: Optional[int] = None      # Total engines scanned
    vt_permalink: Optional[str] = None          # Link to VT report
    vt_last_analysis: Optional[datetime] = None
    enrichment_status: str = "pending"          # "done", "skipped", "error"
    enrichment_error: Optional[str] = None


class FetchResult(BaseModel):
    source: str
    ioc_count: int
    iocs: List[IOC]
    fetched_at: datetime
    errors: List[str] = []


class LibraryStats(BaseModel):
    total_iocs: int
    by_type: dict
    by_source: dict
    last_updated: Optional[datetime]
