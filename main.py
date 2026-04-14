# =============================================================================
# main.py — FastAPI REST API for the CTI Library
# =============================================================================
# Run with:   uvicorn main:app --reload
# Docs at:    http://127.0.0.1:8000/docs  (Swagger UI, auto-generated)
# =============================================================================

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.responses import JSONResponse
from typing import List, Optional
from datetime import datetime, timezone
import json
import os

from config import API_HOST, API_PORT
from models import EnrichedIOC, FetchResult, LibraryStats
from fetchers.otx import fetch_otx_iocs
from fetchers.abusech import fetch_abusech_iocs
from enrichment.virustotal import enrich_iocs
from stix_converter.converter import convert_to_stix_bundle, save_bundle_to_file

app = FastAPI(
    title="CTIL — Cyber Threat Intelligence Library",
    description=(
        "Aggregates IOCs from AlienVault OTX and abuse.ch, enriches them via "
        "VirusTotal, converts to STIX 2.1, and exposes them via REST API."
    ),
    version="1.0.0",
)

# ---------------------------------------------------------------------------
# In-memory store (replace with a DB like SQLite/Postgres for production)
# ---------------------------------------------------------------------------
_store: List[EnrichedIOC] = []
_last_fetch: Optional[datetime] = None
_fetch_in_progress: bool = False

BUNDLE_PATH = "stix_bundle.json"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", tags=["Status"])
def root():
    return {
        "service": "CTIL — Cyber Threat Intelligence Library",
        "status":  "running",
        "docs":    "/docs",
        "iocs_in_memory": len(_store),
        "last_fetch": _last_fetch,
    }


@app.get("/stats", response_model=LibraryStats, tags=["Status"])
def get_stats():
    """Return counts by type and source."""
    by_type:   dict = {}
    by_source: dict = {}

    for ioc in _store:
        by_type[ioc.ioc_type]   = by_type.get(ioc.ioc_type, 0) + 1
        by_source[ioc.source]   = by_source.get(ioc.source, 0) + 1

    return LibraryStats(
        total_iocs=len(_store),
        by_type=by_type,
        by_source=by_source,
        last_updated=_last_fetch,
    )


@app.post("/fetch", tags=["Ingestion"])
def trigger_fetch(
    background_tasks: BackgroundTasks,
    enrich: bool = Query(True,  description="Run VirusTotal enrichment after fetching"),
    max_enrich: int = Query(50, description="Max IOCs to enrich (API limit protection)"),
):
    """
    Trigger a fresh pull from all threat feeds.
    Runs in the background — check /stats to see when it completes.
    """
    global _fetch_in_progress
    if _fetch_in_progress:
        raise HTTPException(status_code=409, detail="A fetch is already in progress.")
    background_tasks.add_task(_run_pipeline, enrich, max_enrich)
    return {"message": "Fetch started in background. Check /stats for progress."}


@app.get("/iocs", response_model=List[EnrichedIOC], tags=["IOCs"])
def get_iocs(
    ioc_type:   Optional[str] = Query(None, description="Filter by type: ip, url, domain, hash"),
    source:     Optional[str] = Query(None, description="Filter by source name"),
    threat_type: Optional[str] = Query(None, description="Filter by threat type"),
    malicious_only: bool = Query(False, description="Only show VT-confirmed malicious"),
    limit:      int = Query(100, le=1000),
    offset:     int = Query(0),
):
    """
    Retrieve IOCs with optional filters.
    """
    results = _store

    if ioc_type:
        results = [i for i in results if i.ioc_type == ioc_type]
    if source:
        results = [i for i in results if source.lower() in i.source.lower()]
    if threat_type:
        results = [i for i in results if i.threat_type == threat_type]
    if malicious_only:
        results = [i for i in results if (i.vt_malicious_count or 0) > 0]

    return results[offset: offset + limit]


@app.get("/iocs/search", response_model=List[EnrichedIOC], tags=["IOCs"])
def search_iocs(q: str = Query(..., description="Value to search for (partial match)")):
    """
    Search IOCs by value (partial string match).
    """
    q_lower = q.lower()
    return [i for i in _store if q_lower in i.value.lower()]


@app.get("/iocs/{ioc_value}", response_model=EnrichedIOC, tags=["IOCs"])
def get_ioc_by_value(ioc_value: str):
    """
    Look up a specific IOC by exact value.
    """
    for ioc in _store:
        if ioc.value == ioc_value:
            return ioc
    raise HTTPException(status_code=404, detail=f"IOC '{ioc_value}' not found.")


@app.post("/stix/export", tags=["STIX"])
def export_stix(
    ioc_type: Optional[str] = Query(None, description="Filter by type before export"),
    save_to_file: bool = Query(True, description="Save bundle to stix_bundle.json"),
):
    """
    Convert all stored IOCs to a STIX 2.1 bundle.
    Returns the bundle as JSON and optionally saves it to disk.
    """
    iocs = _store
    if ioc_type:
        iocs = [i for i in iocs if i.ioc_type == ioc_type]

    if not iocs:
        raise HTTPException(status_code=404, detail="No IOCs in library. Run /fetch first.")

    bundle = convert_to_stix_bundle(iocs)

    if save_to_file:
        save_bundle_to_file(bundle, BUNDLE_PATH)

    return JSONResponse(content=bundle)


@app.get("/stix/bundle", tags=["STIX"])
def download_stix_bundle():
    """
    Download the last saved STIX bundle from disk.
    """
    if not os.path.exists(BUNDLE_PATH):
        raise HTTPException(
            status_code=404,
            detail="No bundle saved yet. POST to /stix/export first."
        )
    with open(BUNDLE_PATH) as f:
        bundle = json.load(f)
    return JSONResponse(content=bundle)


# ---------------------------------------------------------------------------
# Background pipeline
# ---------------------------------------------------------------------------

def _run_pipeline(enrich: bool, max_enrich: int):
    global _store, _last_fetch, _fetch_in_progress
    _fetch_in_progress = True

    print("\n" + "="*60)
    print("CTIL Pipeline Starting")
    print("="*60)

    all_iocs = []

    # 1. Fetch from all sources
    otx_result = fetch_otx_iocs()
    all_iocs.extend(otx_result.iocs)

    abuse_result = fetch_abusech_iocs()
    all_iocs.extend(abuse_result.iocs)

    print(f"\n[Pipeline] Total raw IOCs collected: {len(all_iocs)}")

    # 2. Deduplicate by value
    seen = set()
    unique_iocs = []
    for ioc in all_iocs:
        if ioc.value not in seen:
            seen.add(ioc.value)
            unique_iocs.append(ioc)

    print(f"[Pipeline] After deduplication: {len(unique_iocs)} unique IOCs")

    # 3. Enrich with VirusTotal
    if enrich:
        print(f"\n[Pipeline] Enriching up to {max_enrich} IOCs via VirusTotal...")
        enriched = enrich_iocs(unique_iocs, max_enrichments=max_enrich)
    else:
        from models import EnrichedIOC
        enriched = [EnrichedIOC(**i.model_dump(), enrichment_status="skipped",
                                enrichment_error="enrichment disabled")
                    for i in unique_iocs]

    # 4. Store results
    _store = enriched
    _last_fetch = datetime.now(timezone.utc)
    _fetch_in_progress = False

    print(f"\n[Pipeline] Done. {len(_store)} IOCs now in library.")
    print("="*60 + "\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=API_HOST, port=API_PORT, reload=True)
