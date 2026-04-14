# CTIL — Cyber Threat Intelligence Library

Aggregates IOCs from **AlienVault OTX** and **abuse.ch**, enriches them
via **VirusTotal**, converts everything to **STIX 2.1**, and exposes the
data through a **FastAPI REST API**.

---

## What It Does

```
AlienVault OTX ──┐
                  ├──► Fetch IOCs ──► Deduplicate ──► Enrich (VirusTotal)
abuse.ch ─────────┘                                        │
                                                           ▼
                                                  Convert to STIX 2.1
                                                           │
                                                           ▼
                                               FastAPI REST API  /  JSON file
                                               (ready for OpenCTI / TAXII)
```

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.11 or 3.12 | Check with `python --version` |
| pip | Comes with Python |
| AlienVault OTX account | Free at https://otx.alienvault.com |
| VirusTotal account | Free at https://www.virustotal.com |

---

## Step 1 — Get Your API Keys

### AlienVault OTX
1. Go to https://otx.alienvault.com and create a free account
2. After logging in, click your **username (top right) → Settings**
3. Your API key is shown under **"OTX Key"** — copy it

### VirusTotal
1. Go to https://www.virustotal.com and create a free account
2. After logging in, click your **profile icon (top right) → API Key**
3. Copy the key shown on that page

> **Free tier limits:**
> - OTX: Unlimited reads
> - VirusTotal: 4 requests/minute, 500 requests/day
> The code automatically waits 15 seconds between VT requests to stay within limits.

---

## Step 2 — Set Up the Project

Open a terminal and run the following commands **one at a time**:

```bash
# Clone or copy the project folder to your machine, then:

cd ctil

# Create a virtual environment (keeps dependencies isolated)
python -m venv venv

# Activate the virtual environment
# On Windows:
venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

You should see packages installing. This takes about 1–2 minutes.

---

## Step 3 — Add Your API Keys to config.py

Open `config.py` in any text editor and replace the placeholder values:

```python
# Line 8 — replace with your OTX key
OTX_API_KEY = "abc123yourkeyhere"

# Line 18 — replace with your VirusTotal key
VIRUSTOTAL_API_KEY = "def456yourkeyhere"
```

Save the file. That's all you need to change before running.

---

## Step 4 — Start the API Server

```bash
# Make sure you're in the ctil/ folder and venv is activated
uvicorn main:app --reload
```

You should see output like:
```
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
INFO:     Started reloader process
```

**Leave this terminal open.** The server runs until you press `CTRL+C`.

---

## Step 5 — Use the API

Open your browser and go to:

```
http://127.0.0.1:8000/docs
```

This opens the **Swagger UI** — a visual interface for all API endpoints.
You can trigger fetches and view results directly from here.

---

## API Endpoints

### Trigger a full fetch from all sources
```
POST http://127.0.0.1:8000/fetch
```
- This runs in the background (takes 2–5 minutes depending on VT rate limits)
- Query param `?enrich=false` to skip VirusTotal (faster, no API usage)
- Query param `?max_enrich=20` to limit VT calls (default: 50)

### Check library status
```
GET http://127.0.0.1:8000/stats
```
Returns total IOC count, breakdown by type, and last fetch time.

### Browse all IOCs
```
GET http://127.0.0.1:8000/iocs
```
Optional filters:
- `?ioc_type=ip` — only IPs
- `?ioc_type=hash` — only file hashes
- `?threat_type=botnet`
- `?malicious_only=true` — only VT-confirmed malicious
- `?limit=50&offset=0` — pagination

### Search for a specific value
```
GET http://127.0.0.1:8000/iocs/search?q=185.220
```

### Look up exact IOC
```
GET http://127.0.0.1:8000/iocs/185.220.101.1
```

### Export everything as STIX 2.1 bundle
```
POST http://127.0.0.1:8000/stix/export
```
Returns a STIX 2.1 Bundle JSON and saves `stix_bundle.json` to disk.

### Download last saved STIX bundle
```
GET http://127.0.0.1:8000/stix/bundle
```

---

## Testing Without a Browser (curl)

```bash
# Trigger fetch (no VirusTotal enrichment, faster)
curl -X POST "http://127.0.0.1:8000/fetch?enrich=false"

# Check stats
curl http://127.0.0.1:8000/stats

# Get first 10 IOCs
curl "http://127.0.0.1:8000/iocs?limit=10"

# Export STIX bundle
curl -X POST http://127.0.0.1:8000/stix/export -o bundle.json
```

---

## File Structure

```
ctil/
├── config.py               ← API keys go here
├── models.py               ← IOC data models
├── main.py                 ← FastAPI server
├── requirements.txt        ← Python dependencies
│
├── fetchers/
│   ├── otx.py              ← AlienVault OTX feed
│   └── abusech.py          ← URLhaus, MalwareBazaar, Feodo Tracker
│
├── enrichment/
│   └── virustotal.py       ← VirusTotal enrichment
│
└── stix_converter/
    └── converter.py        ← STIX 2.1 bundle generation
```

---

## Running Individual Modules (for testing)

You can test each component on its own:

```bash
# Test OTX fetcher alone
python fetchers/otx.py

# Test abuse.ch fetcher alone
python fetchers/abusech.py

# Test VirusTotal enrichment on a known malicious hash
python enrichment/virustotal.py

# Test STIX conversion with a dummy IOC
python stix_converter/converter.py
```

---

## Connecting to OpenCTI (when you're ready)

Once you have OpenCTI deployed:

1. Open `config.py`
2. Set `OPENCTI_URL` to your OpenCTI instance URL (e.g. `http://localhost:8080`)
3. Set `OPENCTI_API_KEY` to your OpenCTI API key (found in OpenCTI → Profile)
4. Export a STIX bundle: `POST /stix/export`
5. Import `stix_bundle.json` into OpenCTI via:
   - OpenCTI UI → **Data → Import → Upload file**
   - Or use the OpenCTI Python client to push programmatically

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'fastapi'` | Run `pip install -r requirements.txt` with venv activated |
| OTX returns 0 IOCs | Check your API key in config.py — must be exact, no spaces |
| VirusTotal returns 429 | Rate limit hit — wait 60 seconds, or set `?max_enrich=10` |
| Server won't start on port 8000 | Change `API_PORT` in config.py to e.g. 8001 |
| `venv\Scripts\activate` doesn't work on Windows | Run in PowerShell, not CMD |

---

## What to Say in an Interview

> "The library pulls IOCs from AlienVault OTX and abuse.ch feeds including
> URLhaus, MalwareBazaar, and the Feodo Tracker. Each IOC is deduplicated,
> then optionally enriched through VirusTotal to get engine detection counts
> and confidence scores. The enriched data is converted to STIX 2.1 format
> — using proper Indicator, Malware, and Relationship objects — and exposed
> via a REST API built in FastAPI. The STIX bundle output is designed to be
> imported directly into OpenCTI, which I deployed and configured separately
> to centralise the intelligence."
