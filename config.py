# =============================================================================
# config.py — Put your API keys here before running
# =============================================================================

# --- AlienVault OTX ---
# Sign up free at: https://otx.alienvault.com
# Go to: Settings → API Key (top right)
OTX_API_KEY = "YOUR_OTX_API_KEY_HERE"

# How many days back to pull pulses from OTX (14 is a good default)
OTX_DAYS_BACK = 14

# --- VirusTotal ---
# Sign up free at: https://www.virustotal.com
# Go to: Profile (top right) → API Key
# Free tier = 4 requests/minute, 500/day — the code respects this automatically
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"

# --- abuse.ch ---
# No API key needed — all feeds are public
# These are the feeds pulled:
#   URLhaus  : malicious URLs
#   MalwareBazaar : malware hashes
#   Feodo    : C2 IP addresses (banking trojans / botnets)
ABUSECH_URLHAUS_URL   = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
ABUSECH_MALWARE_URL   = "https://mb-api.abuse.ch/api/v1/"
ABUSECH_FEODO_URL     = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

# --- STIX ---
# Identity that will appear as the author of all STIX objects
STIX_IDENTITY_NAME    = "CTIL - Cyber Threat Intelligence Library"
STIX_IDENTITY_CLASS   = "organization"

# --- OpenCTI (optional — leave blank if not using) ---
# If you deploy OpenCTI later, fill these in and run: python opencti_push.py
OPENCTI_URL           = "http://localhost:8080"
OPENCTI_API_KEY       = "YOUR_OPENCTI_API_KEY_HERE"

# --- API Server ---
# Host and port for the FastAPI server
API_HOST = "127.0.0.1"
API_PORT = 8000

# --- Rate limiting ---
# Seconds to wait between VirusTotal requests (free tier = 15s safe)
VT_RATE_LIMIT_SECONDS = 15
