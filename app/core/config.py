import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
SAMPLES_DIR = DATA_DIR / "samples"
PCAP_DIR = DATA_DIR / "pcaps"
REPORTS_DIR = DATA_DIR / "reports"
DB_PATH = DATA_DIR / "msa_soc.db"

# Create required directories
for directory in [DATA_DIR, UPLOAD_DIR, SAMPLES_DIR, PCAP_DIR, REPORTS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

APP_NAME = "Vanguard MSA (Malware Sandbox & Analysis Platform)"
APP_VERSION = "2.4.0-SOC"
MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100 MB

# Threat Intel settings (analysts can provide API keys or use local high-fidelity intelligence)
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
