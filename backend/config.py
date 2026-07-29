import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
try:
    DATA_DIR.mkdir(exist_ok=True)
except Exception:
    DATA_DIR = Path("/tmp/data")
    DATA_DIR.mkdir(exist_ok=True)

DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DATA_DIR}/scanner.db")
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production-insecure-default")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
AI_PROVIDER = os.getenv("AI_PROVIDER", "rule")
AI_MODEL = os.getenv("AI_MODEL", "gpt-4o-mini")

SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "600"))
MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "3"))
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "10"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

DEFAULT_SCAN_PROFILES = {
    "quick": {
        "name": "Quick Scan",
        "description": "Common ports, fast scan",
        "ports": "22,80,443,8080,8443,3306,5432,6379,27017,3389",
        "scan_type": "tcp_connect",
        "timing": "T4",
        "discovery": True,
    },
    "full": {
        "name": "Full Scan",
        "description": "All ports, service detection",
        "ports": "1-65535",
        "scan_type": "tcp_connect",
        "timing": "T3",
        "discovery": True,
        "service_detect": True,
    },
    "stealth": {
        "name": "Stealth SYN Scan",
        "description": "SYN scan, common ports",
        "ports": "22,80,443,8080,8443",
        "scan_type": "syn",
        "timing": "T2",
        "discovery": True,
    },
    "udp": {
        "name": "UDP Scan",
        "description": "Common UDP ports",
        "ports": "53,67,68,123,161,162,500,514,520,1900",
        "scan_type": "udp",
        "timing": "T3",
        "discovery": True,
    },
    "comprehensive": {
        "name": "Comprehensive Scan",
        "description": "All ports, service+OS detection, UDP top 50",
        "ports": "1-65535",
        "scan_type": "tcp_connect",
        "timing": "T3",
        "discovery": True,
        "service_detect": True,
        "os_detect": True,
        "udp_ports": "53,67,68,123,161,162,500,514,520,1900",
    },
}