import os

path = "/Users/sandesh/myOpenCode/ai-based-nmap-tool/backend/cli/main.py"
parts = []

parts.append("import click")
parts.append("import json")
parts.append("import os")
parts.append("import sys")
parts.append("import time")
parts.append("import urllib.request")
parts.append("import urllib.error")
parts.append("import urllib.parse")
parts.append("from pathlib import Path")
parts.append("from datetime import datetime")
parts.append("from rich.console import Console")
parts.append("from rich.table import Table")
parts.append("from rich.panel import Panel")
parts.append("from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn")
parts.append("")
parts.append("console = Console()")
parts.append("CONFIG_DIR = Path.home() / '.nmap-ai'")
parts.append("CONFIG_FILE = CONFIG_DIR / 'config.json'")
parts.append('API_BASE = "http://localhost:8000/api/v1"')
parts.append("")

with open(path, "w") as f:
    f.write("\n".join(parts))
print("CLI header written")