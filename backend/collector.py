import os
from pathlib import Path
from typing import List
from backend.config import LOGS_DIR
from backend import database
from backend.models import NormalizedEvent
from backend.normalizer import parse_raw_text


def ensure_log_dirs() -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    (LOGS_DIR / "suricata").mkdir(exist_ok=True)
    (LOGS_DIR / "zeek").mkdir(exist_ok=True)


def ingest_from_text(raw_text: str, default_source: str = None) -> List[NormalizedEvent]:
    """Parses raw log text, normalizes events, and persists them into the database."""
    events = parse_raw_text(raw_text, default_source=default_source)
    if events:
        database.save_events_batch(events)
    return events


def scan_and_ingest_directory() -> int:
    """Scans the sensor_logs directory for any eve.json or Zeek logs and ingests them."""
    ensure_log_dirs()
    count = 0
    for root, _, files in os.walk(LOGS_DIR):
        for file in files:
            file_path = Path(root) / file
            if file_path.suffix in (".json", ".log", ".txt"):
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        events = ingest_from_text(content)
                        count += len(events)
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")
    return count
