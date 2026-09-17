import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "edr_platform.db"
LOGS_DIR = BASE_DIR / "sensor_logs"

# Correlation settings
CORRELATION_TIME_WINDOW_SECONDS = 600  # 10 minutes window

# Host and Port
HOST = "127.0.0.1"
PORT = 8000
