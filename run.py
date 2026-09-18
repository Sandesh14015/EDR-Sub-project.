import sys
import threading
import time
import webbrowser
import uvicorn
from backend.config import HOST, PORT


def open_browser():
    time.sleep(1.2)
    url = f"http://{HOST}:{PORT}"
    try:
        webbrowser.open(url)
    except Exception:
        pass


if __name__ == "__main__":
    print("=" * 68)
    print("  🛡️ Network Intrusion Detection & Incident Intelligence Platform")
    print("=" * 68)
    print(f"  * Web Dashboard:        http://{HOST}:{PORT}")
    print(f"  * Interactive API Docs: http://{HOST}:{PORT}/docs")
    print("=" * 68)
    print("  Opening browser automatically...")

    # Open web browser in background thread
    threading.Thread(target=open_browser, daemon=True).start()

    # Start FastAPI server
    uvicorn.run("backend.main:app", host=HOST, port=PORT, reload=False)
