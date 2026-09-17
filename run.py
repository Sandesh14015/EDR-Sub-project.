import sys
import uvicorn
from backend.config import HOST, PORT

if __name__ == "__main__":
    print("=" * 65)
    print("  Network Detection & Incident Intelligence Platform (EDR)")
    print("=" * 65)
    print(f"  * Web Dashboard: http://{HOST}:{PORT}")
    print(f"  * Interactive API Docs: http://{HOST}:{PORT}/docs")
    print("=" * 65)
    uvicorn.run("backend.main:app", host=HOST, port=PORT, reload=True)
