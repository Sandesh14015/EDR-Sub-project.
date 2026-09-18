from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel
from pathlib import Path

from backend import database
from backend.collector import ensure_log_dirs, ingest_from_text, scan_and_ingest_directory
from backend.correlation import correlate_events
from backend.models import (
    Incident,
    IncidentDetail,
    IncidentStatus,
    NormalizedEvent,
)
from backend.reporter import generate_incident_report
from backend.sample_data import (
    get_scenario_c2_beaconing,
    get_scenario_scanning,
    get_scenario_ssh_brute_force,
)
from backend.live_scanner import live_scanner
from backend.timeline import build_attack_timeline

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database on startup
    database.init_db()
    ensure_log_dirs()
    yield
    # Stop background scanner on shutdown
    live_scanner.stop()


app = FastAPI(
    title="Network Detection & Incident Intelligence Platform",
    description="Minimal-stack intelligence layer correlating Suricata detection and Zeek telemetry.",
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for convenience
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Static and Web UI Route ---
@app.get("/", response_class=FileResponse)
def serve_dashboard():
    index_path = FRONTEND_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Dashboard index.html not found.")
    return FileResponse(str(index_path))


# --- API Routes ---
@app.get("/api/status")
def get_system_status():
    incidents = database.get_all_incidents()
    events = database.get_all_events(limit=1000)
    scan_status = live_scanner.get_status()
    return {
        "status": "online",
        "total_events": len(events),
        "total_incidents": len(incidents),
        "open_incidents": len([i for i in incidents if i.status not in (IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE)]),
        "scanner": scan_status,
    }


@app.post("/api/scan/start")
def start_live_scan():
    live_scanner.start()
    return {"message": "Live network traffic monitoring started on your system.", "status": live_scanner.get_status()}


@app.post("/api/scan/stop")
def stop_live_scan():
    live_scanner.stop()
    return {"message": "Live network traffic monitoring stopped.", "status": live_scanner.get_status()}


@app.get("/api/scan/status")
def get_live_scan_status():
    return live_scanner.get_status()


@app.post("/api/scan/snapshot")
def take_scan_snapshot():
    events = live_scanner.scan_once()
    incidents = correlate_events()
    return {
        "message": f"Scanned live network connections. Captured {len(events)} telemetry events and checked intrusion rules.",
        "events_count": len(events),
        "incidents_count": len(incidents),
        "incidents": incidents,
    }


@app.get("/api/system/connections")
def get_active_system_connections(limit: int = 50):
    """Returns real-time active network connections with process context."""
    import psutil
    conns = []
    try:
        raw_conns = psutil.net_connections(kind="inet")
        for c in raw_conns:
            if not c.raddr:
                continue
            proc_name = "Unknown"
            if c.pid:
                try:
                    proc_name = psutil.Process(c.pid).name()
                except Exception:
                    proc_name = f"PID-{c.pid}"
            conns.append({
                "local_ip": c.laddr.ip if c.laddr else "*",
                "local_port": c.laddr.port if c.laddr else 0,
                "remote_ip": c.raddr.ip,
                "remote_port": c.raddr.port,
                "status": c.status or "UNKNOWN",
                "pid": c.pid,
                "process_name": proc_name,
            })
    except Exception as e:
        print(f"Error reading connections: {e}")
    return conns[:limit]


class IngestRequest(BaseModel):
    raw_data: str
    source_hint: Optional[str] = None  # "suricata", "zeek", or None (auto)


@app.post("/api/ingest")
def ingest_data(payload: IngestRequest):
    events = ingest_from_text(payload.raw_data, default_source=payload.source_hint)
    return {
        "message": f"Successfully parsed and ingested {len(events)} events.",
        "events_count": len(events),
        "event_ids": [e.event_id for e in events],
    }


@app.post("/api/correlate")
def run_correlation():
    incidents = correlate_events()
    return {
        "message": f"Correlation completed. {len(incidents)} incidents generated/updated.",
        "incidents_count": len(incidents),
        "incidents": incidents,
    }


@app.get("/api/incidents", response_model=List[Incident])
def list_incidents():
    return database.get_all_incidents()


@app.get("/api/incidents/{incident_id}", response_model=IncidentDetail)
def get_incident_detail(incident_id: str):
    inc = database.get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found.")

    events = database.get_incident_events(incident_id)
    evidence = database.get_incident_evidence(incident_id)
    recs = database.get_incident_recommendations(incident_id)
    timeline = build_attack_timeline(events, inc.threat_category.value)

    return IncidentDetail(
        incident=inc,
        timeline=timeline,
        evidence=evidence,
        recommendations=recs,
        events=events,
    )


class StatusUpdateRequest(BaseModel):
    status: IncidentStatus


@app.patch("/api/incidents/{incident_id}/status")
def update_status(incident_id: str, payload: StatusUpdateRequest):
    success = database.update_incident_status(incident_id, payload.status.value)
    if not success:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return {"message": f"Incident status updated to {payload.status.value}."}


@app.get("/api/incidents/{incident_id}/report")
def get_report(incident_id: str):
    inc = database.get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found.")

    events = database.get_incident_events(incident_id)
    evidence = database.get_incident_evidence(incident_id)
    recs = database.get_incident_recommendations(incident_id)
    timeline = build_attack_timeline(events, inc.threat_category.value)

    report_md = generate_incident_report(inc, timeline, evidence, recs)
    report_id = f"REP-{inc.id}"
    database.save_report(incident_id, report_md, "", report_id)

    return {
        "incident_id": incident_id,
        "report_id": report_id,
        "markdown": report_md,
    }


@app.get("/api/events", response_model=List[NormalizedEvent])
def list_events(limit: int = 100):
    return database.get_all_events(limit=limit)


@app.get("/api/scenarios/{name}")
def get_scenario(name: str):
    if name == "c2":
        return {"name": "Command & Control Periodic Beaconing", "raw_data": get_scenario_c2_beaconing()}
    elif name == "scan":
        return {"name": "Reconnaissance Port Scan", "raw_data": get_scenario_scanning()}
    elif name == "brute_force":
        return {"name": "SSH Credential Brute Force", "raw_data": get_scenario_ssh_brute_force()}
    raise HTTPException(status_code=404, detail=f"Scenario '{name}' not found.")


@app.post("/api/scenarios/{name}/load")
def load_and_run_scenario(name: str):
    if name == "c2":
        data = get_scenario_c2_beaconing()
    elif name == "scan":
        data = get_scenario_scanning()
    elif name == "brute_force":
        data = get_scenario_ssh_brute_force()
    else:
        raise HTTPException(status_code=404, detail=f"Scenario '{name}' not found.")

    events = ingest_from_text(data)
    incidents = correlate_events()
    return {
        "message": f"Loaded scenario '{name}'. Ingested {len(events)} events, created {len(incidents)} incidents.",
        "events_count": len(events),
        "incidents": incidents,
    }


@app.post("/api/clear")
def clear_data():
    database.clear_all_data()
    return {"message": "All database tables cleared."}
