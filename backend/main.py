from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from pathlib import Path

from backend import database
from backend.adapter import detection_adapter
from backend.collector import ensure_log_dirs, scan_and_ingest_directory
from backend.correlation import correlate_events
from backend.live_scanner import live_scanner
from backend.models import (
    Incident,
    IncidentDetail,
    IncidentStatus,
    NormalizedEvent,
    NotificationItem,
)
from backend.reporter import generate_incident_report
from backend.sample_data import (
    get_scenario_account_compromise,
    get_scenario_password_spray,
    get_scenario_endpoint_persistence,
    get_scenario_app_abuse,
    get_scenario_c2_beaconing,
)
from backend.timeline import build_attack_timeline
from backend.wazuh_ips import ips_engine

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    database.init_db()
    ensure_log_dirs()
    yield
    live_scanner.stop()


app = FastAPI(
    title="CYBERGUARD Detection Module (EDR)",
    description="Wazuh Backbone + Suricata IDS/IPS + Incident Intelligence Layer",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Web UI Route ---
@app.get("/", response_class=FileResponse)
def serve_dashboard():
    index_path = FRONTEND_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Dashboard index.html not found.")
    return FileResponse(str(index_path))


# --- System Status ---
@app.get("/api/status")
def get_system_status():
    incidents = database.get_all_incidents()
    events = database.get_all_events(limit=1000)
    notifs = database.get_recent_notifications(limit=10)
    return {
        "status": "online",
        "platform": "CYBERGUARD EDR",
        "total_events": len(events),
        "total_incidents": len(incidents),
        "open_incidents": len([i for i in incidents if i.status not in (IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE)]),
        "blocked_ips_count": len(ips_engine.get_blocked_ips()),
        "scanner": live_scanner.get_status(),
        "recent_notifications": [n.dict() for n in notifs[:3]],
    }


# --- CYBERGUARD Detection Module Adapter Routes ---
class IngestPayload(BaseModel):
    raw_data: str
    source_hint: Optional[str] = None  # "wazuh", "suricata", or None


@app.post("/api/ingest")
def ingest_data(payload: IngestPayload):
    events = detection_adapter.process_generic_stream(payload.raw_data)
    incidents = correlate_events()
    return {
        "message": f"Adapter processed {len(events)} events and updated {len(incidents)} incidents.",
        "events_count": len(events),
        "incidents_count": len(incidents),
    }


@app.post("/api/adapter/wazuh")
def ingest_wazuh_webhook(payload: Dict[str, Any]):
    """Receives JSON alerts directly from Wazuh Server (4.14.x compatible)."""
    events = detection_adapter.process_wazuh_alert(payload)
    incidents = correlate_events()
    return {
        "status": "accepted",
        "events_ingested": len(events),
        "incidents_active": len(incidents),
    }


@app.post("/api/adapter/suricata")
def ingest_suricata_webhook(payload: Dict[str, Any]):
    """Receives Suricata EVE JSON alerts directly."""
    events = detection_adapter.process_suricata_eve(payload)
    incidents = correlate_events()
    return {
        "status": "accepted",
        "events_ingested": len(events),
        "incidents_active": len(incidents),
    }


# --- Notifications Endpoint ---
@app.get("/api/notifications", response_model=List[NotificationItem])
def get_notifications(limit: int = 50):
    return database.get_recent_notifications(limit=limit)


# --- Live Scanner & Host Telemetry ---
@app.post("/api/scan/start")
def start_live_scan():
    live_scanner.start()
    return {"message": "Live host socket scanner started.", "status": live_scanner.get_status()}


@app.post("/api/scan/stop")
def stop_live_scan():
    live_scanner.stop()
    return {"message": "Live host socket scanner stopped.", "status": live_scanner.get_status()}


@app.post("/api/scan/snapshot")
def take_scan_snapshot():
    events = live_scanner.scan_once()
    incidents = correlate_events()
    return {
        "message": f"Inspected active system sockets. Captured {len(events)} telemetry events.",
        "events_count": len(events),
        "incidents_count": len(incidents),
        "incidents": incidents,
    }


@app.get("/api/system/connections")
def get_system_connections(limit: int = 50):
    import psutil
    conns = []
    try:
        raw = psutil.net_connections(kind="inet")
        for c in raw:
            if not c.raddr:
                continue
            pname = "Unknown"
            if c.pid:
                try:
                    pname = psutil.Process(c.pid).name()
                except Exception:
                    pname = f"PID-{c.pid}"
            conns.append({
                "local_ip": c.laddr.ip if c.laddr else "*",
                "local_port": c.laddr.port if c.laddr else 0,
                "remote_ip": c.raddr.ip,
                "remote_port": c.raddr.port,
                "status": c.status or "UNKNOWN",
                "pid": c.pid,
                "process_name": pname,
            })
    except Exception as e:
        print(f"Error reading connections: {e}")
    return conns[:limit]


# --- Correlation & Incidents ---
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


# --- Active Response (IPS) Endpoints ---
class BlockIPRequest(BaseModel):
    ip_address: str
    incident_id: Optional[str] = None
    reason: Optional[str] = "CYBERGUARD Active Response Containment"


@app.post("/api/ips/block")
def block_ip(payload: BlockIPRequest):
    res = ips_engine.block_ip(payload.ip_address, reason=payload.reason or "Active Response")
    if payload.incident_id:
        database.update_incident_status(payload.incident_id, IncidentStatus.CONTAINED.value)
    return res


class UnblockIPRequest(BaseModel):
    ip_address: str


@app.post("/api/ips/unblock")
def unblock_ip(payload: UnblockIPRequest):
    return ips_engine.unblock_ip(payload.ip_address)


class TerminateProcessRequest(BaseModel):
    pid: int
    process_name: Optional[str] = None
    incident_id: Optional[str] = None


@app.post("/api/ips/terminate")
def terminate_process(payload: TerminateProcessRequest):
    res = ips_engine.terminate_process(payload.pid, process_name=payload.process_name)
    if payload.incident_id and res.get("success"):
        database.update_incident_status(payload.incident_id, IncidentStatus.CONTAINED.value)
    return res


@app.get("/api/ips/blocked")
def get_blocked_ips():
    return ips_engine.get_blocked_ips()


# --- Scenarios Endpoint (User End-to-End & 4 Domains) ---
@app.post("/api/scenarios/{name}/load")
def load_scenario(name: str):
    if name == "account_compromise":
        raw = get_scenario_account_compromise()
    elif name == "password_spray":
        raw = get_scenario_password_spray()
    elif name == "endpoint_persistence":
        raw = get_scenario_endpoint_persistence()
    elif name == "app_abuse":
        raw = get_scenario_app_abuse()
    elif name == "c2":
        raw = get_scenario_c2_beaconing()
    else:
        raise HTTPException(status_code=404, detail=f"Scenario '{name}' not found.")

    events = detection_adapter.process_generic_stream(raw)
    incidents = correlate_events()
    return {
        "message": f"Loaded scenario '{name}'. Ingested {len(events)} events, created {len(incidents)} incidents.",
        "events_count": len(events),
        "incidents": incidents,
    }


# --- CYBERGUARD Parent Platform Feed ---
@app.get("/api/cyberguard/feed")
def get_cyberguard_feed():
    """Feeds verified incidents and real-time notifications to the parent CYBERGUARD platform."""
    incidents = database.get_all_incidents()
    notifs = database.get_recent_notifications(limit=25)
    return {
        "module": "CYBERGUARD_EDR_DETECTION",
        "status": "HEALTHY",
        "incidents": [i.dict() for i in incidents],
        "notifications": [n.dict() for n in notifs],
    }


@app.post("/api/clear")
def clear_data():
    database.clear_all_data()
    return {"message": "All CYBERGUARD EDR database tables cleared."}
