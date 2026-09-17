import json
import sqlite3
from typing import Any, Dict, List, Optional
from backend.config import DB_PATH
from backend.models import (
    EvidenceItem,
    Incident,
    IncidentStatus,
    NormalizedEvent,
    RecommendationItem,
    SeverityLevel,
    ThreatCategory,
)


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_connection() as conn:
        cursor = conn.cursor()

        # Events table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                src_ip TEXT,
                src_port INTEGER,
                dst_ip TEXT,
                dst_port INTEGER,
                protocol TEXT,
                domain TEXT,
                severity INTEGER DEFAULT 0,
                signature TEXT,
                flow_id TEXT,
                sensor_id TEXT,
                raw_json TEXT
            )
            """
        )

        # Incidents table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                status TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                confidence INTEGER NOT NULL,
                threat_category TEXT NOT NULL,
                affected_assets TEXT,
                source_entities TEXT,
                destination_entities TEXT,
                first_seen TEXT,
                last_seen TEXT,
                created_at TEXT,
                updated_at TEXT
            )
            """
        )

        # Incident to Events link table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS incident_events (
                incident_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                relationship_type TEXT DEFAULT 'correlated',
                PRIMARY KEY (incident_id, event_id),
                FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
                FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
            )
            """
        )

        # Evidence table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                source TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                description TEXT,
                FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
            )
            """
        )

        # Recommendations table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS recommendations (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                category TEXT NOT NULL,
                priority TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                status TEXT DEFAULT 'OPEN',
                FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
            )
            """
        )

        # Reports table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                report_type TEXT DEFAULT 'INCIDENT_INVESTIGATION',
                content_markdown TEXT,
                content_html TEXT,
                FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
            )
            """
        )
        conn.commit()


def save_event(event: NormalizedEvent) -> None:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO events (
                id, timestamp, source, event_type, src_ip, src_port, dst_ip, dst_port,
                protocol, domain, severity, signature, flow_id, sensor_id, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                event.timestamp,
                event.source,
                event.event_type,
                event.src_ip,
                event.src_port,
                event.dst_ip,
                event.dst_port,
                event.protocol,
                event.domain,
                event.severity,
                event.signature,
                event.flow_id,
                event.sensor_id,
                json.dumps(event.raw_event or {}),
            ),
        )
        conn.commit()


def save_events_batch(events: List[NormalizedEvent]) -> None:
    with get_connection() as conn:
        cursor = conn.cursor()
        for event in events:
            cursor.execute(
                """
                INSERT OR REPLACE INTO events (
                    id, timestamp, source, event_type, src_ip, src_port, dst_ip, dst_port,
                    protocol, domain, severity, signature, flow_id, sensor_id, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.timestamp,
                    event.source,
                    event.event_type,
                    event.src_ip,
                    event.src_port,
                    event.dst_ip,
                    event.dst_port,
                    event.protocol,
                    event.domain,
                    event.severity,
                    event.signature,
                    event.flow_id,
                    event.sensor_id,
                    json.dumps(event.raw_event or {}),
                ),
            )
        conn.commit()


def get_all_events(limit: int = 500) -> List[NormalizedEvent]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        result = []
        for r in rows:
            raw = json.loads(r["raw_json"]) if r["raw_json"] else {}
            result.append(
                NormalizedEvent(
                    event_id=r["id"],
                    timestamp=r["timestamp"],
                    source=r["source"],
                    event_type=r["event_type"],
                    src_ip=r["src_ip"],
                    src_port=r["src_port"],
                    dst_ip=r["dst_ip"],
                    dst_port=r["dst_port"],
                    protocol=r["protocol"],
                    domain=r["domain"],
                    severity=r["severity"],
                    signature=r["signature"],
                    flow_id=r["flow_id"],
                    sensor_id=r["sensor_id"],
                    raw_event=raw,
                )
            )
        return result


def get_event_by_id(event_id: str) -> Optional[NormalizedEvent]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM events WHERE id = ?", (event_id,))
        r = cursor.fetchone()
        if not r:
            return None
        raw = json.loads(r["raw_json"]) if r["raw_json"] else {}
        return NormalizedEvent(
            event_id=r["id"],
            timestamp=r["timestamp"],
            source=r["source"],
            event_type=r["event_type"],
            src_ip=r["src_ip"],
            src_port=r["src_port"],
            dst_ip=r["dst_ip"],
            dst_port=r["dst_port"],
            protocol=r["protocol"],
            domain=r["domain"],
            severity=r["severity"],
            signature=r["signature"],
            flow_id=r["flow_id"],
            sensor_id=r["sensor_id"],
            raw_event=raw,
        )


def save_incident(incident: Incident, event_ids: Optional[List[str]] = None) -> None:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO incidents (
                id, title, description, status, severity, risk_score, confidence,
                threat_category, affected_assets, source_entities, destination_entities,
                first_seen, last_seen, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident.id,
                incident.title,
                incident.description,
                incident.status.value if isinstance(incident.status, IncidentStatus) else incident.status,
                incident.severity.value if isinstance(incident.severity, SeverityLevel) else incident.severity,
                incident.risk_score,
                incident.confidence,
                incident.threat_category.value if isinstance(incident.threat_category, ThreatCategory) else incident.threat_category,
                json.dumps(incident.affected_assets),
                json.dumps(incident.source_entities),
                json.dumps(incident.destination_entities),
                incident.first_seen,
                incident.last_seen,
                incident.created_at,
                incident.updated_at,
            ),
        )

        ids_to_link = event_ids or incident.event_ids
        for eid in ids_to_link:
            cursor.execute(
                """
                INSERT OR IGNORE INTO incident_events (incident_id, event_id, relationship_type)
                VALUES (?, ?, ?)
                """,
                (incident.id, eid, "correlated"),
            )
        conn.commit()


def update_incident_status(incident_id: str, new_status: str) -> bool:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE incidents SET status = ? WHERE id = ?",
            (new_status, incident_id),
        )
        conn.commit()
        return cursor.rowcount > 0


def get_all_incidents() -> List[Incident]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM incidents ORDER BY risk_score DESC, created_at DESC")
        rows = cursor.fetchall()
        result = []
        for r in rows:
            cursor.execute("SELECT event_id FROM incident_events WHERE incident_id = ?", (r["id"],))
            ev_rows = cursor.fetchall()
            ev_ids = [er["event_id"] for er in ev_rows]

            result.append(
                Incident(
                    id=r["id"],
                    title=r["title"],
                    description=r["description"] or "",
                    status=IncidentStatus(r["status"]),
                    severity=SeverityLevel(r["severity"]),
                    risk_score=r["risk_score"],
                    confidence=r["confidence"],
                    threat_category=ThreatCategory(r["threat_category"]),
                    affected_assets=json.loads(r["affected_assets"]) if r["affected_assets"] else [],
                    source_entities=json.loads(r["source_entities"]) if r["source_entities"] else [],
                    destination_entities=json.loads(r["destination_entities"]) if r["destination_entities"] else [],
                    first_seen=r["first_seen"],
                    last_seen=r["last_seen"],
                    created_at=r["created_at"],
                    updated_at=r["updated_at"],
                    event_ids=ev_ids,
                )
            )
        return result


def get_incident_by_id(incident_id: str) -> Optional[Incident]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        r = cursor.fetchone()
        if not r:
            return None

        cursor.execute("SELECT event_id FROM incident_events WHERE incident_id = ?", (incident_id,))
        ev_rows = cursor.fetchall()
        ev_ids = [er["event_id"] for er in ev_rows]

        return Incident(
            id=r["id"],
            title=r["title"],
            description=r["description"] or "",
            status=IncidentStatus(r["status"]),
            severity=SeverityLevel(r["severity"]),
            risk_score=r["risk_score"],
            confidence=r["confidence"],
            threat_category=ThreatCategory(r["threat_category"]),
            affected_assets=json.loads(r["affected_assets"]) if r["affected_assets"] else [],
            source_entities=json.loads(r["source_entities"]) if r["source_entities"] else [],
            destination_entities=json.loads(r["destination_entities"]) if r["destination_entities"] else [],
            first_seen=r["first_seen"],
            last_seen=r["last_seen"],
            created_at=r["created_at"],
            updated_at=r["updated_at"],
            event_ids=ev_ids,
        )


def get_incident_events(incident_id: str) -> List[NormalizedEvent]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT e.* FROM events e
            JOIN incident_events ie ON e.id = ie.event_id
            WHERE ie.incident_id = ?
            ORDER BY e.timestamp ASC
            """,
            (incident_id,),
        )
        rows = cursor.fetchall()
        result = []
        for r in rows:
            raw = json.loads(r["raw_json"]) if r["raw_json"] else {}
            result.append(
                NormalizedEvent(
                    event_id=r["id"],
                    timestamp=r["timestamp"],
                    source=r["source"],
                    event_type=r["event_type"],
                    src_ip=r["src_ip"],
                    src_port=r["src_port"],
                    dst_ip=r["dst_ip"],
                    dst_port=r["dst_port"],
                    protocol=r["protocol"],
                    domain=r["domain"],
                    severity=r["severity"],
                    signature=r["signature"],
                    flow_id=r["flow_id"],
                    sensor_id=r["sensor_id"],
                    raw_event=raw,
                )
            )
        return result


def save_evidence_batch(evidence_list: List[EvidenceItem]) -> None:
    with get_connection() as conn:
        cursor = conn.cursor()
        for ev in evidence_list:
            cursor.execute(
                """
                INSERT OR REPLACE INTO evidence (
                    id, incident_id, type, value, source, timestamp, description
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ev.id,
                    ev.incident_id,
                    ev.type,
                    ev.value,
                    ev.source,
                    ev.timestamp,
                    ev.description,
                ),
            )
        conn.commit()


def get_incident_evidence(incident_id: str) -> List[EvidenceItem]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM evidence WHERE incident_id = ? ORDER BY timestamp ASC",
            (incident_id,),
        )
        rows = cursor.fetchall()
        return [
            EvidenceItem(
                id=r["id"],
                incident_id=r["incident_id"],
                type=r["type"],
                value=r["value"],
                source=r["source"],
                timestamp=r["timestamp"],
                description=r["description"] or "",
            )
            for r in rows
        ]


def save_recommendations_batch(rec_list: List[RecommendationItem]) -> None:
    with get_connection() as conn:
        cursor = conn.cursor()
        for rec in rec_list:
            cursor.execute(
                """
                INSERT OR REPLACE INTO recommendations (
                    id, incident_id, category, priority, recommendation, status
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    rec.id,
                    rec.incident_id,
                    rec.category,
                    rec.priority,
                    rec.recommendation,
                    rec.status,
                ),
            )
        conn.commit()


def get_incident_recommendations(incident_id: str) -> List[RecommendationItem]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM recommendations WHERE incident_id = ? ORDER BY priority DESC",
            (incident_id,),
        )
        rows = cursor.fetchall()
        return [
            RecommendationItem(
                id=r["id"],
                incident_id=r["incident_id"],
                category=r["category"],
                priority=r["priority"],
                recommendation=r["recommendation"],
                status=r["status"],
            )
            for r in rows
        ]


def save_report(incident_id: str, report_md: str, report_html: str, report_id: str) -> None:
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO reports (
                id, incident_id, generated_at, report_type, content_markdown, content_html
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (report_id, incident_id, now, "INCIDENT_INVESTIGATION", report_md, report_html),
        )
        conn.commit()


def get_report(incident_id: str) -> Optional[Dict[str, Any]]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM reports WHERE incident_id = ? ORDER BY generated_at DESC LIMIT 1",
            (incident_id,),
        )
        r = cursor.fetchone()
        if not r:
            return None
        return {
            "id": r["id"],
            "incident_id": r["incident_id"],
            "generated_at": r["generated_at"],
            "report_type": r["report_type"],
            "content_markdown": r["content_markdown"],
            "content_html": r["content_html"],
        }


def clear_all_data() -> None:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM incident_events")
        cursor.execute("DELETE FROM evidence")
        cursor.execute("DELETE FROM recommendations")
        cursor.execute("DELETE FROM reports")
        cursor.execute("DELETE FROM incidents")
        cursor.execute("DELETE FROM events")
        conn.commit()
