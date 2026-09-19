import json
import sqlite3
from contextlib import contextmanager
from typing import Any, Dict, Generator, List, Optional
from backend.config import DB_PATH
from backend.models import (
    EvidenceItem,
    Incident,
    IncidentStatus,
    NormalizedEvent,
    NotificationItem,
    RecommendationItem,
    SeverityLevel,
    ThreatCategory,
    ThreatDomain,
)


@contextmanager
def db_session() -> Generator[sqlite3.Connection, None, None]:
    """Context manager ensuring transactions are committed and connections cleanly closed."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def _ensure_columns(conn: sqlite3.Connection, table_name: str, expected_columns: Dict[str, str]) -> None:
    """Auto-migrates existing tables to add any newly introduced columns."""
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA table_info({table_name})")
    existing = {row["name"] for row in cursor.fetchall()}
    for col_name, col_type in expected_columns.items():
        if col_name not in existing:
            try:
                cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}")
            except Exception as e:
                print(f"Migration note for {table_name}.{col_name}: {e}")


def init_db() -> None:
    with db_session() as conn:
        cursor = conn.cursor()

        # Events table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                domain TEXT DEFAULT 'Network',
                event_type TEXT NOT NULL,
                src_ip TEXT,
                src_port INTEGER,
                dst_ip TEXT,
                dst_port INTEGER,
                protocol TEXT,
                domain_name TEXT,
                severity INTEGER DEFAULT 0,
                signature TEXT,
                flow_id TEXT,
                sensor_id TEXT,
                agent_id TEXT,
                agent_name TEXT,
                rule_id TEXT,
                rule_level INTEGER,
                user TEXT,
                process_name TEXT,
                process_path TEXT,
                process_cmdline TEXT,
                process_pid INTEGER,
                file_path TEXT,
                mitre_json TEXT,
                raw_json TEXT
            )
            """
        )

        _ensure_columns(
            conn,
            "events",
            {
                "domain": "TEXT DEFAULT 'Network'",
                "domain_name": "TEXT",
                "agent_id": "TEXT",
                "agent_name": "TEXT",
                "rule_id": "TEXT",
                "rule_level": "INTEGER",
                "user": "TEXT",
                "process_name": "TEXT",
                "process_path": "TEXT",
                "process_cmdline": "TEXT",
                "process_pid": "INTEGER",
                "file_path": "TEXT",
                "mitre_json": "TEXT",
            },
        )

        # Incidents table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                domain TEXT DEFAULT 'Cross-Domain',
                status TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                confidence INTEGER NOT NULL,
                threat_category TEXT NOT NULL,
                indicators TEXT,
                affected_assets TEXT,
                affected_users TEXT,
                affected_processes TEXT,
                source_entities TEXT,
                destination_entities TEXT,
                mitre_tags TEXT,
                first_seen TEXT,
                last_seen TEXT,
                created_at TEXT,
                updated_at TEXT,
                is_contained INTEGER DEFAULT 0
            )
            """
        )

        _ensure_columns(
            conn,
            "incidents",
            {
                "domain": "TEXT DEFAULT 'Cross-Domain'",
                "indicators": "TEXT",
                "affected_users": "TEXT",
                "affected_processes": "TEXT",
                "mitre_tags": "TEXT",
                "is_contained": "INTEGER DEFAULT 0",
            },
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

        # Notifications table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS notifications (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                incident_id TEXT,
                domain TEXT DEFAULT 'General'
            )
            """
        )


def save_event(event: NormalizedEvent) -> None:
    save_events_batch([event])


def save_events_batch(events: List[NormalizedEvent]) -> None:
    with db_session() as conn:
        cursor = conn.cursor()
        for event in events:
            mitre_data = {
                "tactics": event.mitre_tactics,
                "techniques": event.mitre_techniques,
            }
            cursor.execute(
                """
                INSERT OR REPLACE INTO events (
                    id, timestamp, source, domain, event_type, src_ip, src_port, dst_ip, dst_port,
                    protocol, domain_name, severity, signature, flow_id, sensor_id,
                    agent_id, agent_name, rule_id, rule_level, user, process_name,
                    process_path, process_cmdline, process_pid, file_path, mitre_json, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.timestamp,
                    event.source,
                    event.domain.value if isinstance(event.domain, ThreatDomain) else event.domain,
                    event.event_type,
                    event.src_ip,
                    event.src_port,
                    event.dst_ip,
                    event.dst_port,
                    event.protocol,
                    event.domain_name,
                    event.severity,
                    event.signature,
                    event.flow_id,
                    event.sensor_id,
                    event.agent_id,
                    event.agent_name,
                    event.rule_id,
                    event.rule_level,
                    event.user,
                    event.process_name,
                    event.process_path,
                    event.process_cmdline,
                    event.process_pid,
                    event.file_path,
                    json.dumps(mitre_data),
                    json.dumps(event.raw_event or {}),
                ),
            )


def get_all_events(limit: int = 500) -> List[NormalizedEvent]:
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        result = []
        for r in rows:
            raw = json.loads(r["raw_json"]) if r["raw_json"] else {}
            mitre = json.loads(r["mitre_json"]) if r["mitre_json"] else {}
            result.append(
                NormalizedEvent(
                    event_id=r["id"],
                    timestamp=r["timestamp"],
                    source=r["source"],
                    domain=ThreatDomain(r["domain"]) if r["domain"] in [d.value for d in ThreatDomain] else ThreatDomain.NETWORK,
                    event_type=r["event_type"],
                    src_ip=r["src_ip"],
                    src_port=r["src_port"],
                    dst_ip=r["dst_ip"],
                    dst_port=r["dst_port"],
                    protocol=r["protocol"],
                    domain_name=r["domain_name"],
                    severity=r["severity"],
                    signature=r["signature"],
                    flow_id=r["flow_id"],
                    sensor_id=r["sensor_id"],
                    agent_id=r["agent_id"],
                    agent_name=r["agent_name"],
                    rule_id=r["rule_id"],
                    rule_level=r["rule_level"],
                    user=r["user"],
                    process_name=r["process_name"],
                    process_path=r["process_path"],
                    process_cmdline=r["process_cmdline"],
                    process_pid=r["process_pid"],
                    file_path=r["file_path"],
                    mitre_tactics=mitre.get("tactics", []),
                    mitre_techniques=mitre.get("techniques", []),
                    raw_event=raw,
                )
            )
        return result


def save_incident(incident: Incident, event_ids: Optional[List[str]] = None) -> None:
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO incidents (
                id, title, description, domain, status, severity, risk_score, confidence,
                threat_category, indicators, affected_assets, affected_users, affected_processes,
                source_entities, destination_entities, mitre_tags, first_seen, last_seen,
                created_at, updated_at, is_contained
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident.id,
                incident.title,
                incident.description,
                incident.domain.value if isinstance(incident.domain, ThreatDomain) else incident.domain,
                incident.status.value if isinstance(incident.status, IncidentStatus) else incident.status,
                incident.severity.value if isinstance(incident.severity, SeverityLevel) else incident.severity,
                incident.risk_score,
                incident.confidence,
                incident.threat_category.value if isinstance(incident.threat_category, ThreatCategory) else incident.threat_category,
                json.dumps(incident.indicators),
                json.dumps(incident.affected_assets),
                json.dumps(incident.affected_users),
                json.dumps(incident.affected_processes),
                json.dumps(incident.source_entities),
                json.dumps(incident.destination_entities),
                json.dumps(incident.mitre_tags),
                incident.first_seen,
                incident.last_seen,
                incident.created_at,
                incident.updated_at,
                1 if incident.is_contained else 0,
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


def update_incident_status(incident_id: str, new_status: str) -> bool:
    with db_session() as conn:
        cursor = conn.cursor()
        is_cont = 1 if new_status == IncidentStatus.CONTAINED.value else 0
        cursor.execute(
            "UPDATE incidents SET status = ?, is_contained = max(is_contained, ?) WHERE id = ?",
            (new_status, is_cont, incident_id),
        )
        return cursor.rowcount > 0


def get_all_incidents() -> List[Incident]:
    with db_session() as conn:
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
                    domain=ThreatDomain(r["domain"]) if r["domain"] in [d.value for d in ThreatDomain] else ThreatDomain.CROSS_DOMAIN,
                    status=IncidentStatus(r["status"]),
                    severity=SeverityLevel(r["severity"]),
                    risk_score=r["risk_score"],
                    confidence=r["confidence"],
                    threat_category=ThreatCategory(r["threat_category"]) if r["threat_category"] in [c.value for c in ThreatCategory] else ThreatCategory.UNKNOWN,
                    indicators=json.loads(r["indicators"]) if r["indicators"] else [],
                    affected_assets=json.loads(r["affected_assets"]) if r["affected_assets"] else [],
                    affected_users=json.loads(r["affected_users"]) if r["affected_users"] else [],
                    affected_processes=json.loads(r["affected_processes"]) if r["affected_processes"] else [],
                    source_entities=json.loads(r["source_entities"]) if r["source_entities"] else [],
                    destination_entities=json.loads(r["destination_entities"]) if r["destination_entities"] else [],
                    mitre_tags=json.loads(r["mitre_tags"]) if r["mitre_tags"] else [],
                    first_seen=r["first_seen"],
                    last_seen=r["last_seen"],
                    created_at=r["created_at"],
                    updated_at=r["updated_at"],
                    event_ids=ev_ids,
                    is_contained=bool(r["is_contained"]),
                )
            )
        return result


def get_incident_by_id(incident_id: str) -> Optional[Incident]:
    with db_session() as conn:
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
            domain=ThreatDomain(r["domain"]) if r["domain"] in [d.value for d in ThreatDomain] else ThreatDomain.CROSS_DOMAIN,
            status=IncidentStatus(r["status"]),
            severity=SeverityLevel(r["severity"]),
            risk_score=r["risk_score"],
            confidence=r["confidence"],
            threat_category=ThreatCategory(r["threat_category"]) if r["threat_category"] in [c.value for c in ThreatCategory] else ThreatCategory.UNKNOWN,
            indicators=json.loads(r["indicators"]) if r["indicators"] else [],
            affected_assets=json.loads(r["affected_assets"]) if r["affected_assets"] else [],
            affected_users=json.loads(r["affected_users"]) if r["affected_users"] else [],
            affected_processes=json.loads(r["affected_processes"]) if r["affected_processes"] else [],
            source_entities=json.loads(r["source_entities"]) if r["source_entities"] else [],
            destination_entities=json.loads(r["destination_entities"]) if r["destination_entities"] else [],
            mitre_tags=json.loads(r["mitre_tags"]) if r["mitre_tags"] else [],
            first_seen=r["first_seen"],
            last_seen=r["last_seen"],
            created_at=r["created_at"],
            updated_at=r["updated_at"],
            event_ids=ev_ids,
            is_contained=bool(r["is_contained"]),
        )


def get_incident_events(incident_id: str) -> List[NormalizedEvent]:
    with db_session() as conn:
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
            mitre = json.loads(r["mitre_json"]) if r["mitre_json"] else {}
            result.append(
                NormalizedEvent(
                    event_id=r["id"],
                    timestamp=r["timestamp"],
                    source=r["source"],
                    domain=ThreatDomain(r["domain"]) if r["domain"] in [d.value for d in ThreatDomain] else ThreatDomain.NETWORK,
                    event_type=r["event_type"],
                    src_ip=r["src_ip"],
                    src_port=r["src_port"],
                    dst_ip=r["dst_ip"],
                    dst_port=r["dst_port"],
                    protocol=r["protocol"],
                    domain_name=r["domain_name"],
                    severity=r["severity"],
                    signature=r["signature"],
                    flow_id=r["flow_id"],
                    sensor_id=r["sensor_id"],
                    agent_id=r["agent_id"],
                    agent_name=r["agent_name"],
                    rule_id=r["rule_id"],
                    rule_level=r["rule_level"],
                    user=r["user"],
                    process_name=r["process_name"],
                    process_path=r["process_path"],
                    process_cmdline=r["process_cmdline"],
                    process_pid=r["process_pid"],
                    file_path=r["file_path"],
                    mitre_tactics=mitre.get("tactics", []),
                    mitre_techniques=mitre.get("techniques", []),
                    raw_event=raw,
                )
            )
        return result


def save_evidence_batch(evidence_list: List[EvidenceItem]) -> None:
    with db_session() as conn:
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


def get_incident_evidence(incident_id: str) -> List[EvidenceItem]:
    with db_session() as conn:
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
    with db_session() as conn:
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


def get_incident_recommendations(incident_id: str) -> List[RecommendationItem]:
    with db_session() as conn:
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
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO reports (
                id, incident_id, generated_at, report_type, content_markdown, content_html
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (report_id, incident_id, now, "INCIDENT_INVESTIGATION", report_md, report_html),
        )


def get_report(incident_id: str) -> Optional[Dict[str, Any]]:
    with db_session() as conn:
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


def save_notification(notif: NotificationItem) -> None:
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO notifications (
                id, timestamp, level, title, message, incident_id, domain
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                notif.id,
                notif.timestamp,
                notif.level,
                notif.title,
                notif.message,
                notif.incident_id,
                notif.domain,
            ),
        )


def get_recent_notifications(limit: int = 50) -> List[NotificationItem]:
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM notifications ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        return [
            NotificationItem(
                id=r["id"],
                timestamp=r["timestamp"],
                level=r["level"],
                title=r["title"],
                message=r["message"],
                incident_id=r["incident_id"],
                domain=r["domain"],
            )
            for r in rows
        ]


def clear_all_data() -> None:
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM incident_events")
        cursor.execute("DELETE FROM evidence")
        cursor.execute("DELETE FROM recommendations")
        cursor.execute("DELETE FROM reports")
        cursor.execute("DELETE FROM incidents")
        cursor.execute("DELETE FROM events")
        cursor.execute("DELETE FROM notifications")
