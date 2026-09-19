import uuid
from datetime import datetime, timezone
from typing import Dict, List, Set, Tuple
from backend import database
from backend.classifier import classify_incident_domain_and_threat
from backend.models import (
    EvidenceItem,
    Incident,
    IncidentStatus,
    NormalizedEvent,
    NotificationItem,
    ThreatCategory,
    ThreatDomain,
)
from backend.recommender import generate_recommendations
from backend.risk_engine import calculate_risk_and_confidence


def correlate_events(time_window_seconds: int = 600) -> List[Incident]:
    """
    Correlates multi-sensor security events across 4 domains
    (Authentication, Endpoint, Network, Application) into unified incidents.
    Implements the pipeline: Event -> Evidence -> Classification -> Confidence/Risk -> Notification
    """
    events = database.get_all_events(limit=1000)
    if not events:
        return []

    sorted_events = sorted(events, key=lambda e: e.timestamp)

    # Build host-to-agent mapping from telemetry
    ip_to_agent: Dict[str, str] = {}
    for ev in sorted_events:
        if ev.agent_name:
            if ev.dst_ip:
                ip_to_agent[ev.dst_ip] = ev.agent_name
            if ev.src_ip:
                ip_to_agent[ev.src_ip] = ev.agent_name

    # Grouping events by endpoint context (host / agent or communication pair)
    groups: Dict[str, List[NormalizedEvent]] = {}

    for ev in sorted_events:
        # Resolve target host/agent identifier using IP mapping
        target_host = ev.agent_name or ip_to_agent.get(ev.dst_ip) or ip_to_agent.get(ev.src_ip) or ev.dst_ip or ev.src_ip or "local-system"
        external_peer = ev.src_ip if (ev.src_ip and ev.src_ip != ev.dst_ip and ev.src_ip != "127.0.0.1") else (ev.dst_ip or "external")
        cluster_key = f"{target_host}::{external_peer}"

        if cluster_key not in groups:
            groups[cluster_key] = []
        groups[cluster_key].append(ev)

    created_incidents: List[Incident] = []
    now = datetime.now(timezone.utc).isoformat()

    for cluster_key, group_events in groups.items():
        # Only form an incident if there are alerts, auth events, FIM changes, or suspicious activities
        has_alert = any(e.severity >= 4 or e.event_type in ("alert", "suricata_alert", "auth_failure", "fim_modification", "process_create") for e in group_events)
        if not has_alert and len(group_events) < 3:
            continue

        timestamps = [e.timestamp for e in group_events]
        first_seen = min(timestamps)
        last_seen = max(timestamps)

        # 1. Classification & MITRE ATT&CK Mapping
        domain, threat_cat, title, desc, indicators, mitre_tags = classify_incident_domain_and_threat(group_events)

        # 2. Decoupled Risk & Confidence Scoring
        risk_score, confidence, severity = calculate_risk_and_confidence(group_events, domain=domain)

        # Collect affected entities: internal hosts and agent names are affected assets
        affected_assets = list(
            {e.agent_name for e in group_events if e.agent_name}
            | {e.src_ip for e in group_events if e.src_ip and e.src_ip.startswith(("192.168.", "10.", "172.", "127."))}
            | {e.dst_ip for e in group_events if e.dst_ip and e.dst_ip.startswith(("192.168.", "10.", "172.", "127."))}
        )
        if not affected_assets:
            affected_assets = list({e.dst_ip for e in group_events if e.dst_ip} or {"local-system"})
        affected_users = list({e.user for e in group_events if e.user})
        affected_procs = list({e.process_name for e in group_events if e.process_name})
        dest_entities = list({e.src_ip for e in group_events if e.src_ip and e.src_ip not in affected_assets} | {e.dst_ip for e in group_events if e.dst_ip and e.dst_ip not in affected_assets})
        event_ids = [e.event_id for e in group_events]

        incident_id = f"INC-{uuid.uuid4().hex[:6].upper()}"

        incident = Incident(
            id=incident_id,
            title=title,
            description=desc,
            domain=domain,
            status=IncidentStatus.NEW,
            severity=severity,
            risk_score=risk_score,
            confidence=confidence,
            threat_category=threat_cat,
            indicators=indicators,
            affected_assets=affected_assets,
            affected_users=affected_users,
            affected_processes=affected_procs,
            source_entities=dest_entities,
            destination_entities=dest_entities,
            mitre_tags=mitre_tags,
            first_seen=first_seen,
            last_seen=last_seen,
            created_at=now,
            updated_at=now,
            event_ids=event_ids,
            is_contained=False,
        )

        # Save incident to database
        database.save_incident(incident, event_ids=event_ids)

        # 3. Evidence Extraction (Evidence Store)
        evidence_list: List[EvidenceItem] = []
        for ev in group_events:
            # Suricata Exploit or Network IDS Alert
            if ev.source == "suricata" or ev.event_type == "suricata_alert":
                evidence_list.append(
                    EvidenceItem(
                        id=f"EVD-{uuid.uuid4().hex[:6].upper()}",
                        incident_id=incident_id,
                        type="IDS Exploit Alert",
                        value=ev.signature or "Network Exploit Match",
                        source="Suricata",
                        timestamp=ev.timestamp,
                        description=f"Rule match severity {ev.severity}/10 from {ev.src_ip} targeting port {ev.dst_port or 'N/A'}",
                    )
                )
            # Failed Logins
            elif ev.event_type == "auth_failure":
                evidence_list.append(
                    EvidenceItem(
                        id=f"EVD-{uuid.uuid4().hex[:6].upper()}",
                        incident_id=incident_id,
                        type="Authentication Failure",
                        value=f"User: {ev.user or 'unknown'}",
                        source="Wazuh Auth",
                        timestamp=ev.timestamp,
                        description=f"Failed authentication attempt from {ev.src_ip or 'unknown IP'}",
                    )
                )
            # Successful Login
            elif ev.event_type == "auth_success":
                evidence_list.append(
                    EvidenceItem(
                        id=f"EVD-{uuid.uuid4().hex[:6].upper()}",
                        incident_id=incident_id,
                        type="Successful Login",
                        value=f"User: {ev.user or 'unknown'}",
                        source="Wazuh Auth",
                        timestamp=ev.timestamp,
                        description=f"Subsequent successful login session established by {ev.src_ip or 'unknown IP'}",
                    )
                )
            # Suspicious Process Creation
            elif ev.event_type == "process_create" or ev.process_name:
                evidence_list.append(
                    EvidenceItem(
                        id=f"EVD-{uuid.uuid4().hex[:6].upper()}",
                        incident_id=incident_id,
                        type="Endpoint Process Execution",
                        value=ev.process_cmdline or ev.process_name or "Unknown process",
                        source="Wazuh Sysmon",
                        timestamp=ev.timestamp,
                        description=f"Process {ev.process_name} (PID: {ev.process_pid or 'N/A'}) launched on {ev.agent_name or 'host'}",
                    )
                )
            # FIM Modification
            elif ev.event_type == "fim_modification" or ev.file_path:
                evidence_list.append(
                    EvidenceItem(
                        id=f"EVD-{uuid.uuid4().hex[:6].upper()}",
                        incident_id=incident_id,
                        type="File Integrity Modification (FIM)",
                        value=ev.file_path or "Critical system file",
                        source="Wazuh Syscheck",
                        timestamp=ev.timestamp,
                        description="Unauthorized file alteration or creation detected in monitored directory",
                    )
                )

        database.save_evidence_batch(evidence_list)

        # 4. Generate Defensive Recommendations
        recs = generate_recommendations(
            incident_id=incident_id,
            threat_category=threat_cat,
            affected_assets=affected_assets,
            destination_entities=dest_entities,
            affected_users=affected_users,
            events=group_events,
        )
        database.save_recommendations_batch(recs)

        # 5. Output: Notification Emission
        if risk_score >= 40:
            notif_level = "CRITICAL" if risk_score >= 80 else ("WARNING" if risk_score >= 60 else "INFO")
            notif = NotificationItem(
                id=f"NOTIF-{uuid.uuid4().hex[:6].upper()}",
                timestamp=now,
                level=notif_level,
                title=f"🚨 {title}",
                message=f"[{domain.value.upper()}] Risk {risk_score}/100. {desc}",
                incident_id=incident_id,
                domain=domain.value,
            )
            database.save_notification(notif)

        created_incidents.append(incident)

    return created_incidents
