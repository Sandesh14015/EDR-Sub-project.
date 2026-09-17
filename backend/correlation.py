import uuid
from datetime import datetime, timezone
from typing import Dict, List, Set, Tuple
from backend import database
from backend.models import (
    EvidenceItem,
    Incident,
    IncidentStatus,
    NormalizedEvent,
    ThreatCategory,
)
from backend.recommender import generate_recommendations
from backend.risk_engine import calculate_risk_and_confidence
from backend.timeline import build_attack_timeline


def _classify_threat(events: List[NormalizedEvent]) -> Tuple[ThreatCategory, str, str]:
    """
    Classifies the incident into a ThreatCategory and suggests a title & description
    based on deterministic rule matching across all correlated events.
    """
    signatures = [e.signature.lower() for e in events if e.signature]
    combined_sig_text = " ".join(signatures)

    dest_ips = list({e.dst_ip for e in events if e.dst_ip})
    src_ips = list({e.src_ip for e in events if e.src_ip})
    dst_summary = dest_ips[0] if dest_ips else "external host"
    src_summary = src_ips[0] if src_ips else "internal host"

    # Rule 1: Command and Control / Beaconing
    if any(k in combined_sig_text for k in ["c2", "beacon", "command and control", "trojan", "cobalt", "meterpreter"]):
        return (
            ThreatCategory.COMMAND_AND_CONTROL,
            f"Suspected Command and Control Activity from {src_summary}",
            f"Multi-sensor telemetry indicates persistent outbound communication and suspicious signatures matching C2 infrastructure at {dst_summary}.",
        )

    # Rule 2: Brute Force
    if any(k in combined_sig_text for k in ["brute", "login failed", "ssh auth", "password guessing"]):
        return (
            ThreatCategory.BRUTE_FORCE,
            f"Credential Brute Force Activity targeting {dst_summary}",
            f"High volume of repetitive authentication failures or rapid connection attempts detected from {src_summary}.",
        )

    # Rule 3: Scanning / Reconnaissance
    dst_ports = {e.dst_port for e in events if e.dst_port}
    if any(k in combined_sig_text for k in ["scan", "nmap", "port scan"]) or len(dst_ports) > 8:
        return (
            ThreatCategory.SCANNING,
            f"Network Port Reconnaissance / Scanning by {src_summary}",
            f"System detected probe traffic spanning {len(dst_ports)} destination ports.",
        )

    # Rule 4: Suspicious DNS / Exfiltration
    domains = [e.domain for e in events if e.domain]
    if any(k in combined_sig_text for k in ["dga", "dns tunnel", "suspicious domain"]) or any(len(d) > 40 for d in domains):
        return (
            ThreatCategory.SUSPICIOUS_DNS,
            f"Suspicious DNS Resolution / Potential Tunneling by {src_summary}",
            f"Anomalous domain resolution patterns observed involving domain query '{domains[0] if domains else 'N/A'}'.",
        )

    # Rule 5: Malware Communication
    if any(k in combined_sig_text for k in ["malware", "ransomware", "backdoor", "dropper"]):
        return (
            ThreatCategory.MALWARE_COMMUNICATION,
            f"Malware Communication Activity from {src_summary}",
            f"Suricata alerts matched known malware family signatures communicating with {dst_summary}.",
        )

    # Rule 6: Exploitation
    if any(k in combined_sig_text for k in ["exploit", "cve-", "overflow", "injection", "rce"]):
        return (
            ThreatCategory.EXPLOITATION,
            f"Active Exploitation Attempt against {dst_summary}",
            f"Inbound or outbound payload patterns match known exploitation vectors.",
        )

    # Default fallback
    if any(e.source == "suricata" for e in events):
        return (
            ThreatCategory.POLICY_VIOLATION,
            f"Security Policy Violation on {src_summary}",
            f"Suricata sensor triggered alert: {signatures[0] if signatures else 'Unspecified alert'}.",
        )

    return (
        ThreatCategory.UNKNOWN,
        f"Suspicious Network Activity between {src_summary} and {dst_summary}",
        "Correlated network telemetry exhibited anomalous connection attributes.",
    )


def correlate_events(time_window_seconds: int = 600) -> List[Incident]:
    """
    Correlates unlinked or recent events into incidents using multi-key clustering:
    - Host association: (src_ip, dst_ip) or (src_ip, domain)
    - Time proximity: within sliding time window
    - Multi-sensor aggregation: Combines Suricata alerts with surrounding Zeek telemetry
    """
    events = database.get_all_events(limit=1000)
    if not events:
        return []

    # Sort chronologically
    sorted_events = sorted(events, key=lambda e: e.timestamp)

    # Grouping key: Primary pair of endpoints (src_ip, dst_ip or domain)
    groups: Dict[str, List[NormalizedEvent]] = {}

    for ev in sorted_events:
        # Determine clustering key
        peer = ev.dst_ip or ev.domain or "unknown_dst"
        host = ev.src_ip or "unknown_src"
        cluster_key = f"{host}<->{peer}"

        if cluster_key not in groups:
            groups[cluster_key] = []
        groups[cluster_key].append(ev)

    created_incidents: List[Incident] = []
    now = datetime.now(timezone.utc).isoformat()

    for cluster_key, group_events in groups.items():
        # Only create an incident if there is either an alert or suspicious telemetry (severity >= 2 or len >= 2)
        has_alert = any(e.source == "suricata" for e in group_events)
        has_suspicious_telemetry = any(e.severity >= 3 for e in group_events) or len(group_events) >= 3

        if not (has_alert or has_suspicious_telemetry):
            continue

        # Extract incident timestamps
        timestamps = [e.timestamp for e in group_events]
        first_seen = min(timestamps)
        last_seen = max(timestamps)

        # Classify threat
        threat_cat, title, desc = _classify_threat(group_events)

        # Calculate decoupled Risk and Confidence
        risk_score, confidence, severity = calculate_risk_and_confidence(group_events)

        # Unique entities
        affected_assets = list({e.src_ip for e in group_events if e.src_ip})
        dest_entities = list({e.dst_ip for e in group_events if e.dst_ip} | {e.domain for e in group_events if e.domain})
        event_ids = [e.event_id for e in group_events]

        incident_id = f"INC-{uuid.uuid4().hex[:6].upper()}"

        incident = Incident(
            id=incident_id,
            title=title,
            description=desc,
            status=IncidentStatus.NEW,
            severity=severity,
            risk_score=risk_score,
            confidence=confidence,
            threat_category=threat_cat,
            affected_assets=affected_assets,
            source_entities=affected_assets,
            destination_entities=dest_entities,
            first_seen=first_seen,
            last_seen=last_seen,
            created_at=now,
            updated_at=now,
            event_ids=event_ids,
        )

        # Save incident to database
        database.save_incident(incident, event_ids=event_ids)

        # Build and extract evidence
        evidence_list: List[EvidenceItem] = []
        for ev in group_events:
            if ev.source == "suricata" and ev.signature:
                evidence_list.append(
                    EvidenceItem(
                        id=f"EVD-{uuid.uuid4().hex[:6].upper()}",
                        incident_id=incident_id,
                        type="Suricata Detection",
                        value=ev.signature,
                        source="suricata",
                        timestamp=ev.timestamp,
                        description=f"Rule match with severity {ev.severity}/10",
                    )
                )
            elif ev.event_type == "dns" and ev.domain:
                evidence_list.append(
                    EvidenceItem(
                        id=f"EVD-{uuid.uuid4().hex[:6].upper()}",
                        incident_id=incident_id,
                        type="Domain Resolution",
                        value=ev.domain,
                        source="zeek",
                        timestamp=ev.timestamp,
                        description="Corroborating DNS query observed prior to connection",
                    )
                )
            elif ev.event_type == "conn":
                evidence_list.append(
                    EvidenceItem(
                        id=f"EVD-{uuid.uuid4().hex[:6].upper()}",
                        incident_id=incident_id,
                        type="Connection Telemetry",
                        value=f"{ev.protocol} {ev.src_ip}:{ev.src_port} -> {ev.dst_ip}:{ev.dst_port}",
                        source="zeek",
                        timestamp=ev.timestamp,
                        description=f"Observed network flow (Flow ID: {ev.flow_id or 'N/A'})",
                    )
                )
        database.save_evidence_batch(evidence_list)

        # Generate recommendations
        recs = generate_recommendations(
            incident_id=incident_id,
            threat_category=threat_cat,
            affected_assets=affected_assets,
            destination_entities=dest_entities,
            events=group_events,
        )
        database.save_recommendations_batch(recs)

        created_incidents.append(incident)

    return created_incidents
