from datetime import datetime, timezone
from typing import List
from backend.models import NormalizedEvent, TimelineItem


def build_attack_timeline(events: List[NormalizedEvent], threat_category: str) -> List[TimelineItem]:
    """
    Builds an attack timeline combining:
    1. Chronological raw sensor events (DNS, TCP, TLS, Alert)
    2. Higher-level inferred attack stages clearly marked as `is_inferred=True`
    """
    if not events:
        return []

    # Sort events chronologically
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    timeline: List[TimelineItem] = []

    dns_events = [e for e in sorted_events if e.event_type == "dns"]
    conn_events = [e for e in sorted_events if e.event_type == "conn"]
    alert_events = [e for e in sorted_events if e.source == "suricata"]
    ssl_events = [e for e in sorted_events if e.event_type == "ssl"]

    # Step 1: Add raw events with friendly descriptive labels
    for ev in sorted_events:
        stage = "Observation"
        desc = ev.signature or f"{ev.protocol} traffic {ev.src_ip} -> {ev.dst_ip}:{ev.dst_port}"

        if ev.source == "suricata":
            stage = "🚨 Detection"
            desc = f"Suricata Alert: {ev.signature} (Severity {ev.severity}/10)"
        elif ev.event_type == "dns":
            stage = "Name Resolution"
            desc = f"DNS Query resolved: {ev.domain or 'unknown host'}"
        elif ev.event_type == "ssl":
            stage = "Encrypted Channel"
            desc = f"TLS handshake established to {ev.domain or ev.dst_ip}"
        elif ev.event_type == "http":
            stage = "Web Traffic"
            desc = f"HTTP request: {ev.signature}"
        elif ev.event_type == "conn":
            stage = "Network Connection"
            desc = f"Outbound connection {ev.src_ip}:{ev.src_port} -> {ev.dst_ip}:{ev.dst_port}"

        timeline.append(
            TimelineItem(
                timestamp=ev.timestamp,
                stage=stage,
                description=desc,
                source=f"{ev.source.upper()} ({ev.event_id})",
                is_inferred=False,
            )
        )

    # Step 2: Add inferred stages based on behavioral patterns
    # Pattern: If multiple connections occur to the same destination over time
    if len(conn_events) >= 2:
        last_conn = conn_events[-1]
        timeline.append(
            TimelineItem(
                timestamp=last_conn.timestamp,
                stage="Suspicious Persistence (Inferred)",
                description=f"Repetitive communication pattern detected ({len(conn_events)} connections)",
                source="Intelligence Layer",
                is_inferred=True,
            )
        )

    # Pattern: If alerts exist alongside active connections/DNS
    if alert_events and (conn_events or dns_events):
        last_event = sorted_events[-1]
        inferred_conclusion = (
            f"Potential active {threat_category} session confirmed by multi-sensor telemetry"
        )
        timeline.append(
            TimelineItem(
                timestamp=last_event.timestamp,
                stage="Threat Assessment (Inferred)",
                description=inferred_conclusion,
                source="Intelligence Layer",
                is_inferred=True,
            )
        )

    # Re-sort timeline with inferred steps aligned to timestamps
    return sorted(timeline, key=lambda t: t.timestamp)
