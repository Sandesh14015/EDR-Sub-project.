from typing import List
from backend.models import NormalizedEvent, TimelineItem


def build_attack_timeline(events: List[NormalizedEvent], threat_category: str) -> List[TimelineItem]:
    """Reconstructs the multi-domain chronological attack story with raw and inferred steps."""
    if not events:
        return []

    sorted_events = sorted(events, key=lambda e: e.timestamp)
    timeline: List[TimelineItem] = []

    for ev in sorted_events:
        stage = "Observation"
        desc = ev.signature or f"{ev.protocol} traffic {ev.src_ip} -> {ev.dst_ip}"

        if ev.event_type in ("alert", "suricata_alert") or ev.source == "suricata":
            stage = "🚨 Network Exploit / IDS Detection"
            desc = f"Suricata Alert: {ev.signature} from {ev.src_ip}"
        elif ev.event_type == "auth_failure":
            stage = "Authentication Failure"
            desc = f"Logon failed for account '{ev.user or 'unknown'}' from IP {ev.src_ip or 'unknown'}"
        elif ev.event_type == "auth_success":
            stage = "⚠️ Successful Logon"
            desc = f"Authentication succeeded for account '{ev.user}' from IP {ev.src_ip}"
        elif ev.event_type == "process_create" or ev.process_name:
            stage = "Endpoint Execution"
            desc = f"Process spawned: {ev.process_name} (Command: {ev.process_cmdline or 'N/A'})"
        elif ev.event_type == "fim_modification" or ev.file_path:
            stage = "File Modification (FIM)"
            desc = f"File modified or created: {ev.file_path}"
        elif ev.event_type == "app_auth_failure":
            stage = "Application Authorization Failure"
            desc = f"HTTP 401/403 authorization failure from {ev.src_ip}"
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
            stage = "Network Flow"
            desc = f"Connection {ev.src_ip} -> {ev.dst_ip}:{ev.dst_port}"

        source_label = f"{ev.source.upper()} ({ev.event_id})"
        if ev.agent_name:
            source_label += f" on {ev.agent_name}"

        timeline.append(
            TimelineItem(
                timestamp=ev.timestamp,
                stage=stage,
                description=desc,
                source=source_label,
                is_inferred=False,
            )
        )

    # Inferred attack hypothesis stages
    has_auth_fail = any(e.event_type == "auth_failure" for e in sorted_events)
    has_auth_success = any(e.event_type == "auth_success" for e in sorted_events)
    has_fim_or_proc = any(e.event_type in ("fim_modification", "process_create") for e in sorted_events)
    conn_events = [e for e in sorted_events if e.event_type == "conn"]
    dns_events = [e for e in sorted_events if e.event_type == "dns"]
    alert_events = [e for e in sorted_events if e.source in ("suricata", "zeek") or e.event_type in ("alert", "suricata_alert")]

    if has_auth_fail and has_auth_success:
        last_auth = [e for e in sorted_events if e.event_type == "auth_success"][-1]
        timeline.append(
            TimelineItem(
                timestamp=last_auth.timestamp,
                stage="Account Compromise Confirmed (Inferred)",
                description="Threat actor successfully authenticated following repeated credential attempts",
                source="CYBERGUARD Intelligence Engine",
                is_inferred=True,
            )
        )

    if has_auth_success and has_fim_or_proc:
        last_ev = sorted_events[-1]
        timeline.append(
            TimelineItem(
                timestamp=last_ev.timestamp,
                stage="Post-Exploitation Activity (Inferred)",
                description="Compromised credentials leveraged to alter endpoint files or spawn untrusted binaries",
                source="CYBERGUARD Intelligence Engine",
                is_inferred=True,
            )
        )

    if len(conn_events) >= 2:
        last_conn = conn_events[-1]
        timeline.append(
            TimelineItem(
                timestamp=last_conn.timestamp,
                stage="Suspicious Persistence (Inferred)",
                description=f"Repetitive communication pattern detected ({len(conn_events)} connections)",
                source="CYBERGUARD Intelligence Engine",
                is_inferred=True,
            )
        )

    if alert_events and (conn_events or dns_events):
        last_ev = sorted_events[-1]
        timeline.append(
            TimelineItem(
                timestamp=last_ev.timestamp,
                stage="Threat Assessment (Inferred)",
                description=f"Potential active {threat_category} session confirmed by multi-sensor telemetry",
                source="CYBERGUARD Intelligence Engine",
                is_inferred=True,
            )
        )

    return sorted(timeline, key=lambda t: t.timestamp)
