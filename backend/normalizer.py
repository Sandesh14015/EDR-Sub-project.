import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from backend.models import NormalizedEvent, ThreatDomain


def _parse_timestamp(ts: Any) -> str:
    """Safely converts string, epoch float, or int timestamp into ISO 8601 UTC string."""
    if not ts:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(ts, (int, float)):
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        except Exception:
            return datetime.now(timezone.utc).isoformat()
    if isinstance(ts, str):
        try:
            val = float(ts)
            return datetime.fromtimestamp(val, tz=timezone.utc).isoformat()
        except ValueError:
            pass
        try:
            cleaned = ts.replace("Z", "+00:00")
            dt = datetime.fromisoformat(cleaned)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except Exception:
            return ts
    return datetime.now(timezone.utc).isoformat()


def normalize_wazuh_event(raw: Dict[str, Any], sensor_id: str = "wazuh-server") -> NormalizedEvent:
    """
    Normalizes a Wazuh 4.14.x stable security alert into a NormalizedEvent.
    Handles host logs, Sysmon, FIM (syscheck), authentication, and nested Suricata events.
    """
    event_id = f"WZH-{uuid.uuid4().hex[:8].upper()}"
    ts = _parse_timestamp(raw.get("timestamp"))

    rule = raw.get("rule", {})
    agent = raw.get("agent", {})
    data = raw.get("data", {})
    syscheck = raw.get("syscheck", {})

    rule_id = str(rule.get("id", "0"))
    rule_desc = rule.get("description", "Wazuh Security Alert")
    rule_level = rule.get("level", 3)
    rule_groups = [g.lower() for g in rule.get("groups", [])]

    # Map Wazuh rule level (1-16 scale) to 0-10 severity scale
    if rule_level >= 13:
        severity = 10
    elif rule_level >= 10:
        severity = 8
    elif rule_level >= 7:
        severity = 6
    elif rule_level >= 4:
        severity = 4
    else:
        severity = 2

    # Extract MITRE ATT&CK tags
    mitre = rule.get("mitre", {})
    mitre_tactics = mitre.get("tactic", [])
    if isinstance(mitre_tactics, str):
        mitre_tactics = [mitre_tactics]
    mitre_techniques = mitre.get("technique", []) or mitre.get("id", [])
    if isinstance(mitre_techniques, str):
        mitre_techniques = [mitre_techniques]

    agent_id = str(agent.get("id", ""))
    agent_name = agent.get("name", "local-system")
    agent_ip = agent.get("ip")

    # Extract process & user details (e.g. from Windows Sysmon/Event logs)
    win = data.get("win", {})
    eventdata = win.get("eventdata", {})

    user = (
        data.get("srcuser")
        or data.get("dstuser")
        or eventdata.get("targetUserName")
        or eventdata.get("subjectUserName")
        or raw.get("user")
    )
    src_ip = (
        data.get("srcip")
        or eventdata.get("ipAddress")
        or raw.get("src_ip")
    )
    dst_ip = (
        data.get("dstip")
        or agent_ip
        or raw.get("dest_ip")
        or raw.get("dst_ip")
    )
    dst_port = None
    if "dstport" in data:
        try:
            dst_port = int(data["dstport"])
        except ValueError:
            pass

    proc_name = eventdata.get("processName") or eventdata.get("image")
    proc_cmdline = eventdata.get("commandLine")
    proc_pid = None
    if "processId" in eventdata:
        try:
            proc_pid = int(eventdata["processId"], 0) if isinstance(eventdata["processId"], str) and eventdata["processId"].startswith("0x") else int(eventdata["processId"])
        except (ValueError, TypeError):
            pass

    # Extract FIM details
    file_path = syscheck.get("path") or eventdata.get("targetFilename")

    # Determine Domain & Event Type
    domain = ThreatDomain.ENDPOINT
    event_type = "host_alert"

    # Check for nested Suricata in Wazuh alert
    if "suricata" in data:
        suri = data["suricata"]
        domain = ThreatDomain.NETWORK
        event_type = "suricata_alert"
        if "alert" in suri:
            rule_desc = f"Suricata via Wazuh: {suri['alert'].get('signature', rule_desc)}"
        src_ip = suri.get("src_ip") or src_ip
        dst_ip = suri.get("dest_ip") or dst_ip
        dst_port = suri.get("dest_port") or dst_port

    # Authentication Domain
    elif any(g in rule_groups for g in ["authentication_failed", "authentication_success", "logon_failed", "sshd", "pam", "windows_auth"]):
        domain = ThreatDomain.AUTHENTICATION
        if any("success" in g for g in rule_groups) or "success" in rule_desc.lower():
            event_type = "auth_success"
        else:
            event_type = "auth_failure"
            severity = max(severity, 5)

    # Endpoint Domain: FIM or Sysmon
    elif syscheck or "syscheck" in rule_groups:
        domain = ThreatDomain.ENDPOINT
        event_type = "fim_modification"
        rule_desc = f"FIM Alert: File modified at {file_path or 'critical system path'}"
        severity = max(severity, 7)

    elif "sysmon_event1" in rule_groups or "process_creation" in rule_groups:
        domain = ThreatDomain.ENDPOINT
        event_type = "process_create"
        if proc_name and any(p in proc_name.lower() for p in ["powershell", "cmd", "certutil", "mshta", "rundll32"]):
            severity = max(severity, 8)

    # Application Domain
    elif any(g in rule_groups for g in ["web", "apache", "nginx", "accesslog", "api"]):
        domain = ThreatDomain.APPLICATION
        event_type = "app_activity"
        if any(code in rule_desc for code in ["401", "403"]):
            event_type = "app_auth_failure"
            severity = max(severity, 6)

    # Network Domain
    elif any(g in rule_groups for g in ["firewall", "ids", "suricata", "scan"]):
        domain = ThreatDomain.NETWORK
        event_type = "network_alert"

    return NormalizedEvent(
        event_id=event_id,
        timestamp=ts,
        source="wazuh",
        domain=domain,
        event_type=event_type,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        severity=severity,
        signature=rule_desc,
        agent_id=agent_id,
        agent_name=agent_name,
        rule_id=rule_id,
        rule_level=rule_level,
        user=user,
        process_name=proc_name,
        process_cmdline=proc_cmdline,
        process_pid=proc_pid,
        file_path=file_path,
        mitre_tactics=mitre_tactics,
        mitre_techniques=mitre_techniques,
        sensor_id=sensor_id,
        raw_event=raw,
    )


def normalize_suricata_event(raw: Dict[str, Any], sensor_id: str = "suricata-sensor") -> NormalizedEvent:
    """Normalizes a standalone Suricata eve.json record."""
    event_id = f"SURI-{uuid.uuid4().hex[:8].upper()}"
    ts = _parse_timestamp(raw.get("timestamp"))
    event_type = raw.get("event_type", "alert")
    src_ip = raw.get("src_ip")
    src_port = raw.get("src_port")
    dst_ip = raw.get("dest_ip") or raw.get("dst_ip")
    dst_port = raw.get("dest_port") or raw.get("dst_port")
    proto = (raw.get("proto") or "TCP").upper()
    flow_id = str(raw.get("flow_id")) if raw.get("flow_id") is not None else None

    # Suricata severity: 1=High (map to 9), 2=Med (map to 6), 3=Low (map to 4)
    severity = 3
    signature = "Suricata Network Alert"
    if "alert" in raw and isinstance(raw["alert"], dict):
        alert_info = raw["alert"]
        signature = alert_info.get("signature", signature)
        raw_sev = alert_info.get("severity", 3)
        if raw_sev == 1:
            severity = 9
        elif raw_sev == 2:
            severity = 6
        elif raw_sev == 3:
            severity = 4
        else:
            severity = 2

    # MITRE tags if available in Suricata metadata
    mitre_tactics = []
    mitre_techniques = []
    if "metadata" in raw and isinstance(raw["metadata"], dict):
        mitre_techniques = raw["metadata"].get("mitre_technique_id", [])
        if isinstance(mitre_techniques, str):
            mitre_techniques = [mitre_techniques]

    domain_name = None
    if "dns" in raw and isinstance(raw["dns"], dict):
        domain_name = raw["dns"].get("rrname") or raw["dns"].get("query")
    elif "tls" in raw and isinstance(raw["tls"], dict):
        domain_name = raw["tls"].get("sni")

    agent = raw.get("agent", {})
    agent_id = str(agent.get("id", "")) if agent else None
    agent_name = agent.get("name") if agent else None

    return NormalizedEvent(
        event_id=event_id,
        timestamp=ts,
        source="suricata",
        domain=ThreatDomain.NETWORK,
        event_type="suricata_alert",
        src_ip=src_ip,
        src_port=int(src_port) if src_port is not None else None,
        dst_ip=dst_ip,
        dst_port=int(dst_port) if dst_port is not None else None,
        protocol=proto,
        domain_name=domain_name,
        severity=severity,
        signature=signature,
        flow_id=flow_id,
        sensor_id=sensor_id,
        agent_id=agent_id,
        agent_name=agent_name,
        mitre_tactics=mitre_tactics,
        mitre_techniques=mitre_techniques,
        raw_event=raw,
    )


def normalize_zeek_json_event(raw: Dict[str, Any], sensor_id: str = "zeek-sensor") -> NormalizedEvent:
    """Normalizes an optional Zeek JSON record (conn, dns, ssl, http)."""
    event_id = f"ZEEK-{uuid.uuid4().hex[:8].upper()}"
    ts = _parse_timestamp(raw.get("ts") or raw.get("timestamp"))

    src_ip = raw.get("id.orig_h") or raw.get("orig_h") or raw.get("src_ip")
    src_port = raw.get("id.orig_p") or raw.get("orig_p") or raw.get("src_port")
    dst_ip = raw.get("id.resp_h") or raw.get("resp_h") or raw.get("dst_ip")
    dst_port = raw.get("id.resp_p") or raw.get("resp_p") or raw.get("dst_port")
    proto = (raw.get("proto") or "TCP").upper()
    uid = raw.get("uid")

    domain_name = raw.get("query") or raw.get("server_name") or raw.get("host")
    event_type = "conn"
    signature = f"Zeek connection {src_ip} -> {dst_ip}:{dst_port}"
    severity = 1

    if "query" in raw or raw.get("service") == "dns":
        event_type = "dns"
        domain_name = raw.get("query") or domain_name
        signature = f"DNS Query: {domain_name}"
    elif "server_name" in raw or raw.get("service") == "ssl":
        event_type = "ssl"
        domain_name = raw.get("server_name") or domain_name
        signature = f"TLS/SSL Session to {domain_name or dst_ip}"

    return NormalizedEvent(
        event_id=event_id,
        timestamp=ts,
        source="zeek",
        domain=ThreatDomain.NETWORK,
        event_type=event_type,
        src_ip=str(src_ip) if src_ip else None,
        src_port=int(src_port) if src_port is not None else None,
        dst_ip=str(dst_ip) if dst_ip else None,
        dst_port=int(dst_port) if dst_port is not None else None,
        protocol=proto,
        domain_name=str(domain_name) if domain_name else None,
        severity=severity,
        signature=signature,
        flow_id=uid,
        sensor_id=sensor_id,
        raw_event=raw,
    )


def parse_raw_text(text: str, default_source: Optional[str] = None) -> List[NormalizedEvent]:
    """Auto-detects and parses raw JSON or lines of Wazuh, Suricata, and Zeek logs."""
    results: List[NormalizedEvent] = []
    lines = text.strip().splitlines()

    # Check for full JSON array
    stripped = text.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        try:
            arr = json.loads(stripped)
            for item in arr:
                if isinstance(item, dict):
                    if "rule" in item and "agent" in item:
                        results.append(normalize_wazuh_event(item))
                    elif "alert" in item or "event_type" in item:
                        results.append(normalize_suricata_event(item))
                    else:
                        results.append(normalize_zeek_json_event(item))
            return results
        except Exception:
            pass

    for line in lines:
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("#"):
            continue

        if line_clean.startswith("{"):
            try:
                data = json.loads(line_clean)
                if isinstance(data, dict):
                    if "alert" in data or data.get("event_type") in ("alert", "flow", "drop") or default_source == "suricata":
                        results.append(normalize_suricata_event(data))
                    elif "rule" in data or "agent" in data or default_source == "wazuh":
                        results.append(normalize_wazuh_event(data))
                    elif "uid" in data or "id.orig_h" in data or default_source == "zeek":
                        results.append(normalize_zeek_json_event(data))
                    else:
                        # Fallback inference
                        if "rule" in data:
                            results.append(normalize_wazuh_event(data))
                        elif "dest_ip" in data:
                            results.append(normalize_suricata_event(data))
                        else:
                            results.append(normalize_zeek_json_event(data))
            except json.JSONDecodeError:
                pass

    return results
