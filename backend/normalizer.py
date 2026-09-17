import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from backend.models import NormalizedEvent


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
        # Check if epoch string
        try:
            val = float(ts)
            return datetime.fromtimestamp(val, tz=timezone.utc).isoformat()
        except ValueError:
            pass
        # Normalize ISO strings
        try:
            cleaned = ts.replace("Z", "+00:00")
            dt = datetime.fromisoformat(cleaned)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except Exception:
            return ts
    return datetime.now(timezone.utc).isoformat()


def normalize_suricata_event(raw: Dict[str, Any], sensor_id: str = "sensor-suricata") -> NormalizedEvent:
    """Normalizes a single Suricata eve.json record."""
    event_id = f"SURI-{uuid.uuid4().hex[:8].upper()}"
    ts = _parse_timestamp(raw.get("timestamp"))
    event_type = raw.get("event_type", "alert")
    src_ip = raw.get("src_ip")
    src_port = raw.get("src_port")
    dst_ip = raw.get("dest_ip") or raw.get("dst_ip")
    dst_port = raw.get("dest_port") or raw.get("dst_port")
    proto = (raw.get("proto") or "TCP").upper()
    flow_id = str(raw.get("flow_id")) if raw.get("flow_id") is not None else None

    # Severity mapping: Suricata 1=High, 2=Med, 3=Low, 4=Info -> Normalize to 0-10
    severity = 3
    signature = None
    if "alert" in raw and isinstance(raw["alert"], dict):
        alert_info = raw["alert"]
        signature = alert_info.get("signature")
        raw_sev = alert_info.get("severity", 3)
        if raw_sev == 1:
            severity = 9
        elif raw_sev == 2:
            severity = 6
        elif raw_sev == 3:
            severity = 4
        else:
            severity = 2
    elif event_type == "alert":
        severity = 7

    domain = None
    if "dns" in raw and isinstance(raw["dns"], dict):
        domain = raw["dns"].get("rrname") or raw["dns"].get("query")
    elif "tls" in raw and isinstance(raw["tls"], dict):
        domain = raw["tls"].get("sni")
    elif "http" in raw and isinstance(raw["http"], dict):
        domain = raw["http"].get("hostname")

    return NormalizedEvent(
        event_id=event_id,
        timestamp=ts,
        source="suricata",
        event_type=f"alert_{event_type}" if event_type != "alert" else "alert",
        src_ip=src_ip,
        src_port=int(src_port) if src_port is not None else None,
        dst_ip=dst_ip,
        dst_port=int(dst_port) if dst_port is not None else None,
        protocol=proto,
        domain=domain,
        severity=severity,
        signature=signature,
        flow_id=flow_id,
        sensor_id=sensor_id,
        raw_event=raw,
    )


def normalize_zeek_json_event(raw: Dict[str, Any], sensor_id: str = "sensor-zeek") -> NormalizedEvent:
    """Normalizes a single Zeek JSON record (from conn, dns, ssl, http, etc.)."""
    event_id = f"ZEEK-{uuid.uuid4().hex[:8].upper()}"
    ts = _parse_timestamp(raw.get("ts") or raw.get("timestamp"))

    # Origin and Response addresses in Zeek
    src_ip = raw.get("id.orig_h") or raw.get("orig_h") or raw.get("src_ip")
    src_port = raw.get("id.orig_p") or raw.get("orig_p") or raw.get("src_port")
    dst_ip = raw.get("id.resp_h") or raw.get("resp_h") or raw.get("dst_ip")
    dst_port = raw.get("id.resp_p") or raw.get("resp_p") or raw.get("dst_port")
    proto = (raw.get("proto") or "TCP").upper()
    uid = raw.get("uid")

    domain = raw.get("query") or raw.get("server_name") or raw.get("host")
    event_type = "conn"
    signature = None
    severity = 1  # Standard baseline telemetry severity

    if "query" in raw or raw.get("service") == "dns" or "qtype_name" in raw:
        event_type = "dns"
        domain = raw.get("query") or domain
        signature = f"DNS Query: {domain}" if domain else "DNS Activity"
    elif "server_name" in raw or raw.get("service") == "ssl" or "subject" in raw:
        event_type = "ssl"
        domain = raw.get("server_name") or domain
        signature = f"TLS/SSL Session to {domain or dst_ip}"
    elif "method" in raw or raw.get("service") == "http" or "uri" in raw:
        event_type = "http"
        domain = raw.get("host") or domain
        method = raw.get("method", "GET")
        uri = raw.get("uri", "/")
        signature = f"HTTP {method} {uri}"
    elif "conn_state" in raw:
        conn_state = raw.get("conn_state", "")
        signature = f"Connection State: {conn_state}"
        # Flag suspicious connection states like S0 (SYN attempt without response)
        if conn_state in ("S0", "REJ", "RSTO", "RSTR"):
            severity = 3

    return NormalizedEvent(
        event_id=event_id,
        timestamp=ts,
        source="zeek",
        event_type=event_type,
        src_ip=str(src_ip) if src_ip else None,
        src_port=int(src_port) if src_port is not None else None,
        dst_ip=str(dst_ip) if dst_ip else None,
        dst_port=int(dst_port) if dst_port is not None else None,
        protocol=proto,
        domain=str(domain) if domain else None,
        severity=severity,
        signature=signature or f"Zeek {event_type.upper()} telemetry",
        flow_id=uid,
        sensor_id=sensor_id,
        raw_event=raw,
    )


def normalize_zeek_tsv_line(line: str, fields: List[str], sensor_id: str = "sensor-zeek") -> Optional[NormalizedEvent]:
    """Parses a line of standard Zeek tab-separated log format given the #fields header."""
    parts = line.strip().split("\t")
    if len(parts) != len(fields):
        # Fallback to whitespace split if tab mismatch
        parts = line.strip().split()
        if len(parts) != len(fields):
            return None
    raw = dict(zip(fields, parts))
    # Replace Zeek '-' with None
    clean_raw = {k: (None if v == "-" else v) for k, v in raw.items()}
    return normalize_zeek_json_event(clean_raw, sensor_id=sensor_id)


def parse_raw_text(text: str, default_source: Optional[str] = None) -> List[NormalizedEvent]:
    """
    Intelligently parses raw text input containing either:
    - Multiple JSON objects (line-by-line or JSON array)
    - Mixed Suricata and Zeek JSON logs
    - Zeek TSV logs with #fields headers
    """
    results: List[NormalizedEvent] = []
    lines = text.strip().splitlines()

    # Check if the entire string is a JSON array
    stripped = text.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        try:
            arr = json.loads(stripped)
            for item in arr:
                if isinstance(item, dict):
                    if "alert" in item or "event_type" in item:
                        results.append(normalize_suricata_event(item))
                    else:
                        results.append(normalize_zeek_json_event(item))
            return results
        except Exception:
            pass

    current_tsv_fields: Optional[List[str]] = None

    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue

        # Handle Zeek TSV headers
        if line_clean.startswith("#fields"):
            current_tsv_fields = line_clean.split()[1:]
            continue
        if line_clean.startswith("#"):
            continue

        # If we have TSV fields active and line is not JSON
        if current_tsv_fields and not line_clean.startswith("{"):
            parsed = normalize_zeek_tsv_line(line_clean, current_tsv_fields)
            if parsed:
                results.append(parsed)
                continue

        # Try parsing line as JSON
        if line_clean.startswith("{"):
            try:
                data = json.loads(line_clean)
                if isinstance(data, dict):
                    # Disambiguate source
                    if "alert" in data or data.get("event_type") in ("alert", "flow", "drop"):
                        results.append(normalize_suricata_event(data))
                    elif "uid" in data or "id.orig_h" in data or "service" in data:
                        results.append(normalize_zeek_json_event(data))
                    elif default_source == "suricata":
                        results.append(normalize_suricata_event(data))
                    elif default_source == "zeek":
                        results.append(normalize_zeek_json_event(data))
                    else:
                        # Infer based on fields
                        if "dest_ip" in data:
                            results.append(normalize_suricata_event(data))
                        else:
                            results.append(normalize_zeek_json_event(data))
                    continue
            except json.JSONDecodeError:
                pass

    return results
