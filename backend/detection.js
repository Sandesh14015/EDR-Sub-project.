import os
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import psutil

from backend import database
from backend.correlation import correlate_events
from backend.models import NormalizedEvent, ThreatDomain

# Known high-risk or suspicious ports often used by C2 frameworks, trojans, or cleartext protocols
SUSPICIOUS_PORTS = {
    4444: "Metasploit / Reverse Shell Default Port",
    1337: "Common Hacker / Backdoor Port",
    5555: "Android ADB / Trojan Port",
    6667: "IRC / Botnet C2 Communication",
    8888: "Alternative HTTP / Common C2 Staging Port",
    31337: "Back Orifice / Trojan Port",
    23: "Insecure Telnet Protocol (Cleartext Credential Risk)",
    1080: "SOCKS Proxy (Potential Anonymization / Proxying)",
}

# Processes that should normally not be reaching out directly to arbitrary external public IPs
SUSPICIOUS_OUTBOUND_PROCESSES = {
    "cmd.exe": "Windows Command Prompt making outbound network connection",
    "powershell.exe": "PowerShell making direct external network connection (Potential C2/Download)",
    "pwsh.exe": "PowerShell Core making direct external network connection",
    "certutil.exe": "CertUtil network activity (Common Living-off-the-Land downloader)",
    "rundll32.exe": "RunDLL32 network activity (Common DLL payload execution)",
    "wscript.exe": "Windows Script Host network activity",
    "cscript.exe": "Console Script Host network activity",
    "mshta.exe": "Microsoft HTML Application Host network activity",
    "regsvr32.exe": "Regsvr32 network activity (Squiblydoo execution technique)",
}

# Private IP prefixes (RFC 1918 + loopback)
PRIVATE_IP_PREFIXES = (
    "127.",
    "10.",
    "192.168.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "::1",
    "fe80:",
    "0.0.0.0",
)


def is_external_ip(ip: str) -> bool:
    if not ip:
        return False
    return not any(ip.startswith(prefix) for prefix in PRIVATE_IP_PREFIXES)


class LiveNetworkScanner:
    """
    Monitors live network connections and traffic on the host system.
    Extracts telemetry and evaluates intrusion detection rules in real-time.
    """

    def __init__(self, poll_interval_seconds: float = 3.0):
        self.poll_interval = poll_interval_seconds
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Stats tracking
        self.scanned_connections_count = 0
        self.total_alerts_generated = 0
        self.start_time: Optional[str] = None
        self._seen_signatures: Set[str] = set()

    @property
    def is_running(self) -> bool:
        return self._running

    def get_status(self) -> Dict[str, Any]:
        return {
            "is_scanning": self._running,
            "scanned_connections": self.scanned_connections_count,
            "alerts_generated": self.total_alerts_generated,
            "started_at": self.start_time,
        }

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._running = True
            self.start_time = datetime.now(timezone.utc).isoformat()
            self._thread = threading.Thread(target=self._scan_loop, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            self._running = False
            self._thread = None

    def scan_once(self) -> List[NormalizedEvent]:
        """Performs a single immediate scan of all active system network connections."""
        return self._inspect_system_connections()

    def _scan_loop(self) -> None:
        while self._running:
            try:
                events = self._inspect_system_connections()
                if events:
                    # Run correlation to check if newly ingested telemetry forms/updates incidents
                    correlate_events()
            except Exception as e:
                print(f"[LiveNetworkScanner] Error during scan cycle: {e}")
            time.sleep(self.poll_interval)

    def _inspect_system_connections(self) -> List[NormalizedEvent]:
        """
        Inspects active system network sockets via psutil.
        Generates telemetry events and intrusion alert events.
        """
        try:
            connections = psutil.net_connections(kind="inet")
        except Exception as err:
            print(f"[LiveNetworkScanner] Failed to fetch system connections: {err}")
            return []

        now_iso = datetime.now(timezone.utc).isoformat()
        new_events: List[NormalizedEvent] = []

        # Tracking for port scanning detection: remote_ip -> set of destination ports
        ip_port_map: Dict[str, Set[int]] = {}

        for conn in connections:
            if not conn.raddr:
                continue

            self.scanned_connections_count += 1
            src_ip = conn.laddr.ip if conn.laddr else "127.0.0.1"
            src_port = conn.laddr.port if conn.laddr else 0
            dst_ip = conn.raddr.ip
            dst_port = conn.raddr.port
            proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            status = conn.status or "UNKNOWN"

            # Get process information
            proc_name = "Unknown"
            proc_exe = "Unknown"
            if conn.pid:
                try:
                    p = psutil.Process(conn.pid)
                    proc_name = p.name()
                    proc_exe = p.exe()
                except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                    proc_name = f"PID-{conn.pid}"

            # Track destination ports for scan detection
            if dst_ip not in ip_port_map:
                ip_port_map[dst_ip] = set()
            ip_port_map[dst_ip].add(dst_port)

            # 1. Telemetry Event (Zeek equivalent for host connection)
            telemetry_event = NormalizedEvent(
                event_id=f"SYS-{uuid.uuid4().hex[:8].upper()}",
                timestamp=now_iso,
                source="zeek",  # Normalized as behavioral network observation
                event_type="conn",
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=proto,
                domain=ThreatDomain.NETWORK,
                domain_name=None,
                severity=1,
                signature=f"Connection [{status}] by {proc_name} -> {dst_ip}:{dst_port}",
                flow_id=f"PID_{conn.pid}_{conn.fd or '0'}",
                sensor_id="host-agent-live",
                raw_event={
                    "process_name": proc_name,
                    "process_path": proc_exe,
                    "pid": conn.pid,
                    "status": status,
                    "family": str(conn.family),
                },
            )
            new_events.append(telemetry_event)

            # 2. Rule Evaluation: Malicious or Suspicious Outbound Process
            proc_lower = proc_name.lower()
            if proc_lower in SUSPICIOUS_OUTBOUND_PROCESSES and is_external_ip(dst_ip):
                sig_key = f"susp_proc_{proc_lower}_{dst_ip}_{dst_port}"
                rule_desc = SUSPICIOUS_OUTBOUND_PROCESSES[proc_lower]
                if sig_key not in self._seen_signatures:
                    self._seen_signatures.add(sig_key)
                    self.total_alerts_generated += 1
                    alert_event = NormalizedEvent(
                        event_id=f"IDS-{uuid.uuid4().hex[:8].upper()}",
                        timestamp=now_iso,
                        source="suricata",  # Normalized as IDS Detection
                        event_type="alert",
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        protocol=proto,
                        severity=9,  # High Severity
                        signature=f"INTRUSION ALERT: {rule_desc} -> {dst_ip}:{dst_port}",
                        flow_id=f"PID_{conn.pid}",
                        sensor_id="host-ids-live",
                        raw_event={
                            "rule": "SUSPICIOUS_OUTBOUND_PROCESS",
                            "process_name": proc_name,
                            "process_path": proc_exe,
                            "pid": conn.pid,
                            "destination": f"{dst_ip}:{dst_port}",
                        },
                    )
                    new_events.append(alert_event)

            # 3. Rule Evaluation: Known Dangerous / C2 Ports
            if dst_port in SUSPICIOUS_PORTS and is_external_ip(dst_ip):
                sig_key = f"susp_port_{dst_ip}_{dst_port}"
                port_desc = SUSPICIOUS_PORTS[dst_port]
                if sig_key not in self._seen_signatures:
                    self._seen_signatures.add(sig_key)
                    self.total_alerts_generated += 1
                    alert_event = NormalizedEvent(
                        event_id=f"IDS-{uuid.uuid4().hex[:8].upper()}",
                        timestamp=now_iso,
                        source="suricata",
                        event_type="alert",
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        protocol=proto,
                        severity=8,
                        signature=f"HIGH-RISK PORT DETECTED: Port {dst_port} ({port_desc}) contacted by {proc_name}",
                        flow_id=f"PID_{conn.pid}",
                        sensor_id="host-ids-live",
                        raw_event={
                            "rule": "SUSPICIOUS_PORT_ALERT",
                            "port": dst_port,
                            "description": port_desc,
                            "process_name": proc_name,
                        },
                    )
                    new_events.append(alert_event)

            # 4. Rule Evaluation: Connection State Anomalies (e.g. repeated SYN_SENT without reply)
            if status in ("SYN_SENT",) and is_external_ip(dst_ip):
                telemetry_event.severity = 3
                telemetry_event.signature = f"Unacknowledged SYN probe by {proc_name} -> {dst_ip}:{dst_port}"

        # 5. Rule Evaluation: Port Scanning Detection
        for dest_ip, ports in ip_port_map.items():
            if len(ports) >= 6 and is_external_ip(dest_ip):
                sig_key = f"port_scan_{dest_ip}"
                if sig_key not in self._seen_signatures:
                    self._seen_signatures.add(sig_key)
                    self.total_alerts_generated += 1
                    scan_alert = NormalizedEvent(
                        event_id=f"IDS-{uuid.uuid4().hex[:8].upper()}",
                        timestamp=now_iso,
                        source="suricata",
                        event_type="alert",
                        src_ip="127.0.0.1",
                        dst_ip=dest_ip,
                        protocol="TCP",
                        severity=7,
                        signature=f"POTENTIAL PORT SCAN: {len(ports)} different destination ports contacted on {dest_ip}",
                        sensor_id="host-ids-live",
                        raw_event={
                            "rule": "PORT_SCAN_DETECTED",
                            "ports_contacted": list(ports),
                            "target_ip": dest_ip,
                        },
                    )
                    new_events.append(scan_alert)

        # Save all normalized events to the SQLite database
        if new_events:
            database.save_events_batch(new_events)

        return new_events


# Global scanner instance
live_scanner = LiveNetworkScanner(poll_interval_seconds=3.0)
