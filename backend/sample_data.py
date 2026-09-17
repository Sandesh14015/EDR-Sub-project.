import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List


def get_scenario_c2_beaconing() -> str:
    """
    Realistic multi-stage Command & Control Scenario matching Section 22:
    1. Zeek DNS resolution for malicious C2 domain
    2. Zeek Initial TCP connection
    3. Zeek TLS session handshake
    4. Suricata High-Severity detection
    5. Zeek repeated periodic beaconing sessions
    """
    base_time = datetime(2026, 9, 18, 2, 30, 0, tzinfo=timezone.utc)

    records = [
        # 1. Zeek DNS
        {
            "ts": (base_time).timestamp(),
            "uid": "CZK-DNS-01",
            "id.orig_h": "192.168.1.50",
            "id.orig_p": 54120,
            "id.resp_h": "1.1.1.1",
            "id.resp_p": 53,
            "proto": "udp",
            "service": "dns",
            "query": "c2-cdn-edge.cloud-telemetry.org",
            "qtype_name": "A",
            "answers": ["45.33.32.156"],
        },
        # 2. Zeek TCP Connection
        {
            "ts": (base_time + timedelta(seconds=6)).timestamp(),
            "uid": "CZK-CONN-01",
            "id.orig_h": "192.168.1.50",
            "id.orig_p": 49321,
            "id.resp_h": "45.33.32.156",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "conn_state": "SF",
            "orig_bytes": 1420,
            "resp_bytes": 3840,
        },
        # 3. Zeek TLS session
        {
            "ts": (base_time + timedelta(seconds=9)).timestamp(),
            "uid": "CZK-TLS-01",
            "id.orig_h": "192.168.1.50",
            "id.orig_p": 49321,
            "id.resp_h": "45.33.32.156",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "server_name": "c2-cdn-edge.cloud-telemetry.org",
            "subject": "CN=cloud-telemetry.org",
            "issuer": "CN=Untrusted Self-Signed CA",
        },
        # 4. Suricata Signature Detection
        {
            "timestamp": (base_time + timedelta(seconds=75)).isoformat(),
            "event_type": "alert",
            "src_ip": "192.168.1.50",
            "src_port": 49321,
            "dest_ip": "45.33.32.156",
            "dest_port": 443,
            "proto": "TCP",
            "flow_id": "189230912389",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2028912,
                "rev": 1,
                "signature": "ET MALWARE Cobalt Strike Malleable C2 Periodic Beaconing",
                "category": "A Network Trojan was detected",
                "severity": 1,
            },
        },
        # 5. Zeek repeated beaconing connection
        {
            "ts": (base_time + timedelta(seconds=190)).timestamp(),
            "uid": "CZK-CONN-02",
            "id.orig_h": "192.168.1.50",
            "id.orig_p": 49325,
            "id.resp_h": "45.33.32.156",
            "id.resp_p": 443,
            "proto": "tcp",
            "conn_state": "SF",
            "orig_bytes": 840,
            "resp_bytes": 1250,
        },
        # 6. Zeek second repeated beacon
        {
            "ts": (base_time + timedelta(seconds=310)).timestamp(),
            "uid": "CZK-CONN-03",
            "id.orig_h": "192.168.1.50",
            "id.orig_p": 49330,
            "id.resp_h": "45.33.32.156",
            "id.resp_p": 443,
            "proto": "tcp",
            "conn_state": "SF",
            "orig_bytes": 840,
            "resp_bytes": 1250,
        },
    ]

    return "\n".join([json.dumps(r) for r in records])


def get_scenario_scanning() -> str:
    """Port scanning reconnaissance scenario."""
    base_time = datetime(2026, 9, 18, 3, 10, 0, tzinfo=timezone.utc)
    records = []
    ports = [21, 22, 23, 80, 443, 445, 1433, 3306, 3389, 8080]

    for i, port in enumerate(ports):
        records.append(
            {
                "ts": (base_time + timedelta(seconds=i * 2)).timestamp(),
                "uid": f"CZK-SCAN-{i}",
                "id.orig_h": "192.168.1.105",
                "id.orig_p": 50000 + i,
                "id.resp_h": "192.168.1.1",
                "id.resp_p": port,
                "proto": "tcp",
                "conn_state": "REJ",
            }
        )

    records.append(
        {
            "timestamp": (base_time + timedelta(seconds=22)).isoformat(),
            "event_type": "alert",
            "src_ip": "192.168.1.105",
            "src_port": 50010,
            "dest_ip": "192.168.1.1",
            "dest_port": 3389,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "signature": "ET SCAN Potential Nmap TCP SYN Port Scan Detected",
                "category": "Detection of a Network Scan",
                "severity": 2,
            },
        }
    )

    return "\n".join([json.dumps(r) for r in records])


def get_scenario_ssh_brute_force() -> str:
    """SSH credential brute force scenario."""
    base_time = datetime(2026, 9, 18, 3, 40, 0, tzinfo=timezone.utc)
    records = []

    for i in range(5):
        records.append(
            {
                "ts": (base_time + timedelta(seconds=i * 5)).timestamp(),
                "uid": f"CZK-SSH-{i}",
                "id.orig_h": "203.0.113.88",
                "id.orig_p": 41200 + i,
                "id.resp_h": "192.168.1.20",
                "id.resp_p": 22,
                "proto": "tcp",
                "service": "ssh",
                "conn_state": "SF",
            }
        )

    records.append(
        {
            "timestamp": (base_time + timedelta(seconds=28)).isoformat(),
            "event_type": "alert",
            "src_ip": "203.0.113.88",
            "src_port": 41204,
            "dest_ip": "192.168.1.20",
            "dest_port": 22,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "signature": "ET SCAN Multiple SSH Authentication Failures (Brute Force)",
                "category": "Attempted User Privilege Gain",
                "severity": 2,
            },
        }
    )

    return "\n".join([json.dumps(r) for r in records])
