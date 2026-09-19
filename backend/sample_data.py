import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List


def get_scenario_account_compromise() -> str:
    """
    The exact user-requested multi-stage attack scenario:
    1. Suricata Network Exploit alert (ET EXPLOIT suspicious HTTP request from 185.220.101.5)
    2. Wazuh collects it and observes:
       - 5 failed logins for user 'admin'
       - 1 subsequent successful login
       - New executable created (payload.exe)
       - Critical system file modified (hosts file via FIM)
    Result: Account Compromise (Risk: CRITICAL)
    """
    base_time = datetime(2026, 9, 19, 3, 0, 0, tzinfo=timezone.utc)
    records = []

    # 1. Suricata Network Exploit Alert (forwarded via Wazuh Agent on user-machine)
    records.append({
        "timestamp": (base_time).isoformat(),
        "event_type": "alert",
        "src_ip": "185.220.101.5",
        "src_port": 51234,
        "dest_ip": "192.168.0.249",
        "dest_port": 80,
        "proto": "TCP",
        "flow_id": "981240182",
        "agent": {
            "id": "001",
            "name": "user-machine",
            "ip": "192.168.0.249"
        },
        "alert": {
            "action": "allowed",
            "signature": "ET EXPLOIT Suspicious HTTP Request / Web Application Exploit Attempt",
            "category": "Attempted Administrator Privilege Gain",
            "severity": 1
        }
    })

    # 2. Wazuh: 5 Failed Logins (Windows Event ID 4625 / Wazuh Rule 60122)
    for i in range(5):
        records.append({
            "timestamp": (base_time + timedelta(seconds=10 + i * 4)).isoformat(),
            "rule": {
                "id": "60122",
                "level": 10,
                "description": f"Logon Failure - Bad password for user 'admin' (Attempt #{i+1})",
                "groups": ["windows", "authentication_failed"],
                "mitre": {
                    "id": ["T1110"],
                    "tactic": ["Credential Access"],
                    "technique": ["Brute Force"]
                }
            },
            "agent": {
                "id": "001",
                "name": "user-machine",
                "ip": "192.168.0.249"
            },
            "data": {
                "srcip": "185.220.101.5",
                "srcuser": "admin",
                "win": {
                    "eventdata": {
                        "targetUserName": "admin",
                        "ipAddress": "185.220.101.5"
                    }
                }
            }
        })

    # 3. Wazuh: Successful Login (Windows Event ID 4624 / Wazuh Rule 60106)
    records.append({
        "timestamp": (base_time + timedelta(seconds=35)).isoformat(),
        "rule": {
            "id": "60106",
            "level": 8,
            "description": "Logon Success - User 'admin' authenticated following multiple failures",
            "groups": ["windows", "authentication_success"],
            "mitre": {
                "id": ["T1078"],
                "tactic": ["Defense Evasion", "Persistence"],
                "technique": ["Valid Accounts"]
            }
        },
        "agent": {
            "id": "001",
            "name": "user-machine",
            "ip": "192.168.0.249"
        },
        "data": {
            "srcip": "185.220.101.5",
            "srcuser": "admin",
            "win": {
                "eventdata": {
                    "targetUserName": "admin",
                    "ipAddress": "185.220.101.5"
                }
            }
        }
    })

    # 4. Wazuh: New Executable Created (Sysmon Event ID 11 / Wazuh Rule 92200)
    records.append({
        "timestamp": (base_time + timedelta(seconds=48)).isoformat(),
        "rule": {
            "id": "92200",
            "level": 12,
            "description": "Sysmon - File Created: Suspicious executable written to Temp directory",
            "groups": ["windows", "sysmon_event11", "process_creation"],
            "mitre": {
                "id": ["T1059", "T1105"],
                "tactic": ["Execution", "Command and Control"],
                "technique": ["Ingress Tool Transfer"]
            }
        },
        "agent": {
            "id": "001",
            "name": "user-machine",
            "ip": "192.168.0.249"
        },
        "data": {
            "srcip": "185.220.101.5",
            "win": {
                "eventdata": {
                    "processName": "payload.exe",
                    "image": "C:\\Users\\Admin\\AppData\\Local\\Temp\\payload.exe",
                    "commandLine": "payload.exe --connect 185.220.101.5:4444",
                    "processId": "5812",
                    "targetFilename": "C:\\Users\\Admin\\AppData\\Local\\Temp\\payload.exe"
                }
            }
        }
    })

    # 5. Wazuh: Critical File Modified (FIM Syscheck / Wazuh Rule 550)
    records.append({
        "timestamp": (base_time + timedelta(seconds=55)).isoformat(),
        "rule": {
            "id": "550",
            "level": 12,
            "description": "Integrity checksum changed for critical system file",
            "groups": ["ossec", "syscheck"],
            "mitre": {
                "id": ["T1565"],
                "tactic": ["Impact"],
                "technique": ["Data Manipulation"]
            }
        },
        "agent": {
            "id": "001",
            "name": "user-machine",
            "ip": "192.168.0.249"
        },
        "data": {
            "srcip": "185.220.101.5"
        },
        "syscheck": {
            "path": "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "event": "modified",
            "md5_after": "8b1a9953c4611296a827abf8c47804d7"
        }
    })

    return "\n".join([json.dumps(r) for r in records])


def get_scenario_password_spray() -> str:
    """Authentication Domain: Password spraying across multiple usernames."""
    base_time = datetime(2026, 9, 19, 2, 15, 0, tzinfo=timezone.utc)
    users = ["john.doe", "finance.dept", "db_admin", "dev_ops", "hr_manager"]
    records = []

    for i, u in enumerate(users):
        records.append({
            "timestamp": (base_time + timedelta(seconds=i * 5)).isoformat(),
            "rule": {
                "id": "60122",
                "level": 8,
                "description": f"Logon Failure for user '{u}'",
                "groups": ["windows", "authentication_failed"],
                "mitre": {"id": ["T1110.003"], "tactic": ["Credential Access"], "technique": ["Password Spraying"]}
            },
            "agent": {"id": "001", "name": "user-machine", "ip": "192.168.0.249"},
            "data": {
                "srcip": "203.0.113.77",
                "srcuser": u,
                "win": {"eventdata": {"targetUserName": u, "ipAddress": "203.0.113.77"}}
            }
        })
    return "\n".join([json.dumps(r) for r in records])


def get_scenario_endpoint_persistence() -> str:
    """Endpoint Domain: Suspicious PowerShell execution and Registry persistence."""
    base_time = datetime(2026, 9, 19, 2, 45, 0, tzinfo=timezone.utc)
    records = [
        {
            "timestamp": (base_time).isoformat(),
            "rule": {
                "id": "92001",
                "level": 11,
                "description": "Sysmon - Suspicious Encoded PowerShell Execution",
                "groups": ["windows", "sysmon_event1"],
                "mitre": {"id": ["T1059.001"], "tactic": ["Execution"], "technique": ["PowerShell"]}
            },
            "agent": {"id": "001", "name": "user-machine", "ip": "192.168.0.249"},
            "data": {
                "win": {
                    "eventdata": {
                        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "commandLine": "powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand SQBFAFgA...",
                        "processId": "3412"
                    }
                }
            }
        },
        {
            "timestamp": (base_time + timedelta(seconds=8)).isoformat(),
            "rule": {
                "id": "550",
                "level": 10,
                "description": "FIM - Startup Run Key Modified for Persistence",
                "groups": ["ossec", "syscheck"],
                "mitre": {"id": ["T1547.001"], "tactic": ["Persistence"], "technique": ["Registry Run Keys"]}
            },
            "agent": {"id": "001", "name": "user-machine", "ip": "192.168.0.249"},
            "syscheck": {
                "path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdaterService",
                "event": "modified"
            }
        }
    ]
    return "\n".join([json.dumps(r) for r in records])


def get_scenario_app_abuse() -> str:
    """Application Domain: Spike in API authorization failures (HTTP 401/403)."""
    base_time = datetime(2026, 9, 19, 3, 10, 0, tzinfo=timezone.utc)
    records = []
    for i in range(5):
        records.append({
            "timestamp": (base_time + timedelta(seconds=i * 2)).isoformat(),
            "rule": {
                "id": "31101",
                "level": 7,
                "description": "Web server - Access denied / HTTP 403 Forbidden on API endpoint",
                "groups": ["web", "accesslog"],
                "mitre": {"id": ["T1078"], "tactic": ["Initial Access"], "technique": ["Valid Accounts"]}
            },
            "agent": {"id": "001", "name": "user-machine", "ip": "192.168.0.249"},
            "data": {
                "srcip": "198.51.100.22",
                "dstip": "192.168.0.249"
            }
        })
    return "\n".join([json.dumps(r) for r in records])


def get_scenario_c2_beaconing() -> str:
    """Network Domain: Multi-sensor C2 Periodic Beaconing (Suricata + Zeek)."""
    base_time = datetime(2026, 9, 19, 1, 30, 0, tzinfo=timezone.utc)
    records = [
        # 1. Zeek DNS query
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
        # 2. Zeek initial connection
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
            "server_name": "c2-cdn-edge.cloud-telemetry.org",
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
                "signature": "ET MALWARE Cobalt Strike Malleable C2 Periodic Beaconing",
                "category": "A Network Trojan was detected",
                "severity": 1,
            },
        },
        # 5. Zeek repeated beacon #1
        {
            "ts": (base_time + timedelta(seconds=190)).timestamp(),
            "uid": "CZK-CONN-02",
            "id.orig_h": "192.168.1.50",
            "id.orig_p": 49325,
            "id.resp_h": "45.33.32.156",
            "id.resp_p": 443,
            "proto": "tcp",
            "conn_state": "SF",
        },
        # 6. Zeek repeated beacon #2
        {
            "ts": (base_time + timedelta(seconds=310)).timestamp(),
            "uid": "CZK-CONN-03",
            "id.orig_h": "192.168.1.50",
            "id.orig_p": 49330,
            "id.resp_h": "45.33.32.156",
            "id.resp_p": 443,
            "proto": "tcp",
            "conn_state": "SF",
        },
    ]
    return "\n".join([json.dumps(r) for r in records])
