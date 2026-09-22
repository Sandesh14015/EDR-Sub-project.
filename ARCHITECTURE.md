# WayTrace Architecture

WayTrace is a Node.js and Express detection console for Wazuh, Suricata, Zeek, and live host telemetry. It normalizes events to a unified schema, correlates multi-sensor signals into incidents, and renders evidence, risk scores, and non-alarmist connection investigation cards.

```text
               WINDOWS HOST TELEMETRY
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
    TCP Table    Process Telemetry       DNS
        │                │                │
        └────────────────┼────────────────┘
                         ▼
                   WAYTRACE AGENT
                         │
                         ▼
                  WAYTRACE SERVER
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
     Context        Correlation          Risk
        │                │                │
        └────────────────┼────────────────┘
                         ▼
                     INCIDENT

        NETWORK VISIBILITY:
        Windows/Network ──► Suricata + Zeek ──► Network Evidence ──► WayTrace
```

## Connection Investigation Model

Instead of automatically flagging standard background socket activity as a suspicious alert, WayTrace presents a structured, analyst-friendly **Connection Investigation** card:

```text
┌──────────────────────────────────────────────┐
│ CONNECTION INVESTIGATION                     │
├──────────────────────────────────────────────┤
│ Local Host:       192.168.0.249              │
│                          ↓                   │
│ Remote:           150.171.110.86:443         │
│ Protocol:         TCP/TLS                    │
│ State:            ESTABLISHED                │
│ Process:          chrome.exe (PID 4916)      │
│ Risk:             LOW / MEDIUM / HIGH        │
│ Confidence:       94%                        │
└──────────────────────────────────────────────┘
```

### Structured Behavioral Assessment:
- **Process**: `chrome.exe`
- **Destination**: `150.171.110.86:443`
- **Protocol**: `TLS/HTTPS`
- **Observed behavior**: Established TCP connection, associated with browser process, port 443.
- **Assessment**: *"No malicious behavior observed from connection metadata alone."*

---

## Core Components

- `server.js`: Express routes, static dashboard, OpenAPI UI, and API validation.
- `backend/normalizer.js`: Wazuh, Suricata, Zeek, and CSV dataset parsing.
- `backend/detection.js`: Clustering, 4-domain classification, risk scoring, evidence, recommendations, timelines, and Markdown reports.
- `backend/database.js`: SQLite schema and persistence via `better-sqlite3` (`data/waytrace.db`).
- `backend/scanner.js`: Host socket and process telemetry via `systeminformation` (periodic scans run every 3 seconds).
- `backend/ips.js`: Active Response engine executing Windows Firewall IP blocking and process termination.
- `backend/scenarios.js`: Pre-packaged attack records for 5 scenario workflows.
- `frontend/index.html`: Clean HTML/CSS/JS analyst console with Connection Investigation card rendering.

