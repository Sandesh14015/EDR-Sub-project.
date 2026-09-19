# CYBERGUARD Detection Module (EDR / XDR Sub-Project)

The **CYBERGUARD Detection Module** is the core endpoint and network detection and response engine within the **CYBERGUARD** security ecosystem.

Built on **Wazuh 4.14.7** as the backbone and **Suricata** as the network IDS/IPS sensor (with optional **Zeek** network telemetry), the module normalizes, correlates, and responds to threats across 4 distinct domains.

> **"Wazuh monitors the endpoint. Suricata guards the network. CYBERGUARD correlates multi-domain telemetry and executes active response."**

---

## 🏗️ Architectural Overview

```
                         CYBERGUARD
                      Detection MODULE 

       ┌─────────────────────────────────────┐
       │             ENDPOINT                │
       │                                     │
       │         Wazuh 4.14.7 Agent          │
       │              │                      │
       │        ┌─────┼─────────┐            │
       │        │     │         │            │
       │       Logs   FIM    Inventory       │
       │        │     │         │            │
       │        └─────┼─────────┘            │
       │              │                      │
       └──────────────┼──────────────────────┘
                      │
                      │
 Network ────────► Suricata ───► eve.json
                      │
                      ▼
       ┌─────────────────────────────────────┐
       │     CYBERGUARD Detection Engine     │
       │                                     │
       │  1. Ingestion Adapter               │
       │  2. Multi-Domain Normalizer         │
       │  3. Correlation & Clustering        │
       │  4. Evidence Extraction             │
       │  5. Risk & Confidence Scoring       │
       │  6. Active Response IPS             │
       │  7. Real-Time Notification Stream   │
       └─────────────────────────────────────┘
```

---

## 🎯 4 Core Threat Domains

1. **Authentication Attacks**:
   - Repeated failed logins
   - Brute force & password spraying
   - Suspicious successful logins following failed attempts
   - Unusual source IPs and devices
2. **Endpoint Attacks**:
   - Suspicious processes & command lines (`powershell.exe`, `mimikatz`, `certutil.exe`)
   - Malware execution indicators
   - Unauthorized file modifications via Wazuh FIM Syscheck
   - Persistence mechanisms (registry keys, scheduled tasks)
3. **Network Attacks**:
   - Port scans & service sweeps
   - Exploit traffic & malicious connections
   - C2 communication & beaconing
   - Suspicious DNS anomalies
   - Suricata IDS/IPS signatures
4. **Application Activity**:
   - Web login events & brute force
   - API abuse & rate limiting violations
   - HTTP 401/403 authorization failures
   - Suspicious application behaviors

---

## 🔄 The 5-Stage Detection Pipeline

$$\text{Event} \longrightarrow \text{Evidence} \longrightarrow \text{Classification} \longrightarrow \text{Confidence / Risk} \longrightarrow \text{Notification}$$

1. **Event**: Ingests alerts from Wazuh 4.14.7, Suricata EVE, Zeek, or live Windows socket monitors.
2. **Evidence**: Extracts and links corroborating artifacts (logon records, modified file paths, IDS rules) into an immutable evidence store.
3. **Classification**: Maps incidents to MITRE ATT&CK techniques and threat categories (e.g. *Possible Account Compromise*).
4. **Confidence / Risk**: Decoupled scoring calculating Risk (0–100) and Confidence (0–100%) based on multi-sensor agreement.
5. **Notification & Active Response**: Pushes instant notifications to analysts and triggers Active Response IPS actions (Windows Firewall IP block, taskkill process termination).

---

## 🚀 Quick Start

### 1. Requirements & Installation
Requires Python 3.10+:
```bash
pip install -r requirements.txt
```

### 2. Start CYBERGUARD
```bash
python run.py
```
- **Web Dashboard**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **REST API & Swagger Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## 🧪 Running the Test Suite

Run the full automated test suite covering end-to-end multi-domain attacks, Active Response IPS, and live network scanning:
```bash
python -m unittest discover tests
```
*12 out of 12 tests pass cleanly.*

---

## 🛡️ Active Response IPS API

- `POST /api/ips/block`: Block an offending IP address in Windows Firewall via `netsh advfirewall`.
- `POST /api/ips/unblock`: Remove a temporary firewall block rule.
- `POST /api/ips/terminate`: Terminate an active malicious process by PID or name.
- `GET /api/notifications`: Retrieve real-time CYBERGUARD incident notifications.
- `GET /api/cyberguard/feed`: Complete normalized telemetry and incident feed.
