# Network Detection & Incident Intelligence Platform

## 1. Project Overview

This project is a network security monitoring and incident intelligence platform built around **Suricata** and **Zeek**.

The platform does not treat Suricata or Zeek as the final product. Instead, they act as network sensors that provide security events and network telemetry to an intelligence layer developed as part of this project.

The platform is designed to:

- Detect suspicious and malicious network activity
- Collect detailed network telemetry
- Correlate events from Suricata and Zeek
- Build attack timelines
- Calculate incident risk scores
- Track incident status throughout an investigation
- Preserve supporting evidence
- Generate investigation reports
- Recommend future security measures
- Present all information through a security operations dashboard

### Core concept

> **Suricata detects. Zeek observes. The intelligence layer correlates. The incident engine explains.**

---

# 2. High-Level Architecture

```text
                         ┌─────────────────┐
                         │    NETWORK      │
                         └────────┬────────┘
                                  │
                          TAP / SPAN / NIC
                                  │
                ┌─────────────────┴─────────────────┐
                │                                   │
         ┌──────▼──────┐                     ┌──────▼──────┐
         │  SURICATA   │                     │    ZEEK     │
         │             │                     │             │
         │ IDS / IPS   │                     │ Telemetry   │
         └──────┬──────┘                     └──────┬──────┘
                │                                   │
             eve.json                          Zeek Logs
                │                                   │
                └────────────────┬──────────────────┘
                                 ▼
                     ┌──────────────────────┐
                     │   EVENT COLLECTOR    │
                     │       Python         │
                     └──────────┬───────────┘
                                ▼
                     ┌──────────────────────┐
                     │     NORMALIZER       │
                     └──────────┬───────────┘
                                ▼
                     ┌──────────────────────┐
                     │  CORRELATION ENGINE  │
                     └──────────┬───────────┘
                                │
               ┌────────────────┼────────────────┐
               ▼                ▼                ▼
        ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
        │  TIMELINE   │  │    RISK     │  │   THREAT    │
        │   ENGINE    │  │   ENGINE    │  │ CLASSIFIER  │
        └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
               └────────────────┼─────────────────┘
                                ▼
                     ┌──────────────────────┐
                     │   INCIDENT ENGINE    │
                     └──────────┬───────────┘
                                │
            ┌───────────────────┼──────────────────┐
            ▼                   ▼                  ▼
      ┌───────────┐      ┌────────────┐     ┌────────────┐
      │ EVIDENCE  │      │ REPORT     │     │RECOMMENDER │
      │   STORE   │      │ GENERATOR  │     │   ENGINE   │
      └─────┬─────┘      └─────┬──────┘     └─────┬──────┘
            └──────────────────┼───────────────────┘
                               ▼
                    ┌──────────────────────┐
                    │      POSTGRESQL      │
                    └──────────┬───────────┘
                               ▼
                    ┌──────────────────────┐
                    │      FASTAPI         │
                    │ REST + WebSocket     │
                    └──────────┬───────────┘
                               ▼
                    ┌──────────────────────┐
                    │    REACT / NEXT.JS   │
                    │     SOC DASHBOARD    │
                    └──────────────────────┘
```

---

# 3. System Philosophy

The platform follows a sensor → intelligence → incident workflow.

```text
Network Traffic
      ↓
Sensors
      ↓
Raw Security Events
      ↓
Normalization
      ↓
Correlation
      ↓
Threat Understanding
      ↓
Incident Creation
      ↓
Risk Assessment
      ↓
Attack Timeline
      ↓
Recommendations
      ↓
Investigation Report
```

Suricata and Zeek should remain independent processes. The project should integrate their outputs rather than modify or merge their source code.

---

# 4. Sensor Layer

## 4.1 Suricata

Suricata is responsible primarily for:

- IDS detection
- Signature-based detection
- Protocol inspection
- Suspicious traffic identification
- Optional IPS functionality
- Security alerts

Typical output:

```text
/var/log/suricata/eve.json
```

Example event fields:

```json
{
  "timestamp": "2026-09-18T02:14:23Z",
  "event_type": "alert",
  "src_ip": "192.168.1.50",
  "src_port": 49321,
  "dest_ip": "45.x.x.x",
  "dest_port": 443,
  "proto": "TCP",
  "alert": {
    "signature": "Suspicious TLS Activity",
    "severity": 2
  }
}
```

Suricata answers:

> **"Did a known or rule-defined suspicious pattern occur?"**

---

## 4.2 Zeek

Zeek is responsible primarily for:

- Network visibility
- Connection telemetry
- DNS activity
- HTTP activity
- TLS/SSL activity
- SSH activity
- File/network metadata
- Protocol-level logs
- Behavioral context

Common logs include:

```text
conn.log
dns.log
http.log
ssl.log
ssh.log
files.log
```

Zeek answers:

> **"What happened on the network around this activity?"**

---

# 5. Sensor Deployment

For a prototype, Suricata and Zeek can run on the same Linux monitoring machine.

```text
┌─────────────────────────────┐
│      Monitoring Server      │
│                             │
│  ┌──────────┐ ┌──────────┐  │
│  │ Suricata │ │   Zeek   │  │
│  └──────────┘ └──────────┘  │
│                             │
│       Event Collector       │
└──────────────┬──────────────┘
               │
               ▼
           Application
```

For a real network deployment, the sensor machine should receive traffic through an appropriate monitoring interface, such as a network TAP or switch SPAN/mirror port.

The important rule is:

> A sensor can only analyze traffic that is actually visible to its network interface.

Installing Suricata or Zeek on a cloud application server does not automatically provide visibility into every user's traffic.

---

# 6. Ingestion Layer

The ingestion layer continuously receives or reads events from the sensors.

Recommended initial implementation:

- Python
- FastAPI for API services
- Background workers for event ingestion

Responsibilities:

1. Watch Suricata `eve.json`
2. Read Zeek logs
3. Parse incoming events
4. Attach ingestion metadata
5. Forward events to normalization

```text
Suricata eve.json ──┐
                    ├──> Event Collector
Zeek logs ──────────┘
                          ↓
                     Normalization
```

---

# 7. Event Normalization

Suricata and Zeek use different event structures.

The normalization layer converts both into a common internal event schema.

Example:

```json
{
  "event_id": "EVT-98231",
  "timestamp": "2026-09-18T02:14:23Z",
  "source": "suricata",
  "src_ip": "192.168.1.50",
  "src_port": 49321,
  "dst_ip": "45.x.x.x",
  "dst_port": 443,
  "protocol": "TCP",
  "event_type": "network_alert",
  "severity": 8,
  "signature": "Suspicious TLS Activity",
  "raw_reference": "..."
}
```

A Zeek event should be represented using the same common schema wherever possible.

### Recommended common fields

```text
event_id
timestamp
source
event_type
src_ip
src_port
dst_ip
dst_port
protocol
domain
severity
signature
flow_id
sensor_id
raw_event
```

Additional tool-specific data should be retained rather than discarded.

---

# 8. Correlation Engine

The correlation engine is the central intelligence component.

Its purpose is to determine which events are related.

Possible correlation keys:

- Source IP
- Destination IP
- Source port
- Destination port
- Protocol
- Flow ID
- Domain
- Session
- Time window
- Sensor
- Event type

Example:

```text
Suricata Alert
      +
Zeek DNS Event
      +
Zeek Connection Event
      +
Zeek TLS Event
      ↓
Correlation
      ↓
Potentially related activity
```

### Example correlation rule

Events may be considered related when:

```text
same source IP
AND
related destination
AND
within a defined time window
```

The correlation engine should avoid creating one incident for every individual alert.

Instead:

```text
10 Suricata alerts
+
25 Zeek events
+
same host
+
same campaign/time window
        ↓
ONE INCIDENT
```

---

# 9. Incident Entity

A central incident object should contain:

```text
Incident ID
Title
Description
Status
Severity
Risk Score
Confidence Score
Threat Category
Affected Assets
Source Entities
Destination Entities
First Seen
Last Seen
Created At
Updated At
```

Example:

```json
{
  "incident_id": "INC-1024",
  "title": "Possible Command and Control Activity",
  "status": "INVESTIGATING",
  "severity": "HIGH",
  "risk_score": 87,
  "confidence": 91,
  "first_seen": "2026-09-18T02:30:59Z",
  "last_seen": "2026-09-18T02:35:10Z"
}
```

---

# 10. Attack Timeline Engine

The timeline engine reconstructs the sequence of network events associated with an incident.

Example raw events:

```text
10:30:59  DNS query
10:31:05  External TCP connection
10:31:08  TLS session
10:32:14  Suricata alert
10:34:10  Repeated connection
10:35:10  Repeated connection
```

Timeline:

```text
                    INCIDENT TIMELINE

10:30:59 ── DNS Query
              │
10:31:05 ── External Connection
              │
10:31:08 ── TLS Session
              │
10:32:14 ── 🚨 Suricata Detection
              │
10:34:10 ── Repeated Communication
              │
10:35:10 ── Possible C2 Behavior
```

The timeline should preserve both:

1. Raw observed events
2. Higher-level inferred events

Inferred events must be clearly marked as inferred or suspected.

---

# 11. Threat Classification

The platform can classify incidents into categories such as:

```text
Reconnaissance
Scanning
Brute Force
Exploitation
Malware Communication
Command and Control
Suspicious DNS
Data Transfer
Policy Violation
Unknown
```

Initial implementation should use deterministic rules.

Later versions can introduce ML/AI classification.

### Important principle

Do not begin with an AI model.

First build:

```text
Reliable telemetry
      ↓
Reliable normalization
      ↓
Reliable correlation
      ↓
Reliable rule-based classification
      ↓
Then ML/AI
```

This makes the system explainable and easier to validate.

---

# 12. Risk Engine

The risk engine calculates the platform's own risk score instead of simply copying Suricata severity.

Possible factors:

```text
Detection Severity
Behavioral Suspicion
Event Frequency
Asset Criticality
Persistence
Historical Evidence
Detection Confidence
```

Example conceptual model:

```text
Risk Score =
    weighted detection severity
  + behavioral evidence
  + frequency
  + asset criticality
  + persistence
  + historical evidence
```

Normalize the final score to:

```text
0–20    LOW
21–40   MODERATE
41–60   MEDIUM
61–80   HIGH
81–100  CRITICAL
```

### Keep Risk and Confidence separate

Example:

```text
Risk:       91 / 100
Confidence: 87%
```

Risk answers:

> How dangerous could this incident be?

Confidence answers:

> How confident are we that our assessment is correct?

---

# 13. Incident Status Engine

Recommended lifecycle:

```text
NEW
 ↓
TRIAGED
 ↓
INVESTIGATING
 ↓
CONFIRMED
 ↓
CONTAINED
 ↓
RESOLVED
```

Alternative branch:

```text
NEW
 ↓
FALSE POSITIVE
```

### Status meanings

| Status | Meaning |
|---|---|
| NEW | Incident automatically created |
| TRIAGED | Initial analyst assessment completed |
| INVESTIGATING | Evidence is being analyzed |
| CONFIRMED | Malicious/suspicious activity confirmed |
| CONTAINED | Immediate containment has been performed |
| RESOLVED | Investigation and remediation completed |
| FALSE POSITIVE | Activity determined not to be a security incident |

---

# 14. Evidence Store

Every incident should have traceable evidence.

Example:

```text
INC-1024
│
├── Suricata Alerts
│   ├── EVT-001
│   └── EVT-008
│
├── Zeek Events
│   ├── DNS-019
│   ├── CONN-092
│   └── TLS-021
│
├── Source IPs
│   └── 192.168.1.50
│
├── Destination IPs
│   └── 45.x.x.x
│
└── Domains
    └── suspicious.example
```

Evidence should answer:

> **"Why did the system create this incident?"**

Raw events should be retained where practical so investigators can trace derived conclusions back to the original telemetry.

---

# 15. Recommendation Engine

The recommendation engine generates future security measures based on the incident.

Recommendations should initially be advisory rather than automatically executed.

### Immediate measures

```text
Investigate affected endpoint
Review suspicious destination
Consider containment if confirmed malicious
```

### Short-term measures

```text
Search for similar activity
Review other hosts contacting the destination
Review related DNS activity
Improve detection coverage
```

### Long-term measures

```text
Improve network segmentation
Add monitoring for recurring behavior
Review security controls
Create/update detection rules
```

Recommendations should be tied to evidence whenever possible.

---

# 16. Report Generator

The report generator combines incident information into an investigation report.

Example structure:

```text
SECURITY INCIDENT REPORT

Incident ID:
INC-1024

Threat:
Possible Command and Control Activity

Risk:
91 / 100

Confidence:
87%

Severity:
HIGH

Status:
INVESTIGATING

Affected Host:
192.168.1.50

First Observed:
02:30:59

Last Observed:
02:35:10
```

## Timeline

```text
02:30:59  DNS query
02:31:05  External connection
02:31:08  TLS session
02:32:14  Suricata detection
02:34:10  Repeated communication
02:35:10  C2 behavior suspected
```

## Evidence

```text
2 Suricata detections
17 Zeek events
1 suspicious domain
1 affected endpoint
```

## Recommendations

```text
Investigate endpoint
Review related traffic
Search historical activity
Consider containment
```

---

# 17. Backend Architecture

Recommended backend:

```text
FastAPI
│
├── /events
├── /incidents
├── /incidents/{id}
├── /incidents/{id}/timeline
├── /incidents/{id}/evidence
├── /incidents/{id}/risk
├── /incidents/{id}/recommendations
├── /incidents/{id}/report
└── /health
```

For real-time dashboard updates:

```text
WebSocket
```

Example flow:

```text
Suricata detects event
        ↓
Event Collector
        ↓
Correlation Engine
        ↓
Incident updated
        ↓
WebSocket event
        ↓
Dashboard updates
```

---

# 18. Database Architecture

PostgreSQL is sufficient for the initial implementation.

Recommended tables:

```text
events
incidents
incident_events
evidence
recommendations
reports
assets
sensors
```

## events

```text
id
timestamp
source
event_type
src_ip
src_port
dst_ip
dst_port
protocol
severity
raw_event
sensor_id
```

## incidents

```text
id
title
description
status
severity
risk_score
confidence
threat_category
first_seen
last_seen
created_at
updated_at
```

## incident_events

```text
incident_id
event_id
relationship_type
```

## evidence

```text
id
incident_id
type
value
source
timestamp
description
```

## recommendations

```text
id
incident_id
priority
recommendation
status
```

## reports

```text
id
incident_id
generated_at
report_type
report_location
```

---

# 19. Frontend Architecture

Recommended frontend:

- React or Next.js
- TypeScript
- Tailwind CSS
- Recharts or equivalent visualization library

Main dashboard sections:

```text
Dashboard
│
├── Overview
├── Incidents
├── Incident Details
│   ├── Timeline
│   ├── Risk
│   ├── Evidence
│   ├── Related Events
│   ├── Recommendations
│   └── Report
├── Network Activity
├── Threat Trends
└── Settings
```

### Incident page

```text
┌──────────────────────────────────────────────┐
│ INCIDENT #INC-1024                           │
│ Possible C2 Activity                         │
│                                              │
│ Risk: 91/100       Confidence: 87%           │
│ Status: INVESTIGATING                        │
├──────────────────────────────────────────────┤
│                                              │
│ ATTACK TIMELINE                              │
│                                              │
│ 02:30 DNS                                    │
│ 02:31 Connection                             │
│ 02:32 🚨 Detection                           │
│ 02:34 Repeated Communication                 │
│ 02:35 C2 Suspected                           │
│                                              │
├──────────────────────────────────────────────┤
│ Evidence | Related Events | Recommendations  │
├──────────────────────────────────────────────┤
│ Generate Investigation Report                │
└──────────────────────────────────────────────┘
```

---

# 20. Recommended Technology Stack

## Sensor Layer

```text
Suricata
Zeek
Linux
```

## Backend

```text
Python
FastAPI
Pydantic
```

## Processing

```text
Python
Rule Engine
Optional scikit-learn later
```

## Database

```text
PostgreSQL
```

## Real-time communication

```text
WebSocket
```

## Frontend

```text
React / Next.js
TypeScript
Tailwind CSS
```

## Optional future technologies

```text
Redis
Kafka
Elasticsearch/OpenSearch
Neo4j
XGBoost
PyTorch
```

These should be introduced only when scale or functionality requires them.

---

# 21. Security Data Flow

The complete data flow is:

```text
                   NETWORK TRAFFIC
                          │
                          ▼
              ┌─────────────────────┐
              │  Network Sensors    │
              │                     │
              │ Suricata + Zeek     │
              └──────────┬──────────┘
                         │
                         ▼
                 RAW SENSOR DATA
                         │
                         ▼
                 EVENT COLLECTOR
                         │
                         ▼
                  NORMALIZATION
                         │
                         ▼
                    CORRELATION
                         │
                         ▼
                 THREAT ANALYSIS
                         │
             ┌───────────┼───────────┐
             ▼           ▼           ▼
         Timeline      Risk       Classification
             │           │           │
             └───────────┼───────────┘
                         ▼
                  INCIDENT ENGINE
                         │
             ┌───────────┼────────────┐
             ▼           ▼            ▼
          Evidence     Status    Recommendations
             │           │            │
             └───────────┼────────────┘
                         ▼
                    REPORTING
                         │
                         ▼
                    REST API
                         │
                         ▼
                 SECURITY DASHBOARD
```

---

# 22. Example End-to-End Scenario

A controlled test environment generates synthetic traffic.

```text
Test Host
   ↓
Synthetic Traffic
   ↓
Network Interface
```

Suricata detects a rule match:

```text
🚨 Suspicious network activity
```

Zeek records surrounding activity:

```text
DNS request
TCP connection
TLS session
Repeated connection
```

The collector receives both.

```text
Suricata ──┐
           ├──> Normalization
Zeek ──────┘
```

The correlation engine determines that the events are related.

```text
Related events
      ↓
Incident INC-1024
```

The platform calculates:

```text
Risk: 87/100
Confidence: 91%
```

The timeline engine generates:

```text
10:30 DNS
10:31 TCP connection
10:32 Suricata alert
10:34 Repeated communication
10:35 Possible C2
```

The incident status becomes:

```text
INVESTIGATING
```

The recommendation engine produces:

```text
Investigate affected host
Review related network traffic
Search for similar activity
Consider containment if confirmed
```

Finally, the report generator produces an investigation report.

---

# 23. MVP Development Plan

Do not build the entire architecture at once.

## Phase 1 — Sensor Lab

Goal:

```text
Suricata
+
Zeek
+
Synthetic traffic
```

Verify that both sensors observe the same controlled traffic.

---

## Phase 2 — Event Collection

Build:

```text
Suricata → Collector
Zeek → Collector
```

Parse and store raw events.

---

## Phase 3 — Normalization

Create the common event schema.

```text
Suricata events ──┐
                  ├──> Common Event Model
Zeek events ──────┘
```

---

## Phase 4 — Correlation

Implement basic correlation using:

```text
Source IP
Destination IP
Time window
Protocol
Flow/session identifiers
```

Create incidents from groups of related events.

---

## Phase 5 — Timeline

Build:

```text
Incident
   ↓
Ordered events
   ↓
Timeline
```

---

## Phase 6 — Risk Scoring

Start with a transparent rule/weighted scoring model.

Do not use ML initially.

---

## Phase 7 — Incident Management

Add:

```text
Status
Severity
Assignment
Evidence
Comments
```

---

## Phase 8 — Recommendations

Build an evidence-based rule engine for recommended actions.

---

## Phase 9 — Reporting

Generate:

```text
Incident summary
Timeline
Risk
Evidence
Recommendations
```

---

## Phase 10 — Intelligence/ML

Only after enough reliable data exists, introduce:

```text
Behavioral anomaly detection
Threat classification
Risk prediction
Clustering
Pattern discovery
```

---

# 24. Future Expansion

The architecture can later support endpoint telemetry.

```text
                         SECURITY ENVIRONMENT
                                  │
             ┌────────────────────┼────────────────────┐
             │                    │                    │
             ▼                    ▼                    ▼
         Suricata                Zeek               Sysmon
         Network IDS          Network Telemetry    Endpoint
             │                    │                    │
             └────────────────────┼────────────────────┘
                                  ▼
                           CORRELATION ENGINE
                                  ▼
                           INCIDENT ENGINE
                                  ▼
                         SECURITY INTELLIGENCE
```

This allows the platform to correlate:

```text
Network Event
+
Endpoint Event
+
Authentication Event
+
Historical Activity
```

and create a richer incident story.

---

# 25. Key Design Principles

### 1. Suricata and Zeek are sensors

They are not the complete platform.

### 2. Your correlation engine is the core intelligence

It turns isolated events into incidents.

### 3. Preserve raw evidence

Every important conclusion should be traceable to source events.

### 4. Separate risk from confidence

High risk does not necessarily mean high certainty.

### 5. Keep recommendations explainable

The system should explain why it recommends an action.

### 6. Treat inferred attack stages as hypotheses

Network telemetry can suggest attack behavior but may not prove every stage.

### 7. Start deterministic

Build reliable rules before adding ML/AI.

### 8. Keep automated response controlled

Recommendations should not automatically perform destructive actions without explicit authorization.

---

# 26. Final Product Concept

The final product can be described as:

> **A network security intelligence platform that combines Suricata's threat detection with Zeek's network telemetry to correlate security events into incidents, reconstruct attack timelines, calculate risk and confidence scores, track incident status, preserve evidence, generate investigation reports, and recommend future defensive measures.**

The fundamental pipeline is:

```text
REAL NETWORK TRAFFIC
        ↓
SURICATA + ZEEK
        ↓
RAW SENSOR EVIDENCE
        ↓
EVENT NORMALIZATION
        ↓
CORRELATION
        ↓
THREAT CLASSIFICATION
        ↓
ATTACK TIMELINE
        ↓
RISK + CONFIDENCE
        ↓
INCIDENT CREATION
        ↓
EVIDENCE + STATUS
        ↓
RECOMMENDATIONS
        ↓
INVESTIGATION REPORT
        ↓
SECURITY DASHBOARD
```
