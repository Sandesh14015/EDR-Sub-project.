# Network Detection & Incident Intelligence Platform (EDR Sub-Project)

A network security monitoring and incident intelligence platform built around **Suricata** detection and **Zeek** network telemetry.

> **"Suricata detects. Zeek observes. The intelligence layer correlates. The incident engine explains."**

---

## Minimal Stack Architecture

This project is implemented with a lightweight, zero-overhead stack:
- **Backend**: Python (`FastAPI`, `uvicorn`, `pydantic`)
- **Database**: SQLite (embedded, zero database server configuration needed)
- **Frontend**: Clean white-background single-page interface (pure HTML, modern CSS, vanilla JavaScript with no npm build steps)
- **Core Pipeline**:
  - `normalizer.py`: Unifies Suricata `eve.json` alerts and Zeek logs (`conn.log`, `dns.log`, `ssl.log`, `http.log`) into a common schema.
  - `correlation.py`: Groups multi-sensor alerts and connection telemetry by IP pairs, flow, and time window into singular incidents to prevent alert fatigue.
  - `risk_engine.py`: Computes decoupled Risk (0–100) and Confidence (0–100%) scores.
  - `timeline.py`: Reconstructs chronological attack timelines with explicit raw vs. inferred steps.
  - `recommender.py`: Generates tiered, evidence-driven mitigation actions (Immediate, Short-Term, Long-Term).
  - `reporter.py`: Compiles full SOC investigation reports with one-click Markdown/download export.

---

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Start the Platform
```bash
python run.py
```

- **Web Dashboard**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive Swagger API Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## How to Use the Minimal White Dashboard

1. **Load Pre-built Scenarios**:
   - Click **`Load C2 Beaconing`**, **`Load Port Scan`**, or **`Load SSH Brute Force`** to instantly populate authentic sensor logs and generate correlated incidents.
2. **Custom Log Ingestion**:
   - Paste any Suricata `eve.json` alert or Zeek JSON/TSV logs into the textarea in the **Data Input Space**.
   - Click **`Ingest & Normalize Logs`**, then **`Run Correlation Engine`**.
3. **Inspect Incidents**:
   - Click **`Inspect`** on any incident row in the incidents table.
   - Explore the **Attack Timeline**, **Evidence Store**, **Recommendations**, and **Investigation Report**.
   - Update lifecycle status (`NEW` $\to$ `INVESTIGATING` $\to$ `RESOLVED`).

---

## Running Automated Tests
```bash
python -m unittest tests/test_pipeline.py
```
