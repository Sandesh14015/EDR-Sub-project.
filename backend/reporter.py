from datetime import datetime, timezone
from typing import List
from backend.models import EvidenceItem, Incident, RecommendationItem, TimelineItem


def generate_incident_report(
    incident: Incident,
    timeline: List[TimelineItem],
    evidence: List[EvidenceItem],
    recommendations: List[RecommendationItem],
) -> str:
    """Generates an executive and technical investigation report in Markdown format."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    affected = ", ".join(incident.affected_assets) if incident.affected_assets else "N/A"
    sources = ", ".join(incident.source_entities) if incident.source_entities else "N/A"
    destinations = ", ".join(incident.destination_entities) if incident.destination_entities else "N/A"

    timeline_lines = []
    for item in timeline:
        inferred_tag = " *(Inferred)*" if item.is_inferred else ""
        timeline_lines.append(f"- **{item.timestamp}** | [{item.source}] **{item.stage}**: {item.description}{inferred_tag}")
    timeline_str = "\n".join(timeline_lines) if timeline_lines else "No timeline events recorded."

    evidence_lines = []
    for ev in evidence:
        evidence_lines.append(f"- **[{ev.source.upper()}]** {ev.type.upper()}: `{ev.value}` — {ev.description}")
    evidence_str = "\n".join(evidence_lines) if evidence_lines else "No evidence recorded."

    rec_immediate = [f"- {r.recommendation}" for r in recommendations if r.category == "Immediate"]
    rec_short = [f"- {r.recommendation}" for r in recommendations if r.category == "Short-Term"]
    rec_long = [f"- {r.recommendation}" for r in recommendations if r.category == "Long-Term"]

    report_md = f"""# SECURITY INCIDENT INVESTIGATION REPORT

**Report Generated:** {now}  
**Platform:** Network Detection & Incident Intelligence Platform  

---

## 1. Executive Summary

| Field | Details |
|---|---|
| **Incident ID** | `{incident.id}` |
| **Title** | {incident.title} |
| **Threat Category** | {incident.threat_category.value} |
| **Status** | **{incident.status.value}** |
| **Severity** | **{incident.severity.value}** |
| **Risk Score** | **{incident.risk_score} / 100** |
| **Detection Confidence** | **{incident.confidence}%** |
| **Affected Assets** | {affected} |
| **Source Entities** | {sources} |
| **Destination Entities** | {destinations} |
| **First Observed** | {incident.first_seen} |
| **Last Observed** | {incident.last_seen} |

### Description
{incident.description}

---

## 2. Attack Reconstruction Timeline

{timeline_str}

---

## 3. Corroborated Evidence Store

{evidence_str}

---

## 4. Recommended Action Plan

### Immediate Actions
{chr(10).join(rec_immediate) if rec_immediate else "- No immediate actions."}

### Short-Term Investigation
{chr(10).join(rec_short) if rec_short else "- No short-term actions."}

### Long-Term Hardening
{chr(10).join(rec_long) if rec_long else "- No long-term actions."}

---
*Report automatically compiled by EDR Network Intelligence Correlation Layer.*
"""
    return report_md.strip()
