from typing import List, Tuple
from backend.models import NormalizedEvent, SeverityLevel


def calculate_risk_and_confidence(events: List[NormalizedEvent]) -> Tuple[int, int, SeverityLevel]:
    """
    Calculates:
    1. Risk Score (0-100): How dangerous the incident could be.
    2. Confidence Score (0-100%): How certain we are based on corroborating telemetry.
    3. SeverityLevel: LOW, MODERATE, MEDIUM, HIGH, CRITICAL.

    Principles:
    - Suricata provides detection severity.
    - Zeek provides corroborating telemetry and behavioral persistence.
    - Risk and Confidence are strictly decoupled.
    """
    if not events:
        return 0, 0, SeverityLevel.LOW

    suricata_events = [e for e in events if e.source == "suricata"]
    zeek_events = [e for e in events if e.source == "zeek"]

    # 1. Base Detection Severity (0 - 45 points)
    max_severity = max([e.severity for e in events], default=0)
    # Severity in events is 0-10, scale to 45
    detection_score = min(45, int((max_severity / 10.0) * 45))

    # 2. Event Frequency & Persistence (0 - 25 points)
    event_count = len(events)
    frequency_score = min(25, int(event_count * 2.5))

    # 3. Behavioral Evidence from Zeek (0 - 20 points)
    behavioral_score = 0
    zeek_types = {e.event_type for e in zeek_events}
    if "dns" in zeek_types:
        behavioral_score += 5
    if "conn" in zeek_types:
        behavioral_score += 5
    if "ssl" in zeek_types or "http" in zeek_types:
        behavioral_score += 5

    # Check for repetitive connections or suspicious states
    suspicious_states = any(
        e.severity >= 3 for e in zeek_events
    )
    if suspicious_states:
        behavioral_score += 5

    # 4. Multi-sensor Cross-Confirmation (0 - 10 points)
    multi_sensor_score = 10 if (suricata_events and zeek_events) else 0

    # Total Raw Risk Score
    raw_risk = detection_score + frequency_score + behavioral_score + multi_sensor_score
    risk_score = min(100, max(5, raw_risk))

    # Determine Severity Level
    if risk_score <= 20:
        severity = SeverityLevel.LOW
    elif risk_score <= 40:
        severity = SeverityLevel.MODERATE
    elif risk_score <= 60:
        severity = SeverityLevel.MEDIUM
    elif risk_score <= 80:
        severity = SeverityLevel.HIGH
    else:
        severity = SeverityLevel.CRITICAL

    # --- Confidence Score Calculation (0 - 100%) ---
    # Answers: "How confident are we that our assessment is correct?"
    base_confidence = 35

    # Corroboration bonus:
    # 1. Both Suricata and Zeek observed the traffic: +30%
    if suricata_events and zeek_events:
        base_confidence += 30

    # 2. Multiple independent event types observed (e.g. DNS + CONN + ALERT): +20%
    all_types = {e.event_type for e in events}
    if len(all_types) >= 3:
        base_confidence += 20
    elif len(all_types) >= 2:
        base_confidence += 10

    # 3. Frequency / repetitive consistency bonus: +15%
    if len(events) >= 5:
        base_confidence += 15
    elif len(events) >= 2:
        base_confidence += 5

    confidence_score = min(98, max(25, base_confidence))

    return risk_score, confidence_score, severity
