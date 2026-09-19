from typing import List, Tuple
from backend.models import NormalizedEvent, SeverityLevel, ThreatDomain


def calculate_risk_and_confidence(
    events: List[NormalizedEvent],
    domain: ThreatDomain = ThreatDomain.CROSS_DOMAIN,
) -> Tuple[int, int, SeverityLevel]:
    """
    Calculates:
    1. Risk Score (0-100): Potential damage and threat impact.
    2. Confidence Score (0-100%): Certainty based on multi-sensor corroboration.
    3. SeverityLevel: LOW, MODERATE, MEDIUM, HIGH, CRITICAL.
    """
    if not events:
        return 0, 0, SeverityLevel.LOW

    # 1. Base Detection Severity (0 - 40 points)
    max_severity = max([e.severity for e in events], default=0)
    detection_score = min(40, int((max_severity / 10.0) * 40))

    # 2. Cross-Domain Corroboration Bonus (0 - 30 points)
    # If events span multiple domains (e.g. Network + Auth + Endpoint)
    distinct_domains = {e.domain for e in events}
    domain_score = 0
    if len(distinct_domains) >= 3 or domain == ThreatDomain.CROSS_DOMAIN:
        domain_score = 30
    elif len(distinct_domains) >= 2:
        domain_score = 20
    elif len(distinct_domains) == 1:
        domain_score = 10

    # 3. High-Impact Attack Behavioral Indicators (0 - 20 points)
    impact_score = 0
    event_types = {e.event_type for e in events}
    has_auth_fail = "auth_failure" in event_types
    has_auth_success = "auth_success" in event_types
    has_fim = "fim_modification" in event_types
    has_proc = "process_create" in event_types
    has_network = any(e.source in ("suricata", "zeek") for e in events)

    # Critical Account Takeover combo
    if has_auth_fail and has_auth_success:
        impact_score += 10
    if has_fim or has_proc:
        impact_score += 10
    if any(k in (e.signature or "").lower() for e in events for k in ["c2", "beacon", "trojan", "cobalt", "exploit"]):
        impact_score = min(20, impact_score + 10)

    # 4. Volume & Persistence (0 - 10 points)
    volume_score = min(10, len(events) * 2)

    # Compute Total Risk Score
    raw_risk = detection_score + domain_score + impact_score + volume_score
    risk_score = min(100, max(10, raw_risk))

    # Severity Level Mapping
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

    # =========================================================================
    # Confidence Score Calculation (0 - 100%)
    # Answers: "How certain are we that this is a verified threat?"
    # =========================================================================
    base_confidence = 40

    # Multi-source corroboration (Wazuh + Suricata or Cross-Domain)
    sources = {e.source for e in events}
    if len(sources) >= 2 or domain == ThreatDomain.CROSS_DOMAIN or any(e.source == "suricata" for e in events):
        base_confidence += 30

    # Multi-domain or multi-telemetry layer agreement (e.g. DNS + Conn + Alert or Host + Network)
    event_types = {e.event_type for e in events}
    if len(distinct_domains) >= 2 or domain == ThreatDomain.CROSS_DOMAIN or len(event_types) >= 3:
        base_confidence += 15
    elif len(event_types) >= 2:
        base_confidence += 10

    # Sequence consistency (e.g. failed login before success)
    if has_auth_fail and has_auth_success:
        base_confidence += 10

    confidence_score = min(98, max(30, base_confidence))

    return risk_score, confidence_score, severity
