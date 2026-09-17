import uuid
from typing import List
from backend.models import NormalizedEvent, RecommendationItem, ThreatCategory


def generate_recommendations(
    incident_id: str,
    threat_category: ThreatCategory,
    affected_assets: List[str],
    destination_entities: List[str],
    events: List[NormalizedEvent],
) -> List[RecommendationItem]:
    """
    Generates actionable, evidence-driven security recommendations categorized into:
    - Immediate measures
    - Short-term measures
    - Long-term measures
    """
    recs: List[RecommendationItem] = []
    asset_str = ", ".join(affected_assets) if affected_assets else "the affected host"
    dest_str = ", ".join(destination_entities) if destination_entities else "the external entity"

    # Immediate actions
    recs.append(
        RecommendationItem(
            id=f"REC-{uuid.uuid4().hex[:6].upper()}",
            incident_id=incident_id,
            category="Immediate",
            priority="HIGH",
            recommendation=f"Review and isolate endpoint ({asset_str}) from the network if malicious behavior is confirmed.",
        )
    )
    recs.append(
        RecommendationItem(
            id=f"REC-{uuid.uuid4().hex[:6].upper()}",
            incident_id=incident_id,
            category="Immediate",
            priority="HIGH",
            recommendation=f"Temporarily block outbound egress traffic to suspicious destination ({dest_str}) on perimeter firewall.",
        )
    )

    # Threat category specific immediate actions
    if threat_category in (ThreatCategory.COMMAND_AND_CONTROL, ThreatCategory.MALWARE_COMMUNICATION):
        recs.append(
            RecommendationItem(
                id=f"REC-{uuid.uuid4().hex[:6].upper()}",
                incident_id=incident_id,
                category="Immediate",
                priority="HIGH",
                recommendation=f"Dump volatile memory and process trees on {asset_str} to identify unauthorized beaconing processes.",
            )
        )
    elif threat_category in (ThreatCategory.BRUTE_FORCE, ThreatCategory.SCANNING):
        recs.append(
            RecommendationItem(
                id=f"REC-{uuid.uuid4().hex[:6].upper()}",
                incident_id=incident_id,
                category="Immediate",
                priority="HIGH",
                recommendation=f"Enforce rate-limiting or IP block on incoming requests from external sources on targeted ports.",
            )
        )

    # Short-term actions
    recs.append(
        RecommendationItem(
            id=f"REC-{uuid.uuid4().hex[:6].upper()}",
            incident_id=incident_id,
            category="Short-Term",
            priority="MEDIUM",
            recommendation=f"Search Zeek connection logs across all internal subnets for any other hosts communicating with {dest_str}.",
        )
    )
    recs.append(
        RecommendationItem(
            id=f"REC-{uuid.uuid4().hex[:6].upper()}",
            incident_id=incident_id,
            category="Short-Term",
            priority="MEDIUM",
            recommendation="Review internal DNS queries for unusual DGA patterns or high-entropy hostnames over the past 48 hours.",
        )
    )

    # Long-term actions
    recs.append(
        RecommendationItem(
            id=f"REC-{uuid.uuid4().hex[:6].upper()}",
            incident_id=incident_id,
            category="Long-Term",
            priority="LOW",
            recommendation="Implement stricter micro-segmentation policies between user workstations and critical infrastructure.",
        )
    )
    recs.append(
        RecommendationItem(
            id=f"REC-{uuid.uuid4().hex[:6].upper()}",
            incident_id=incident_id,
            category="Long-Term",
            priority="LOW",
            recommendation="Tune Suricata signatures and add custom Zeek policy scripts to automatically alert on persistent low-frequency beacons.",
        )
    )

    return recs
