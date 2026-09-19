import uuid
from typing import List
from backend.models import NormalizedEvent, RecommendationItem, ThreatCategory, ThreatDomain


def generate_recommendations(
    incident_id: str,
    threat_category: ThreatCategory,
    affected_assets: List[str],
    destination_entities: List[str],
    affected_users: List[str],
    events: List[NormalizedEvent],
) -> List[RecommendationItem]:
    """Generates prioritized, actionable defensive recommendations."""
    recs: List[RecommendationItem] = []
    asset_str = ", ".join(affected_assets) if affected_assets else "the affected endpoint"
    user_str = ", ".join(affected_users) if affected_users else "the affected user account"
    dest_str = ", ".join(destination_entities) if destination_entities else "the threat actor address"

    # 1. ACCOUNT COMPROMISE / CROSS-DOMAIN
    if threat_category in (ThreatCategory.ACCOUNT_TAKEOVER, ThreatCategory.AUTHENTICATION_ATTACK, ThreatCategory.BRUTE_FORCE):
        recs.append(
            RecommendationItem(
                id=f"REC-{uuid.uuid4().hex[:6].upper()}",
                incident_id=incident_id,
                category="Immediate",
                priority="CRITICAL",
                recommendation=f"Terminate active sessions and immediately reset credentials for {user_str}.",
            )
        )
        recs.append(
            RecommendationItem(
                id=f"REC-{uuid.uuid4().hex[:6].upper()}",
                incident_id=incident_id,
                category="Immediate",
                priority="HIGH",
                recommendation=f"Isolate endpoint ({asset_str}) from the corporate LAN to contain potential lateral movement.",
            )
        )
        recs.append(
            RecommendationItem(
                id=f"REC-{uuid.uuid4().hex[:6].upper()}",
                incident_id=incident_id,
                category="Immediate",
                priority="HIGH",
                recommendation=f"Block attacker IP ({dest_str}) across all perimeter and host firewalls via Active Response.",
            )
        )
        recs.append(
            RecommendationItem(
                id=f"REC-{uuid.uuid4().hex[:6].upper()}",
                incident_id=incident_id,
                category="Short-Term",
                priority="MEDIUM",
                recommendation=f"Investigate source IP {dest_str} for prior failed authentication attempts across other internal servers.",
            )
        )
        recs.append(
            RecommendationItem(
                id=f"REC-{uuid.uuid4().hex[:6].upper()}",
                incident_id=incident_id,
                category="Long-Term",
                priority="LOW",
                recommendation="Enforce Multi-Factor Authentication (MFA) and account lockout thresholds after 5 consecutive failures.",
            )
        )
        return recs

    # 2. ENDPOINT COMPROMISE / FIM / PROCESS
    if threat_category in (ThreatCategory.ENDPOINT_COMPROMISE, ThreatCategory.SUSPICIOUS_PROCESS, ThreatCategory.FILE_INTEGRITY_VIOLATION):
        recs.append(
            RecommendationItem(
                id=f"REC-{uuid.uuid4().hex[:6].upper()}",
                incident_id=incident_id,
                category="Immediate",
                priority="CRITICAL",
                recommendation=f"Terminate the suspicious process tree and quarantine unauthorized executables on {asset_str}.",
            )
        )
        recs.append(
            RecommendationItem(
                id=f"REC-{uuid.uuid4().hex[:6].upper()}",
                incident_id=incident_id,
                category="Immediate",
                priority="HIGH",
                recommendation="Inspect modified system files detected by Wazuh FIM and restore verified copies from clean backups.",
            )
        )
        recs.append(
            RecommendationItem(
                id=f"REC-{uuid.uuid4().hex[:6].upper()}",
                incident_id=incident_id,
                category="Short-Term",
                priority="MEDIUM",
                recommendation="Inspect Registry Run keys, Startup folders, and Scheduled Tasks for persistence hooks.",
            )
        )
        recs.append(
            RecommendationItem(
                id=f"REC-{uuid.uuid4().hex[:6].upper()}",
                incident_id=incident_id,
                category="Long-Term",
                priority="LOW",
                recommendation="Implement AppLocker / Application Whitelisting to prevent unauthorized binaries executing in Temp directories.",
            )
        )
        return recs

    # 3. NETWORK / C2 / SCANNING
    recs.append(
        RecommendationItem(
            id=f"REC-{uuid.uuid4().hex[:6].upper()}",
            incident_id=incident_id,
            category="Immediate",
            priority="HIGH",
            recommendation=f"Block all ingress and egress traffic to {dest_str} at the host firewall.",
        )
    )
    recs.append(
        RecommendationItem(
            id=f"REC-{uuid.uuid4().hex[:6].upper()}",
            incident_id=incident_id,
            category="Short-Term",
            priority="MEDIUM",
            recommendation="Review Suricata sensor rules and search Zeek telemetry for any other internal hosts beaconing to the same infrastructure.",
        )
    )
    recs.append(
        RecommendationItem(
            id=f"REC-{uuid.uuid4().hex[:6].upper()}",
            incident_id=incident_id,
            category="Long-Term",
            priority="LOW",
            recommendation="Implement network micro-segmentation and egress traffic filtering.",
        )
    )
    return recs
