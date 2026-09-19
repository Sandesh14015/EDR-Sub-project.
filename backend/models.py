from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ThreatDomain(str, Enum):
    AUTHENTICATION = "Authentication"
    ENDPOINT = "Endpoint"
    NETWORK = "Network"
    APPLICATION = "Application"
    CROSS_DOMAIN = "Cross-Domain"


class IncidentStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONFIRMED = "CONFIRMED"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatCategory(str, Enum):
    ACCOUNT_TAKEOVER = "Account Takeover"
    AUTHENTICATION_ATTACK = "Authentication Attack"
    BRUTE_FORCE = "Brute Force"
    PASSWORD_SPRAYING = "Password Spraying"
    SUSPICIOUS_LOGIN = "Suspicious Login"
    ENDPOINT_COMPROMISE = "Endpoint Compromise"
    SUSPICIOUS_PROCESS = "Suspicious Process Execution"
    MALWARE_INDICATOR = "Malware Indicator"
    FILE_INTEGRITY_VIOLATION = "Unauthorized File Modification (FIM)"
    PERSISTENCE_ACTIVITY = "Persistence Mechanism"
    RECONNAISSANCE = "Reconnaissance"
    SCANNING = "Scanning"
    EXPLOITATION = "Exploitation"
    MALWARE_COMMUNICATION = "Malware Communication"
    COMMAND_AND_CONTROL = "Command and Control"
    SUSPICIOUS_DNS = "Suspicious DNS"
    DATA_EXFILTRATION = "Data Exfiltration"
    APPLICATION_ABUSE = "Application / API Abuse"
    POLICY_VIOLATION = "Policy Violation"
    UNKNOWN = "Unknown"


class NormalizedEvent(BaseModel):
    event_id: str
    timestamp: str
    source: str  # "wazuh", "suricata", "zeek", or "system_live"
    domain: ThreatDomain = ThreatDomain.NETWORK
    event_type: str  # "alert", "auth_failure", "auth_success", "process_create", "fim", "conn", etc.
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = "TCP"
    domain_name: Optional[str] = None
    severity: int = 0  # Normalized 0 to 10
    signature: Optional[str] = None
    flow_id: Optional[str] = None
    sensor_id: Optional[str] = "sensor-01"

    # Wazuh 4.x Specific Attributes
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    rule_id: Optional[str] = None
    rule_level: Optional[int] = None  # Wazuh 1-16
    user: Optional[str] = None
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    process_cmdline: Optional[str] = None
    process_pid: Optional[int] = None
    file_path: Optional[str] = None
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)

    raw_event: Optional[Dict[str, Any]] = None


class TimelineItem(BaseModel):
    timestamp: str
    stage: str
    description: str
    source: str
    is_inferred: bool = False


class EvidenceItem(BaseModel):
    id: str
    incident_id: str
    type: str  # "ids_alert", "auth_failure", "auth_success", "process_exec", "fim_change", "c2_flow"
    value: str
    source: str
    timestamp: str
    description: str


class RecommendationItem(BaseModel):
    id: str
    incident_id: str
    category: str  # "Immediate", "Short-Term", "Long-Term"
    priority: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    recommendation: str
    status: str = "OPEN"


class NotificationItem(BaseModel):
    id: str
    timestamp: str
    level: str  # "INFO", "WARNING", "CRITICAL"
    title: str
    message: str
    incident_id: Optional[str] = None
    domain: str = "General"


class Incident(BaseModel):
    id: str
    title: str
    description: str
    domain: ThreatDomain = ThreatDomain.CROSS_DOMAIN
    status: IncidentStatus = IncidentStatus.NEW
    severity: SeverityLevel = SeverityLevel.MEDIUM
    risk_score: int = 0  # 0-100
    confidence: int = 0  # 0-100%
    threat_category: ThreatCategory = ThreatCategory.UNKNOWN
    indicators: List[str] = Field(default_factory=list)
    affected_assets: List[str] = Field(default_factory=list)
    affected_users: List[str] = Field(default_factory=list)
    affected_processes: List[str] = Field(default_factory=list)
    source_entities: List[str] = Field(default_factory=list)
    destination_entities: List[str] = Field(default_factory=list)
    mitre_tags: List[str] = Field(default_factory=list)
    first_seen: str
    last_seen: str
    created_at: str
    updated_at: str
    event_ids: List[str] = Field(default_factory=list)
    is_contained: bool = False


class IncidentDetail(BaseModel):
    incident: Incident
    timeline: List[TimelineItem] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    recommendations: List[RecommendationItem] = Field(default_factory=list)
    events: List[NormalizedEvent] = Field(default_factory=list)
