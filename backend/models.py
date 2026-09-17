from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


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
    RECONNAISSANCE = "Reconnaissance"
    SCANNING = "Scanning"
    BRUTE_FORCE = "Brute Force"
    EXPLOITATION = "Exploitation"
    MALWARE_COMMUNICATION = "Malware Communication"
    COMMAND_AND_CONTROL = "Command and Control"
    SUSPICIOUS_DNS = "Suspicious DNS"
    DATA_TRANSFER = "Data Transfer"
    POLICY_VIOLATION = "Policy Violation"
    UNKNOWN = "Unknown"


class NormalizedEvent(BaseModel):
    event_id: str
    timestamp: str
    source: str  # "suricata" or "zeek"
    event_type: str  # "alert", "dns", "conn", "ssl", "http", etc.
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = "TCP"
    domain: Optional[str] = None
    severity: int = 0  # 0 to 10
    signature: Optional[str] = None
    flow_id: Optional[str] = None
    sensor_id: Optional[str] = "sensor-01"
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
    type: str  # "alert", "dns", "connection", "ioc", etc.
    value: str
    source: str
    timestamp: str
    description: str


class RecommendationItem(BaseModel):
    id: str
    incident_id: str
    category: str  # "immediate", "short_term", "long_term"
    priority: str  # "HIGH", "MEDIUM", "LOW"
    recommendation: str
    status: str = "OPEN"


class Incident(BaseModel):
    id: str
    title: str
    description: str
    status: IncidentStatus = IncidentStatus.NEW
    severity: SeverityLevel = SeverityLevel.MEDIUM
    risk_score: int = 0  # 0-100
    confidence: int = 0  # 0-100%
    threat_category: ThreatCategory = ThreatCategory.UNKNOWN
    affected_assets: List[str] = Field(default_factory=list)
    source_entities: List[str] = Field(default_factory=list)
    destination_entities: List[str] = Field(default_factory=list)
    first_seen: str
    last_seen: str
    created_at: str
    updated_at: str
    event_ids: List[str] = Field(default_factory=list)


class IncidentDetail(BaseModel):
    incident: Incident
    timeline: List[TimelineItem] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    recommendations: List[RecommendationItem] = Field(default_factory=list)
    events: List[NormalizedEvent] = Field(default_factory=list)
