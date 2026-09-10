"""Incident model, state machine and audit trail."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, ConfigDict, Field

from .ocsf import utcnow


class IncidentStatus(str, Enum):
    NEW = "new"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED_FALSE_POSITIVE = "closed_false_positive"


#: Allowed transitions of the incident state machine.  Every transition is
#: audited; anything not listed here is rejected by the incident manager.
ALLOWED_TRANSITIONS: Dict[IncidentStatus, Set[IncidentStatus]] = {
    IncidentStatus.NEW: {IncidentStatus.TRIAGED, IncidentStatus.CLOSED_FALSE_POSITIVE},
    IncidentStatus.TRIAGED: {
        IncidentStatus.INVESTIGATING,
        IncidentStatus.CLOSED_FALSE_POSITIVE,
        IncidentStatus.RESOLVED,
    },
    IncidentStatus.INVESTIGATING: {
        IncidentStatus.CONTAINED,
        IncidentStatus.RESOLVED,
        IncidentStatus.CLOSED_FALSE_POSITIVE,
    },
    IncidentStatus.CONTAINED: {IncidentStatus.RESOLVED, IncidentStatus.INVESTIGATING},
    IncidentStatus.RESOLVED: {IncidentStatus.INVESTIGATING},
    IncidentStatus.CLOSED_FALSE_POSITIVE: {IncidentStatus.INVESTIGATING},
}

TERMINAL_STATUSES = {IncidentStatus.RESOLVED, IncidentStatus.CLOSED_FALSE_POSITIVE}


class IncidentSeverity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TimelineEntry(BaseModel):
    """One row of the investigation timeline."""

    model_config = ConfigDict(extra="allow")

    time: datetime
    kind: str  # event | alert | response | note | status
    title: str
    detail: Optional[str] = None
    actor: Optional[str] = None
    source_ip: Optional[str] = None
    hostname: Optional[str] = None
    event_id: Optional[str] = None
    alert_id: Optional[str] = None
    class_name: Optional[str] = None
    outcome: Optional[str] = None
    severity: Optional[str] = None
    tactics: List[str] = Field(default_factory=list)


class AuditEntry(BaseModel):
    model_config = ConfigDict(extra="allow")

    time: datetime = Field(default_factory=utcnow)
    actor: str = "system"
    action: str = ""
    detail: Optional[str] = None
    data: Dict[str, Any] = Field(default_factory=dict)


class IncidentNote(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    time: datetime = Field(default_factory=utcnow)
    author: str
    body: str


class Incident(BaseModel):
    model_config = ConfigDict(extra="allow", validate_assignment=True)

    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    key: str = ""  # human reference, e.g. INC-2041
    tenant: str = "default"

    title: str
    summary: Optional[str] = None
    status: IncidentStatus = IncidentStatus.NEW
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    owner: Optional[str] = None

    risk_score: int = 0
    risk_factors: List[str] = Field(default_factory=list)
    scenario: Optional[str] = None  # correlation scenario id, e.g. account_compromise

    alert_ids: List[str] = Field(default_factory=list)
    event_ids: List[str] = Field(default_factory=list)
    entity_keys: List[str] = Field(default_factory=list)
    principal: Optional[str] = None
    source_ips: List[str] = Field(default_factory=list)
    hostnames: List[str] = Field(default_factory=list)

    tactics: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)

    timeline: List[TimelineEntry] = Field(default_factory=list)
    notes: List[IncidentNote] = Field(default_factory=list)
    audit: List[AuditEntry] = Field(default_factory=list)

    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    closed_at: Optional[datetime] = None
    close_reason: Optional[str] = None
    dedup_key: str = ""

    def can_transition_to(self, target: IncidentStatus) -> bool:
        return target in ALLOWED_TRANSITIONS.get(self.status, set())

    @property
    def is_open(self) -> bool:
        return self.status not in TERMINAL_STATUSES

    @property
    def evidence_count(self) -> int:
        return len(self.event_ids)

    def record(self, action: str, actor: str = "system", detail: Optional[str] = None,
               **data: Any) -> AuditEntry:
        entry = AuditEntry(actor=actor, action=action, detail=detail, data=data)
        self.audit.append(entry)
        self.updated_at = utcnow()
        return entry

    def to_document(self) -> Dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)
