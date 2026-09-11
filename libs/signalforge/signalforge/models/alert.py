"""Alert model - the output of the detection engine."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from .ocsf import Enrichment, utcnow


class AlertStatus(str, Enum):
    NEW = "new"
    TRIAGED = "triaged"
    CORRELATED = "correlated"
    CLOSED = "closed"
    SUPPRESSED = "suppressed"
    FALSE_POSITIVE = "false_positive"


LEVEL_SEVERITY: Dict[str, int] = {
    "informational": 1,
    "low": 3,
    "medium": 5,
    "high": 8,
    "critical": 10,
}


class DetectionMatch(BaseModel):
    """Why a rule fired: the searches that matched and the fields involved."""

    model_config = ConfigDict(extra="allow")

    condition: str = ""
    matched_selections: List[str] = Field(default_factory=list)
    matched_fields: Dict[str, Any] = Field(default_factory=dict)
    event_count: int = 1
    timeframe_seconds: Optional[int] = None


class Alert(BaseModel):
    model_config = ConfigDict(extra="allow", validate_assignment=True)

    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant: str = "default"

    # Rule provenance (detection-as-code metadata)
    rule_id: str
    rule_title: str
    rule_level: str = "medium"
    rule_version: Optional[str] = None
    rule_path: Optional[str] = None
    rule_author: Optional[str] = None
    description: Optional[str] = None
    falsepositives: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)

    # Scoring
    severity: int = 5  # 1-10, from rule level
    confidence: int = 7  # 1-10, from rule metadata
    asset_criticality: int = 5  # 1-10, from the asset inventory
    context_modifier: float = 1.0
    risk_score: int = 0
    risk_level: str = "low"
    risk_factors: List[str] = Field(default_factory=list)

    # MITRE ATT&CK
    tactics: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)

    # Entities (correlation keys)
    principal: Optional[str] = None
    target_principal: Optional[str] = None
    source_ip: Optional[str] = None
    hostname: Optional[str] = None
    session_uid: Optional[str] = None
    resources: List[str] = Field(default_factory=list)

    # Evidence
    detection: DetectionMatch = Field(default_factory=DetectionMatch)
    event_ids: List[str] = Field(default_factory=list)
    sample_event: Optional[Dict[str, Any]] = None
    enrichments: List[Enrichment] = Field(default_factory=list)

    #: True for rules that exist only to feed correlation (Sigma building
    #: blocks). They are real alerts, but they do not belong in the queue an
    #: analyst works - they would bury everything else.
    is_building_block: bool = False

    # Lifecycle
    status: AlertStatus = AlertStatus.NEW
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    occurrences: int = 1
    dedup_key: str = ""
    incident_id: Optional[str] = None
    suppressed_reason: Optional[str] = None
    created_at: datetime = Field(default_factory=utcnow)

    def model_post_init(self, __context: Any) -> None:
        if not self.dedup_key:
            self.dedup_key = self.compute_dedup_key()

    def compute_dedup_key(self) -> str:
        """Same rule + same entity set = same logical alert."""
        parts = [
            self.tenant,
            self.rule_id,
            self.principal or "-",
            self.source_ip or "-",
            self.hostname or "-",
            self.session_uid or "-",
        ]
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:32]

    def entity_keys(self) -> List[str]:
        """Correlation keys: the identities this alert can be joined on."""
        keys = []
        if self.principal:
            keys.append("user:%s" % self.principal.lower())
        if self.target_principal and self.target_principal != self.principal:
            keys.append("user:%s" % self.target_principal.lower())
        if self.source_ip:
            keys.append("ip:%s" % self.source_ip)
        if self.hostname:
            keys.append("host:%s" % self.hostname.lower())
        if self.session_uid:
            keys.append("session:%s" % self.session_uid)
        return keys

    def to_document(self) -> Dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)
