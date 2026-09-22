"""Request and response models for the HTTP API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    email: str
    password: str
    tenant: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: Dict[str, Any]


class RefreshRequest(BaseModel):
    refresh_token: str


class CreateUserRequest(BaseModel):
    email: str
    password: str
    role: str = "analyst"
    full_name: Optional[str] = None


class IngestRecord(BaseModel):
    """One raw log record handed to the collector endpoint."""

    model_config = ConfigDict(extra="allow")

    source: str = Field(description="Source key, e.g. linux.sshd, aws.cloudtrail, app.audit")
    payload: Dict[str, Any] = Field(default_factory=dict)
    raw: Optional[str] = None
    collector: Optional[str] = None
    received_at: Optional[datetime] = None


class IngestRequest(BaseModel):
    records: List[IngestRecord]
    #: Run detection synchronously (default) or only normalize and store.
    detect: bool = True


class IngestResponse(BaseModel):
    accepted: int
    events: int
    alerts: int
    correlations: int
    incidents: int
    dlq: int
    indexed: int
    duplicates: int
    duration_ms: float
    incident_keys: List[str] = Field(default_factory=list)
    alert_ids: List[str] = Field(default_factory=list)


class EventSearchRequest(BaseModel):
    text: Optional[str] = None
    class_uids: List[int] = Field(default_factory=list)
    principal: Optional[str] = None
    source_ip: Optional[str] = None
    hostname: Optional[str] = None
    session_uid: Optional[str] = None
    status_id: Optional[int] = None
    min_severity_id: Optional[int] = None
    start: Optional[datetime] = None
    end: Optional[datetime] = None
    size: int = Field(default=50, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)
    ascending: bool = False


class EventSearchResponse(BaseModel):
    total: int
    took_ms: int
    events: List[Dict[str, Any]]


class AlertSummary(BaseModel):
    alert_id: str
    rule_id: str
    rule_title: str
    rule_level: str
    status: str
    risk_score: int
    risk_level: str
    principal: Optional[str] = None
    source_ip: Optional[str] = None
    hostname: Optional[str] = None
    occurrences: int
    is_building_block: bool = False
    first_seen: datetime
    last_seen: datetime
    tactics: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)
    incident_id: Optional[str] = None


class IncidentSummary(BaseModel):
    incident_id: str
    key: str
    title: str
    status: str
    severity: str
    owner: Optional[str] = None
    assignee_id: Optional[str] = None
    team_id: Optional[str] = None
    team_slug: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    sla_ack_due: Optional[datetime] = None
    sla_resolve_due: Optional[datetime] = None
    waiting_until: Optional[datetime] = None
    waiting_reason: Optional[str] = None
    #: Send this back on a mutation to be told about a concurrent edit.
    version: int = 1
    risk_score: int
    risk_level: str
    scenario: Optional[str] = None
    principal: Optional[str] = None
    source_ips: List[str] = Field(default_factory=list)
    hostnames: List[str] = Field(default_factory=list)
    tactics: List[Dict[str, str]] = Field(default_factory=list)
    techniques: List[Dict[str, str]] = Field(default_factory=list)
    alert_count: int = 0
    evidence_count: int = 0
    first_seen: datetime
    last_seen: datetime
    updated_at: datetime


class TimelineItem(BaseModel):
    time: datetime
    kind: str
    title: str
    detail: Optional[str] = None
    actor: Optional[str] = None
    source_ip: Optional[str] = None
    hostname: Optional[str] = None
    outcome: Optional[str] = None
    severity: Optional[str] = None
    class_name: Optional[str] = None
    event_id: Optional[str] = None
    alert_id: Optional[str] = None
    tactics: List[str] = Field(default_factory=list)


class IncidentDetail(IncidentSummary):
    summary: Optional[str] = None
    risk_factors: List[str] = Field(default_factory=list)
    alerts: List[AlertSummary] = Field(default_factory=list)
    timeline: List[TimelineItem] = Field(default_factory=list)
    notes: List[Dict[str, Any]] = Field(default_factory=list)
    audit: List[Dict[str, Any]] = Field(default_factory=list)
    response_actions: List[Dict[str, Any]] = Field(default_factory=list)
    suggested_playbooks: List[Dict[str, Any]] = Field(default_factory=list)


class TransitionRequest(BaseModel):
    status: str
    reason: Optional[str] = None
    #: Required when moving to ``waiting``: when to put it back in the queue.
    waiting_until: Optional[datetime] = None
    #: The version the caller last read. Supplying it turns a concurrent edit
    #: into a 409 instead of a silent overwrite.
    expected_version: Optional[int] = None


class AssignRequest(BaseModel):
    owner: Optional[str] = None


class ClaimRequest(BaseModel):
    expected_version: Optional[int] = None
    #: Leads reassigning after a shift ends; ignored for unclaimed incidents.
    force: bool = False


class UnclaimRequest(BaseModel):
    reason: Optional[str] = None
    expected_version: Optional[int] = None


class TransferRequest(BaseModel):
    team: str = Field(min_length=1, description="target team slug or id")
    reason: str = Field(min_length=3, max_length=2000)
    expected_version: Optional[int] = None
    keep_assignee: bool = False


class TeamRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    slug: Optional[str] = None
    description: Optional[str] = None
    is_default: bool = False


class TeamMemberRequest(BaseModel):
    user: str = Field(min_length=1, description="user email or id")
    role: str = Field(default="member", pattern="^(member|lead)$")


class LinkRequest(BaseModel):
    incident: str = Field(min_length=1, description="the other incident's key or id")
    relationship: str = Field(default="related_to", pattern="^(related_to|duplicate_of|caused_by)$")
    reason: Optional[str] = None


class MergeRequest(BaseModel):
    """Fold ``incident`` into the one addressed by the route."""

    incident: str = Field(min_length=1, description="the incident to merge away")
    reason: Optional[str] = None
    expected_version: Optional[int] = None


class NoteRequest(BaseModel):
    body: str = Field(min_length=1, max_length=8000)


class CommentRequest(BaseModel):
    body: str = Field(min_length=1, max_length=8000)
    #: Set to reply to an existing comment on the same incident.
    parent_id: Optional[str] = None


class ResponseRequest(BaseModel):
    playbook: str
    target: Optional[str] = None
    params: Dict[str, Any] = Field(default_factory=dict)


class ApprovalRequest(BaseModel):
    reason: Optional[str] = None
    execute_now: bool = True


class RuleSummary(BaseModel):
    id: str
    name: Optional[str] = None
    title: str
    kind: str
    level: str
    status: str
    description: Optional[str] = None
    author: Optional[str] = None
    logsource: Dict[str, Any] = Field(default_factory=dict)
    tactics: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)
    falsepositives: List[str] = Field(default_factory=list)
    stateful: bool = False
    timeframe_seconds: Optional[int] = None
    condition: Optional[str] = None
    correlation_type: Optional[str] = None
    correlation_rules: List[str] = Field(default_factory=list)
    source_path: Optional[str] = None
    revision: Optional[int] = None


class RetroHuntRequest(BaseModel):
    rule_id: str
    earliest: Optional[str] = "now-7d"
    latest: Optional[str] = None
    size: int = Field(default=50, ge=1, le=500)


class SbomIngestRequest(BaseModel):
    application: Optional[str] = None
    environment: str = "production"
    criticality: str = "medium"
    owner: Optional[str] = None
    document: Dict[str, Any]


class VulnerabilityRequest(BaseModel):
    vuln_id: str
    package_name: str
    affected_range: str
    ecosystem: Optional[str] = None
    severity: str = "unknown"
    cvss_score: Optional[float] = None
    fixed_version: Optional[str] = None
    title: Optional[str] = None
    references: List[str] = Field(default_factory=list)


class SimulateRequest(BaseModel):
    scenario: Optional[str] = None
    normal_events: int = Field(default=0, ge=0, le=20000)
    seed: int = 1337
    minutes_ago: int = Field(default=10, ge=0, le=1440)


class OverviewResponse(BaseModel):
    critical_alerts: int
    high_alerts: int
    events_today: int
    open_incidents: int
    alerts_total: int
    incidents_total: int
    mean_detection_latency_ms: float
    events_by_class: Dict[str, int] = Field(default_factory=dict)
    events_by_severity: Dict[str, int] = Field(default_factory=dict)
    incidents_by_status: Dict[str, int] = Field(default_factory=dict)
    top_rules: List[Dict[str, Any]] = Field(default_factory=list)
    supply_chain: Dict[str, Any] = Field(default_factory=dict)
    generated_at: datetime
