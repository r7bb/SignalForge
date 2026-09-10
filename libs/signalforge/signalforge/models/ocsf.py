"""OCSF 1.3-shaped event model.

SignalForge normalizes every source into a single event object modelled on the
Open Cybersecurity Schema Framework so that detections are written once against
stable field names instead of once per vendor.  The model is deliberately a
*subset* of OCSF: the objects and attributes the platform actually reasons
about (identity, endpoints, devices, API calls, resources, status, severity)
plus a small number of SignalForge-specific bookkeeping fields that are kept in
their own namespace (``sf_*``) so they never collide with the standard.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_serializer

OCSF_VERSION = "1.3.0"


# --------------------------------------------------------------------------- #
# OCSF class / activity / status identifiers used by the platform
# --------------------------------------------------------------------------- #
class ClassUid:
    FILE_SYSTEM_ACTIVITY = 1001
    PROCESS_ACTIVITY = 1007
    ACCOUNT_CHANGE = 3001
    AUTHENTICATION = 3002
    AUTHORIZE_SESSION = 3003
    ENTITY_MANAGEMENT = 3004
    USER_ACCESS_MANAGEMENT = 3005
    GROUP_MANAGEMENT = 3006
    HTTP_ACTIVITY = 4002
    WEB_RESOURCES_ACTIVITY = 6001
    API_ACTIVITY = 6003
    DATASTORE_ACTIVITY = 6005


CLASS_NAMES: Dict[int, str] = {
    ClassUid.FILE_SYSTEM_ACTIVITY: "File System Activity",
    ClassUid.PROCESS_ACTIVITY: "Process Activity",
    ClassUid.ACCOUNT_CHANGE: "Account Change",
    ClassUid.AUTHENTICATION: "Authentication",
    ClassUid.AUTHORIZE_SESSION: "Authorize Session",
    ClassUid.ENTITY_MANAGEMENT: "Entity Management",
    ClassUid.USER_ACCESS_MANAGEMENT: "User Access Management",
    ClassUid.GROUP_MANAGEMENT: "Group Management",
    ClassUid.HTTP_ACTIVITY: "HTTP Activity",
    ClassUid.WEB_RESOURCES_ACTIVITY: "Web Resources Activity",
    ClassUid.API_ACTIVITY: "API Activity",
    ClassUid.DATASTORE_ACTIVITY: "Datastore Activity",
}

# OCSF category_uid is the leading digit(s) of class_uid.
CATEGORY_NAMES: Dict[int, str] = {
    1: "System Activity",
    2: "Findings",
    3: "Identity & Access Management",
    4: "Network Activity",
    5: "Discovery",
    6: "Application Activity",
}


class StatusId:
    UNKNOWN = 0
    SUCCESS = 1
    FAILURE = 2
    OTHER = 99


STATUS_NAMES: Dict[int, str] = {
    StatusId.UNKNOWN: "Unknown",
    StatusId.SUCCESS: "Success",
    StatusId.FAILURE: "Failure",
    StatusId.OTHER: "Other",
}


class SeverityId:
    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6


SEVERITY_NAMES: Dict[int, str] = {
    SeverityId.UNKNOWN: "Unknown",
    SeverityId.INFORMATIONAL: "Informational",
    SeverityId.LOW: "Low",
    SeverityId.MEDIUM: "Medium",
    SeverityId.HIGH: "High",
    SeverityId.CRITICAL: "Critical",
    SeverityId.FATAL: "Fatal",
}


def utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class _Base(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True, validate_assignment=True)


# --------------------------------------------------------------------------- #
# OCSF objects
# --------------------------------------------------------------------------- #
class Product(_Base):
    name: Optional[str] = None
    vendor_name: Optional[str] = None
    version: Optional[str] = None
    feature: Optional[str] = None


class Metadata(_Base):
    version: str = OCSF_VERSION
    product: Product = Field(default_factory=Product)
    uid: Optional[str] = None
    correlation_uid: Optional[str] = None
    original_time: Optional[str] = None
    logged_time: Optional[datetime] = None
    processed_time: Optional[datetime] = None
    log_name: Optional[str] = None
    log_provider: Optional[str] = None
    labels: List[str] = Field(default_factory=list)
    sequence: Optional[int] = None


class Location(_Base):
    country: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[int] = None
    coordinates: Optional[List[float]] = None


class Endpoint(_Base):
    ip: Optional[str] = None
    port: Optional[int] = None
    hostname: Optional[str] = None
    domain: Optional[str] = None
    uid: Optional[str] = None
    svc_name: Optional[str] = None
    location: Optional[Location] = None
    intermediate_ips: List[str] = Field(default_factory=list)


class Os(_Base):
    name: Optional[str] = None
    type: Optional[str] = None
    version: Optional[str] = None


class Device(_Base):
    uid: Optional[str] = None
    hostname: Optional[str] = None
    ip: Optional[str] = None
    type: Optional[str] = None
    os: Optional[Os] = None
    region: Optional[str] = None
    # Non-standard but essential for risk scoring; kept explicit and documented.
    criticality: Optional[str] = None


class Group(_Base):
    name: Optional[str] = None
    uid: Optional[str] = None
    type: Optional[str] = None
    privileges: List[str] = Field(default_factory=list)


class User(_Base):
    name: Optional[str] = None
    uid: Optional[str] = None
    email_addr: Optional[str] = None
    domain: Optional[str] = None
    type: Optional[str] = None
    type_id: Optional[int] = None
    groups: List[Group] = Field(default_factory=list)
    has_mfa: Optional[bool] = None


class Session(_Base):
    uid: Optional[str] = None
    created_time: Optional[datetime] = None
    is_mfa: Optional[bool] = None
    is_remote: Optional[bool] = None
    issuer: Optional[str] = None
    expiration_time: Optional[datetime] = None


class Process(_Base):
    name: Optional[str] = None
    pid: Optional[int] = None
    cmd_line: Optional[str] = None
    user: Optional[User] = None
    parent_process: Optional["Process"] = None


class Actor(_Base):
    user: Optional[User] = None
    session: Optional[Session] = None
    process: Optional[Process] = None
    invoked_by: Optional[str] = None
    app_name: Optional[str] = None
    authorizations: List[str] = Field(default_factory=list)


class ApiService(_Base):
    name: Optional[str] = None
    version: Optional[str] = None


class ApiRequest(_Base):
    uid: Optional[str] = None
    flags: List[str] = Field(default_factory=list)


class ApiResponse(_Base):
    code: Optional[int] = None
    error: Optional[str] = None
    message: Optional[str] = None


class Api(_Base):
    operation: Optional[str] = None
    service: Optional[ApiService] = None
    request: Optional[ApiRequest] = None
    response: Optional[ApiResponse] = None
    version: Optional[str] = None


class HttpRequest(_Base):
    http_method: Optional[str] = None
    url: Optional[str] = None
    user_agent: Optional[str] = None
    referrer: Optional[str] = None


class HttpResponse(_Base):
    code: Optional[int] = None
    length: Optional[int] = None


class Resource(_Base):
    uid: Optional[str] = None
    name: Optional[str] = None
    type: Optional[str] = None
    owner: Optional[User] = None
    labels: List[str] = Field(default_factory=list)
    # "low" | "medium" | "high" | "critical" - drives AssetCriticality in scoring.
    criticality: Optional[str] = None
    data_classification: Optional[str] = None


class FileObj(_Base):
    name: Optional[str] = None
    path: Optional[str] = None
    type: Optional[str] = None
    size: Optional[int] = None
    hashes: Dict[str, str] = Field(default_factory=dict)


class Observable(_Base):
    """A pivotable indicator extracted from the event (OCSF ``observables``)."""

    name: str
    type: str  # ip | domain | hostname | user | email | file_hash | url | api_key
    value: str


class Enrichment(_Base):
    name: str
    provider: str
    value: Optional[str] = None
    created_time: datetime = Field(default_factory=utcnow)
    data: Dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# The event
# --------------------------------------------------------------------------- #
class OcsfEvent(_Base):
    """A normalized security event."""

    # Classification
    class_uid: int
    class_name: Optional[str] = None
    category_uid: Optional[int] = None
    category_name: Optional[str] = None
    activity_id: int = 0
    activity_name: Optional[str] = None
    type_uid: Optional[int] = None
    type_name: Optional[str] = None

    # Time
    time: datetime = Field(default_factory=utcnow)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration: Optional[int] = None

    # Outcome / severity
    status_id: int = StatusId.UNKNOWN
    status: Optional[str] = None
    status_code: Optional[str] = None
    status_detail: Optional[str] = None
    severity_id: int = SeverityId.INFORMATIONAL
    severity: Optional[str] = None

    # Entities
    metadata: Metadata = Field(default_factory=Metadata)
    actor: Optional[Actor] = None
    user: Optional[User] = None  # target principal (account change, access mgmt)
    src_endpoint: Optional[Endpoint] = None
    dst_endpoint: Optional[Endpoint] = None
    device: Optional[Device] = None
    api: Optional[Api] = None
    http_request: Optional[HttpRequest] = None
    http_response: Optional[HttpResponse] = None
    resources: List[Resource] = Field(default_factory=list)
    file: Optional[FileObj] = None
    group: Optional[Group] = None

    # Auth specifics
    auth_protocol: Optional[str] = None
    auth_protocol_id: Optional[int] = None
    logon_type: Optional[str] = None
    is_mfa: Optional[bool] = None

    message: Optional[str] = None
    observables: List[Observable] = Field(default_factory=list)
    enrichments: List[Enrichment] = Field(default_factory=list)
    unmapped: Dict[str, Any] = Field(default_factory=dict)

    # --- SignalForge bookkeeping (namespaced, not part of OCSF) -----------
    sf_event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sf_tenant: str = "default"
    sf_source: Optional[str] = None  # collector/source identifier
    sf_ingested_at: datetime = Field(default_factory=utcnow)
    sf_dedup_key: Optional[str] = None
    sf_raw: Optional[str] = None
    sf_risk_score: Optional[int] = None

    @field_serializer("time", "start_time", "end_time", "sf_ingested_at", when_used="json")
    def _ser_dt(self, value: Optional[datetime]) -> Optional[str]:
        return value.isoformat() if value else None

    def model_post_init(self, __context: Any) -> None:  # noqa: D105
        if self.class_name is None:
            self.class_name = CLASS_NAMES.get(self.class_uid)
        if self.category_uid is None:
            self.category_uid = self.class_uid // 1000
        if self.category_name is None:
            self.category_name = CATEGORY_NAMES.get(self.category_uid or 0)
        if self.activity_name is None:
            self.activity_name = activity_name(self.class_uid, self.activity_id)
        if self.type_uid is None:
            self.type_uid = self.class_uid * 100 + self.activity_id
        if self.type_name is None and self.class_name and self.activity_name:
            self.type_name = "%s: %s" % (self.class_name, self.activity_name)
        if self.status is None:
            self.status = STATUS_NAMES.get(self.status_id)
        if self.severity is None:
            self.severity = SEVERITY_NAMES.get(self.severity_id)
        if self.time.tzinfo is None:
            self.time = self.time.replace(tzinfo=timezone.utc)
        if self.sf_dedup_key is None:
            self.sf_dedup_key = self.compute_dedup_key()

    # --- convenience accessors used across the platform ------------------
    @property
    def principal(self) -> Optional[str]:
        """Best-effort "who did this" identifier."""
        actor_user = self.actor.user if self.actor else None
        for candidate in (
            actor_user.email_addr if actor_user else None,
            actor_user.name if actor_user else None,
            self.user.email_addr if self.user else None,
            self.user.name if self.user else None,
        ):
            if candidate:
                return candidate
        return None

    @property
    def target_principal(self) -> Optional[str]:
        if self.user:
            return self.user.email_addr or self.user.name
        return None

    @property
    def source_ip(self) -> Optional[str]:
        return self.src_endpoint.ip if self.src_endpoint else None

    @property
    def hostname(self) -> Optional[str]:
        if self.device and self.device.hostname:
            return self.device.hostname
        if self.dst_endpoint and self.dst_endpoint.hostname:
            return self.dst_endpoint.hostname
        return None

    @property
    def session_uid(self) -> Optional[str]:
        if self.actor and self.actor.session:
            return self.actor.session.uid
        return None

    @property
    def is_failure(self) -> bool:
        return self.status_id == StatusId.FAILURE

    def compute_dedup_key(self) -> str:
        """Stable content hash so the same log delivered twice collapses.

        Deliberately excludes ingestion-time metadata (``sf_event_id``,
        ``sf_ingested_at``, ``metadata.processed_time``) so at-least-once
        delivery from the bus does not produce duplicate security events.
        """
        parts = [
            self.sf_tenant,
            str(self.class_uid),
            str(self.activity_id),
            self.time.isoformat(),
            str(self.principal),
            str(self.target_principal),
            str(self.source_ip),
            str(self.hostname),
            str(self.status_id),
            str(self.api.operation if self.api else None),
            self.metadata.uid or "",
            self.sf_raw or self.message or "",
        ]
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()

    def add_observable(self, name: str, type_: str, value: Optional[str]) -> None:
        if not value:
            return
        if any(o.type == type_ and o.value == value for o in self.observables):
            return
        self.observables.append(Observable(name=name, type=type_, value=value))

    def derive_observables(self) -> "OcsfEvent":
        """Populate ``observables`` from the mapped entities."""
        self.add_observable("src_endpoint.ip", "ip", self.source_ip)
        if self.dst_endpoint:
            self.add_observable("dst_endpoint.ip", "ip", self.dst_endpoint.ip)
        self.add_observable("actor.user.name", "user", self.principal)
        self.add_observable("user.name", "user", self.target_principal)
        self.add_observable("device.hostname", "hostname", self.hostname)
        if self.file:
            for algo, digest in (self.file.hashes or {}).items():
                self.add_observable("file.hashes.%s" % algo, "file_hash", digest)
        if self.http_request and self.http_request.url:
            self.add_observable("http_request.url", "url", self.http_request.url)
        return self

    def to_document(self) -> Dict[str, Any]:
        """JSON-safe dict for the security event store."""
        return self.model_dump(mode="json", exclude_none=True)


Process.model_rebuild()


class RawLogRecord(BaseModel):
    """A single log line/record as handed over by a collector."""

    model_config = ConfigDict(extra="allow")

    source: str  # e.g. "linux.sshd", "aws.cloudtrail", "webapp.audit"
    tenant: str = "default"
    payload: Dict[str, Any] = Field(default_factory=dict)
    raw: Optional[str] = None
    received_at: datetime = Field(default_factory=utcnow)
    collector: Optional[str] = None
    offset: Optional[int] = None

    def key(self) -> str:
        blob = self.raw if self.raw is not None else repr(sorted(self.payload.items()))
        return hashlib.sha256(("%s|%s|%s" % (self.tenant, self.source, blob)).encode()).hexdigest()


# --------------------------------------------------------------------------- #
# Flattening (used by the Sigma evaluator and the dashboard)
# --------------------------------------------------------------------------- #
def flatten_event(event: Any, prefix: str = "") -> Dict[str, Any]:
    """Flatten an event (model or dict) into dotted field paths.

    Lists of scalars are preserved as lists (Sigma treats a list-valued field as
    "any element matches"); lists of objects are expanded both as ``field[i].x``
    and collapsed into ``field.x`` multi-values so ``resources.criticality``
    matches any resource.
    """
    if isinstance(event, BaseModel):
        data = event.model_dump(mode="json", exclude_none=True)
    else:
        data = event
    flat: Dict[str, Any] = {}

    def _merge(key: str, value: Any) -> None:
        if key in flat:
            existing = flat[key]
            if isinstance(existing, list):
                if value not in existing:
                    existing.append(value)
            elif existing != value:
                flat[key] = [existing, value]
        else:
            flat[key] = value

    def _walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                _walk(value, "%s.%s" % (path, key) if path else str(key))
        elif isinstance(node, list):
            if node and all(not isinstance(item, (dict, list)) for item in node):
                _merge(path, node)
                return
            for index, item in enumerate(node):
                _walk(item, "%s[%d]" % (path, index))
                if isinstance(item, dict):
                    for key, value in item.items():
                        if not isinstance(value, (dict, list)):
                            _merge("%s.%s" % (path, key), value)
        else:
            _merge(path, node)

    _walk(data, prefix)
    return flat


# --------------------------------------------------------------------------- #
# OCSF activity_id -> name, per class.  Mappers only set the numeric id; the
# human-readable name (which detections and the UI use) is filled in here.
# --------------------------------------------------------------------------- #
ACTIVITY_NAMES: Dict[int, Dict[int, str]] = {
    ClassUid.FILE_SYSTEM_ACTIVITY: {
        1: "Create", 2: "Read", 3: "Update", 4: "Delete", 5: "Rename",
        6: "Set Attributes", 7: "Set Security", 8: "Get Attributes", 14: "Open",
    },
    ClassUid.PROCESS_ACTIVITY: {
        1: "Launch", 2: "Terminate", 3: "Open", 4: "Inject", 5: "Set User ID",
    },
    ClassUid.ACCOUNT_CHANGE: {
        1: "Create", 2: "Enable", 3: "Password Change", 4: "Password Reset",
        5: "Disable", 6: "Delete", 7: "Attach Policy", 8: "Detach Policy",
        9: "Lock", 10: "MFA Factor Enable", 11: "MFA Factor Disable",
        12: "Unlock", 13: "User Access Change", 14: "Group Access Change",
    },
    ClassUid.AUTHENTICATION: {
        1: "Logon", 2: "Logoff", 3: "Authentication Ticket",
        4: "Service Ticket Request", 5: "Service Ticket Renew", 6: "Preauth",
    },
    ClassUid.AUTHORIZE_SESSION: {
        1: "Assign Privileges", 2: "Assign Groups",
    },
    ClassUid.ENTITY_MANAGEMENT: {
        1: "Create", 2: "Read", 3: "Update", 4: "Delete", 5: "Move",
        6: "Enroll", 7: "Unenroll", 8: "Enable", 9: "Disable",
    },
    ClassUid.USER_ACCESS_MANAGEMENT: {
        1: "Assign Privileges", 2: "Revoke Privileges",
    },
    ClassUid.GROUP_MANAGEMENT: {
        1: "Assign Privileges", 2: "Revoke Privileges", 3: "Add User",
        4: "Remove User", 5: "Delete", 6: "Create",
    },
    ClassUid.HTTP_ACTIVITY: {
        1: "Connect", 2: "Delete", 3: "Get", 4: "Head", 5: "Options",
        6: "Post", 7: "Put", 8: "Trace", 9: "Patch",
    },
    ClassUid.WEB_RESOURCES_ACTIVITY: {
        1: "Create", 2: "Read", 3: "Update", 4: "Delete", 5: "Search",
        6: "Import", 7: "Export", 8: "Share",
    },
    ClassUid.API_ACTIVITY: {
        1: "Create", 2: "Read", 3: "Update", 4: "Delete",
    },
    ClassUid.DATASTORE_ACTIVITY: {
        1: "Read", 2: "Update", 3: "Connect", 4: "Query", 5: "Write",
        6: "Create", 7: "Delete", 8: "Encrypt", 9: "Decrypt",
    },
}


def activity_name(class_uid: int, activity_id: int) -> Optional[str]:
    if activity_id == 99:
        return "Other"
    if activity_id == 0:
        return "Unknown"
    return ACTIVITY_NAMES.get(class_uid, {}).get(activity_id)
