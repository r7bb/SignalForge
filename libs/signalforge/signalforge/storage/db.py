"""Relational metadata store (PostgreSQL in production, SQLite in tests).

The security *events* live in OpenSearch; everything that needs transactions,
uniqueness or joins lives here: tenants, analysts, the detection registry,
alerts, incidents, notes, the audit trail, approval-gated response actions,
cached threat intel and the SBOM/vulnerability graph.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

from ..config import Settings, get_settings

#: JSONB on PostgreSQL, plain JSON on SQLite.
JsonType = JSON().with_variant(JSONB, "postgresql")


def utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


# --------------------------------------------------------------------------- #
# Tenancy and identity
# --------------------------------------------------------------------------- #
class Tenant(Base, TimestampMixin):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    key: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    users: Mapped[List["User"]] = relationship(back_populates="tenant")


class User(Base, TimestampMixin):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_users_tenant_email"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    email: Mapped[str] = mapped_column(String(255), index=True)
    full_name: Mapped[Optional[str]] = mapped_column(String(255))
    password_hash: Mapped[str] = mapped_column(String(255))
    #: viewer | analyst | responder | admin
    role: Mapped[str] = mapped_column(String(32), default="analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    tenant: Mapped[Tenant] = relationship(back_populates="users")


# --------------------------------------------------------------------------- #
# Detection registry (rule versioning)
# --------------------------------------------------------------------------- #
class Detection(Base, TimestampMixin):
    __tablename__ = "detections"
    __table_args__ = (UniqueConstraint("rule_id", name="uq_detections_rule_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    rule_id: Mapped[str] = mapped_column(String(128), index=True)
    name: Mapped[Optional[str]] = mapped_column(String(128))
    title: Mapped[str] = mapped_column(String(512))
    level: Mapped[str] = mapped_column(String(32), default="medium")
    status: Mapped[str] = mapped_column(String(32), default="experimental")
    kind: Mapped[str] = mapped_column(String(32), default="detection")  # detection | correlation
    source_path: Mapped[Optional[str]] = mapped_column(String(512))
    #: sha256 of the rule document - changes on every edit, so alerts can be
    #: attributed to the exact rule version that produced them.
    content_hash: Mapped[str] = mapped_column(String(64))
    revision: Mapped[int] = mapped_column(Integer, default=1)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    tactics: Mapped[Any] = mapped_column(JsonType, default=list)
    techniques: Mapped[Any] = mapped_column(JsonType, default=list)
    metadata_json: Mapped[Any] = mapped_column(JsonType, default=dict)

    versions: Mapped[List["DetectionVersion"]] = relationship(
        back_populates="detection", cascade="all, delete-orphan"
    )


class DetectionVersion(Base):
    __tablename__ = "detection_versions"
    __table_args__ = (
        UniqueConstraint("detection_id", "revision", name="uq_detection_version"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    detection_id: Mapped[str] = mapped_column(ForeignKey("detections.id"), index=True)
    revision: Mapped[int] = mapped_column(Integer)
    content_hash: Mapped[str] = mapped_column(String(64))
    document: Mapped[Any] = mapped_column(JsonType)
    author: Mapped[Optional[str]] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    detection: Mapped[Detection] = relationship(back_populates="versions")


# --------------------------------------------------------------------------- #
# Alerts and incidents
# --------------------------------------------------------------------------- #
class Alert(Base, TimestampMixin):
    __tablename__ = "alerts"
    __table_args__ = (
        UniqueConstraint("tenant", "dedup_key", name="uq_alerts_tenant_dedup"),
        Index("ix_alerts_tenant_last_seen", "tenant", "last_seen"),
        Index("ix_alerts_tenant_status", "tenant", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    rule_id: Mapped[str] = mapped_column(String(128), index=True)
    rule_title: Mapped[str] = mapped_column(String(512))
    rule_level: Mapped[str] = mapped_column(String(32), default="medium")
    rule_revision: Mapped[Optional[int]] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    risk_level: Mapped[str] = mapped_column(String(32), default="low")
    severity: Mapped[int] = mapped_column(Integer, default=5)
    confidence: Mapped[int] = mapped_column(Integer, default=7)
    principal: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    target_principal: Mapped[Optional[str]] = mapped_column(String(255))
    source_ip: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    session_uid: Mapped[Optional[str]] = mapped_column(String(128))
    dedup_key: Mapped[str] = mapped_column(String(64), index=True)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    incident_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), index=True
    )
    tactics: Mapped[Any] = mapped_column(JsonType, default=list)
    techniques: Mapped[Any] = mapped_column(JsonType, default=list)
    #: Full Alert pydantic document (evidence, enrichments, matched fields).
    payload: Mapped[Any] = mapped_column(JsonType, default=dict)

    incident: Mapped[Optional["Incident"]] = relationship(back_populates="alerts")


class Incident(Base, TimestampMixin):
    __tablename__ = "incidents"
    __table_args__ = (
        UniqueConstraint("tenant", "key", name="uq_incidents_tenant_key"),
        Index("ix_incidents_tenant_status", "tenant", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    key: Mapped[str] = mapped_column(String(32), index=True)  # INC-2041
    title: Mapped[str] = mapped_column(String(512))
    summary: Mapped[Optional[str]] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)
    severity: Mapped[str] = mapped_column(String(32), default="medium")
    owner: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    scenario: Mapped[Optional[str]] = mapped_column(String(128), index=True)
    dedup_key: Mapped[str] = mapped_column(String(64), index=True)
    principal: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    close_reason: Mapped[Optional[str]] = mapped_column(Text)
    tactics: Mapped[Any] = mapped_column(JsonType, default=list)
    techniques: Mapped[Any] = mapped_column(JsonType, default=list)
    payload: Mapped[Any] = mapped_column(JsonType, default=dict)

    alerts: Mapped[List[Alert]] = relationship(back_populates="incident")
    notes: Mapped[List["IncidentNote"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    actions: Mapped[List["ResponseAction"]] = relationship(back_populates="incident")


class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    author: Mapped[str] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    incident: Mapped[Incident] = relationship(back_populates="notes")


class IncidentSequence(Base):
    """Per-tenant counter behind the human-readable ``INC-####`` key."""

    __tablename__ = "incident_sequences"

    tenant: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_value: Mapped[int] = mapped_column(Integer, default=2000)


class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (Index("ix_audit_tenant_created", "tenant", "created_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    actor: Mapped[str] = mapped_column(String(255), default="system")
    action: Mapped[str] = mapped_column(String(128), index=True)
    entity_type: Mapped[Optional[str]] = mapped_column(String(64))
    entity_id: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    detail: Mapped[Optional[str]] = mapped_column(Text)
    data: Mapped[Any] = mapped_column(JsonType, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# --------------------------------------------------------------------------- #
# Response automation
# --------------------------------------------------------------------------- #
class ResponseAction(Base, TimestampMixin):
    __tablename__ = "response_actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    incident_id: Mapped[Optional[str]] = mapped_column(ForeignKey("incidents.id"), index=True)
    playbook: Mapped[str] = mapped_column(String(128), index=True)
    target: Mapped[Optional[str]] = mapped_column(String(255))
    params: Mapped[Any] = mapped_column(JsonType, default=dict)
    #: pending_approval | approved | rejected | executing | executed | failed
    status: Mapped[str] = mapped_column(String(32), default="pending_approval", index=True)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=True)
    requested_by: Mapped[str] = mapped_column(String(255))
    approved_by: Mapped[Optional[str]] = mapped_column(String(255))
    rejected_reason: Mapped[Optional[str]] = mapped_column(Text)
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    result: Mapped[Any] = mapped_column(JsonType, default=dict)

    incident: Mapped[Optional[Incident]] = relationship(back_populates="actions")


# --------------------------------------------------------------------------- #
# Threat intelligence cache
# --------------------------------------------------------------------------- #
class Indicator(Base, TimestampMixin):
    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint("type", "value", "provider", name="uq_indicator_identity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    type: Mapped[str] = mapped_column(String(32), index=True)  # ip | domain | file_hash | url
    value: Mapped[str] = mapped_column(String(512), index=True)
    provider: Mapped[str] = mapped_column(String(64), default="static-feed")
    verdict: Mapped[str] = mapped_column(String(32), default="unknown")
    score: Mapped[int] = mapped_column(Integer, default=0)
    categories: Mapped[Any] = mapped_column(JsonType, default=list)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    data: Mapped[Any] = mapped_column(JsonType, default=dict)


# --------------------------------------------------------------------------- #
# Software supply chain (SBOM)
# --------------------------------------------------------------------------- #
class Application(Base, TimestampMixin):
    __tablename__ = "applications"
    __table_args__ = (UniqueConstraint("tenant", "name", name="uq_app_tenant_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(255))
    environment: Mapped[str] = mapped_column(String(64), default="production")
    criticality: Mapped[str] = mapped_column(String(32), default="medium")
    owner: Mapped[Optional[str]] = mapped_column(String(255))

    sboms: Mapped[List["Sbom"]] = relationship(back_populates="application",
                                               cascade="all, delete-orphan")


class Sbom(Base):
    __tablename__ = "sboms"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    format: Mapped[str] = mapped_column(String(32))  # cyclonedx | spdx
    spec_version: Mapped[Optional[str]] = mapped_column(String(32))
    serial_number: Mapped[Optional[str]] = mapped_column(String(128))
    component_count: Mapped[int] = mapped_column(Integer, default=0)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    application: Mapped[Application] = relationship(back_populates="sboms")
    components: Mapped[List["SbomComponent"]] = relationship(
        back_populates="sbom", cascade="all, delete-orphan"
    )


class Component(Base):
    __tablename__ = "components"
    __table_args__ = (UniqueConstraint("purl", name="uq_component_purl"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    purl: Mapped[str] = mapped_column(String(512), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    version: Mapped[str] = mapped_column(String(128), index=True)
    ecosystem: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    licenses: Mapped[Any] = mapped_column(JsonType, default=list)


class SbomComponent(Base):
    __tablename__ = "sbom_components"
    __table_args__ = (
        UniqueConstraint("sbom_id", "component_id", name="uq_sbom_component"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    sbom_id: Mapped[str] = mapped_column(ForeignKey("sboms.id"), index=True)
    component_id: Mapped[str] = mapped_column(ForeignKey("components.id"), index=True)
    direct: Mapped[bool] = mapped_column(Boolean, default=True)
    scope: Mapped[Optional[str]] = mapped_column(String(32))

    sbom: Mapped[Sbom] = relationship(back_populates="components")
    component: Mapped[Component] = relationship()


class Vulnerability(Base, TimestampMixin):
    __tablename__ = "vulnerabilities"
    __table_args__ = (UniqueConstraint("vuln_id", name="uq_vuln_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    vuln_id: Mapped[str] = mapped_column(String(64), index=True)  # CVE-2026-1234 / GHSA-...
    title: Mapped[Optional[str]] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(32), default="unknown", index=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float)
    ecosystem: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    package_name: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    #: Inclusive lower / exclusive upper bounds, e.g. ">=2.4.0 <2.4.2".
    affected_range: Mapped[Optional[str]] = mapped_column(String(255))
    fixed_version: Mapped[Optional[str]] = mapped_column(String(128))
    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    references: Mapped[Any] = mapped_column(JsonType, default=list)
    data: Mapped[Any] = mapped_column(JsonType, default=dict)


class ComponentVulnerability(Base):
    __tablename__ = "component_vulnerabilities"
    __table_args__ = (
        UniqueConstraint("component_id", "vulnerability_id", name="uq_component_vuln"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    component_id: Mapped[str] = mapped_column(ForeignKey("components.id"), index=True)
    vulnerability_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)
    matched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    status: Mapped[str] = mapped_column(String(32), default="affected")  # affected | fixed | ignored

    component: Mapped[Component] = relationship()
    vulnerability: Mapped[Vulnerability] = relationship()


# --------------------------------------------------------------------------- #
# Engine / session management
# --------------------------------------------------------------------------- #
_ENGINE: Optional[Engine] = None
_SESSION_FACTORY: Optional[sessionmaker] = None


def create_db_engine(settings: Optional[Settings] = None) -> Engine:
    settings = settings or get_settings()
    kwargs: Dict[str, Any] = {"echo": settings.database_echo, "future": True}
    if settings.database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    else:
        kwargs.update({"pool_pre_ping": True, "pool_size": 10, "max_overflow": 20})
    return create_engine(settings.database_url, **kwargs)


def get_engine(settings: Optional[Settings] = None, *, refresh: bool = False) -> Engine:
    global _ENGINE, _SESSION_FACTORY
    if _ENGINE is None or refresh:
        _ENGINE = create_db_engine(settings)
        _SESSION_FACTORY = sessionmaker(bind=_ENGINE, expire_on_commit=False, future=True)
    return _ENGINE


def get_session_factory(settings: Optional[Settings] = None) -> sessionmaker:
    get_engine(settings)
    assert _SESSION_FACTORY is not None
    return _SESSION_FACTORY


def init_db(settings: Optional[Settings] = None, *, drop: bool = False) -> Engine:
    engine = get_engine(settings, refresh=True)
    if drop:
        Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    return engine


def session_scope() -> Generator[Session, None, None]:
    """FastAPI dependency / context manager yielding a transactional session."""
    factory = get_session_factory()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def reset_db_state() -> None:
    """Test helper: forget the cached engine and session factory."""
    global _ENGINE, _SESSION_FACTORY
    if _ENGINE is not None:
        _ENGINE.dispose()
    _ENGINE = None
    _SESSION_FACTORY = None


def next_incident_key(session: Session, tenant: str) -> str:
    """Allocate the next ``INC-####`` key for a tenant (row-locked)."""
    # SQLite has no row locks; PostgreSQL takes one so two correlators cannot
    # allocate the same incident key.
    lockable = bool(session.bind) and session.bind.dialect.name != "sqlite"
    row = session.get(IncidentSequence, tenant, with_for_update=lockable)
    if row is None:
        row = IncidentSequence(tenant=tenant, last_value=2000)
        session.add(row)
        session.flush()
    row.last_value += 1
    session.flush()
    return "INC-%d" % row.last_value


def record_audit(
    session: Session,
    *,
    tenant: str,
    actor: str,
    action: str,
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    detail: Optional[str] = None,
    **data: Any,
) -> AuditLog:
    entry = AuditLog(
        tenant=tenant, actor=actor, action=action, entity_type=entity_type,
        entity_id=entity_id, detail=detail, data=data or {},
    )
    session.add(entry)
    return entry
