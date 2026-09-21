"""What a notification is, and who it is for."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


def utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class NotificationKind(str, Enum):
    """Why somebody is being told.

    Deliberately a closed set: an operator choosing which notifications to
    receive needs a stable vocabulary, and "every audit action" is not one.
    """

    MENTIONED = "mentioned"
    ASSIGNED = "assigned"
    TRANSFERRED = "transferred"
    SLA_BREACHED = "sla_breached"
    INCIDENT_CLOSED = "incident_closed"
    RESPONSE_REQUESTED = "response_requested"


class DeliveryStatus(str, Enum):
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    #: Deliberately not sent - the actor's own action, or no channel configured.
    SUPPRESSED = "suppressed"


#: Notifications a channel should treat as urgent enough to interrupt someone.
URGENT_KINDS = frozenset({NotificationKind.SLA_BREACHED, NotificationKind.RESPONSE_REQUESTED})


@dataclass
class Notification:
    """One thing to tell one person."""

    kind: NotificationKind
    tenant: str
    recipient_email: str
    subject: str
    body: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    recipient_user_id: Optional[str] = None
    incident_key: Optional[str] = None
    incident_id: Optional[str] = None
    actor: Optional[str] = None
    payload: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=utcnow)

    @property
    def urgent(self) -> bool:
        return self.kind in URGENT_KINDS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "tenant": self.tenant,
            "recipient": self.recipient_email,
            "incident": self.incident_key,
            "actor": self.actor,
            "subject": self.subject,
            "body": self.body,
            "urgent": self.urgent,
            "payload": dict(self.payload),
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class DeliveryResult:
    notification_id: str
    channel: str
    status: DeliveryStatus
    detail: Optional[str] = None
    attempts: int = 1

    @property
    def ok(self) -> bool:
        return self.status in (DeliveryStatus.SENT, DeliveryStatus.SUPPRESSED)


@dataclass
class DispatchReport:
    """The outcome of one dispatch call, for the caller and the worker log."""

    considered: int = 0
    sent: int = 0
    suppressed: int = 0
    failed: int = 0
    results: List[DeliveryResult] = field(default_factory=list)

    def record(self, result: DeliveryResult) -> None:
        self.results.append(result)
        self.considered += 1
        if result.status is DeliveryStatus.SENT:
            self.sent += 1
        elif result.status is DeliveryStatus.SUPPRESSED:
            self.suppressed += 1
        else:
            self.failed += 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "considered": self.considered,
            "sent": self.sent,
            "suppressed": self.suppressed,
            "failed": self.failed,
        }
