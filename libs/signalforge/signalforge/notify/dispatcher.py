"""Who gets told, and what happens when delivery fails.

Recipients come from the watch list, the assignee and the owning team's leads,
minus the person who caused the event. Notifying somebody about their own
action is the fastest way to get a channel muted, and a muted channel is worse
than no channel.

Every notification is persisted before delivery is attempted, so a failure is
visible and retryable rather than lost in a log line. The retry policy lives
here and nowhere else: channels report success or failure and never back off
themselves.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

from sqlalchemy import select

from ..storage import db as dbm
from .channels import Channel, build_channels, describe
from .models import (
    DeliveryResult,
    DeliveryStatus,
    DispatchReport,
    Notification,
    NotificationKind,
)

logger = logging.getLogger("signalforge.notify")

#: Attempt 1 immediately, then after a minute, then five, then thirty. Four
#: attempts over about half an hour: enough to ride out a webhook restart
#: without hammering an endpoint that is genuinely gone.
RETRY_BACKOFF_SECONDS = (0, 60, 300, 1800)
MAX_ATTEMPTS = len(RETRY_BACKOFF_SECONDS)


class NotificationService:
    def __init__(
        self,
        session_factory: Any,
        settings: Any = None,
        channels: Optional[Sequence[Channel]] = None,
    ) -> None:
        from ..config import get_settings

        self.session_factory = session_factory
        self.settings = settings or get_settings()
        self.channels: List[Channel] = (
            list(channels) if channels is not None else build_channels(self.settings)
        )
        logger.info("notification channels", extra={"channels": describe(self.channels)})

    # ------------------------------------------------------------------ #
    # Recipients
    # ------------------------------------------------------------------ #
    def recipients_for(
        self,
        tenant: str,
        incident_row: Any,
        kind: NotificationKind,
        *,
        actor: Optional[str] = None,
        explicit: Optional[Iterable[str]] = None,
    ) -> List[Dict[str, str]]:
        """Resolve ``{email, user_id}`` recipients, excluding the actor.

        ``explicit`` wins when given (a mention names exactly who it means);
        otherwise the audience is the watch list plus the assignee plus the
        owning team's leads.
        """
        with self.session_factory() as session:
            wanted: Dict[str, str] = {}

            if explicit is not None:
                for email in explicit:
                    user = self._user_by_email(session, tenant, email)
                    if user is not None:
                        wanted[user.email] = user.id
            else:
                for watcher, user in session.execute(
                    select(dbm.IncidentWatcher, dbm.User)
                    .join(dbm.User, dbm.User.id == dbm.IncidentWatcher.user_id)
                    .where(dbm.IncidentWatcher.incident_id == incident_row.id)
                ).all():
                    wanted[user.email] = watcher.user_id

                if incident_row.assignee_id:
                    assignee = session.get(dbm.User, incident_row.assignee_id)
                    if assignee is not None:
                        wanted[assignee.email] = assignee.id

                # A breach or a transfer is the lead's problem even if they are
                # not personally watching every case in their queue.
                if kind in (NotificationKind.SLA_BREACHED, NotificationKind.TRANSFERRED):
                    for lead in self._team_leads(session, incident_row.team_id):
                        wanted[lead.email] = lead.id

            if actor:
                wanted.pop(actor, None)
            return [
                {"email": email, "user_id": user_id} for email, user_id in sorted(wanted.items())
            ]

    @staticmethod
    def _user_by_email(session: Any, tenant: str, email: str) -> Optional[Any]:
        tenant_row = session.scalars(select(dbm.Tenant).where(dbm.Tenant.key == tenant)).first()
        if tenant_row is None:
            return None
        return session.scalars(
            select(dbm.User).where(dbm.User.tenant_id == tenant_row.id, dbm.User.email == email)
        ).first()

    @staticmethod
    def _team_leads(session: Any, team_id: Optional[str]) -> List[Any]:
        if not team_id:
            return []
        return list(
            session.scalars(
                select(dbm.User)
                .join(dbm.TeamMember, dbm.TeamMember.user_id == dbm.User.id)
                .where(dbm.TeamMember.team_id == team_id, dbm.TeamMember.role == "lead")
            ).all()
        )

    # ------------------------------------------------------------------ #
    # Queueing and delivery
    # ------------------------------------------------------------------ #
    def notify(
        self,
        tenant: str,
        reference: str,
        kind: NotificationKind,
        subject: str,
        body: str,
        *,
        actor: Optional[str] = None,
        explicit: Optional[Iterable[str]] = None,
        payload: Optional[Dict[str, Any]] = None,
        deliver: bool = True,
    ) -> DispatchReport:
        """Queue a notification for everybody who should hear about it."""
        report = DispatchReport()
        if not self.settings.notify_enabled:
            return report

        with self.session_factory() as session:
            incident_row = self._find_incident(session, tenant, reference)
            if incident_row is None:
                logger.warning("notification for unknown incident", extra={"incident": reference})
                return report
            recipients = self.recipients_for(
                tenant, incident_row, kind, actor=actor, explicit=explicit
            )
            queued: List[Notification] = []
            for recipient in recipients:
                notification = Notification(
                    kind=kind,
                    tenant=tenant,
                    recipient_email=recipient["email"],
                    recipient_user_id=recipient["user_id"],
                    subject=subject,
                    body=body,
                    incident_key=incident_row.key,
                    incident_id=incident_row.id,
                    actor=actor,
                    payload=dict(payload or {}),
                )
                session.add(
                    dbm.Notification(
                        id=notification.id,
                        tenant=tenant,
                        kind=kind.value,
                        incident_id=incident_row.id,
                        incident_key=incident_row.key,
                        recipient_email=notification.recipient_email,
                        recipient_user_id=notification.recipient_user_id,
                        actor=actor,
                        subject=subject,
                        body=body,
                        payload=dict(payload or {}),
                        status=DeliveryStatus.PENDING.value,
                    )
                )
                queued.append(notification)
            session.commit()

        if not self.channels:
            # Nothing configured. Mark them suppressed rather than leaving rows
            # pending forever for a retry that can never succeed.
            for notification in queued:
                self._record(notification.id, DeliveryStatus.SUPPRESSED, "no channel configured")
                report.record(
                    DeliveryResult(
                        notification.id, "none", DeliveryStatus.SUPPRESSED, "no channel configured"
                    )
                )
            return report

        if deliver:
            for notification in queued:
                report.record(self._deliver(notification))
        return report

    def _deliver(self, notification: Notification) -> DeliveryResult:
        """Send to every channel. One channel failing fails the notification."""
        failures: List[str] = []
        for channel in self.channels:
            result = channel.send(notification)
            if result.status is DeliveryStatus.FAILED:
                failures.append("%s: %s" % (channel.name, result.detail))

        if failures:
            detail = "; ".join(failures)
            attempts = self._record(notification.id, DeliveryStatus.FAILED, detail)
            logger.warning(
                "notification delivery failed",
                extra={"recipient": notification.recipient_email, "detail": detail},
            )
            return DeliveryResult(
                notification.id, describe(self.channels), DeliveryStatus.FAILED, detail, attempts
            )

        attempts = self._record(notification.id, DeliveryStatus.SENT)
        return DeliveryResult(
            notification.id, describe(self.channels), DeliveryStatus.SENT, None, attempts
        )

    def _record(
        self, notification_id: str, status: DeliveryStatus, detail: Optional[str] = None
    ) -> int:
        with self.session_factory() as session:
            row = session.get(dbm.Notification, notification_id)
            if row is None:
                return 0
            row.attempts = (row.attempts or 0) + 1
            row.status = status.value
            row.last_error = detail
            if status is DeliveryStatus.SENT:
                row.sent_at = datetime.now(tz=timezone.utc)
            session.commit()
            return row.attempts

    # ------------------------------------------------------------------ #
    # Retry
    # ------------------------------------------------------------------ #
    def retry_failed(
        self, tenant: Optional[str] = None, *, now: Optional[datetime] = None, limit: int = 100
    ) -> DispatchReport:
        """Re-send failed notifications whose backoff has elapsed.

        Gives up after ``MAX_ATTEMPTS``: a webhook that has refused four times
        over half an hour is not coming back inside this window, and retrying
        forever turns the table into a queue nobody drains.
        """
        now = now or datetime.now(tz=timezone.utc)
        report = DispatchReport()
        if not self.channels:
            return report

        with self.session_factory() as session:
            query = select(dbm.Notification).where(
                dbm.Notification.status == DeliveryStatus.FAILED.value,
                dbm.Notification.attempts < MAX_ATTEMPTS,
            )
            if tenant:
                query = query.where(dbm.Notification.tenant == tenant)
            rows = session.scalars(query.limit(limit)).all()
            due: List[Notification] = []
            for row in rows:
                updated = row.updated_at or row.created_at
                if updated.tzinfo is None:
                    updated = updated.replace(tzinfo=timezone.utc)
                wait = RETRY_BACKOFF_SECONDS[min(row.attempts, MAX_ATTEMPTS - 1)]
                if now - updated < timedelta(seconds=wait):
                    continue
                due.append(
                    Notification(
                        id=row.id,
                        kind=NotificationKind(row.kind),
                        tenant=row.tenant,
                        recipient_email=row.recipient_email,
                        recipient_user_id=row.recipient_user_id,
                        subject=row.subject,
                        body=row.body,
                        incident_key=row.incident_key,
                        incident_id=row.incident_id,
                        actor=row.actor,
                        payload=dict(row.payload or {}),
                    )
                )

        for notification in due:
            report.record(self._deliver(notification))
        if report.considered:
            logger.info("notification retry", extra=report.to_dict())
        return report

    def pending(self, tenant: str, *, limit: int = 50) -> List[Dict[str, Any]]:
        """Recent notifications and their delivery state, newest first."""
        with self.session_factory() as session:
            rows = session.scalars(
                select(dbm.Notification)
                .where(dbm.Notification.tenant == tenant)
                .order_by(dbm.Notification.created_at.desc())
                .limit(limit)
            ).all()
            return [
                {
                    "id": row.id,
                    "kind": row.kind,
                    "incident": row.incident_key,
                    "recipient": row.recipient_email,
                    "subject": row.subject,
                    "status": row.status,
                    "attempts": row.attempts,
                    "last_error": row.last_error,
                    "created_at": row.created_at,
                    "sent_at": row.sent_at,
                }
                for row in rows
            ]

    @staticmethod
    def _find_incident(session: Any, tenant: str, reference: str) -> Optional[Any]:
        row = session.scalars(
            select(dbm.Incident).where(dbm.Incident.tenant == tenant, dbm.Incident.key == reference)
        ).first()
        if row is not None:
            return row
        row = session.get(dbm.Incident, reference)
        return row if row is not None and row.tenant == tenant else None
