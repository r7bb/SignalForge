"""Request / approve / execute lifecycle for response actions.

State machine::

    pending_approval --approve--> approved --execute--> executed | failed
                     \\--reject---> rejected

Only a user whose role is listed in the playbook's ``approver_roles`` can
approve, an action can never be approved by the analyst who requested it
(four-eyes), and every step writes an audit row plus an incident timeline entry.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from sqlalchemy import select

from ..config import Settings, get_settings
from ..models.incident import TimelineEntry
from ..storage import db as dbm
from .playbooks import (
    LabAdapter,
    PlaybookResult,
    ResponseError,
    execute,
    get_playbook,
    suggest_target,
)

log = logging.getLogger("signalforge.response.service")

STATUS_PENDING = "pending_approval"
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"
STATUS_EXECUTED = "executed"
STATUS_FAILED = "failed"


class ResponseService:
    def __init__(
        self,
        session_factory: Any,
        *,
        settings: Optional[Settings] = None,
        incidents: Any = None,
        adapter: Optional[LabAdapter] = None,
    ) -> None:
        self.session_factory = session_factory
        self.settings = settings or get_settings()
        self.incidents = incidents
        self.adapter = adapter or LabAdapter(self.settings)

    # ------------------------------------------------------------------ #
    def request(
        self,
        *,
        tenant: str,
        playbook: str,
        actor: str,
        incident_id: Optional[str] = None,
        target: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record a response request.  Never executes anything by itself."""
        definition = get_playbook(playbook)
        if target is None and incident_id and self.incidents is not None:
            incident = self.incidents.get(tenant, incident_id)
            if incident is not None:
                target = suggest_target(playbook, incident)
        if definition.target_kind != "none" and not target:
            raise ResponseError(
                "playbook %r needs a %s target" % (playbook, definition.target_kind)
            )

        with self.session_factory() as session:
            row = dbm.ResponseAction(
                tenant=tenant,
                incident_id=self._resolve_incident_id(session, tenant, incident_id),
                playbook=playbook,
                target=target,
                params=dict(params or {}),
                status=STATUS_PENDING,
                dry_run=bool(self.settings.response_dry_run),
                requested_by=actor,
            )
            session.add(row)
            dbm.record_audit(
                session,
                tenant=tenant,
                actor=actor,
                action="response.requested",
                entity_type="response_action",
                entity_id=row.id,
                detail="%s -> %s" % (playbook, target or "-"),
                playbook=playbook,
                target=target,
                incident_id=row.incident_id,
            )
            session.commit()
            action = _to_dict(row)

        self._timeline(
            tenant,
            incident_id,
            TimelineEntry(
                time=datetime.now(tz=timezone.utc),
                kind="response",
                title="Response requested: %s" % definition.title,
                detail="target %s, awaiting approval" % (target or "n/a"),
                actor=actor,
            ),
        )

        # The escape hatch exists for automated tests only - make it obvious.
        if not self.settings.response_require_approval:
            log.warning(
                "approval requirement disabled - auto-approving",
                extra={"playbook": playbook, "action_id": action["id"]},
            )
            return self.approve(
                tenant=tenant, action_id=action["id"], actor="system:auto-approve", role="admin"
            )
        return action

    # ------------------------------------------------------------------ #
    def approve(
        self,
        *,
        tenant: str,
        action_id: str,
        actor: str,
        role: str,
        execute_now: bool = True,
    ) -> Dict[str, Any]:
        definition_name: str
        with self.session_factory() as session:
            row = self._require(session, tenant, action_id)
            if row.status != STATUS_PENDING:
                raise ResponseError(
                    "action %s is %s, not awaiting approval" % (action_id, row.status)
                )
            definition = get_playbook(row.playbook)
            if role not in definition.approver_roles:
                raise ResponseError(
                    "role %r cannot approve %r (allowed: %s)"
                    % (role, row.playbook, ", ".join(definition.approver_roles))
                )
            if row.requested_by == actor and not actor.startswith("system:"):
                raise ResponseError("%s requested this action and cannot also approve it" % actor)
            row.status = STATUS_APPROVED
            row.approved_by = actor
            definition_name = definition.title
            dbm.record_audit(
                session,
                tenant=tenant,
                actor=actor,
                action="response.approved",
                entity_type="response_action",
                entity_id=row.id,
                detail=row.playbook,
                role=role,
            )
            session.commit()
            incident_id = row.incident_id
            action = _to_dict(row)

        self._timeline(
            tenant,
            incident_id,
            TimelineEntry(
                time=datetime.now(tz=timezone.utc),
                kind="response",
                title="Response approved: %s" % definition_name,
                detail="approved by %s" % actor,
                actor=actor,
            ),
        )
        if execute_now:
            return self.run(tenant=tenant, action_id=action_id, actor=actor)
        return action

    def reject(
        self, *, tenant: str, action_id: str, actor: str, reason: Optional[str] = None
    ) -> Dict[str, Any]:
        with self.session_factory() as session:
            row = self._require(session, tenant, action_id)
            if row.status != STATUS_PENDING:
                raise ResponseError("action %s is %s" % (action_id, row.status))
            row.status = STATUS_REJECTED
            row.rejected_reason = reason
            dbm.record_audit(
                session,
                tenant=tenant,
                actor=actor,
                action="response.rejected",
                entity_type="response_action",
                entity_id=row.id,
                detail=reason,
            )
            session.commit()
            incident_id = row.incident_id
            action = _to_dict(row)
        self._timeline(
            tenant,
            incident_id,
            TimelineEntry(
                time=datetime.now(tz=timezone.utc),
                kind="response",
                title="Response rejected",
                detail=reason,
                actor=actor,
            ),
        )
        return action

    # ------------------------------------------------------------------ #
    def run(self, *, tenant: str, action_id: str, actor: str) -> Dict[str, Any]:
        """Execute an approved action."""
        with self.session_factory() as session:
            row = self._require(session, tenant, action_id)
            if row.status != STATUS_APPROVED:
                raise ResponseError(
                    "action %s must be approved before execution (currently %s)"
                    % (action_id, row.status)
                )
            playbook, target, params = row.playbook, row.target, dict(row.params or {})
            incident_id = row.incident_id
            incident_key = None
            if incident_id:
                incident_row = session.get(dbm.Incident, incident_id)
                incident_key = incident_row.key if incident_row else None

        try:
            result: PlaybookResult = execute(
                playbook,
                target=target,
                params=params,
                actor=actor,
                incident_key=incident_key,
                settings=self.settings,
                adapter=self.adapter,
            )
            status = STATUS_EXECUTED if result.ok else STATUS_FAILED
        except Exception as exc:
            log.exception("playbook execution failed", extra={"playbook": playbook})
            result = PlaybookResult(
                False, "execution error: %s" % exc, bool(self.settings.response_dry_run)
            )
            status = STATUS_FAILED

        with self.session_factory() as session:
            row = self._require(session, tenant, action_id)
            row.status = status
            row.executed_at = datetime.now(tz=timezone.utc)
            row.result = result.to_dict()
            dbm.record_audit(
                session,
                tenant=tenant,
                actor=actor,
                action="response.executed" if result.ok else "response.failed",
                entity_type="response_action",
                entity_id=row.id,
                detail=result.message,
                dry_run=result.dry_run,
                playbook=playbook,
                target=target,
            )
            session.commit()
            action = _to_dict(row)

        self._timeline(
            tenant,
            incident_id,
            TimelineEntry(
                time=datetime.now(tz=timezone.utc),
                kind="response",
                title="Response %s: %s" % ("executed" if result.ok else "failed", playbook),
                detail=result.message + (" [dry run]" if result.dry_run else ""),
                actor=actor,
            ),
        )
        return action

    # ------------------------------------------------------------------ #
    def list(
        self,
        tenant: str,
        *,
        incident_id: Optional[str] = None,
        status: Optional[Sequence[str]] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        with self.session_factory() as session:
            query = select(dbm.ResponseAction).where(dbm.ResponseAction.tenant == tenant)
            if incident_id:
                resolved = self._resolve_incident_id(session, tenant, incident_id)
                query = query.where(dbm.ResponseAction.incident_id == resolved)
            if status:
                query = query.where(dbm.ResponseAction.status.in_(list(status)))
            rows = session.scalars(
                query.order_by(dbm.ResponseAction.created_at.desc()).limit(limit)
            ).all()
            return [_to_dict(row) for row in rows]

    def get(self, tenant: str, action_id: str) -> Optional[Dict[str, Any]]:
        with self.session_factory() as session:
            row = session.scalars(
                select(dbm.ResponseAction).where(
                    dbm.ResponseAction.tenant == tenant, dbm.ResponseAction.id == action_id
                )
            ).first()
            return _to_dict(row) if row else None

    # ------------------------------------------------------------------ #
    @staticmethod
    def _require(session: Any, tenant: str, action_id: str) -> dbm.ResponseAction:
        row = session.scalars(
            select(dbm.ResponseAction).where(
                dbm.ResponseAction.tenant == tenant, dbm.ResponseAction.id == action_id
            )
        ).first()
        if row is None:
            raise ResponseError("unknown response action %r" % action_id)
        return row

    @staticmethod
    def _resolve_incident_id(session: Any, tenant: str, reference: Optional[str]) -> Optional[str]:
        if not reference:
            return None
        row = session.scalars(
            select(dbm.Incident).where(dbm.Incident.tenant == tenant, dbm.Incident.id == reference)
        ).first()
        if row is None:
            row = session.scalars(
                select(dbm.Incident).where(
                    dbm.Incident.tenant == tenant, dbm.Incident.key == reference
                )
            ).first()
        return row.id if row else None

    def _timeline(self, tenant: str, incident_id: Optional[str], entry: TimelineEntry) -> None:
        if not incident_id or self.incidents is None:
            return
        try:
            self.incidents.append_timeline(
                tenant, incident_id, entry, actor=entry.actor or "system"
            )
        except Exception as exc:  # timeline is best-effort, the audit row is the record
            log.warning("could not append response to timeline", extra={"error": str(exc)})


def _to_dict(row: dbm.ResponseAction) -> Dict[str, Any]:
    return {
        "id": row.id,
        "tenant": row.tenant,
        "incident_id": row.incident_id,
        "playbook": row.playbook,
        "target": row.target,
        "params": dict(row.params or {}),
        "status": row.status,
        "dry_run": row.dry_run,
        "requested_by": row.requested_by,
        "approved_by": row.approved_by,
        "rejected_reason": row.rejected_reason,
        "executed_at": row.executed_at,
        "result": dict(row.result or {}),
        "created_at": row.created_at,
    }
