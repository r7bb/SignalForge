"""SOC performance metrics: the numbers a shift is actually judged on.

Everything here is computed from timestamps the case management already
records - ``created_at``, ``acknowledged_at``, ``closed_at`` and the audit
trail - so nothing needs to be instrumented separately and there is no second
source of truth to drift.

Definitions, stated because every SIEM means something slightly different:

MTTD
    Detection time minus the first event the incident contains. How long the
    attacker had before anything noticed.
MTTA
    ``acknowledged_at - created_at``. How long the incident sat before a person
    took it. Measured from the **first** claim, so passing a case around later
    does not flatter the number.
MTTR
    ``closed_at - created_at``, split by disposition: a false positive closed
    in two minutes and a real intrusion contained in six hours are not the same
    achievement and should not average together.
Queue age
    The oldest unclaimed open incident per queue. The leading indicator - it
    goes bad before MTTA does.
Reopen rate
    Incidents that left a terminal state, over **analyst closures**. High means
    cases are being closed to clear the queue rather than because they are
    finished.

    Two different closure counts appear in the report and they are not
    interchangeable. ``incidents_closed`` is how many incidents opened in the
    window are closed *now*, which includes the ones the correlator superseded
    into a chain. ``analyst_closures`` counts close actions in the audit trail,
    which is what the reopen rate divides by: an incident absorbed into a
    larger case was never a human deciding it was finished, so counting it
    would flatter the number.
"""

from __future__ import annotations

import statistics
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence

from sqlalchemy import func, select

from ..models.incident import ACTIVE_STATUSES, IncidentStatus
from ..sla import STATE_BREACHED, SlaPolicy, evaluate_clock, load_policy
from ..storage import db as dbm


def _seconds(start: Optional[datetime], end: Optional[datetime]) -> Optional[float]:
    if start is None or end is None:
        return None
    start = start if start.tzinfo else start.replace(tzinfo=timezone.utc)
    end = end if end.tzinfo else end.replace(tzinfo=timezone.utc)
    delta = (end - start).total_seconds()
    return delta if delta >= 0 else None


def _summarise(samples: Sequence[float]) -> Dict[str, Any]:
    """Mean *and* p50/p90, because a mean alone hides the tail that hurts."""
    if not samples:
        return {"count": 0, "mean_seconds": None, "p50_seconds": None, "p90_seconds": None}
    ordered = sorted(samples)
    return {
        "count": len(ordered),
        "mean_seconds": round(statistics.fmean(ordered), 1),
        "p50_seconds": round(statistics.median(ordered), 1),
        "p90_seconds": round(ordered[min(int(len(ordered) * 0.9), len(ordered) - 1)], 1),
    }


class SocMetrics:
    """Read-only projections over the incident tables."""

    def __init__(self, session_factory: Any, policy: Optional[SlaPolicy] = None) -> None:
        self.session_factory = session_factory
        self.policy = policy or load_policy()

    # ------------------------------------------------------------------ #
    def report(
        self,
        tenant: str,
        *,
        days: int = 7,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        now = now or datetime.now(tz=timezone.utc)
        since = now - timedelta(days=days)

        with self.session_factory() as session:
            rows = session.scalars(
                select(dbm.Incident).where(
                    dbm.Incident.tenant == tenant, dbm.Incident.created_at >= since
                )
            ).all()
            open_rows = session.scalars(
                select(dbm.Incident).where(
                    dbm.Incident.tenant == tenant,
                    dbm.Incident.status.in_([s.value for s in ACTIVE_STATUSES]),
                )
            ).all()
            teams = {
                team.id: team
                for team in session.scalars(select(dbm.Team).where(dbm.Team.tenant == tenant)).all()
            }
            users = {
                user.id: user
                for user in session.scalars(
                    select(dbm.User)
                    .join(dbm.Tenant, dbm.Tenant.id == dbm.User.tenant_id)
                    .where(dbm.Tenant.key == tenant)
                ).all()
            }
            # Both counted from the audit trail rather than current state: an
            # incident that was closed and then reopened still *happened*, and
            # judging the reopen rate against rows that are closed right now
            # makes the denominator shrink exactly when it matters.
            terminal = [
                IncidentStatus.RESOLVED.value,
                IncidentStatus.CLOSED_FALSE_POSITIVE.value,
            ]
            reopened = (
                session.scalar(
                    select(func.count())
                    .select_from(dbm.AuditLog)
                    .where(
                        dbm.AuditLog.tenant == tenant,
                        dbm.AuditLog.action == "incident.status_changed",
                        dbm.AuditLog.created_at >= since,
                        dbm.AuditLog.data["from_status"].as_string().in_(terminal),
                    )
                )
                or 0
            )
            analyst_closures = (
                session.scalar(
                    select(func.count())
                    .select_from(dbm.AuditLog)
                    .where(
                        dbm.AuditLog.tenant == tenant,
                        dbm.AuditLog.action == "incident.status_changed",
                        dbm.AuditLog.created_at >= since,
                        dbm.AuditLog.data["to_status"].as_string().in_(terminal),
                    )
                )
                or 0
            )

        ack_samples: List[float] = []
        resolve_by_disposition: Dict[str, List[float]] = {"resolved": [], "false_positive": []}
        detect_samples: List[float] = []
        per_team: Dict[str, Dict[str, List[float]]] = {}
        per_analyst: Dict[str, Dict[str, List[float]]] = {}
        closed = 0
        sla_ack_met = sla_ack_total = 0
        sla_resolve_met = sla_resolve_total = 0

        for row in rows:
            ack = _seconds(row.created_at, row.acknowledged_at)
            if ack is not None:
                ack_samples.append(ack)

            detect = _seconds(row.first_seen, row.created_at)
            if detect is not None:
                detect_samples.append(detect)

            resolution = _seconds(row.created_at, row.closed_at)
            if resolution is not None:
                closed += 1
                bucket = (
                    "false_positive"
                    if row.status == IncidentStatus.CLOSED_FALSE_POSITIVE.value
                    else "resolved"
                )
                resolve_by_disposition[bucket].append(resolution)

            # SLA attainment, judged the same way the dashboard judges a chip.
            if row.sla_ack_due is not None:
                clock = evaluate_clock(
                    "acknowledge", row.sla_ack_due, row.acknowledged_at, row.created_at, now=now
                )
                sla_ack_total += 1
                sla_ack_met += clock.state != STATE_BREACHED
            if row.sla_resolve_due is not None:
                clock = evaluate_clock(
                    "resolve", row.sla_resolve_due, row.closed_at, row.created_at, now=now
                )
                sla_resolve_total += 1
                sla_resolve_met += clock.state != STATE_BREACHED

            if row.team_id:
                slot = per_team.setdefault(row.team_id, {"ack": [], "resolve": []})
                if ack is not None:
                    slot["ack"].append(ack)
                if resolution is not None:
                    slot["resolve"].append(resolution)
            if row.assignee_id:
                slot = per_analyst.setdefault(row.assignee_id, {"ack": [], "resolve": []})
                if ack is not None:
                    slot["ack"].append(ack)
                if resolution is not None:
                    slot["resolve"].append(resolution)

        return {
            "window_days": days,
            "since": since.isoformat(),
            "incidents_opened": len(rows),
            "mttd": _summarise(detect_samples),
            "mtta": _summarise(ack_samples),
            "mttr": {
                "resolved": _summarise(resolve_by_disposition["resolved"]),
                "false_positive": _summarise(resolve_by_disposition["false_positive"]),
                "combined": _summarise(
                    resolve_by_disposition["resolved"] + resolve_by_disposition["false_positive"]
                ),
            },
            "sla": {
                "acknowledge": _attainment(sla_ack_met, sla_ack_total),
                "resolve": _attainment(sla_resolve_met, sla_resolve_total),
            },
            # Closed right now (includes correlator supersession).
            "incidents_closed": closed,
            # Human close actions in the window - the reopen-rate denominator.
            "analyst_closures": analyst_closures,
            "reopened": reopened,
            "reopen_rate": (round(reopened / analyst_closures, 3) if analyst_closures else None),
            "queues": self._queue_ages(open_rows, teams, now),
            "by_team": [
                {
                    "team": teams[team_id].slug if team_id in teams else team_id,
                    "name": teams[team_id].name if team_id in teams else None,
                    "mtta": _summarise(values["ack"]),
                    "mttr": _summarise(values["resolve"]),
                }
                for team_id, values in sorted(
                    per_team.items(), key=lambda kv: -len(kv[1]["ack"] or kv[1]["resolve"])
                )
            ],
            "by_analyst": [
                {
                    "analyst": users[user_id].email if user_id in users else user_id,
                    "mtta": _summarise(values["ack"]),
                    "mttr": _summarise(values["resolve"]),
                }
                for user_id, values in sorted(
                    per_analyst.items(), key=lambda kv: -len(kv[1]["ack"] or kv[1]["resolve"])
                )
            ],
        }

    @staticmethod
    def _queue_ages(
        open_rows: Sequence[Any], teams: Dict[str, Any], now: datetime
    ) -> List[Dict[str, Any]]:
        buckets: Dict[Optional[str], Dict[str, Any]] = {}
        for row in open_rows:
            slot = buckets.setdefault(
                row.team_id,
                {"open": 0, "unclaimed": 0, "oldest_unclaimed_seconds": None},
            )
            slot["open"] += 1
            if row.assignee_id is None:
                slot["unclaimed"] += 1
                age = _seconds(row.created_at, now)
                if age is not None and (
                    slot["oldest_unclaimed_seconds"] is None
                    or age > slot["oldest_unclaimed_seconds"]
                ):
                    slot["oldest_unclaimed_seconds"] = round(age, 1)

        result = []
        for team_id, slot in buckets.items():
            team = teams.get(team_id) if team_id else None
            result.append(
                {
                    "team": team.slug if team else "unrouted",
                    "name": team.name if team else None,
                    **slot,
                }
            )
        # Worst queue first: the oldest unclaimed item is the thing to act on.
        result.sort(key=lambda item: item["oldest_unclaimed_seconds"] or -1, reverse=True)
        return result


def _attainment(met: int, total: int) -> Dict[str, Any]:
    return {
        "met": met,
        "total": total,
        "breached": total - met,
        "attainment": round(met / total, 3) if total else None,
    }
