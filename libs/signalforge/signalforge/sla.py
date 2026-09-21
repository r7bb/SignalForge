"""Service-level targets: the two clocks every incident runs against.

``acknowledge`` is the time until a person claims it, ``resolve`` the time
until it reaches a terminal state. Both start when the incident opens, and both
are per-severity policy read from ``schemas/sla.yml`` rather than constants in
the code - they are the numbers a SOC is judged on, so they belong in git where
a change to them is reviewable.

Breach is **derived, never stored as a flag**. A stored boolean is wrong the
moment the clock passes and nothing has run to update it; computing it from the
due time and the timestamps means the answer is right whenever it is asked.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

logger = logging.getLogger("signalforge.sla")

DEFAULT_WARN_AT = 0.75

#: Used when no policy file is present, so a deployment without one still gets
#: sensible clocks rather than none at all.
BUILTIN_TARGETS: Dict[str, Dict[str, Optional[int]]] = {
    "critical": {"acknowledge_minutes": 15, "resolve_minutes": 240},
    "high": {"acknowledge_minutes": 60, "resolve_minutes": 480},
    "medium": {"acknowledge_minutes": 240, "resolve_minutes": 1440},
    "low": {"acknowledge_minutes": 1440, "resolve_minutes": 10080},
    "informational": {"acknowledge_minutes": None, "resolve_minutes": None},
}

#: The three states a clock can be in.
STATE_OK = "ok"
STATE_AT_RISK = "at_risk"
STATE_BREACHED = "breached"
STATE_MET = "met"  # a finished clock that came in under its target
STATE_NONE = "none"  # no target for this severity


@dataclass(frozen=True)
class SlaTarget:
    severity: str
    acknowledge_minutes: Optional[int]
    resolve_minutes: Optional[int]

    @property
    def has_targets(self) -> bool:
        return self.acknowledge_minutes is not None or self.resolve_minutes is not None


@dataclass(frozen=True)
class SlaPolicy:
    targets: Dict[str, SlaTarget]
    warn_at: float = DEFAULT_WARN_AT
    source_path: Optional[str] = None

    def target_for(self, severity: Any) -> SlaTarget:
        key = str(getattr(severity, "value", severity) or "medium").lower()
        return self.targets.get(key) or SlaTarget(key, None, None)

    def due_times(
        self, severity: Any, opened_at: datetime
    ) -> tuple[Optional[datetime], Optional[datetime]]:
        """``(acknowledge_due, resolve_due)`` for an incident opening now."""
        target = self.target_for(severity)
        ack = (
            opened_at + timedelta(minutes=target.acknowledge_minutes)
            if target.acknowledge_minutes is not None
            else None
        )
        resolve = (
            opened_at + timedelta(minutes=target.resolve_minutes)
            if target.resolve_minutes is not None
            else None
        )
        return ack, resolve


@dataclass(frozen=True)
class ClockState:
    """Where one clock stands right now."""

    name: str  # acknowledge | resolve
    due_at: Optional[datetime]
    completed_at: Optional[datetime]
    state: str
    seconds_remaining: Optional[int] = None
    seconds_over: Optional[int] = None

    @property
    def breached(self) -> bool:
        return self.state == STATE_BREACHED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "due_at": self.due_at.isoformat() if self.due_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "state": self.state,
            "seconds_remaining": self.seconds_remaining,
            "seconds_over": self.seconds_over,
        }


def evaluate_clock(
    name: str,
    due_at: Optional[datetime],
    completed_at: Optional[datetime],
    opened_at: Optional[datetime] = None,
    *,
    now: Optional[datetime] = None,
    warn_at: float = DEFAULT_WARN_AT,
) -> ClockState:
    """Classify one clock.

    A finished clock is judged against when it finished, not against now - an
    incident acknowledged inside its window stays *met* forever, rather than
    turning into a breach the moment the window passes.
    """
    now = now or datetime.now(tz=timezone.utc)
    if due_at is None:
        return ClockState(name=name, due_at=None, completed_at=completed_at, state=STATE_NONE)

    due_at = _as_utc(due_at)
    if completed_at is not None:
        completed_at = _as_utc(completed_at)
        if completed_at <= due_at:
            return ClockState(
                name=name,
                due_at=due_at,
                completed_at=completed_at,
                state=STATE_MET,
                seconds_remaining=int((due_at - completed_at).total_seconds()),
            )
        return ClockState(
            name=name,
            due_at=due_at,
            completed_at=completed_at,
            state=STATE_BREACHED,
            seconds_over=int((completed_at - due_at).total_seconds()),
        )

    if now > due_at:
        return ClockState(
            name=name,
            due_at=due_at,
            completed_at=None,
            state=STATE_BREACHED,
            seconds_over=int((now - due_at).total_seconds()),
        )

    remaining = int((due_at - now).total_seconds())
    state = STATE_OK
    if opened_at is not None:
        opened_at = _as_utc(opened_at)
        window = (due_at - opened_at).total_seconds()
        if window > 0 and (now - opened_at).total_seconds() / window >= warn_at:
            state = STATE_AT_RISK
    return ClockState(
        name=name,
        due_at=due_at,
        completed_at=None,
        state=state,
        seconds_remaining=remaining,
    )


def evaluate_incident(
    incident: Any, *, policy: Optional[SlaPolicy] = None, now: Optional[datetime] = None
) -> Dict[str, Any]:
    """Both clocks for an incident, plus a single headline state."""
    policy = policy or load_policy()
    opened_at = getattr(incident, "created_at", None) or getattr(incident, "first_seen", None)

    acknowledge = evaluate_clock(
        "acknowledge",
        getattr(incident, "sla_ack_due", None),
        getattr(incident, "acknowledged_at", None),
        opened_at,
        now=now,
        warn_at=policy.warn_at,
    )
    resolve = evaluate_clock(
        "resolve",
        getattr(incident, "sla_resolve_due", None),
        getattr(incident, "closed_at", None),
        opened_at,
        now=now,
        warn_at=policy.warn_at,
    )

    # The worst of the two is what an analyst needs to see on a queue row.
    ranking = {STATE_BREACHED: 3, STATE_AT_RISK: 2, STATE_OK: 1, STATE_MET: 0, STATE_NONE: -1}
    headline = max((acknowledge, resolve), key=lambda clock: ranking[clock.state])

    return {
        "state": headline.state,
        "acknowledge": acknowledge.to_dict(),
        "resolve": resolve.to_dict(),
        "breached": acknowledge.breached or resolve.breached,
    }


def load_policy(path: Optional[str] = None) -> SlaPolicy:
    """Read the policy file, falling back to the built-in targets."""
    if path is None:
        from .config import get_settings

        path = get_settings().sla_path
    return _load_cached(str(path))


@lru_cache(maxsize=8)
def _load_cached(path: str) -> SlaPolicy:
    file_path = Path(path)
    if not file_path.exists():
        logger.info("no SLA policy file; using built-in targets", extra={"path": path})
        return SlaPolicy(targets=_build_targets(BUILTIN_TARGETS))

    try:
        document = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        logger.warning("SLA policy is not valid YAML; using built-in targets", extra={"path": path})
        return SlaPolicy(targets=_build_targets(BUILTIN_TARGETS))

    raw_targets = document.get("targets") or {}
    merged = {**BUILTIN_TARGETS}
    for severity, values in raw_targets.items():
        if isinstance(values, dict):
            merged[str(severity).lower()] = values

    warn_at = (document.get("defaults") or {}).get("warn_at", DEFAULT_WARN_AT)
    try:
        warn_at = float(warn_at)
    except (TypeError, ValueError):
        warn_at = DEFAULT_WARN_AT
    warn_at = min(max(warn_at, 0.0), 1.0)

    return SlaPolicy(targets=_build_targets(merged), warn_at=warn_at, source_path=str(file_path))


def reset_policy_cache() -> None:
    """Test helper - drop the cached policy."""
    _load_cached.cache_clear()


def _build_targets(raw: Dict[str, Dict[str, Optional[int]]]) -> Dict[str, SlaTarget]:
    targets: Dict[str, SlaTarget] = {}
    for severity, values in raw.items():
        targets[severity] = SlaTarget(
            severity=severity,
            acknowledge_minutes=_positive_int(values.get("acknowledge_minutes")),
            resolve_minutes=_positive_int(values.get("resolve_minutes")),
        )
    return targets


def _positive_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
