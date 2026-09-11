"""Incident case management: dedup, state machine, timeline and audit trail."""

from .manager import (
    SINGLE_ALERT_INCIDENT_THRESHOLD,
    IncidentError,
    IncidentManager,
)

__all__ = [
    "SINGLE_ALERT_INCIDENT_THRESHOLD",
    "IncidentError",
    "IncidentManager",
]
