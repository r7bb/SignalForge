"""Incident case management: dedup, state machine, timeline and audit trail."""

from .manager import (
    SINGLE_ALERT_INCIDENT_THRESHOLD,
    IncidentConflict,
    IncidentError,
    IncidentManager,
    IncidentPermissionError,
)
from .metrics import SocMetrics
from .presence import PresenceTracker, Viewer
from .teams import TeamError, TeamService

__all__ = [
    "SINGLE_ALERT_INCIDENT_THRESHOLD",
    "IncidentConflict",
    "IncidentError",
    "IncidentManager",
    "IncidentPermissionError",
    "PresenceTracker",
    "SocMetrics",
    "TeamError",
    "TeamService",
    "Viewer",
]
