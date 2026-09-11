"""Correlation and risk scoring."""

from .engine import CorrelationEngine, CorrelationHit, CorrelationStats, group_value
from .risk import (
    RISK_BANDS,
    ContextSignals,
    RiskAssessment,
    build_context,
    risk_level,
    score_alert,
    score_incident,
    severity_for_level,
)

__all__ = [
    "RISK_BANDS",
    "ContextSignals",
    "CorrelationEngine",
    "CorrelationHit",
    "CorrelationStats",
    "RiskAssessment",
    "build_context",
    "group_value",
    "risk_level",
    "score_alert",
    "score_incident",
    "severity_for_level",
]
