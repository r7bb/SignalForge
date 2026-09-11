"""Risk scoring.

**This is SignalForge's own experimental model, not an industry standard.**

An alert's score is the geometric mean of three 1-10 factors, scaled to 0-100
and then adjusted by a bounded behavioural-context modifier::

    base  = 100 * (severity/10 * confidence/10 * asset_criticality/10) ** (1/3)

    score = base + (100 - base) * (modifier - 1) / (CEILING - 1)   if modifier >= 1
          = base * modifier                                         otherwise

The geometric mean is used deliberately: a single weak factor (say, a detection
with low confidence) pulls the score down without any one factor being able to
dominate, and a rule that is severe *and* confident *and* pointed at a critical
asset is what actually reaches the top band.

Aggravating context consumes the *remaining headroom* to 100 rather than
multiplying the score, so context can always push an alert up the bands but can
never on its own make a mediocre detection critical.  Mitigating context (a
load-test account, a maintenance window) multiplies, because there the intent is
to genuinely deflate the score.

Incidents are scored from the alerts correlated into them using the same
headroom idea - a chain of related behaviour is stronger evidence than its
parts, and each additional stage closes part of the gap to 100::

    bonuses = chain_bonus + breadth_bonus + intel_bonus + scenario_complete_bonus
    score   = max_alert_score + (100 - max_alert_score) * bonuses / 100

Bands: 0-29 informational, 30-49 low, 50-69 medium, 70-89 high, 90-100 critical.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from ..assets import AssetInventory, get_inventory
from ..models.alert import LEVEL_SEVERITY, Alert
from ..models.ocsf import OcsfEvent

#: Lower bound -> band name.
RISK_BANDS = (
    (90, "critical"),
    (70, "high"),
    (50, "medium"),
    (30, "low"),
    (0, "informational"),
)

#: Multiplicative context modifiers, applied to the base score.
CONTEXT_WEIGHTS: Dict[str, float] = {
    "external_source": 1.10,
    "known_malicious_indicator": 1.30,
    "anonymizing_infrastructure": 1.20,
    "no_mfa": 1.10,
    "off_hours": 1.05,
    "privileged_target": 1.15,
    "critical_asset_touched": 1.15,
    "first_seen_source": 1.10,
    "service_account": 0.85,
    "load_test_account": 0.40,
    "known_maintenance_window": 0.70,
}

#: The context multiplier is clamped so no single signal can swamp the model.
CONTEXT_FLOOR = 0.35
CONTEXT_CEILING = 1.60

#: Aggravating context can move an alert by at most this many points.  Without
#: the cap, maximal context would carry *any* base score to 100, which would let
#: a weak detection in a bad neighbourhood outrank a strong one.
CONTEXT_MAX_UPLIFT = 25.0

CHAIN_BONUS_PER_STAGE = 6  # each extra correlated alert in the chain
BREADTH_BONUS_PER_TACTIC = 5  # each extra ATT&CK tactic observed
INTEL_BONUS = 8  # a confirmed malicious indicator in the chain
CHAIN_COMPLETE_BONUS = 10  # the full scenario sequence was observed


def risk_level(score: int) -> str:
    for threshold, name in RISK_BANDS:
        if score >= threshold:
            return name
    return "informational"


def clamp(value: float, low: float = 0, high: float = 100) -> int:
    return int(max(low, min(high, round(value))))


def apply_modifier(base: float, modifier: float) -> float:
    """Aggravating context fills headroom (capped); mitigating context multiplies."""
    if modifier >= 1.0:
        share = (modifier - 1.0) / (CONTEXT_CEILING - 1.0)
        uplift = min((100.0 - base) * share, CONTEXT_MAX_UPLIFT * share)
        return base + uplift
    return base * modifier


@dataclass
class ContextSignals:
    """Behavioural context around an alert, gathered by the detection engine."""

    signals: List[str] = field(default_factory=list)

    def add(self, name: str, present: bool = True) -> ContextSignals:
        if present and name in CONTEXT_WEIGHTS and name not in self.signals:
            self.signals.append(name)
        return self

    @property
    def modifier(self) -> float:
        modifier = 1.0
        for signal in self.signals:
            modifier *= CONTEXT_WEIGHTS[signal]
        return max(CONTEXT_FLOOR, min(CONTEXT_CEILING, modifier))

    @property
    def suppressing(self) -> bool:
        """True when context says this is almost certainly benign."""
        return "load_test_account" in self.signals or "known_maintenance_window" in self.signals

    def describe(self) -> List[str]:
        return [
            "%s (x%.2f)" % (signal.replace("_", " "), CONTEXT_WEIGHTS[signal])
            for signal in self.signals
        ]


@dataclass
class RiskAssessment:
    score: int
    level: str
    factors: List[str] = field(default_factory=list)
    components: Dict[str, Any] = field(default_factory=dict)


def score_alert(
    *,
    severity: int,
    confidence: int,
    asset_criticality: int,
    context: Optional[ContextSignals] = None,
) -> RiskAssessment:
    """Score a single alert on the 0-100 scale."""
    severity = max(1, min(10, severity))
    confidence = max(1, min(10, confidence))
    asset_criticality = max(1, min(10, asset_criticality))
    context = context or ContextSignals()

    product = (severity / 10.0) * (confidence / 10.0) * (asset_criticality / 10.0)
    base = 100.0 * (product ** (1.0 / 3.0))
    modifier = context.modifier
    score = clamp(apply_modifier(base, modifier))
    return RiskAssessment(
        score=score,
        level=risk_level(score),
        factors=[
            "severity %d/10" % severity,
            "confidence %d/10" % confidence,
            "asset criticality %d/10" % asset_criticality,
            *context.describe(),
        ],
        components={
            "severity": severity,
            "confidence": confidence,
            "asset_criticality": asset_criticality,
            "base": round(base, 1),
            "context_modifier": round(modifier, 3),
        },
    )


def severity_for_level(level: str) -> int:
    return LEVEL_SEVERITY.get(level.lower(), 5)


def build_context(
    event: OcsfEvent,
    *,
    inventory: Optional[AssetInventory] = None,
    internal_networks: Sequence[str] = (),
    intel_verdict: Optional[str] = None,
    now: Optional[datetime] = None,
) -> ContextSignals:
    """Derive context signals for an alert from its triggering event."""
    import ipaddress

    inventory = inventory or get_inventory()
    context = ContextSignals()
    principal = event.principal

    source_ip = event.source_ip
    if source_ip:
        try:
            address = ipaddress.ip_address(source_ip)
            internal = any(
                address in ipaddress.ip_network(network, strict=False)
                for network in internal_networks
            )
            context.add("external_source", not internal)
        except ValueError:
            pass
    if intel_verdict in {"malicious", "known_bad"}:
        context.add("known_malicious_indicator")
    elif intel_verdict in {"anonymizer", "tor", "proxy", "vpn"}:
        context.add("anonymizing_infrastructure")

    if event.class_uid == 3002 and event.is_failure is False and event.is_mfa is False:
        context.add("no_mfa")

    reference = now or event.time
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    if reference.hour < 6 or reference.hour >= 22 or reference.weekday() >= 5:
        context.add("off_hours")

    target = event.target_principal or principal
    if (event.user and (event.user.type or "").lower() == "admin") or (
        event.group and (event.group.type or "").lower() == "privileged"
    ):
        context.add("privileged_target")
    if (
        inventory.user_level(target) == "critical"
        or inventory.host_level(event.hostname) == "critical"
    ):
        context.add("critical_asset_touched")
    if any((resource.criticality or "").lower() == "critical" for resource in event.resources):
        context.add("critical_asset_touched")

    if inventory.is_service_account(principal):
        context.add("service_account")
    if inventory.is_load_test_account(principal):
        context.add("load_test_account")
    return context


def score_incident(
    alerts: Sequence[Alert],
    *,
    scenario_complete: bool = False,
    intel_hit: bool = False,
) -> RiskAssessment:
    """Score an incident from the alerts correlated into it."""
    if not alerts:
        return RiskAssessment(score=0, level="informational")

    scores = sorted((alert.risk_score for alert in alerts), reverse=True)
    tactics = {tactic for alert in alerts for tactic in alert.tactics}
    distinct_rules = {alert.rule_id for alert in alerts}

    chain_bonus = CHAIN_BONUS_PER_STAGE * max(0, len(distinct_rules) - 1)
    breadth_bonus = BREADTH_BONUS_PER_TACTIC * max(0, len(tactics) - 1)
    intel_bonus = INTEL_BONUS if intel_hit else 0
    complete_bonus = CHAIN_COMPLETE_BONUS if scenario_complete else 0

    bonuses = chain_bonus + breadth_bonus + intel_bonus + complete_bonus
    # Bonuses close part of the remaining distance to 100, so more corroborating
    # evidence always raises the score without every long chain hitting 100.
    score = clamp(scores[0] + (100.0 - scores[0]) * bonuses / 100.0)
    factors = ["highest alert %d/100" % scores[0]]
    if chain_bonus:
        factors.append(
            "+%d correlated stages (%d distinct detections)" % (chain_bonus, len(distinct_rules))
        )
    if breadth_bonus:
        factors.append("+%d ATT&CK tactics observed (%d)" % (breadth_bonus, len(tactics)))
    if intel_bonus:
        factors.append("+%d threat-intel match" % intel_bonus)
    if complete_bonus:
        factors.append("+%d full scenario sequence observed" % complete_bonus)
    return RiskAssessment(
        score=score,
        level=risk_level(score),
        factors=factors,
        components={
            "alert_scores": scores,
            "distinct_rules": len(distinct_rules),
            "tactics": sorted(tactics),
            "chain_bonus": chain_bonus,
            "breadth_bonus": breadth_bonus,
            "intel_bonus": intel_bonus,
            "scenario_complete_bonus": complete_bonus,
        },
    )
