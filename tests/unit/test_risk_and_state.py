"""The risk model, ATT&CK helpers and sliding-window state."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from signalforge.attack import kill_chain, sort_tactics, tactic_name, technique_name
from signalforge.correlate.risk import (
    CONTEXT_CEILING,
    ContextSignals,
    build_context,
    risk_level,
    score_alert,
    score_incident,
    severity_for_level,
)
from signalforge.detect.state import SlidingWindow, SuppressionCache, WindowEntry, WindowStore
from signalforge.models.alert import Alert
from signalforge.models.ocsf import RawLogRecord
from signalforge.normalize import normalize

NOW = datetime(2026, 9, 10, 13, 40, tzinfo=timezone.utc)


# ------------------------------------------------------------------- bands ---
@pytest.mark.parametrize(
    ("score", "band"),
    [
        (0, "informational"),
        (29, "informational"),
        (30, "low"),
        (49, "low"),
        (50, "medium"),
        (69, "medium"),
        (70, "high"),
        (89, "high"),
        (90, "critical"),
        (100, "critical"),
    ],
)
def test_risk_bands(score: int, band: str) -> None:
    assert risk_level(score) == band


def test_severity_from_rule_level() -> None:
    assert severity_for_level("critical") == 10
    assert severity_for_level("medium") == 5
    assert severity_for_level("informational") == 1


# ------------------------------------------------------------- alert scores ---
def test_documented_worked_example() -> None:
    """The README's "unusual administrator login" must stay reproducible."""
    assessment = score_alert(severity=8, confidence=9, asset_criticality=9)
    assert assessment.score == 87
    assert assessment.level == "high"
    assert assessment.components["base"] == pytest.approx(86.5, abs=0.2)


def test_aggravating_context_moves_up_but_cannot_dominate() -> None:
    plain = score_alert(severity=8, confidence=9, asset_criticality=9).score
    with_context = score_alert(
        severity=8,
        confidence=9,
        asset_criticality=9,
        context=ContextSignals().add("external_source").add("no_mfa"),
    ).score
    assert with_context > plain

    # A weak detection stays out of the top band no matter how bad the context.
    weak = score_alert(
        severity=3,
        confidence=4,
        asset_criticality=3,
        context=ContextSignals()
        .add("external_source")
        .add("known_malicious_indicator")
        .add("no_mfa")
        .add("off_hours")
        .add("privileged_target"),
    )
    assert weak.score < 70


def test_mitigating_context_deflates_and_suppresses() -> None:
    context = ContextSignals().add("load_test_account")
    assert context.suppressing
    assert context.modifier < 1
    assert score_alert(severity=5, confidence=8, asset_criticality=5, context=context).score < 30


def test_context_modifier_is_clamped() -> None:
    context = ContextSignals()
    for signal in (
        "external_source",
        "known_malicious_indicator",
        "anonymizing_infrastructure",
        "no_mfa",
        "off_hours",
        "privileged_target",
        "critical_asset_touched",
        "first_seen_source",
    ):
        context.add(signal)
    assert context.modifier == pytest.approx(CONTEXT_CEILING)


def test_unknown_context_signals_are_ignored() -> None:
    context = ContextSignals().add("definitely_not_a_signal")
    assert context.signals == []
    assert context.modifier == 1.0


def test_scores_are_monotonic_in_every_factor() -> None:
    base = score_alert(severity=5, confidence=5, asset_criticality=5).score
    assert score_alert(severity=8, confidence=5, asset_criticality=5).score > base
    assert score_alert(severity=5, confidence=8, asset_criticality=5).score > base
    assert score_alert(severity=5, confidence=5, asset_criticality=8).score > base


def test_out_of_range_factors_are_clamped() -> None:
    assert score_alert(severity=99, confidence=99, asset_criticality=99).score <= 100
    assert score_alert(severity=0, confidence=0, asset_criticality=0).score >= 0


# ---------------------------------------------------------- incident scores ---
def build_chain() -> list:
    return [
        Alert(
            rule_id="r1",
            rule_title="Repeated failures",
            risk_score=15,
            tactics=["credential_access"],
        ),
        Alert(
            rule_id="r2",
            rule_title="Success after failures",
            risk_score=40,
            tactics=["initial_access"],
        ),
        Alert(
            rule_id="r3",
            rule_title="Privilege grant",
            risk_score=68,
            tactics=["privilege_escalation"],
        ),
        Alert(
            rule_id="r4", rule_title="Credential created", risk_score=76, tactics=["persistence"]
        ),
    ]


def test_incident_score_escalates_with_the_chain() -> None:
    chain = build_chain()
    scores = [
        score_incident(chain[:n], scenario_complete=(n == 4), intel_hit=(n >= 3)).score
        for n in range(1, 5)
    ]
    assert scores == sorted(scores)
    assert scores[0] == 15
    assert scores[-1] >= 85
    assert risk_level(scores[-1]) in {"high", "critical"}


def test_incident_score_never_exceeds_one_hundred() -> None:
    alerts = [
        Alert(rule_id="r%d" % index, rule_title="t", risk_score=95, tactics=["impact"])
        for index in range(10)
    ]
    score = score_incident(alerts, scenario_complete=True, intel_hit=True).score
    # Bonuses close the remaining gap to 100 proportionally, so a long chain of
    # already-critical alerts approaches the ceiling without ever passing it.
    assert 95 <= score <= 100


def test_empty_incident_scores_zero() -> None:
    assessment = score_incident([])
    assert assessment.score == 0
    assert assessment.level == "informational"


def test_incident_factors_explain_the_score() -> None:
    assessment = score_incident(build_chain(), scenario_complete=True, intel_hit=True)
    joined = " ".join(assessment.factors)
    assert "correlated stages" in joined
    assert "ATT&CK tactics" in joined
    assert "threat-intel" in joined
    assert assessment.components["distinct_rules"] == 4


# ------------------------------------------------------------------ context ---
def test_context_is_derived_from_the_event() -> None:
    event = normalize(
        RawLogRecord(
            source="linux.sshd",
            tenant="acme",
            raw="Sep 10 13:41:02 web-01 sshd[1]: Failed password for alex from 185.220.101.7 port 1 ssh2",
        )
    )
    context = build_context(
        event,
        internal_networks=["10.0.0.0/8"],
        intel_verdict="malicious",
        now=NOW,
    )
    assert "external_source" in context.signals
    assert "known_malicious_indicator" in context.signals
    assert context.modifier > 1


def test_internal_addresses_are_not_flagged_external() -> None:
    event = normalize(
        RawLogRecord(
            source="linux.sshd",
            raw="Sep 10 13:41:02 web-01 sshd[1]: Failed password for alex from 10.0.4.82 port 1 ssh2",
        )
    )
    context = build_context(event, internal_networks=["10.0.0.0/8"], now=NOW)
    assert "external_source" not in context.signals


def test_off_hours_is_detected() -> None:
    event = normalize(
        RawLogRecord(
            source="linux.sshd",
            raw="Sep 10 03:12:00 web-01 sshd[1]: Failed password for alex from 10.0.4.82 port 1 ssh2",
        )
    )
    context = build_context(
        event,
        internal_networks=["10.0.0.0/8"],
        now=datetime(2026, 9, 10, 3, 12, tzinfo=timezone.utc),
    )
    assert "off_hours" in context.signals


def test_load_test_account_is_recognised_from_the_inventory() -> None:
    event = normalize(
        RawLogRecord(
            source="linux.sshd",
            raw="Sep 10 13:41:02 web-01 sshd[1]: Failed password for loadtest from 10.0.9.11 port 1 ssh2",
        )
    )
    assert build_context(event, now=NOW).suppressing


# ------------------------------------------------------------------- ATT&CK ---
def test_tactics_sort_into_kill_chain_order() -> None:
    ordered = sort_tactics(["persistence", "credential_access", "initial_access"])
    assert ordered == ["initial_access", "persistence", "credential_access"]
    assert [step["name"] for step in kill_chain(["persistence", "initial_access"])] == [
        "Initial Access",
        "Persistence",
    ]


def test_attack_names() -> None:
    assert tactic_name("credential_access") == "Credential Access"
    assert technique_name("t1110.001") == "Brute Force: Password Guessing"
    assert technique_name("T9999") == "T9999"  # unknown ids pass through


# ------------------------------------------------------------------ windows ---
def test_sliding_window_expires_by_time() -> None:
    window = SlidingWindow(timespan=300)
    for index in range(5):
        window.add(WindowEntry(time=NOW + timedelta(seconds=index * 30), ref="e%d" % index))
    assert window.count(NOW + timedelta(seconds=120)) == 5
    # Ten minutes later everything has aged out.
    assert window.count(NOW + timedelta(seconds=900)) == 0


def test_sliding_window_keeps_time_order_for_late_arrivals() -> None:
    window = SlidingWindow(timespan=600)
    window.add(WindowEntry(time=NOW + timedelta(seconds=60), ref="late-second"))
    window.add(WindowEntry(time=NOW, ref="late-first"))
    assert [entry.ref for entry in window.entries(NOW + timedelta(seconds=90))] == [
        "late-first",
        "late-second",
    ]


def test_sliding_window_distinct_counts_values() -> None:
    window = SlidingWindow(timespan=3600)
    for country in ("US", "US", "NL"):
        window.add(WindowEntry(time=NOW, ref="e", value=country))
    assert window.count(NOW) == 3
    assert window.distinct(NOW) == 2


def test_window_store_sweeps_expired_keys() -> None:
    store = WindowStore(default_timespan=60)
    store.window(("rule", "acme", "alex")).add(WindowEntry(time=NOW, ref="e1"))
    assert store.size == 1
    assert store.sweep(NOW + timedelta(seconds=600)) == 1
    assert store.size == 0


def test_suppression_cache_respects_its_ttl() -> None:
    cache = SuppressionCache(ttl_seconds=300)
    key = ("rule", "acme", "alex")
    assert cache.seen(key, NOW) is False  # first time records it
    assert cache.seen(key, NOW + timedelta(seconds=60)) is True
    assert cache.seen(key, NOW + timedelta(seconds=600)) is False
    cache.forget(key)
    assert cache.seen(key, NOW + timedelta(seconds=601)) is False
