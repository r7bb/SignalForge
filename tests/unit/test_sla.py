"""SLA clock semantics.

The behaviour worth pinning down is that a *finished* clock is judged against
when it finished, not against now - otherwise an incident acknowledged well
inside its window silently becomes a breach once the window passes.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from signalforge.sla import (
    BUILTIN_TARGETS,
    STATE_AT_RISK,
    STATE_BREACHED,
    STATE_MET,
    STATE_NONE,
    STATE_OK,
    SlaPolicy,
    SlaTarget,
    evaluate_clock,
    evaluate_incident,
    load_policy,
    reset_policy_cache,
)

OPENED = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)


def at(minutes: int) -> datetime:
    return OPENED + timedelta(minutes=minutes)


# --------------------------------------------------------------- one clock
def test_no_target_means_no_clock() -> None:
    state = evaluate_clock("acknowledge", None, None, OPENED, now=at(999))
    assert state.state == STATE_NONE and not state.breached


def test_an_unfinished_clock_inside_its_window_is_ok() -> None:
    state = evaluate_clock("acknowledge", at(60), None, OPENED, now=at(10))
    assert state.state == STATE_OK
    assert state.seconds_remaining == 50 * 60


def test_it_turns_at_risk_near_the_deadline() -> None:
    # warn_at 0.75 of a 60 minute window -> at risk from minute 45.
    assert evaluate_clock("acknowledge", at(60), None, OPENED, now=at(44)).state == STATE_OK
    assert evaluate_clock("acknowledge", at(60), None, OPENED, now=at(45)).state == STATE_AT_RISK
    assert evaluate_clock("acknowledge", at(60), None, OPENED, now=at(59)).state == STATE_AT_RISK


def test_an_unfinished_clock_past_its_deadline_is_breached() -> None:
    state = evaluate_clock("acknowledge", at(60), None, OPENED, now=at(75))
    assert state.state == STATE_BREACHED and state.breached
    assert state.seconds_over == 15 * 60


def test_a_clock_finished_inside_its_window_stays_met_forever() -> None:
    """The regression this guards: judged on completion, not on now."""
    completed = at(30)
    for observation in (at(31), at(120), at(10_000)):
        state = evaluate_clock("acknowledge", at(60), completed, OPENED, now=observation)
        assert state.state == STATE_MET, "met at %s" % observation
        assert not state.breached


def test_a_clock_finished_late_is_breached_by_how_much() -> None:
    state = evaluate_clock("resolve", at(60), at(90), OPENED, now=at(1000))
    assert state.state == STATE_BREACHED
    assert state.seconds_over == 30 * 60


def test_naive_timestamps_are_treated_as_utc() -> None:
    """SQLite hands back naive datetimes; comparing one to an aware now raises."""
    naive_due = at(60).replace(tzinfo=None)
    state = evaluate_clock("acknowledge", naive_due, None, OPENED, now=at(10))
    assert state.state == STATE_OK


# ------------------------------------------------------------- both clocks
class FakeIncident:
    def __init__(self, **kwargs) -> None:
        self.created_at = OPENED
        self.severity = "high"
        self.acknowledged_at = None
        self.closed_at = None
        self.sla_ack_due = at(60)
        self.sla_resolve_due = at(480)
        for key, value in kwargs.items():
            setattr(self, key, value)


def test_the_headline_state_is_the_worse_of_the_two_clocks() -> None:
    # Acknowledged in time, but the resolve clock has blown.
    incident = FakeIncident(acknowledged_at=at(10))
    state = evaluate_incident(incident, now=at(600))
    assert state["acknowledge"]["state"] == STATE_MET
    assert state["resolve"]["state"] == STATE_BREACHED
    assert state["state"] == STATE_BREACHED
    assert state["breached"] is True


def test_both_clocks_healthy_reports_ok() -> None:
    state = evaluate_incident(FakeIncident(), now=at(5))
    assert state["state"] == STATE_OK and state["breached"] is False


def test_a_closed_incident_that_met_both_is_not_breached() -> None:
    incident = FakeIncident(acknowledged_at=at(5), closed_at=at(120))
    state = evaluate_incident(incident, now=at(10_000))
    assert state["state"] == STATE_MET and state["breached"] is False


# ------------------------------------------------------------------ policy
def test_due_times_come_from_the_severity() -> None:
    policy = SlaPolicy(
        targets={
            "critical": SlaTarget("critical", 15, 240),
            "informational": SlaTarget("informational", None, None),
        }
    )
    ack, resolve = policy.due_times("critical", OPENED)
    assert ack == at(15) and resolve == at(240)

    # Informational deliberately has no clocks: a target on work nobody intends
    # to do only manufactures breaches.
    ack, resolve = policy.due_times("informational", OPENED)
    assert ack is None and resolve is None


def test_an_unknown_severity_gets_no_targets() -> None:
    policy = SlaPolicy(targets={})
    assert policy.due_times("nonsense", OPENED) == (None, None)


def test_the_shipped_policy_loads(tmp_path) -> None:
    from tests.conftest import REPO_ROOT

    reset_policy_cache()
    policy = load_policy(str(REPO_ROOT / "schemas" / "sla.yml"))
    assert 0 < policy.warn_at <= 1
    # Tighter severities must have tighter targets - otherwise the bands are
    # decorative.
    critical = policy.target_for("critical")
    high = policy.target_for("high")
    assert critical.acknowledge_minutes < high.acknowledge_minutes
    assert critical.resolve_minutes < high.resolve_minutes
    assert policy.target_for("informational").acknowledge_minutes is None


def test_a_missing_policy_file_falls_back_to_the_builtins(tmp_path) -> None:
    reset_policy_cache()
    policy = load_policy(str(tmp_path / "nope.yml"))
    assert (
        policy.target_for("critical").acknowledge_minutes
        == (BUILTIN_TARGETS["critical"]["acknowledge_minutes"])
    )


def test_a_malformed_policy_file_falls_back_rather_than_crashing(tmp_path) -> None:
    bad = tmp_path / "sla.yml"
    bad.write_text("targets: [this is a list, not a mapping\n")
    reset_policy_cache()
    policy = load_policy(str(bad))
    assert policy.target_for("high").acknowledge_minutes is not None


def test_partial_overrides_keep_the_builtin_defaults(tmp_path) -> None:
    partial = tmp_path / "sla.yml"
    partial.write_text(
        "defaults:\n  warn_at: 0.5\ntargets:\n  high:\n    acknowledge_minutes: 5\n"
        "    resolve_minutes: 30\n"
    )
    reset_policy_cache()
    policy = load_policy(str(partial))
    assert policy.warn_at == 0.5
    assert policy.target_for("high").acknowledge_minutes == 5
    # critical was not overridden, so it keeps the built-in target.
    assert policy.target_for("critical").acknowledge_minutes == 15


@pytest.mark.parametrize("bad_warn", ["nonsense", -1, 5])
def test_warn_at_is_clamped_to_a_fraction(tmp_path, bad_warn) -> None:
    path = tmp_path / "sla.yml"
    path.write_text("defaults:\n  warn_at: %s\n" % bad_warn)
    reset_policy_cache()
    assert 0.0 <= load_policy(str(path)).warn_at <= 1.0
