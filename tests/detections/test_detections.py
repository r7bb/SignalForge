"""Run every detection's declared test cases.

Each rule in ``detections/`` ships a ``*.tests.yml`` with at least one
positive, one negative and one false-positive case; this module turns them into
individual pytest cases so a broken detection fails CI by name.
"""

from __future__ import annotations

from typing import List

import pytest

from tests.conftest import BASE_TIME, REPO_ROOT
from tests.detections.harness import DetectionCase, collect_cases, run_case

DETECTIONS_DIR = REPO_ROOT / "detections"

CASES: List[DetectionCase] = collect_cases(DETECTIONS_DIR)

pytestmark = pytest.mark.detections


def test_cases_were_discovered() -> None:
    assert CASES, "no detection test cases found under %s" % DETECTIONS_DIR


@pytest.mark.parametrize("case", CASES, ids=[case.id for case in CASES])
def test_detection_case(case: DetectionCase, engine, correlator) -> None:
    outcome = run_case(case, BASE_TIME, engine=engine, correlator=correlator)
    rule_id = case.target_rule_id

    if case.expect == "alert":
        alerts = outcome.alerts_for(rule_id)
        assert alerts, "expected %s to alert; got alerts for %s from %d events" % (
            rule_id,
            sorted({a.rule_id for a in outcome.alerts}) or "nothing",
            len(outcome.events),
        )
        if case.expect_min_risk is not None:
            assert outcome.max_alert_risk(rule_id) >= case.expect_min_risk, (
                "risk %d below expected minimum %d"
                % (outcome.max_alert_risk(rule_id), case.expect_min_risk)
            )

    elif case.expect == "no_alert":
        alerts = outcome.alerts_for(rule_id)
        assert not alerts, "expected no %s alert, got %d (risk %s)" % (
            rule_id,
            len(alerts),
            [a.risk_score for a in alerts],
        )

    elif case.expect == "correlation":
        hits = outcome.hits_for(rule_id)
        assert hits, "expected correlation %s; observed alerts %s and correlations %s" % (
            rule_id,
            [a.rule_id for a in outcome.alerts],
            [h.correlation.id for h in outcome.hits],
        )
        if case.expect_min_risk is not None:
            assert outcome.max_incident_risk(rule_id) >= case.expect_min_risk, (
                "incident risk %d below expected minimum %d"
                % (outcome.max_incident_risk(rule_id), case.expect_min_risk)
            )

    elif case.expect == "no_correlation":
        hits = outcome.hits_for(rule_id)
        assert not hits, "expected no %s correlation, got %d (sequence %s)" % (
            rule_id,
            len(hits),
            [h.sequence for h in hits],
        )

    else:  # pragma: no cover - guarded by the harness
        pytest.fail("unknown expectation %r" % case.expect)


def test_every_rule_has_all_three_test_kinds() -> None:
    """Detection engineering discipline: no rule ships without an FP case."""
    by_rule: dict = {}
    for case in CASES:
        by_rule.setdefault(case.rule_id, set()).add(case.kind)
    missing = {
        rule_id: sorted({"positive", "negative", "false_positive"} - kinds)
        for rule_id, kinds in by_rule.items()
        if {"positive", "negative", "false_positive"} - kinds
    }
    assert not missing, "rules missing test kinds: %s" % missing
