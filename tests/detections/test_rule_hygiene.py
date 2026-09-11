"""The rule linter, as a test - this is the gate CI runs on detection PRs."""

from __future__ import annotations

import pytest
from signalforge.sigma import lint_rules, load_ruleset
from signalforge.sigma.errors import SigmaParseError

from tests.conftest import REPO_ROOT

DETECTIONS_DIR = REPO_ROOT / "detections"

pytestmark = pytest.mark.detections


def test_ruleset_loads_strictly() -> None:
    ruleset = load_ruleset(DETECTIONS_DIR, strict=True)
    assert ruleset.rules, "no detection rules loaded"
    assert ruleset.correlations, "no correlation rules loaded"
    assert not ruleset.errors


def test_linter_reports_no_errors() -> None:
    report = lint_rules(DETECTIONS_DIR)
    assert report.ok, "\n".join(problem.format() for problem in report.errors)


def test_every_rule_is_tested() -> None:
    report = lint_rules(DETECTIONS_DIR)
    assert report.tested_rules == report.rule_count + report.correlation_count


def test_correlation_references_resolve() -> None:
    ruleset = load_ruleset(DETECTIONS_DIR)
    assert ruleset.unresolved_references() == []


def test_rule_ids_and_names_are_unique() -> None:
    ruleset = load_ruleset(DETECTIONS_DIR)
    ids = list(ruleset.rules) + list(ruleset.correlations)
    assert len(ids) == len(set(ids))
    names = [
        rule.name
        for rule in list(ruleset.rules.values()) + list(ruleset.correlations.values())
        if rule.name
    ]
    assert len(names) == len(set(names))


def test_stateful_rules_declare_a_timeframe() -> None:
    ruleset = load_ruleset(DETECTIONS_DIR)
    for rule in ruleset.stateful_rules:
        assert rule.timeframe, "%s aggregates without a timeframe" % rule.id


def test_malformed_rule_is_rejected(tmp_path) -> None:
    """A rule whose condition references a missing selection must not load."""
    bad = tmp_path / "broken.yml"
    bad.write_text(
        "title: Broken\n"
        "id: sf-broken-0001\n"
        "logsource:\n  category: authentication\n"
        "detection:\n"
        "  selection:\n    class_uid: 3002\n"
        "  condition: selection and not filter_that_does_not_exist\n",
        encoding="utf-8",
    )
    with pytest.raises(SigmaParseError):
        load_ruleset(tmp_path, strict=True)

    report = lint_rules(tmp_path, require_tests=False)
    assert not report.ok
    assert any(problem.code == "parse-error" for problem in report.errors)


def test_typo_in_field_name_is_rejected(tmp_path) -> None:
    """A field that is not part of OCSF can never match - fail the build."""
    bad = tmp_path / "typo.yml"
    bad.write_text(
        "title: Typo\n"
        "id: sf-typo-0001\n"
        "logsource:\n  category: authentication\n"
        "detection:\n"
        "  selection:\n    src_endpoint.adress: 10.0.0.1\n"
        "  condition: selection\n",
        encoding="utf-8",
    )
    report = lint_rules(tmp_path, require_tests=False)
    assert any(problem.code == "unknown-field" for problem in report.errors)


def test_rule_without_attack_tags_is_rejected(tmp_path) -> None:
    bad = tmp_path / "untagged.yml"
    bad.write_text(
        "title: Untagged\n"
        "id: sf-untagged-0001\n"
        "logsource:\n  category: authentication\n"
        "detection:\n"
        "  selection:\n    class_uid: 3002\n"
        "  condition: selection\n",
        encoding="utf-8",
    )
    report = lint_rules(tmp_path, require_tests=False)
    assert any(problem.code == "missing-attack-tactic" for problem in report.errors)
