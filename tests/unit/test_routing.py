"""Routing rule parsing and matching semantics."""

from __future__ import annotations

import pytest
from signalforge.routing import (
    RoutingError,
    RoutingFacts,
    RoutingRule,
    RoutingTable,
    load_routing_table,
    parse_rule,
)


def rule(**overrides) -> RoutingRule:
    payload = {"id": "r1", "team": "identity", "priority": 10, "match": {}}
    payload.update(overrides)
    return parse_rule(payload)


# ------------------------------------------------------------------ parsing
def test_a_rule_needs_an_id_and_a_team() -> None:
    with pytest.raises(RoutingError, match="needs an id"):
        parse_rule({"team": "identity"})
    with pytest.raises(RoutingError, match="needs a team"):
        parse_rule({"id": "r1"})


def test_unknown_match_fields_are_rejected() -> None:
    """A typo in a match block is a rule that silently never fires."""
    with pytest.raises(RoutingError, match="unknown field"):
        parse_rule({"id": "r1", "team": "identity", "match": {"scenrio": "x"}})


def test_risk_bounds_are_validated() -> None:
    with pytest.raises(RoutingError, match="must be a number"):
        parse_rule({"id": "r1", "team": "t", "match": {"min_risk": "high"}})
    with pytest.raises(RoutingError, match="must be 0-100"):
        parse_rule({"id": "r1", "team": "t", "match": {"min_risk": 500}})
    with pytest.raises(RoutingError, match="min_risk above max_risk"):
        parse_rule({"id": "r1", "team": "t", "match": {"min_risk": 80, "max_risk": 20}})


def test_a_rule_with_no_match_block_is_a_catch_all() -> None:
    assert rule().is_catch_all
    assert rule().matches(RoutingFacts(scenario="anything"))


# ----------------------------------------------------------------- matching
def test_scenario_and_tactic_match_any_listed_value() -> None:
    scenario_rule = rule(match={"scenario": ["account_compromise", "brute_force"]})
    assert scenario_rule.matches(RoutingFacts(scenario="brute_force"))
    assert not scenario_rule.matches(RoutingFacts(scenario="cloud_persistence"))

    tactic_rule = rule(match={"tactic": ["credential_access"]})
    assert tactic_rule.matches(RoutingFacts(tactics=("initial_access", "credential_access")))
    assert not tactic_rule.matches(RoutingFacts(tactics=("collection",)))


def test_conditions_within_a_rule_are_anded() -> None:
    strict = rule(match={"scenario": ["account_compromise"], "min_risk": 70})
    assert strict.matches(RoutingFacts(scenario="account_compromise", risk_score=88))
    assert not strict.matches(RoutingFacts(scenario="account_compromise", risk_score=40))
    assert not strict.matches(RoutingFacts(scenario="mfa_removal", risk_score=95))


def test_risk_bounds_are_inclusive() -> None:
    banded = rule(match={"min_risk": 30, "max_risk": 69})
    assert banded.matches(RoutingFacts(risk_score=30))
    assert banded.matches(RoutingFacts(risk_score=69))
    assert not banded.matches(RoutingFacts(risk_score=70))


def test_glob_patterns_work_on_identifiers() -> None:
    by_rule = rule(match={"rule_id": ["sf-cloud-*"]})
    assert by_rule.matches(RoutingFacts(rule_ids=("sf-auth-0001", "sf-cloud-0002")))
    assert not by_rule.matches(RoutingFacts(rule_ids=("sf-auth-0001",)))

    by_host = rule(match={"hostname": ["prod-*"]})
    assert by_host.matches(RoutingFacts(hostnames=("prod-api-01",)))
    assert not by_host.matches(RoutingFacts(hostnames=("staging-01",)))


def test_severity_and_tenant_match_exactly() -> None:
    crit = rule(match={"severity": ["critical"]})
    assert crit.matches(RoutingFacts(severity="critical"))
    assert not crit.matches(RoutingFacts(severity="high"))

    scoped = rule(match={"tenant": ["acme"]})
    assert scoped.matches(RoutingFacts(tenant="acme"))
    assert not scoped.matches(RoutingFacts(tenant="other"))


def test_a_disabled_rule_never_matches() -> None:
    assert not rule(enabled=False).matches(RoutingFacts())


# -------------------------------------------------------------- resolution
def test_lowest_priority_number_wins() -> None:
    table = RoutingTable(
        rules=[
            parse_rule({"id": "catch-all", "team": "triage", "priority": 9000}),
            parse_rule(
                {
                    "id": "specific",
                    "team": "identity",
                    "priority": 10,
                    "match": {"tactic": ["credential_access"]},
                }
            ),
        ]
    )
    matched = table.match(RoutingFacts(tactics=("credential_access",)))
    assert matched is not None and matched.team == "identity"

    # Nothing specific applies -> the catch-all.
    fallback = table.match(RoutingFacts(tactics=("collection",)))
    assert fallback is not None and fallback.team == "triage"


def test_equal_priorities_resolve_deterministically() -> None:
    """Two rules at the same priority must not depend on file order."""
    first = RoutingTable(
        rules=[
            parse_rule({"id": "bbb", "team": "b", "priority": 10}),
            parse_rule({"id": "aaa", "team": "a", "priority": 10}),
        ]
    )
    second = RoutingTable(
        rules=[
            parse_rule({"id": "aaa", "team": "a", "priority": 10}),
            parse_rule({"id": "bbb", "team": "b", "priority": 10}),
        ]
    )
    assert first.match(RoutingFacts()).id == second.match(RoutingFacts()).id == "aaa"


def test_no_rules_means_no_match() -> None:
    assert RoutingTable().match(RoutingFacts()) is None


def test_explain_reports_every_rule_with_its_verdict() -> None:
    table = RoutingTable(
        rules=[
            parse_rule({"id": "a", "team": "x", "priority": 1, "match": {"min_risk": 90}}),
            parse_rule({"id": "b", "team": "y", "priority": 2}),
        ]
    )
    verdicts = {r.id: hit for r, hit in table.explain(RoutingFacts(risk_score=50))}
    assert verdicts == {"a": False, "b": True}


# ------------------------------------------------------------------ loading
def test_loading_collects_errors_instead_of_raising(tmp_path) -> None:
    (tmp_path / "good.yml").write_text("id: ok\nteam: identity\npriority: 5\n")
    (tmp_path / "bad.yml").write_text("id: broken\n")  # no team
    table = load_routing_table(tmp_path)
    assert [r.id for r in table.rules] == ["ok"]
    assert len(table.errors) == 1 and "needs a team" in table.errors[0]


def test_strict_loading_raises(tmp_path) -> None:
    (tmp_path / "bad.yml").write_text("id: broken\n")
    with pytest.raises(RoutingError, match="needs a team"):
        load_routing_table(tmp_path, strict=True)


def test_duplicate_ids_are_rejected(tmp_path) -> None:
    (tmp_path / "a.yml").write_text("id: dup\nteam: one\n")
    (tmp_path / "b.yml").write_text("id: dup\nteam: two\n")
    table = load_routing_table(tmp_path)
    assert len(table.rules) == 1
    assert any("duplicate routing rule id" in error for error in table.errors)


def test_a_missing_directory_is_an_empty_table(tmp_path) -> None:
    table = load_routing_table(tmp_path / "nope")
    assert table.rules == [] and table.errors == []


def test_multi_document_files_are_supported(tmp_path) -> None:
    (tmp_path / "many.yml").write_text(
        "id: one\nteam: a\npriority: 1\n---\nid: two\nteam: b\npriority: 2\n"
    )
    assert [r.id for r in load_routing_table(tmp_path).rules] == ["one", "two"]


# ------------------------------------------------------- the shipped rules
def test_the_shipped_routing_table_is_valid() -> None:
    from tests.conftest import REPO_ROOT

    table = load_routing_table(REPO_ROOT / "routing", strict=True)
    assert table.rules, "the repository ships routing rules"
    assert table.errors == []
    # Exactly one catch-all, and it must be last so it cannot shadow anything.
    catch_alls = [rule for rule in table.rules if rule.is_catch_all]
    assert len(catch_alls) == 1
    assert table.rules[-1] is catch_alls[0]
