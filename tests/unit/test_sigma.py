"""The Sigma implementation: conditions, modifiers, evaluation, compilation."""

from __future__ import annotations

import base64

import pytest
import yaml
from signalforge.models.ocsf import ClassUid, OcsfEvent, RawLogRecord
from signalforge.normalize import normalize
from signalforge.sigma import (
    SigmaConditionError,
    SigmaParseError,
    apply_field_mapping,
    compile_rule,
    evaluate,
    parse_condition,
    parse_rule_document,
    parse_timespan,
    resolve_field,
)
from signalforge.sigma.condition import And, Not, Or, Wildcard
from signalforge.sigma.matching import FieldMatcher, KeywordMatcher
from signalforge.sigma.pipeline import event_logsource, event_matches_logsource


def build_rule(body: str):
    return apply_field_mapping(parse_rule_document(yaml.safe_load(body)))


# --------------------------------------------------------------- conditions --
def test_and_binds_tighter_than_or() -> None:
    parsed = parse_condition("a or b and c", ["a", "b", "c"])
    assert isinstance(parsed.expression, Or)
    assert isinstance(parsed.expression.children[1], And)


def test_not_and_parentheses() -> None:
    parsed = parse_condition("a and not (b or c)", ["a", "b", "c"])
    assert isinstance(parsed.expression, And)
    assert isinstance(parsed.expression.children[1], Not)


def test_quantifiers_expand_to_the_matching_searches() -> None:
    parsed = parse_condition(
        "1 of selection_* and all of filter_*",
        ["selection_a", "selection_b", "filter_x", "filter_y"],
    )
    any_node, all_node = parsed.expression.children
    assert isinstance(any_node, Wildcard) and any_node.quantifier == "any"
    assert any_node.resolved == ("selection_a", "selection_b")
    assert isinstance(all_node, Wildcard) and all_node.quantifier == "all"
    assert all_node.resolved == ("filter_x", "filter_y")

    # With a negation in front, the quantifier sits under the Not node.
    negated = parse_condition(
        "1 of selection_* and not all of filter_*",
        ["selection_a", "selection_b", "filter_1", "filter_2"],
    )
    not_node = negated.expression.children[1]
    assert isinstance(not_node, Not)
    assert isinstance(not_node.child, Wildcard) and not_node.child.quantifier == "all"


def test_all_of_them_matches_every_search() -> None:
    parsed = parse_condition("all of them", ["a", "b", "c"])
    assert set(parsed.expression.identifiers()) == {"a", "b", "c"}


def test_aggregation_tail_is_parsed() -> None:
    parsed = parse_condition("selection | count() by actor.user.name >= 5", ["selection"])
    assert parsed.is_stateful
    assert parsed.aggregation.group_by == "actor.user.name"
    assert parsed.aggregation.operator == ">="
    assert parsed.aggregation.threshold == 5
    assert parsed.aggregation.compare(5) and not parsed.aggregation.compare(4)


def test_distinct_count_aggregation() -> None:
    parsed = parse_condition("selection | count(src_endpoint.ip) by user.name > 3", ["selection"])
    assert parsed.aggregation.field == "src_endpoint.ip"
    assert parsed.aggregation.compare(4) and not parsed.aggregation.compare(3)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "selection and",
        "selection or or filter",
        "missing_selection",
        "1 of nothing_*",
        "selection | count() by user",
        "selection | median() by user > 3",
        "selection extra",
    ],
)
def test_malformed_conditions_are_rejected(text: str) -> None:
    with pytest.raises(SigmaConditionError):
        parse_condition(text, ["selection", "filter"])


# ---------------------------------------------------------------- modifiers --
FLAT = {
    "actor.user.name": "Alex",
    "status": "Failure",
    "src_endpoint.ip": "185.220.101.7",
    "http_response.code": 403,
    "api.operation": "CreateAccessKey",
    "resources.criticality": ["high", "low"],
    "user.groups.name": None,
    "is_mfa": False,
}


@pytest.mark.parametrize(
    ("key", "value", "expected"),
    [
        ("actor.user.name", "alex", True),  # case-insensitive by default
        ("actor.user.name|cased", "alex", False),
        ("actor.user.name", "al*", True),
        ("actor.user.name", "a?ex", True),
        ("status|contains", "ail", True),
        ("api.operation|startswith", "Create", True),
        ("api.operation|endswith", "Key", True),
        ("api.operation|startswith", "Delete", False),
        ("src_endpoint.ip|cidr", "185.220.0.0/16", True),
        ("src_endpoint.ip|cidr", "10.0.0.0/8", False),
        ("http_response.code|gte", 400, True),
        ("http_response.code|lt", 400, False),
        ("http_response.code", 403, True),
        ("resources.criticality", "high", True),
        ("resources.criticality|all", ["high", "low"], True),
        ("resources.criticality|all", ["high", "critical"], False),
        ("user.groups.name", None, True),
        ("missing.field", None, True),
        ("actor.user.name|exists", "true", True),
        ("missing.field|exists", "true", False),
        ("status|re", "^Fail", True),
        ("status|re|i", "^fail", True),
        ("is_mfa", False, True),
        ("is_mfa", True, False),
    ],
)
def test_field_modifier_semantics(key: str, value: object, expected: bool) -> None:
    assert FieldMatcher.compile(key, value).match(FLAT) is expected


def test_value_list_is_an_or() -> None:
    matcher = FieldMatcher.compile("api.operation", ["DeleteTrail", "CreateAccessKey"])
    assert matcher.match(FLAT)


def test_base64offset_finds_the_value_at_every_byte_alignment() -> None:
    matcher = FieldMatcher.compile("cmd|base64offset|contains", "Invoke-Mimikatz")
    for padding in ("", "X", "XX"):
        blob = base64.b64encode((padding + "Invoke-Mimikatz tail").encode()).decode()
        assert matcher.match({"cmd": "powershell -enc " + blob})
    assert not matcher.match({"cmd": base64.b64encode(b"entirely harmless").decode()})


def test_utf16_base64_variant() -> None:
    matcher = FieldMatcher.compile("cmd|utf16le|base64offset|contains", "IEX")
    blob = base64.b64encode("IEX (New-Object Net.WebClient)".encode("utf-16-le")).decode()
    assert matcher.match({"cmd": blob})


def test_windash_expands_dash_variants() -> None:
    matcher = FieldMatcher.compile("cmd|windash|contains", "-enc")
    assert matcher.match({"cmd": "powershell /enc ..."})
    assert matcher.match({"cmd": "powershell -enc ..."})


def test_fieldref_compares_two_fields() -> None:
    matcher = FieldMatcher.compile("actor.user.name|fieldref", "user.name")
    assert matcher.match({"actor.user.name": "alex", "user.name": "ALEX"})
    assert not matcher.match({"actor.user.name": "alex", "user.name": "dana"})


def test_keyword_search_scans_every_value() -> None:
    assert KeywordMatcher(values=("CreateAccessKey",)).match(FLAT)
    assert not KeywordMatcher(values=("DeleteTrail",)).match(FLAT)


def test_unknown_modifier_is_rejected() -> None:
    with pytest.raises(SigmaParseError):
        FieldMatcher.compile("actor.user.name|shout", "alex")


# --------------------------------------------------------------- rule model --
def test_rule_metadata_and_attack_tags() -> None:
    rule = build_rule("""
title: Example
id: sf-test-0001
name: example_rule
level: high
status: test
tags: [attack.credential_access, attack.t1110, attack.t1110.001, not-an-attack-tag]
logsource: {category: authentication}
detection:
  selection: {class_uid: 3002}
  condition: selection
""")
    assert rule.tactics == ["credential_access"]
    assert rule.techniques == ["T1110", "T1110.001"]
    assert rule.reference_names == ["example_rule", "sf-test-0001"]
    assert not rule.is_stateful


def test_rule_requires_id_title_and_detection() -> None:
    for body in [
        "title: No id\ndetection:\n  selection: {a: 1}\n  condition: selection\n",
        "id: sf-x\ndetection:\n  selection: {a: 1}\n  condition: selection\n",
        "title: No detection\nid: sf-x\n",
        "title: No condition\nid: sf-x\ndetection:\n  selection: {a: 1}\n",
    ]:
        with pytest.raises(SigmaParseError):
            parse_rule_document(yaml.safe_load(body))


def test_invalid_level_is_rejected() -> None:
    with pytest.raises(SigmaParseError):
        parse_rule_document(
            yaml.safe_load(
                "title: T\nid: sf-x\nlevel: catastrophic\n"
                "detection:\n  selection: {a: 1}\n  condition: selection\n"
            )
        )


def test_list_of_maps_is_an_or_of_ands() -> None:
    rule = build_rule("""
title: Either shape
id: sf-test-0002
logsource: {category: authentication}
detection:
  selection:
    - {class_uid: 3002, status: Failure}
    - {class_uid: 3002, status: Success}
  condition: selection
""")
    search = rule.searches["selection"]
    assert len(search.groups) == 2
    assert search.match({"class_uid": 3002, "status": "Success"})
    assert not search.match({"class_uid": 3002, "status": "Other"})


@pytest.mark.parametrize(
    ("text", "seconds"),
    [
        ("30s", 30),
        ("5m", 300),
        ("2h", 7200),
        ("7d", 604800),
        ("1w", 604800),
        (45, 45),
    ],
)
def test_timespan_parsing(text: object, seconds: int) -> None:
    assert parse_timespan(text) == seconds


def test_invalid_timespan_is_rejected() -> None:
    with pytest.raises(SigmaParseError):
        parse_timespan("soon")


# --------------------------------------------------------- correlation rules --
def test_correlation_rule_parsing() -> None:
    correlation = parse_rule_document(
        yaml.safe_load("""
title: Chain
id: sf-corr-test
level: critical
correlation:
  type: temporal_ordered
  rules: [stage_one, stage_two]
  group-by: [actor.user.name]
  timespan: 15m
""")
    )
    assert correlation.type == "temporal_ordered"
    assert correlation.is_ordered
    assert correlation.timespan == 900
    assert correlation.rule_refs == ["stage_one", "stage_two"]


def test_value_count_correlation_requires_a_field() -> None:
    with pytest.raises(SigmaParseError):
        parse_rule_document(
            yaml.safe_load("""
title: Bad value count
id: sf-corr-bad
correlation:
  type: value_count
  rules: [stage_one]
  group-by: [actor.user.name]
  timespan: 1h
  condition: {gte: 2}
""")
        )


def test_temporal_correlation_needs_two_rules() -> None:
    with pytest.raises(SigmaParseError):
        parse_rule_document(
            yaml.safe_load("""
title: Lonely
id: sf-corr-lonely
correlation:
  type: temporal
  rules: [only_one]
  timespan: 5m
""")
        )


def test_event_count_correlation_comparisons() -> None:
    correlation = parse_rule_document(
        yaml.safe_load("""
title: Count
id: sf-corr-count
correlation:
  type: event_count
  rules: [stage_one]
  group-by: [src_endpoint.ip]
  timespan: 10m
  condition: {gt: 3}
""")
    )
    assert correlation.compare(4) and not correlation.compare(3)
    assert correlation.threshold == 3


# ------------------------------------------------------------------ pipeline --
def test_field_aliases_are_mapped_to_ocsf() -> None:
    assert resolve_field("TargetUserName") == "user.name"
    assert resolve_field("sourceIPAddress") == "src_endpoint.ip"
    assert resolve_field("CommandLine") == "actor.process.cmd_line"
    assert resolve_field("actor.user.name") == "actor.user.name"

    rule = build_rule("""
title: Vendor field names
id: sf-test-0003
logsource: {category: authentication, product: aws}
detection:
  selection: {EventName: ConsoleLogin, SourceIPAddress|cidr: 0.0.0.0/0}
  condition: selection
""")
    assert rule.searches["selection"].fields == ["api.operation", "src_endpoint.ip"]


def test_logsource_scopes_rules_to_event_classes() -> None:
    rule = build_rule("""
title: AWS only
id: sf-test-0004
logsource: {category: authentication, product: aws}
detection:
  selection: {status: Success}
  condition: selection
""")
    sshd = normalize(
        RawLogRecord(
            source="linux.sshd",
            raw="Sep 10 13:42:10 web-01 sshd[1]: Accepted password for alex from 10.0.4.82 port 1 ssh2",
        )
    )
    cloud = normalize(
        RawLogRecord(
            source="aws.cloudtrail",
            payload={
                "eventTime": "2026-09-10T13:00:00Z",
                "eventName": "ConsoleLogin",
                "eventSource": "signin.amazonaws.com",
                "userIdentity": {"type": "IAMUser", "userName": "alex"},
                "responseElements": {"ConsoleLogin": "Success"},
            },
        )
    )
    assert event_logsource(sshd)["product"] == "linux"
    assert not event_matches_logsource(rule, sshd)
    assert event_matches_logsource(rule, cloud)


# ----------------------------------------------------------------- evaluate --
def test_evaluation_reports_matched_searches_and_evidence() -> None:
    rule = build_rule("""
title: Failures excluding machine accounts
id: sf-test-0005
logsource: {category: authentication}
fields: [src_endpoint.ip]
detection:
  selection: {class_uid: 3002, status: Failure}
  filter_machine: {actor.user.name|endswith: '$'}
  condition: selection and not filter_machine
""")
    event = normalize(
        RawLogRecord(
            source="linux.sshd",
            raw="Sep 10 13:41:02 web-01 sshd[1]: Failed password for alex from 10.0.4.82 port 1 ssh2",
        )
    )
    result = evaluate(rule, event)
    assert result.matched
    assert result.matched_selections == ["selection"]
    assert result.matched_fields["status"] == "Failure"
    assert result.matched_fields["src_endpoint.ip"] == "10.0.4.82"  # from `fields`

    machine = normalize(
        RawLogRecord(
            source="linux.sshd",
            raw="Sep 10 13:41:02 web-01 sshd[1]: Failed password for svc$ from 10.0.4.82 port 1 ssh2",
        )
    )
    assert not evaluate(rule, machine).matched


def test_evaluation_short_circuits_on_logsource() -> None:
    rule = build_rule("""
title: Datastore only
id: sf-test-0006
logsource: {category: datastore}
detection:
  selection: {class_uid: 6005}
  condition: selection
""")
    event = OcsfEvent(class_uid=ClassUid.AUTHENTICATION, activity_id=1)
    assert not evaluate(rule, event).matched


# ------------------------------------------------------ opensearch backend ---
def test_compiled_query_shape() -> None:
    rule = build_rule("""
title: Compile me
id: sf-test-0007
logsource: {category: authentication, product: linux}
detection:
  selection: {status: Failure, activity_id: 1}
  filter_machine: {actor.user.name|endswith: '$'}
  timeframe: 5m
  condition: selection and not filter_machine | count() by actor.user.name >= 5
""")
    body = compile_rule(rule, tenant="acme", earliest="now-7d", size=25)
    filters = body["query"]["bool"]["filter"]
    assert {"terms": {"class_uid": [3002]}} in filters
    assert {"term": {"sf_tenant": "acme"}} in filters
    assert any("range" in clause for clause in filters)
    grouped = body["aggs"]["grouped"]["terms"]
    assert grouped["field"] == "actor.user.name"
    assert grouped["min_doc_count"] == 5


def test_compiled_query_uses_wildcards_and_ranges() -> None:
    rule = build_rule("""
title: Modifier compilation
id: sf-test-0008
logsource: {category: datastore}
detection:
  selection:
    resources.name|contains: customer
    unmapped.record_count|gte: 1000
  condition: selection
""")
    body = compile_rule(rule)
    rendered = repr(body)
    assert "wildcard" in rendered and "*customer*" in rendered
    assert "range" in rendered and "gte" in rendered
