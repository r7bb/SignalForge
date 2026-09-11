"""Rule linter - the gate the CI pipeline runs on every detection PR.

Checks metadata hygiene (stable id, description, author, ATT&CK tags,
documented false positives), that conditions and correlation references
resolve, that referenced fields actually exist in the OCSF schema, and that
every rule ships positive / negative / false-positive tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

import yaml

from ..models.fields import is_known_field
from .errors import SigmaError
from .loader import iter_rule_files, load_documents, load_rule_tests, test_file_for
from .matching import FieldMatcher
from .pipeline import apply_field_mapping, resolve_field
from .rule import SigmaCorrelationRule, SigmaRule, parse_rule_document

REQUIRED_TEST_KINDS = ("positive", "negative", "false_positive")


@dataclass
class Problem:
    path: str
    rule_id: Optional[str]
    severity: str  # "error" | "warning"
    code: str
    message: str

    def format(self) -> str:
        return "%s [%s] %s: %s (%s)" % (
            self.severity.upper(),
            self.code,
            self.path,
            self.message,
            self.rule_id or "-",
        )


@dataclass
class LintReport:
    problems: List[Problem]
    rule_count: int = 0
    correlation_count: int = 0
    tested_rules: int = 0

    @property
    def errors(self) -> List[Problem]:
        return [p for p in self.problems if p.severity == "error"]

    @property
    def warnings(self) -> List[Problem]:
        return [p for p in self.problems if p.severity == "warning"]

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "rule_count": self.rule_count,
            "correlation_count": self.correlation_count,
            "tested_rules": self.tested_rules,
            "errors": [p.__dict__ for p in self.errors],
            "warnings": [p.__dict__ for p in self.warnings],
        }


def lint_rules(
    paths: Union[str, Path, Sequence[Union[str, Path]]] = "detections",
    *,
    require_tests: bool = True,
    require_attack_tags: bool = True,
) -> LintReport:
    problems: List[Problem] = []
    seen_ids: Dict[str, str] = {}
    seen_names: Dict[str, str] = {}
    rules: Dict[str, SigmaRule] = {}
    correlations: List[SigmaCorrelationRule] = []
    tested = 0

    for path in iter_rule_files(paths):
        rel = str(path)
        try:
            documents = load_documents(path)
        except yaml.YAMLError as exc:
            problems.append(Problem(rel, None, "error", "invalid-yaml", str(exc)))
            continue
        if not documents:
            problems.append(Problem(rel, None, "error", "empty-file", "no YAML documents"))
            continue

        for document in documents:
            try:
                rule = parse_rule_document(document, rel)
            except SigmaError as exc:
                problems.append(Problem(rel, document.get("id"), "error", "parse-error", str(exc)))
                continue

            if rule.id in seen_ids:
                problems.append(
                    Problem(
                        rel,
                        rule.id,
                        "error",
                        "duplicate-id",
                        "id already used by %s" % seen_ids[rule.id],
                    )
                )
            seen_ids[rule.id] = rel
            if rule.name:
                if rule.name in seen_names:
                    problems.append(
                        Problem(
                            rel,
                            rule.id,
                            "error",
                            "duplicate-name",
                            "name %r already used by %s" % (rule.name, seen_names[rule.name]),
                        )
                    )
                seen_names[rule.name] = rel

            problems.extend(_lint_metadata(rule, rel, require_attack_tags))

            if isinstance(rule, SigmaRule):
                rules[rule.id] = rule
                problems.extend(_lint_fields(apply_field_mapping(rule), rel))
                if rule.is_stateful and not rule.timeframe:
                    problems.append(
                        Problem(
                            rel,
                            rule.id,
                            "error",
                            "missing-timeframe",
                            "aggregation conditions require detection.timeframe",
                        )
                    )
            else:
                correlations.append(rule)

            if require_tests:
                test_path = test_file_for(path)
                cases = load_rule_tests(path)
                if not test_path or not cases:
                    problems.append(
                        Problem(
                            rel,
                            rule.id,
                            "error",
                            "missing-tests",
                            "no %s.tests.yml with test cases" % path.stem,
                        )
                    )
                else:
                    tested += 1
                    problems.extend(_lint_tests(rule, cases, str(test_path)))

    # Correlation references must resolve to a rule id or name in the set.
    known = set(seen_ids) | set(seen_names)
    for correlation in correlations:
        for reference in correlation.rule_refs:
            if reference not in known:
                problems.append(
                    Problem(
                        correlation.source_path or "-",
                        correlation.id,
                        "error",
                        "unresolved-reference",
                        "correlation references unknown rule %r" % reference,
                    )
                )

    return LintReport(
        problems=problems,
        rule_count=len(rules),
        correlation_count=len(correlations),
        tested_rules=tested,
    )


def _lint_metadata(rule: Any, path: str, require_attack_tags: bool) -> List[Problem]:
    problems: List[Problem] = []
    if not rule.description:
        problems.append(
            Problem(
                path,
                rule.id,
                "warning",
                "missing-description",
                "rules should describe what they detect",
            )
        )
    if not getattr(rule, "author", None):
        problems.append(Problem(path, rule.id, "warning", "missing-author", "no author set"))
    if require_attack_tags and not rule.tactics:
        problems.append(
            Problem(
                path,
                rule.id,
                "error",
                "missing-attack-tactic",
                "add an attack.<tactic> tag for ATT&CK mapping",
            )
        )
    if require_attack_tags and not rule.techniques:
        problems.append(
            Problem(path, rule.id, "warning", "missing-attack-technique", "add an attack.tXXXX tag")
        )
    if not rule.falsepositives:
        problems.append(
            Problem(
                path, rule.id, "warning", "missing-falsepositives", "document known benign triggers"
            )
        )
    if rule.status == "deprecated":
        problems.append(Problem(path, rule.id, "warning", "deprecated", "rule is deprecated"))
    if isinstance(rule, SigmaRule) and not rule.logsource.as_dict():
        problems.append(
            Problem(
                path,
                rule.id,
                "error",
                "missing-logsource",
                "logsource must scope the rule to a category/product",
            )
        )
    return problems


def _lint_fields(rule: SigmaRule, path: str) -> List[Problem]:
    problems: List[Problem] = []
    for search in rule.searches.values():
        for group in search.groups:
            for matcher in group:
                if not isinstance(matcher, FieldMatcher):
                    continue
                if not is_known_field(matcher.field):
                    problems.append(
                        Problem(
                            path,
                            rule.id,
                            "error",
                            "unknown-field",
                            "field %r is not part of the OCSF schema (search %r)"
                            % (matcher.field, search.name),
                        )
                    )
    for field_name in rule.fields:
        if not is_known_field(resolve_field(field_name)):
            problems.append(
                Problem(
                    path,
                    rule.id,
                    "warning",
                    "unknown-display-field",
                    "fields entry %r is not an OCSF path" % field_name,
                )
            )
    aggregation = rule.condition.aggregation
    if (
        aggregation
        and aggregation.group_by
        and not is_known_field(resolve_field(aggregation.group_by))
    ):
        problems.append(
            Problem(
                path,
                rule.id,
                "error",
                "unknown-groupby-field",
                "aggregation groups by unknown field %r" % aggregation.group_by,
            )
        )
    return problems


def _lint_tests(rule: Any, cases: List[Dict[str, Any]], path: str) -> List[Problem]:
    problems: List[Problem] = []
    kinds = {str(case.get("kind") or "").lower() for case in cases}
    for required in REQUIRED_TEST_KINDS:
        if required not in kinds:
            problems.append(
                Problem(
                    path,
                    rule.id,
                    "error",
                    "missing-test-kind",
                    "no %r test case" % required,
                )
            )
    for index, case in enumerate(cases):
        if not case.get("name"):
            problems.append(
                Problem(
                    path, rule.id, "warning", "unnamed-test", "test case #%d has no name" % index
                )
            )
        if not case.get("events") and not case.get("logs"):
            problems.append(
                Problem(
                    path,
                    rule.id,
                    "error",
                    "empty-test",
                    "test case %r has no events" % case.get("name", index),
                )
            )
    return problems
