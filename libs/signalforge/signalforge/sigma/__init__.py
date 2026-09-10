"""Sigma support: parsing, field-modifier semantics, evaluation and backends."""

from .condition import Aggregation, ParsedCondition, parse_condition
from .errors import (
    SigmaConditionError,
    SigmaError,
    SigmaParseError,
    SigmaValidationError,
)
from .evaluator import MatchResult, evaluate, evaluate_flat
from .loader import RuleSet, load_rule_tests, load_ruleset, test_file_for
from .matching import FieldMatcher, KeywordMatcher
from .opensearch_backend import compile_rule
from .pipeline import apply_field_mapping, event_logsource, event_matches_logsource, resolve_field
from .rule import (
    LogSource,
    Search,
    SigmaCorrelationRule,
    SigmaRule,
    parse_rule_document,
    parse_timespan,
)
from .validate import LintReport, Problem, lint_rules

__all__ = [
    "Aggregation",
    "FieldMatcher",
    "KeywordMatcher",
    "LintReport",
    "LogSource",
    "MatchResult",
    "ParsedCondition",
    "Problem",
    "RuleSet",
    "Search",
    "SigmaConditionError",
    "SigmaCorrelationRule",
    "SigmaError",
    "SigmaParseError",
    "SigmaRule",
    "SigmaValidationError",
    "apply_field_mapping",
    "compile_rule",
    "evaluate",
    "evaluate_flat",
    "event_logsource",
    "event_matches_logsource",
    "lint_rules",
    "load_rule_tests",
    "load_ruleset",
    "parse_condition",
    "parse_rule_document",
    "parse_timespan",
    "resolve_field",
    "test_file_for",
]
