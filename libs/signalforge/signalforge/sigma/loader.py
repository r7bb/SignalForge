"""Load a detection-as-code rule directory into an in-memory rule set."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple, Union

import yaml

from ..models.ocsf import OcsfEvent
from .errors import SigmaError, SigmaParseError
from .pipeline import apply_field_mapping, event_matches_logsource, logsource_filter
from .rule import VALID_LEVELS, SigmaCorrelationRule, SigmaRule, parse_rule_document

log = logging.getLogger("signalforge.sigma")

RULE_SUFFIXES = (".yml", ".yaml")
TEST_MARKERS = (".tests.yml", ".tests.yaml", "_test.yml", "_tests.yml")

AnyRule = Union[SigmaRule, SigmaCorrelationRule]


@dataclass
class RuleSet:
    """Every loaded rule plus the indexes the detection engine needs."""

    rules: Dict[str, SigmaRule] = field(default_factory=dict)
    correlations: Dict[str, SigmaCorrelationRule] = field(default_factory=dict)
    errors: List[Tuple[str, str]] = field(default_factory=list)
    _by_name: Dict[str, str] = field(default_factory=dict, repr=False)
    _by_class: Dict[int, List[str]] = field(default_factory=dict, repr=False)
    _unscoped: List[str] = field(default_factory=list, repr=False)

    # -- construction ------------------------------------------------------
    def add(self, rule: AnyRule) -> None:
        target = self.rules if isinstance(rule, SigmaRule) else self.correlations
        if rule.id in self.rules or rule.id in self.correlations:
            raise SigmaParseError("duplicate rule id %r" % rule.id, rule.source_path)
        if rule.name:
            if rule.name in self._by_name:
                raise SigmaParseError("duplicate rule name %r" % rule.name, rule.source_path)
            self._by_name[rule.name] = rule.id
        self._by_name.setdefault(rule.id, rule.id)
        target[rule.id] = rule  # type: ignore[assignment]
        if isinstance(rule, SigmaRule):
            self._index(rule)

    def _index(self, rule: SigmaRule) -> None:
        class_uids = logsource_filter(rule).get("class_uid")
        if class_uids:
            for class_uid in class_uids:
                self._by_class.setdefault(class_uid, []).append(rule.id)
        else:
            self._unscoped.append(rule.id)

    # -- lookup ------------------------------------------------------------
    def resolve(self, reference: str) -> Optional[AnyRule]:
        rule_id = self._by_name.get(reference, reference)
        return self.rules.get(rule_id) or self.correlations.get(rule_id)

    def rule_id_for(self, reference: str) -> Optional[str]:
        rule = self.resolve(reference)
        return rule.id if rule else None

    def candidates_for(self, event: OcsfEvent) -> List[SigmaRule]:
        """Rules whose logsource can match this event (cheap class_uid index)."""
        ids = list(self._by_class.get(event.class_uid, ())) + self._unscoped
        return [
            self.rules[rule_id]
            for rule_id in ids
            if event_matches_logsource(self.rules[rule_id], event)
        ]

    def correlations_referencing(self, rule_id: str) -> List[SigmaCorrelationRule]:
        out = []
        for correlation in self.correlations.values():
            if rule_id in {self.rule_id_for(ref) for ref in correlation.rule_refs}:
                out.append(correlation)
        return out

    def unresolved_references(self) -> List[Tuple[str, str]]:
        """``(correlation_id, reference)`` pairs that point at nothing."""
        problems = []
        for correlation in self.correlations.values():
            for reference in correlation.rule_refs:
                if self.resolve(reference) is None:
                    problems.append((correlation.id, reference))
        return problems

    def __len__(self) -> int:
        return len(self.rules) + len(self.correlations)

    @property
    def stateful_rules(self) -> List[SigmaRule]:
        return [rule for rule in self.rules.values() if rule.is_stateful]


def iter_rule_files(paths: Union[str, Path, Sequence[Union[str, Path]]]) -> Iterator[Path]:
    """Yield every rule file under ``paths``, skipping rule *test* files."""
    if isinstance(paths, (str, Path)):
        paths = [paths]
    for entry in paths:
        root = Path(entry)
        if root.is_file():
            if root.suffix.lower() in RULE_SUFFIXES and not is_test_file(root):
                yield root
            continue
        if not root.exists():
            continue
        for candidate in sorted(root.rglob("*")):
            if (
                candidate.is_file()
                and candidate.suffix.lower() in RULE_SUFFIXES
                and not is_test_file(candidate)
                and "tests" not in candidate.parts[:-1]
            ):
                yield candidate


def is_test_file(path: Path) -> bool:
    name = path.name.lower()
    return any(name.endswith(marker) for marker in TEST_MARKERS)


def load_documents(path: Path) -> List[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [doc for doc in yaml.safe_load_all(handle) if isinstance(doc, dict)]


def load_ruleset(
    paths: Union[str, Path, Sequence[Union[str, Path]]] = "detections",
    *,
    min_level: Optional[str] = None,
    include_deprecated: bool = False,
    strict: bool = False,
) -> RuleSet:
    """Load, field-map and index every rule under ``paths``.

    ``strict=True`` re-raises the first parse error (used by CI); otherwise the
    bad rule is skipped and recorded in ``RuleSet.errors`` so one broken file
    cannot take the detection pipeline down.
    """
    ruleset = RuleSet()
    threshold = VALID_LEVELS.index(min_level.lower()) if min_level else 0
    for path in iter_rule_files(paths):
        try:
            documents = load_documents(path)
        except yaml.YAMLError as exc:
            if strict:
                raise SigmaParseError("invalid YAML: %s" % exc, str(path)) from exc
            ruleset.errors.append((str(path), "invalid YAML: %s" % exc))
            continue
        for document in documents:
            try:
                rule = parse_rule_document(document, str(path))
                if not include_deprecated and rule.status in {"deprecated", "unsupported"}:
                    continue
                if VALID_LEVELS.index(rule.level) < threshold:
                    continue
                if isinstance(rule, SigmaRule):
                    rule = apply_field_mapping(rule)
                ruleset.add(rule)
            except SigmaError as exc:
                if strict:
                    raise
                log.warning("skipping rule", extra={"path": str(path), "error": str(exc)})
                ruleset.errors.append((str(path), str(exc)))
    unresolved = ruleset.unresolved_references()
    if unresolved:
        messages = ["%s -> %s" % pair for pair in unresolved]
        if strict:
            raise SigmaParseError("unresolved correlation references: %s" % ", ".join(messages))
        ruleset.errors.extend(("correlation:%s" % cid, "unresolved reference %r" % ref)
                              for cid, ref in unresolved)
    log.info(
        "loaded ruleset",
        extra={"rules": len(ruleset.rules), "correlations": len(ruleset.correlations),
               "errors": len(ruleset.errors)},
    )
    return ruleset


def load_rule_tests(rule_path: Union[str, Path]) -> List[Dict[str, Any]]:
    """Load the ``*.tests.yml`` companion file for a rule, if present."""
    path = Path(rule_path)
    for marker in (".tests.yml", ".tests.yaml"):
        test_path = path.parent / (path.stem + marker)
        if test_path.exists():
            documents = load_documents(test_path)
            cases: List[Dict[str, Any]] = []
            for document in documents:
                cases.extend(document.get("tests") or [])
            return cases
    return []


def test_file_for(rule_path: Union[str, Path]) -> Optional[Path]:
    path = Path(rule_path)
    for marker in (".tests.yml", ".tests.yaml"):
        candidate = path.parent / (path.stem + marker)
        if candidate.exists():
            return candidate
    return None
