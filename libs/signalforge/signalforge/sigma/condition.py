"""Sigma ``condition`` expression parser.

Grammar (Sigma specification, plus the aggregation tail):

    condition   := expression [ "|" aggregation ]
    expression  := term { ("and" | "or") term }
    term        := [ "not" ] factor
    factor      := "(" expression ")"
                 | ("1" | "all") "of" ( "them" | pattern )
                 | identifier
    aggregation := "count" "(" [field] ")" ["by" field] operator number

Search identifiers may use ``*`` as a wildcard (``selection_*``).  The parser
produces a small typed AST that both the in-memory evaluator and the OpenSearch
backend walk, so the two paths can never drift on operator precedence.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from .errors import SigmaConditionError

_TOKEN_RE = re.compile(r"\s*(\(|\)|\||>=|<=|==|!=|>|<|[A-Za-z0-9_*?.\-]+)")

_OPERATORS = {">=", "<=", ">", "<", "==", "!="}


class Node:
    """Base AST node."""

    def identifiers(self) -> List[str]:
        return []


@dataclass(frozen=True)
class SearchRef(Node):
    name: str

    def identifiers(self) -> List[str]:
        return [self.name]


@dataclass(frozen=True)
class Wildcard(Node):
    """``1 of selection_*`` / ``all of them`` expansion, resolved at bind time."""

    pattern: str
    quantifier: str  # "any" | "all"
    resolved: Sequence[str] = field(default_factory=tuple)

    def identifiers(self) -> List[str]:
        return list(self.resolved)


@dataclass(frozen=True)
class And(Node):
    children: Sequence[Node]

    def identifiers(self) -> List[str]:
        return [i for child in self.children for i in child.identifiers()]


@dataclass(frozen=True)
class Or(Node):
    children: Sequence[Node]

    def identifiers(self) -> List[str]:
        return [i for child in self.children for i in child.identifiers()]


@dataclass(frozen=True)
class Not(Node):
    child: Node

    def identifiers(self) -> List[str]:
        return self.child.identifiers()


@dataclass(frozen=True)
class Aggregation:
    """``| count() by user > 5`` - evaluated statefully by the detection engine."""

    function: str = "count"
    field: Optional[str] = None
    group_by: Optional[str] = None
    operator: str = ">"
    threshold: float = 0.0

    def compare(self, value: float) -> bool:
        if self.operator == ">":
            return value > self.threshold
        if self.operator == ">=":
            return value >= self.threshold
        if self.operator == "<":
            return value < self.threshold
        if self.operator == "<=":
            return value <= self.threshold
        if self.operator in {"==", "="}:
            return value == self.threshold
        if self.operator == "!=":
            return value != self.threshold
        raise SigmaConditionError("unsupported aggregation operator %r" % self.operator)


@dataclass(frozen=True)
class ParsedCondition:
    expression: Node
    aggregation: Optional[Aggregation] = None
    source: str = ""

    @property
    def is_stateful(self) -> bool:
        return self.aggregation is not None


def tokenize(text: str) -> List[str]:
    tokens: List[str] = []
    position = 0
    while position < len(text):
        match = _TOKEN_RE.match(text, position)
        if not match:
            remainder = text[position:].strip()
            if not remainder:
                break
            raise SigmaConditionError("unexpected character at %r" % remainder[:12])
        tokens.append(match.group(1))
        position = match.end()
    return tokens


class _Parser:
    def __init__(self, tokens: List[str], available: Sequence[str]) -> None:
        self.tokens = tokens
        self.pos = 0
        self.available = list(available)

    # -- token helpers ----------------------------------------------------
    def peek(self) -> Optional[str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def next(self) -> Optional[str]:
        token = self.peek()
        if token is not None:
            self.pos += 1
        return token

    def expect(self, value: str) -> None:
        token = self.next()
        if token is None or token.lower() != value:
            raise SigmaConditionError("expected %r but found %r" % (value, token))

    # -- grammar ----------------------------------------------------------
    def parse_expression(self) -> Node:
        node = self.parse_and()
        children = [node]
        while (self.peek() or "").lower() == "or":
            self.next()
            children.append(self.parse_and())
        return Or(tuple(children)) if len(children) > 1 else node

    def parse_and(self) -> Node:
        node = self.parse_term()
        children = [node]
        while (self.peek() or "").lower() == "and":
            self.next()
            children.append(self.parse_term())
        return And(tuple(children)) if len(children) > 1 else node

    def parse_term(self) -> Node:
        token = self.peek()
        if token is not None and token.lower() == "not":
            self.next()
            return Not(self.parse_term())
        return self.parse_factor()

    def parse_factor(self) -> Node:
        token = self.next()
        if token is None:
            raise SigmaConditionError("unexpected end of condition")
        if token == "(":
            node = self.parse_expression()
            self.expect(")")
            return node
        lowered = token.lower()
        if lowered in {"1", "any", "all"}:
            nxt = (self.peek() or "").lower()
            if nxt == "of":
                self.next()
                quantifier = "all" if lowered == "all" else "any"
                target = self.next()
                if target is None:
                    raise SigmaConditionError("'%s of' must be followed by a target" % lowered)
                return self._expand(target, quantifier)
        if lowered in {"and", "or", ")", "|"}:
            raise SigmaConditionError("unexpected token %r in condition" % token)
        return SearchRef(token)

    def _expand(self, target: str, quantifier: str) -> Node:
        pattern = "*" if target.lower() == "them" else target
        matches = sorted(name for name in self.available if fnmatch.fnmatch(name, pattern))
        if not matches:
            raise SigmaConditionError(
                "'%s of %s' matches no search identifier" % (quantifier, target)
            )
        return Wildcard(pattern=pattern, quantifier=quantifier, resolved=tuple(matches))

    def parse_aggregation(self) -> Aggregation:
        function = (self.next() or "").lower()
        if function not in {"count", "min", "max", "sum", "avg"}:
            raise SigmaConditionError("unsupported aggregation function %r" % function)
        agg_field = None
        if self.peek() == "(":
            self.next()
            if self.peek() != ")":
                agg_field = self.next()
            self.expect(")")
        group_by = None
        if (self.peek() or "").lower() == "by":
            self.next()
            group_by = self.next()
        operator = self.next()
        if operator not in _OPERATORS:
            raise SigmaConditionError("expected comparison operator, found %r" % operator)
        raw_threshold = self.next()
        try:
            threshold = float(raw_threshold)  # type: ignore[arg-type]
        except (TypeError, ValueError) as exc:
            raise SigmaConditionError(
                "aggregation threshold must be numeric, got %r" % raw_threshold
            ) from exc
        return Aggregation(
            function=function,
            field=agg_field,
            group_by=group_by,
            operator=operator,
            threshold=threshold,
        )


def parse_condition(text: str, available_searches: Sequence[str]) -> ParsedCondition:
    """Parse a Sigma condition against the rule's search identifiers."""
    if not isinstance(text, str) or not text.strip():
        raise SigmaConditionError("condition must be a non-empty string")
    tokens = tokenize(text)
    if not tokens:
        raise SigmaConditionError("condition %r produced no tokens" % text)
    parser = _Parser(tokens, available_searches)
    expression = parser.parse_expression()
    aggregation = None
    if parser.peek() == "|":
        parser.next()
        aggregation = parser.parse_aggregation()
    if parser.peek() is not None:
        raise SigmaConditionError("trailing tokens in condition: %r" % parser.tokens[parser.pos :])
    unknown = sorted(set(expression.identifiers()) - set(available_searches))
    if unknown:
        raise SigmaConditionError(
            "condition references undefined search identifier(s): %s" % ", ".join(unknown)
        )
    return ParsedCondition(expression=expression, aggregation=aggregation, source=text)
