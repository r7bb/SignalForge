"""Sigma parsing / validation errors."""

from __future__ import annotations

from typing import List, Optional


class SigmaError(Exception):
    """Base class for every Sigma problem SignalForge reports."""


class SigmaParseError(SigmaError):
    def __init__(self, message: str, rule_path: Optional[str] = None) -> None:
        super().__init__(message if not rule_path else "%s (%s)" % (message, rule_path))
        self.message = message
        self.rule_path = rule_path


class SigmaConditionError(SigmaParseError):
    """The ``condition`` expression is malformed or references unknown searches."""


class SigmaValidationError(SigmaError):
    """Raised by the rule linter; carries every problem found."""

    def __init__(self, problems: List[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems
