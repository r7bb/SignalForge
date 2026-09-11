"""Version comparison and range matching for dependency vulnerabilities.

Deliberately small and predictable: versions are split into numeric and
alphabetic segments and compared segment by segment, with a pre-release suffix
ordering below the release it belongs to (``2.4.0-rc1 < 2.4.0``).  That covers
semver, PEP 440's common shapes and Maven-style versions well enough to decide
"is this installed version inside the affected range", which is the only
question the SBOM feature asks.

Range syntax (as used by OSV/GHSA advisories, space-separated constraints that
must all hold)::

    ">=2.4.0 <2.4.2"    ">2.0"    "==1.2.3"    "<3"    "*"
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple, Union

_SEGMENT_RE = re.compile(r"(\d+|[a-zA-Z]+)")
_CONSTRAINT_RE = re.compile(r"^(>=|<=|==|!=|=|>|<|~>|\^)?\s*(.+)$")

#: Suffixes that sort *below* the plain release.
_PRERELEASE_RANK = {
    "dev": -5,
    "alpha": -4,
    "a": -4,
    "beta": -3,
    "b": -3,
    "rc": -2,
    "pre": -2,
    "preview": -2,
    "snapshot": -2,
}

Segment = Union[int, str]


def parse_version(version: str) -> Tuple[List[Segment], List[Segment]]:
    """Split ``2.4.1-rc2+build5`` into release and pre-release segments."""
    text = str(version or "").strip().lstrip("vV")
    text = text.split("+", 1)[0]  # build metadata is not ordered
    if "-" in text:
        release_text, _, pre_text = text.partition("-")
    else:
        release_text, pre_text = text, ""
    release = [_coerce(part) for part in _SEGMENT_RE.findall(release_text)]
    prerelease = [_coerce(part) for part in _SEGMENT_RE.findall(pre_text)]
    return release, prerelease


def compare_versions(left: str, right: str) -> int:
    """Return -1, 0 or 1 for ``left`` vs ``right``."""
    left_release, left_pre = parse_version(left)
    right_release, right_pre = parse_version(right)

    order = _compare_segments(left_release, right_release)
    if order != 0:
        return order
    # Equal releases: any pre-release sorts below the plain release.
    if left_pre and not right_pre:
        return -1
    if right_pre and not left_pre:
        return 1
    return _compare_segments(left_pre, right_pre)


def _compare_segments(left: List[Segment], right: List[Segment]) -> int:
    for index in range(max(len(left), len(right))):
        a = left[index] if index < len(left) else 0
        b = right[index] if index < len(right) else 0
        rank_a, rank_b = _rank(a), _rank(b)
        if rank_a != rank_b:
            return -1 if rank_a < rank_b else 1
        if isinstance(a, int) and isinstance(b, int):
            if a != b:
                return -1 if a < b else 1
        else:
            sa, sb = str(a).lower(), str(b).lower()
            if sa != sb:
                return -1 if sa < sb else 1
    return 0


def _rank(segment: Segment) -> int:
    """Numeric segments outrank alphabetic ones; known pre-release words sort low."""
    if isinstance(segment, int):
        return 0
    return _PRERELEASE_RANK.get(str(segment).lower(), 1)


def _coerce(part: str) -> Segment:
    return int(part) if part.isdigit() else part


def satisfies(version: str, constraint: str) -> bool:
    """Does ``version`` satisfy a single constraint such as ``>=2.4.0``?"""
    constraint = constraint.strip()
    if not constraint or constraint in {"*", "any"}:
        return True
    match = _CONSTRAINT_RE.match(constraint)
    if not match:
        return False
    operator, target = match.group(1) or "==", match.group(2).strip()
    order = compare_versions(version, target)
    if operator in {"==", "="}:
        return order == 0
    if operator == "!=":
        return order != 0
    if operator == ">":
        return order > 0
    if operator == ">=":
        return order >= 0
    if operator == "<":
        return order < 0
    if operator == "<=":
        return order <= 0
    if operator == "^":  # caret: same major
        return order >= 0 and _same_index(version, target, 0)
    if operator == "~>":  # tilde: same major.minor
        return order >= 0 and _same_index(version, target, 0) and _same_index(version, target, 1)
    return False


def matches_range(version: Optional[str], spec: Optional[str]) -> bool:
    """Does ``version`` fall inside a space-separated range spec?"""
    if not version:
        return False
    if not spec or spec.strip() in {"*", "any"}:
        return True
    constraints = [part for part in re.split(r"[,\s]+", spec.strip()) if part]
    return all(satisfies(version, constraint) for constraint in constraints)


def is_fixed_by(version: Optional[str], fixed_version: Optional[str]) -> bool:
    """True when the installed version already includes the fix."""
    if not version or not fixed_version:
        return False
    return compare_versions(version, fixed_version) >= 0


def _same_index(version: str, target: str, index: int) -> bool:
    left, _ = parse_version(version)
    right, _ = parse_version(target)
    a = left[index] if index < len(left) else 0
    b = right[index] if index < len(right) else 0
    return a == b
