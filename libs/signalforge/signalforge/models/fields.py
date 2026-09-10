"""Introspect the OCSF model for the set of valid field paths.

The rule linter uses this to reject detections that reference a field which can
never exist (a typo like ``src_endpoint.adress`` silently never fires, which is
the worst failure mode a detection can have).
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Dict, List, Optional, Set, Union, get_args, get_origin

from pydantic import BaseModel

from .ocsf import OcsfEvent

#: Paths below these prefixes are free-form by design.
OPEN_PREFIXES = ("unmapped.", "enrichments.", "metadata.", "file.hashes.", "sf_")

MAX_DEPTH = 4


def _unwrap(annotation: Any) -> List[Any]:
    """Strip Optional/List/Dict wrappers down to the underlying type(s)."""
    origin = get_origin(annotation)
    if origin is Union:
        return [arg for arg in get_args(annotation) if arg is not type(None)]  # noqa: E721
    if origin in (list, set, tuple, dict):
        args = get_args(annotation)
        return list(args[-1:]) if args else []
    return [annotation]


def _walk(model: Any, prefix: str, depth: int, seen: Set[Any], out: Set[str]) -> None:
    if depth > MAX_DEPTH or not (isinstance(model, type) and issubclass(model, BaseModel)):
        return
    if (model, prefix) in seen:
        return
    seen.add((model, prefix))
    for name, info in model.model_fields.items():
        path = "%s%s" % (prefix, name)
        out.add(path)
        for candidate in _unwrap(info.annotation):
            if isinstance(candidate, type) and issubclass(candidate, BaseModel):
                _walk(candidate, path + ".", depth + 1, seen, out)


@lru_cache(maxsize=1)
def ocsf_field_paths() -> frozenset:
    """Every dotted field path an OCSF event can expose."""
    out: Set[str] = set()
    _walk(OcsfEvent, "", 0, set(), out)
    return frozenset(out)


def is_known_field(path: str) -> bool:
    """True when ``path`` is a real OCSF field (or an intentionally open one)."""
    if path in ocsf_field_paths():
        return True
    if path.startswith(OPEN_PREFIXES):
        return True
    # Array indices (``resources[0].name``) collapse to the base path.
    normalized = path.split("[", 1)[0]
    return normalized in ocsf_field_paths()
