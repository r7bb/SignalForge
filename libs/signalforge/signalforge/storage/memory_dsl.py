"""A tiny OpenSearch Query DSL interpreter for the in-memory event store.

It supports exactly the constructs the Sigma backend and the platform's own
queries emit (``bool``, ``term``, ``terms``, ``wildcard``, ``regexp``,
``range``, ``exists``, ``query_string``, plus ``terms``/``cardinality``
aggregations with ``min_doc_count`` and ``bucket_selector``).  That keeps
retro-hunting and the rule-preview endpoint working in tests and on a laptop
without a cluster, while production runs the same body against OpenSearch.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Dict, List, Optional, Sequence

from ..models.ocsf import OcsfEvent, flatten_event
from ..sigma.matching import glob_to_regex


def execute_dsl(body: Dict[str, Any], events: Sequence[OcsfEvent]) -> Dict[str, Any]:
    """Run a search body against a list of events, returning an OpenSearch-shaped response."""
    flattened = [(event, flatten_event(event)) for event in events]
    query = body.get("query") or {"match_all": {}}
    matches = [(event, flat) for event, flat in flattened if _match(query, flat, event)]

    ascending = False
    for sort_clause in body.get("sort") or []:
        if isinstance(sort_clause, dict):
            for _, options in sort_clause.items():
                ascending = (options or {}).get("order", "desc") == "asc"
    matches.sort(key=lambda pair: (pair[0].time, pair[0].sf_ingested_at), reverse=not ascending)

    size = int(body.get("size", 10))
    offset = int(body.get("from", 0))
    window = matches[offset : offset + size] if size else []
    response: Dict[str, Any] = {
        "took": 0,
        "timed_out": False,
        "hits": {
            "total": {"value": len(matches), "relation": "eq"},
            "hits": [
                {
                    "_index": "sf-events-memory",
                    "_id": event.sf_dedup_key,
                    "_source": event.to_document(),
                }
                for event, _ in window
            ],
        },
    }
    aggs = body.get("aggs") or body.get("aggregations")
    if aggs:
        response["aggregations"] = {name: _aggregate(spec, matches) for name, spec in aggs.items()}
    return response


# --------------------------------------------------------------------------- #
# Query clauses
# --------------------------------------------------------------------------- #
def _match(clause: Dict[str, Any], flat: Dict[str, Any], event: OcsfEvent) -> bool:
    if not clause:
        return True
    kind, options = next(iter(clause.items()))
    if kind == "match_all":
        return True
    if kind == "bool":
        return _match_bool(options or {}, flat, event)
    if kind == "term":
        return _match_term(options, flat)
    if kind == "terms":
        field, values = next(iter(options.items()))
        observed = _values(flat, field)
        return any(_eq(o, v, False) for o in observed for v in values)
    if kind == "wildcard":
        field, spec = next(iter(options.items()))
        pattern, case_insensitive = _spec(spec)
        regex = glob_to_regex(str(pattern), case_sensitive=not case_insensitive)
        return any(regex.match(str(o)) for o in _values(flat, field) if o is not None)
    if kind == "prefix":
        field, spec = next(iter(options.items()))
        prefix, case_insensitive = _spec(spec)
        return any(
            str(o).lower().startswith(str(prefix).lower())
            if case_insensitive
            else str(o).startswith(str(prefix))
            for o in _values(flat, field)
            if o is not None
        )
    if kind == "regexp":
        field, spec = next(iter(options.items()))
        pattern, case_insensitive = _spec(spec)
        regex = re.compile(str(pattern), re.IGNORECASE if case_insensitive else 0)
        return any(regex.search(str(o)) for o in _values(flat, field) if o is not None)
    if kind == "range":
        field, bounds = next(iter(options.items()))
        return _match_range(field, bounds, flat, event)
    if kind == "exists":
        field = options.get("field")
        return any(o is not None for o in _values(flat, field))
    if kind == "query_string":
        needle = str(options.get("query", "")).strip("*").lower()
        haystack = json.dumps(event.to_document(), default=str).lower()
        return needle in haystack
    if kind == "script":
        # Painless scripts (fieldref) are not emulated; treat as non-matching.
        return False
    raise ValueError("unsupported query clause %r" % kind)


def _match_bool(options: Dict[str, Any], flat: Dict[str, Any], event: OcsfEvent) -> bool:
    for clause in _as_list(options.get("filter")) + _as_list(options.get("must")):
        if not _match(clause, flat, event):
            return False
    for clause in _as_list(options.get("must_not")):
        if _match(clause, flat, event):
            return False
    should = _as_list(options.get("should"))
    if should:
        minimum = int(options.get("minimum_should_match", 1))
        hits = sum(1 for clause in should if _match(clause, flat, event))
        if hits < minimum:
            return False
    return True


def _match_term(options: Dict[str, Any], flat: Dict[str, Any]) -> bool:
    field, spec = next(iter(options.items()))
    value, case_insensitive = _spec(spec)
    observed = _values(flat, field)
    # An ip-typed field accepts CIDR notation in a term query.
    if isinstance(value, str) and "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
            for item in observed:
                try:
                    if ipaddress.ip_address(str(item)) in network:
                        return True
                except ValueError:
                    continue
            return False
        except ValueError:
            pass
    return any(_eq(item, value, not case_insensitive) for item in observed)


def _match_range(
    field: str, bounds: Dict[str, Any], flat: Dict[str, Any], event: OcsfEvent
) -> bool:
    for item in _values(flat, field):
        if item is None:
            continue
        left = _comparable(item)
        if left is None:
            continue
        if all(_within_bound(left, operator, raw) for operator, raw in bounds.items()):
            return True
    return False


#: Range operator -> the comparison it asserts.
_RANGE_OPERATORS = {
    "gte": lambda left, right: left >= right,
    "gt": lambda left, right: left > right,
    "lte": lambda left, right: left <= right,
    "lt": lambda left, right: left < right,
}


def _within_bound(left: Any, operator: str, raw: Any) -> bool:
    right = _comparable(raw)
    if right is None or not isinstance(right, type(left)):
        right = _coerce_like(left, raw)
    if right is None:
        return False
    compare = _RANGE_OPERATORS.get(operator)
    # An unrecognised bound is ignored rather than treated as a match.
    return compare(left, right) if compare else False


# --------------------------------------------------------------------------- #
# Aggregations
# --------------------------------------------------------------------------- #
def _aggregate(spec: Dict[str, Any], matches: Sequence[Any]) -> Dict[str, Any]:
    terms = spec.get("terms")
    if not terms:
        return {}
    field = terms["field"]
    size = int(terms.get("size", 10))
    min_doc_count = int(terms.get("min_doc_count", 1))
    buckets: Dict[Any, List[Any]] = {}
    for event, flat in matches:
        for value in _values(flat, field):
            if value is None:
                continue
            buckets.setdefault(value, []).append((event, flat))

    sub_aggs = spec.get("aggs") or {}
    selector = None
    cardinality_field = None
    for name, sub in sub_aggs.items():
        if "cardinality" in sub:
            cardinality_field = (name, sub["cardinality"]["field"])
        if "bucket_selector" in sub:
            selector = sub["bucket_selector"]

    out = []
    for key, rows in buckets.items():
        bucket: Dict[str, Any] = {"key": key, "doc_count": len(rows)}
        if cardinality_field:
            name, card_field = cardinality_field
            distinct = {
                value
                for _, flat in rows
                for value in _values(flat, card_field)
                if value is not None
            }
            bucket[name] = {"value": len(distinct)}
        if bucket["doc_count"] < min_doc_count:
            continue
        if selector and not _bucket_selector(selector, bucket):
            continue
        out.append(bucket)
    out.sort(key=lambda bucket: bucket["doc_count"], reverse=True)
    return {"buckets": out[:size]}


_SELECTOR_RE = re.compile(r"params\.(\w+)\s*(>=|<=|==|!=|>|<)\s*([\d.]+)")


def _bucket_selector(selector: Dict[str, Any], bucket: Dict[str, Any]) -> bool:
    script = selector.get("script", "")
    if isinstance(script, dict):
        script = script.get("source", "")
    match = _SELECTOR_RE.search(str(script))
    if not match:
        return True
    param, operator, threshold = match.group(1), match.group(2), float(match.group(3))
    path = str((selector.get("buckets_path") or {}).get(param, param) or param)
    value = bucket.get(path)
    if isinstance(value, dict):
        value = value.get("value")
    if value is None:
        return False
    value = float(value)
    return {
        ">": value > threshold,
        ">=": value >= threshold,
        "<": value < threshold,
        "<=": value <= threshold,
        "==": value == threshold,
        "!=": value != threshold,
    }[operator]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _as_list(value: Any) -> List[Dict[str, Any]]:
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def _spec(spec: Any) -> Any:
    """Unpack ``{"value": x, "case_insensitive": true}`` or a bare value."""
    if isinstance(spec, dict):
        return spec.get("value"), bool(spec.get("case_insensitive", False))
    return spec, False


def _values(flat: Dict[str, Any], field: Optional[str]) -> List[Any]:
    """Every value at ``field``, as a list. Never ``None``: a missing field is
    an empty list, which is what the callers iterate over."""
    if not field or field not in flat:
        return []
    value = flat[field]
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _eq(left: Any, right: Any, case_sensitive: bool) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return bool(left) == bool(right)
    if isinstance(right, (int, float)) and not isinstance(right, str):
        try:
            return float(left) == float(right)
        except (TypeError, ValueError):
            return False
    if case_sensitive:
        return str(left) == str(right)
    return str(left).lower() == str(right).lower()


def _comparable(value: Any) -> Any:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value)
    try:
        return float(text)
    except ValueError:
        pass
    from ..timeutil import parse_time

    parsed = parse_time(text)
    return parsed


def _coerce_like(left: Any, raw: Any) -> Any:
    if isinstance(left, float):
        try:
            return float(raw)
        except (TypeError, ValueError):
            return None
    from ..timeutil import parse_time

    if isinstance(raw, str) and raw.startswith("now"):
        # Relative time windows are resolved by the caller in production; treat
        # "now-..." as "no lower bound" in the in-memory backend.
        return None
    return parse_time(raw)
