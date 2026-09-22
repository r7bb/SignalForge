"""Compile Sigma rules to OpenSearch Query DSL.

Used for retro-hunting ("run this new detection over the last 30 days") and by
the dashboard's rule-preview endpoint.  Live detection uses the streaming
evaluator instead; both walk the same AST and the same compiled matchers, so a
rule cannot mean two different things in the two paths.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .condition import And, Node, Not, Or, SearchRef, Wildcard
from .errors import SigmaParseError
from .matching import _WILDCARD_RE, FieldMatcher, KeywordMatcher
from .pipeline import logsource_filter
from .rule import Search, SigmaRule

#: Fields stored as OpenSearch ``ip`` type - CIDR terms work natively there.
IP_FIELDS = {"src_endpoint.ip", "dst_endpoint.ip", "device.ip"}


def _field_query(matcher: FieldMatcher) -> Dict[str, Any]:
    field_name = matcher.field
    modifiers = matcher.modifiers

    if "exists" in modifiers:
        wants = str(matcher.values[0]).lower() in {"true", "yes", "1"}
        clause: Dict[str, Any] = {"exists": {"field": field_name}}
        return clause if wants else {"bool": {"must_not": clause}}

    if "fieldref" in modifiers:
        # OpenSearch cannot compare two fields without a script.
        script = " || ".join(
            "doc['%s'].size()!=0 && doc['%s'].size()!=0 && doc['%s'].value==doc['%s'].value"
            % (field_name, str(v), field_name, str(v))
            for v in matcher.values
        )
        return {"script": {"script": {"source": script, "lang": "painless"}}}

    if "cidr" in modifiers:
        clauses: List[Dict[str, Any]] = [
            {"term": {field_name: str(value)}} for value in matcher.values
        ]
        if field_name not in IP_FIELDS:
            clauses = [
                {"prefix": {field_name: str(value).split("/", 1)[0].rstrip("0.")}}
                for value in matcher.values
            ]
        return _combine(clauses, matcher.is_all)

    if "re" in modifiers:
        flags = "CASE_INSENSITIVE" if "i" in modifiers else None
        clauses = []
        for value in matcher.values:
            regexp: Dict[str, Any] = {"value": str(value)}
            if flags:
                regexp["case_insensitive"] = True
            clauses.append({"regexp": {field_name: regexp}})
        return _combine(clauses, matcher.is_all)

    for comparison, operator in (("lt", "lt"), ("lte", "lte"), ("gt", "gt"), ("gte", "gte")):
        if comparison in modifiers:
            clauses = [{"range": {field_name: {operator: value}}} for value in matcher.values]
            return _combine(clauses, matcher.is_all)

    clauses = []
    null_clause: Optional[Dict[str, Any]] = None
    for value in matcher.expanded_values():
        if value is None:
            null_clause = {"bool": {"must_not": {"exists": {"field": field_name}}}}
            continue
        if isinstance(value, bool):
            clauses.append({"term": {field_name: value}})
            continue
        if isinstance(value, (int, float)):
            clauses.append({"term": {field_name: value}})
            continue
        text = str(value)
        if "contains" in modifiers:
            text = "*%s*" % text
        elif "startswith" in modifiers:
            text = "%s*" % text
        elif "endswith" in modifiers:
            text = "*%s" % text
        if _WILDCARD_RE.search(text):
            clauses.append(
                {
                    "wildcard": {
                        field_name: {"value": text, "case_insensitive": not matcher.case_sensitive}
                    }
                }
            )
        else:
            clauses.append(
                {
                    "term": {
                        field_name: {"value": text, "case_insensitive": not matcher.case_sensitive}
                    }
                }
            )
    if null_clause is not None:
        clauses.append(null_clause)
    if not clauses:
        raise SigmaParseError("field %r has no comparable values" % field_name)
    return _combine(clauses, matcher.is_all)


def _keyword_query(matcher: KeywordMatcher) -> Dict[str, Any]:
    clauses = [
        {
            "query_string": {
                "query": "*%s*" % str(value).strip("*"),
                "fields": ["*"],
                "analyze_wildcard": True,
            }
        }
        for value in matcher.values
    ]
    return _combine(clauses, False)


def _combine(clauses: List[Dict[str, Any]], require_all: bool) -> Dict[str, Any]:
    if len(clauses) == 1:
        return clauses[0]
    if require_all:
        return {"bool": {"filter": clauses}}
    return {"bool": {"should": clauses, "minimum_should_match": 1}}


def _search_query(search: Search) -> Dict[str, Any]:
    group_queries = []
    for group in search.groups:
        clauses = [
            _keyword_query(matcher)
            if isinstance(matcher, KeywordMatcher)
            else _field_query(matcher)
            for matcher in group
        ]
        group_queries.append(clauses[0] if len(clauses) == 1 else {"bool": {"filter": clauses}})
    if len(group_queries) == 1:
        return group_queries[0]
    return {"bool": {"should": group_queries, "minimum_should_match": 1}}


def _node_query(node: Node, searches: Dict[str, Search]) -> Dict[str, Any]:
    if isinstance(node, SearchRef):
        search = searches.get(node.name)
        if search is None:
            raise SigmaParseError("condition references unknown search %r" % node.name)
        return _search_query(search)
    if isinstance(node, Wildcard):
        clauses = [_search_query(searches[name]) for name in node.resolved]
        return _combine(clauses, node.quantifier == "all")
    if isinstance(node, And):
        return {"bool": {"filter": [_node_query(child, searches) for child in node.children]}}
    if isinstance(node, Or):
        return {
            "bool": {
                "should": [_node_query(child, searches) for child in node.children],
                "minimum_should_match": 1,
            }
        }
    if isinstance(node, Not):
        return {"bool": {"must_not": [_node_query(node.child, searches)]}}
    raise SigmaParseError("unknown condition node %r" % type(node).__name__)


def compile_rule(
    rule: SigmaRule,
    *,
    tenant: Optional[str] = None,
    earliest: Optional[str] = None,
    latest: Optional[str] = None,
    size: int = 100,
) -> Dict[str, Any]:
    """Return a complete OpenSearch search body for a rule.

    Stateful rules (``| count() by field >= N``) additionally get a ``terms``
    aggregation with ``min_doc_count`` so the threshold is applied server-side.
    """
    filters: List[Dict[str, Any]] = [_node_query(rule.condition.expression, rule.searches)]

    logsource = logsource_filter(rule)
    class_uids = logsource.get("class_uid")
    if class_uids:
        filters.append({"terms": {"class_uid": list(class_uids)}})
    if logsource.get("product"):
        filters.append(
            {
                "term": {
                    "metadata.product.vendor_name": {
                        "value": logsource["product"],
                        "case_insensitive": True,
                    }
                }
            }
        )
    if logsource.get("service"):
        filters.append(
            {
                "term": {
                    "metadata.log_name": {"value": logsource["service"], "case_insensitive": True}
                }
            }
        )
    if tenant:
        filters.append({"term": {"sf_tenant": tenant}})
    if earliest or latest:
        time_range: Dict[str, Any] = {}
        if earliest:
            time_range["gte"] = earliest
        if latest:
            time_range["lte"] = latest
        filters.append({"range": {"time": time_range}})

    body: Dict[str, Any] = {
        "size": size,
        "query": {"bool": {"filter": filters}},
        "sort": [{"time": {"order": "desc"}}],
        "_source": True,
    }

    aggregation = rule.condition.aggregation
    if aggregation is not None:
        group_by = aggregation.group_by or "sf_tenant"
        threshold = int(aggregation.threshold)
        min_doc_count = threshold if aggregation.operator == ">=" else threshold + 1
        if aggregation.function == "count" and aggregation.field:
            body["aggs"] = {
                "grouped": {
                    "terms": {"field": group_by, "size": 100},
                    "aggs": {
                        "distinct": {"cardinality": {"field": aggregation.field}},
                        "threshold": {
                            "bucket_selector": {
                                "buckets_path": {"value": "distinct"},
                                "script": "params.value %s %s"
                                % (_script_operator(aggregation.operator), threshold),
                            }
                        },
                    },
                }
            }
        else:
            body["aggs"] = {
                "grouped": {
                    "terms": {
                        "field": group_by,
                        "size": 100,
                        "min_doc_count": max(min_doc_count, 1),
                        "order": {"_count": "desc"},
                    }
                }
            }
        body["size"] = min(size, 10)
    return body


def _script_operator(operator: str) -> str:
    return {"==": "==", "!=": "!=", ">": ">", ">=": ">=", "<": "<", "<=": "<="}[operator]
