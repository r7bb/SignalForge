"""Logsource pipeline: bridge Sigma's vendor vocabulary and the OCSF schema.

Two jobs, mirroring what a pySigma processing pipeline does:

1. **Field mapping** - community Sigma rules speak Windows/AWS/Okta field names
   (``TargetUserName``, ``sourceIPAddress``, ``eventType``).  Those are rewritten
   to OCSF paths so one detection works across every source.
2. **Logsource resolution** - a rule scoped to ``category: authentication`` must
   only see OCSF Authentication events.  The pipeline turns the ``logsource``
   block into a concrete event filter used both by the streaming evaluator and
   by the OpenSearch backend.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Dict, List, Optional

from ..models.ocsf import ClassUid, OcsfEvent
from .matching import FieldMatcher
from .rule import Search, SigmaRule

#: Sigma logsource category -> OCSF class_uid set.
CATEGORY_TO_CLASS: Dict[str, List[int]] = {
    "authentication": [ClassUid.AUTHENTICATION],
    "auth": [ClassUid.AUTHENTICATION],
    "logon": [ClassUid.AUTHENTICATION],
    "iam": [
        ClassUid.ACCOUNT_CHANGE,
        ClassUid.AUTHORIZE_SESSION,
        ClassUid.USER_ACCESS_MANAGEMENT,
        ClassUid.GROUP_MANAGEMENT,
        ClassUid.ENTITY_MANAGEMENT,
    ],
    "account_change": [ClassUid.ACCOUNT_CHANGE],
    "identity": [
        ClassUid.ACCOUNT_CHANGE,
        ClassUid.USER_ACCESS_MANAGEMENT,
        ClassUid.GROUP_MANAGEMENT,
    ],
    "privilege": [
        ClassUid.USER_ACCESS_MANAGEMENT,
        ClassUid.AUTHORIZE_SESSION,
        ClassUid.GROUP_MANAGEMENT,
    ],
    "process_creation": [ClassUid.PROCESS_ACTIVITY],
    "process": [ClassUid.PROCESS_ACTIVITY],
    "file_event": [ClassUid.FILE_SYSTEM_ACTIVITY],
    "file_access": [ClassUid.FILE_SYSTEM_ACTIVITY],
    "api": [ClassUid.API_ACTIVITY],
    "cloudtrail": [ClassUid.API_ACTIVITY, ClassUid.DATASTORE_ACTIVITY],
    "datastore": [ClassUid.DATASTORE_ACTIVITY],
    "database": [ClassUid.DATASTORE_ACTIVITY],
    "webserver": [ClassUid.HTTP_ACTIVITY, ClassUid.WEB_RESOURCES_ACTIVITY],
    "proxy": [ClassUid.HTTP_ACTIVITY],
    "application": [
        ClassUid.API_ACTIVITY,
        ClassUid.HTTP_ACTIVITY,
        ClassUid.WEB_RESOURCES_ACTIVITY,
        ClassUid.DATASTORE_ACTIVITY,
    ],
}

#: Vendor product name (as seen in ``metadata.product``) -> Sigma product token.
PRODUCT_ALIASES: Dict[str, str] = {
    "linux host": "linux",
    "linux": "linux",
    "aws cloudtrail": "aws",
    "aws": "aws",
    "okta system log": "okta",
    "okta": "okta",
    "signalforge lab app": "app",
    "signalforge": "app",
}

#: Sigma field name -> OCSF field path.  Case-insensitive on lookup.
FIELD_ALIASES: Dict[str, str] = {
    # identity
    "user": "actor.user.name",
    "username": "actor.user.name",
    "subjectusername": "actor.user.name",
    "subjectusersid": "actor.user.uid",
    "actor": "actor.user.name",
    "useridentity.username": "actor.user.name",
    "useridentity.type": "actor.user.type",
    "useridentity.principalid": "actor.user.uid",
    "targetusername": "user.name",
    "target_user": "user.name",
    "targetuser": "user.name",
    "email": "actor.user.email_addr",
    "useremail": "actor.user.email_addr",
    "group": "group.name",
    "groupname": "group.name",
    "targetgroupname": "group.name",
    # network / host
    "sourceip": "src_endpoint.ip",
    "source_ip": "src_endpoint.ip",
    "src_ip": "src_endpoint.ip",
    "srcip": "src_endpoint.ip",
    "ipaddress": "src_endpoint.ip",
    "clientip": "src_endpoint.ip",
    "sourceipaddress": "src_endpoint.ip",
    "sourceport": "src_endpoint.port",
    "destinationip": "dst_endpoint.ip",
    "dst_ip": "dst_endpoint.ip",
    "destinationport": "dst_endpoint.port",
    "computer": "device.hostname",
    "computername": "device.hostname",
    "hostname": "device.hostname",
    "host": "device.hostname",
    "workstationname": "device.hostname",
    # process / file
    "commandline": "actor.process.cmd_line",
    "image": "actor.process.name",
    "processname": "actor.process.name",
    "parentimage": "actor.process.parent_process.name",
    "targetfilename": "file.path",
    "filename": "file.name",
    "filepath": "file.path",
    "sha256": "file.hashes.sha256",
    "md5": "file.hashes.md5",
    # cloud / api
    "eventname": "api.operation",
    "eventsource": "api.service.name",
    "operation": "api.operation",
    "requestparameters.username": "user.name",
    "awsregion": "device.region",
    "useragent": "http_request.user_agent",
    "errorcode": "status_code",
    "eventtype": "unmapped.eventType",
    # http
    "c-uri": "http_request.url",
    "cs-uri": "http_request.url",
    "uri": "http_request.url",
    "url": "http_request.url",
    "method": "http_request.http_method",
    "cs-method": "http_request.http_method",
    "sc-status": "http_response.code",
    "statuscode": "http_response.code",
    # outcome
    "outcome": "status",
    "result": "status",
    "eventid": "metadata.uid",
    "logontype": "logon_type",
    "mfa": "is_mfa",
}


def resolve_field(field_name: str) -> str:
    """Map a Sigma field name onto its OCSF path (identity if already OCSF)."""
    key = field_name.strip()
    if key in FIELD_ALIASES:
        return FIELD_ALIASES[key]
    lowered = key.lower()
    if lowered in FIELD_ALIASES:
        return FIELD_ALIASES[lowered]
    return key


def apply_field_mapping(rule: SigmaRule) -> SigmaRule:
    """Return the rule with every search field rewritten to its OCSF path."""
    mapped_searches: Dict[str, Search] = {}
    for name, search in rule.searches.items():
        groups = []
        for group in search.groups:
            new_group = []
            for matcher in group:
                if isinstance(matcher, FieldMatcher):
                    resolved = resolve_field(matcher.field)
                    if resolved != matcher.field:
                        matcher = replace(matcher, field=resolved)
                new_group.append(matcher)
            groups.append(new_group)
        mapped_searches[name] = Search(name=name, groups=groups)
    rule.searches = mapped_searches
    return rule


def event_logsource(event: OcsfEvent) -> Dict[str, Optional[str]]:
    """The Sigma logsource triple an OCSF event belongs to."""
    category = None
    for name, class_uids in CATEGORY_TO_CLASS.items():
        if event.class_uid in class_uids and name in {
            "authentication",
            "iam",
            "process_creation",
            "file_event",
            "api",
            "datastore",
            "webserver",
        }:
            category = name
            break
    product_name = (event.metadata.product.name or "").lower()
    vendor_name = (event.metadata.product.vendor_name or "").lower()
    product = PRODUCT_ALIASES.get(product_name) or PRODUCT_ALIASES.get(vendor_name)
    service = event.metadata.log_name or event.metadata.product.feature
    return {
        "category": category,
        "product": product,
        "service": (service or "").lower() or None,
    }


def logsource_filter(rule: SigmaRule) -> Dict[str, Any]:
    """Concrete event filter implied by the rule's ``logsource`` block."""
    filters: Dict[str, Any] = {}
    logsource = rule.logsource
    if logsource.category:
        class_uids = CATEGORY_TO_CLASS.get(logsource.category)
        if class_uids:
            filters["class_uid"] = class_uids
        else:
            filters["_unknown_category"] = logsource.category
    if logsource.product:
        filters["product"] = logsource.product
    if logsource.service:
        filters["service"] = logsource.service
    return filters


def event_matches_logsource(rule: SigmaRule, event: OcsfEvent) -> bool:
    """Cheap prefilter: does this event belong to the rule's logsource?"""
    filters = logsource_filter(rule)
    if "_unknown_category" in filters:
        # Unknown category: fall back to the declared triple comparison.
        return rule.matches_logsource(event_logsource(event))
    class_uids = filters.get("class_uid")
    if class_uids and event.class_uid not in class_uids:
        return False
    observed = event_logsource(event)
    for key in ("product", "service"):
        expected = filters.get(key)
        if expected and (observed.get(key) or "") != expected:
            return False
    return True
