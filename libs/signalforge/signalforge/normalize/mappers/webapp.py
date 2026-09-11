"""SignalForge lab application audit log -> OCSF.

This is the shape the bundled demo application (and the telemetry generator)
emits: a flat JSON audit record.  It exercises the application-activity side of
the schema - API calls, token creation, role changes and data access.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ...models.ocsf import (
    Actor,
    Api,
    ApiRequest,
    ApiResponse,
    ApiService,
    ClassUid,
    Device,
    Endpoint,
    Group,
    HttpRequest,
    HttpResponse,
    OcsfEvent,
    RawLogRecord,
    Resource,
    Session,
    SeverityId,
    StatusId,
    User,
)
from ...timeutil import parse_time
from ..base import Mapper, NormalizationError, register

#: action -> (class_uid, activity_id, severity_id)
_ACTION_MAP: Dict[str, Any] = {
    "login": (ClassUid.AUTHENTICATION, 1, SeverityId.INFORMATIONAL),
    "login_failed": (ClassUid.AUTHENTICATION, 1, SeverityId.LOW),
    "logout": (ClassUid.AUTHENTICATION, 2, SeverityId.INFORMATIONAL),
    "mfa_challenge": (ClassUid.AUTHENTICATION, 6, SeverityId.INFORMATIONAL),
    "password_change": (ClassUid.ACCOUNT_CHANGE, 3, SeverityId.LOW),
    "password_reset": (ClassUid.ACCOUNT_CHANGE, 4, SeverityId.MEDIUM),
    "mfa_disabled": (ClassUid.ACCOUNT_CHANGE, 11, SeverityId.HIGH),
    "user_created": (ClassUid.ACCOUNT_CHANGE, 1, SeverityId.MEDIUM),
    "user_deleted": (ClassUid.ACCOUNT_CHANGE, 6, SeverityId.MEDIUM),
    "role_change": (ClassUid.USER_ACCESS_MANAGEMENT, 1, SeverityId.HIGH),
    "permission_revoke": (ClassUid.USER_ACCESS_MANAGEMENT, 2, SeverityId.LOW),
    "api_key_created": (ClassUid.ACCOUNT_CHANGE, 1, SeverityId.HIGH),
    "api_key_revoked": (ClassUid.ACCOUNT_CHANGE, 6, SeverityId.LOW),
    "api_request": (ClassUid.API_ACTIVITY, 2, SeverityId.INFORMATIONAL),
    "data_access": (ClassUid.DATASTORE_ACTIVITY, 1, SeverityId.INFORMATIONAL),
    "data_export": (ClassUid.DATASTORE_ACTIVITY, 1, SeverityId.MEDIUM),
    "data_delete": (ClassUid.DATASTORE_ACTIVITY, 7, SeverityId.MEDIUM),
    "config_change": (ClassUid.API_ACTIVITY, 3, SeverityId.MEDIUM),
    "http_request": (ClassUid.HTTP_ACTIVITY, 3, SeverityId.INFORMATIONAL),
}

_HTTP_ACTIVITY = {
    "CONNECT": 1,
    "DELETE": 2,
    "GET": 3,
    "HEAD": 4,
    "OPTIONS": 5,
    "POST": 6,
    "PUT": 7,
    "TRACE": 8,
    "PATCH": 9,
}

_PRIVILEGED_ROLES = {"admin", "administrator", "owner", "superuser", "security-admin"}


@register
class WebAppMapper(Mapper):
    source = "app"
    product_name = "SignalForge Lab App"
    vendor_name = "SignalForge"

    def map(self, record: RawLogRecord) -> Optional[OcsfEvent]:
        payload = record.payload or {}
        action = str(payload.get("action") or payload.get("event") or "").lower()
        if not action:
            raise NormalizationError("app record without action/event", record)

        class_uid, activity_id, severity = _ACTION_MAP.get(
            action, (ClassUid.API_ACTIVITY, 99, SeverityId.INFORMATIONAL)
        )

        outcome = str(payload.get("outcome") or payload.get("result") or "").lower()
        status_code = payload.get("status_code") or payload.get("http_status")
        if action == "login_failed" or outcome in {"failure", "failed", "denied", "error"}:
            status_id = StatusId.FAILURE
        elif outcome in {"success", "ok", "allowed"} or not outcome:
            status_id = StatusId.SUCCESS
        else:
            status_id = StatusId.OTHER
        if isinstance(status_code, int) and status_code >= 400:
            status_id = StatusId.FAILURE

        method = str(payload.get("method") or "").upper()
        if class_uid == ClassUid.HTTP_ACTIVITY and method in _HTTP_ACTIVITY:
            activity_id = _HTTP_ACTIVITY[method]

        actor_name = payload.get("user") or payload.get("actor") or payload.get("username")
        target_name = payload.get("target_user") or payload.get("target")
        new_role = payload.get("new_role") or payload.get("role")
        if new_role and str(new_role).lower() in _PRIVILEGED_ROLES:
            severity = max(severity, SeverityId.HIGH)

        resource_name = payload.get("resource") or payload.get("object")
        event = OcsfEvent(
            class_uid=class_uid,
            activity_id=activity_id,
            status_id=status_id,
            status_code=str(status_code) if status_code is not None else None,
            status_detail=payload.get("reason") or payload.get("detail"),
            severity_id=severity,
            time=parse_time(
                payload.get("timestamp") or payload.get("time"), reference=record.received_at
            )
            or record.received_at,
            actor=Actor(
                user=User(
                    name=actor_name,
                    email_addr=actor_name if "@" in str(actor_name or "") else None,
                    uid=str(payload.get("user_id")) if payload.get("user_id") else None,
                    type="Service" if payload.get("is_service_account") else "User",
                    groups=[Group(name=str(payload["current_role"]))]
                    if payload.get("current_role")
                    else [],
                ),
                session=Session(
                    uid=payload.get("session_id"),
                    is_mfa=payload.get("mfa_used"),
                    is_remote=True,
                ),
                app_name=payload.get("app") or payload.get("client_id"),
            ),
            user=User(
                name=target_name,
                email_addr=target_name if "@" in str(target_name or "") else None,
                type="Admin" if str(new_role or "").lower() in _PRIVILEGED_ROLES else "User",
                groups=[
                    Group(
                        name=str(new_role),
                        type="Privileged"
                        if str(new_role).lower() in _PRIVILEGED_ROLES
                        else "Standard",
                    )
                ]
                if new_role
                else [],
            )
            if target_name or new_role
            else None,
            src_endpoint=Endpoint(
                ip=payload.get("ip") or payload.get("source_ip"), port=payload.get("source_port")
            ),
            dst_endpoint=Endpoint(
                hostname=payload.get("host") or payload.get("service"),
                svc_name=payload.get("service") or "signalforge-lab-app",
                port=payload.get("port"),
            ),
            device=Device(hostname=payload.get("host"), type="Web Server"),
            api=Api(
                operation=payload.get("endpoint") or payload.get("operation") or action,
                service=ApiService(name=payload.get("service") or "lab-app"),
                request=ApiRequest(uid=payload.get("request_id")),
                response=ApiResponse(
                    code=status_code if isinstance(status_code, int) else None,
                    error=payload.get("error"),
                ),
            )
            if class_uid in {ClassUid.API_ACTIVITY, ClassUid.DATASTORE_ACTIVITY}
            else None,
            http_request=HttpRequest(
                http_method=method or None,
                url=payload.get("path") or payload.get("url"),
                user_agent=payload.get("user_agent"),
            )
            if method or payload.get("path") or payload.get("user_agent")
            else None,
            http_response=HttpResponse(code=status_code) if isinstance(status_code, int) else None,
            resources=[
                Resource(
                    uid=str(payload.get("resource_id") or resource_name),
                    name=str(resource_name),
                    type=payload.get("resource_type") or "application-resource",
                    criticality=payload.get("resource_criticality"),
                    data_classification=payload.get("data_classification"),
                    labels=[str(payload["data_classification"])]
                    if payload.get("data_classification")
                    else [],
                )
            ]
            if resource_name
            else [],
            is_mfa=payload.get("mfa_used"),
            logon_type=payload.get("logon_type")
            or ("Web" if class_uid == ClassUid.AUTHENTICATION else None),
            metadata={
                "uid": payload.get("event_id") or payload.get("request_id"),
                "log_name": "app.audit",
                "labels": [action],
            },
            unmapped={
                "action": action,
                "record_count": payload.get("record_count"),
                "bytes": payload.get("bytes"),
                "new_role": new_role,
                "previous_role": payload.get("previous_role") or payload.get("current_role"),
                "token_id": payload.get("token_id") or payload.get("api_key_id"),
                "is_service_account": payload.get("is_service_account"),
            },
            message=payload.get("message") or "%s by %s" % (action, actor_name or "unknown"),
        )
        return event
