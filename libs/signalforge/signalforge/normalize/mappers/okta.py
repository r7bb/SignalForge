"""Okta System Log (identity provider) -> OCSF."""

from __future__ import annotations

from typing import Any, Dict, Optional

from ...models.ocsf import (
    Actor,
    ClassUid,
    Device,
    Endpoint,
    Group,
    Location,
    OcsfEvent,
    RawLogRecord,
    Resource,
    SeverityId,
    Session,
    StatusId,
    User,
)
from ...timeutil import parse_time
from ..base import Mapper, NormalizationError, register

#: Okta eventType -> (class_uid, activity_id, severity_id)
_EVENT_MAP: Dict[str, Any] = {
    "user.session.start": (ClassUid.AUTHENTICATION, 1, SeverityId.INFORMATIONAL),
    "user.session.end": (ClassUid.AUTHENTICATION, 2, SeverityId.INFORMATIONAL),
    "user.authentication.sso": (ClassUid.AUTHENTICATION, 1, SeverityId.INFORMATIONAL),
    "user.authentication.auth_via_mfa": (ClassUid.AUTHENTICATION, 6, SeverityId.INFORMATIONAL),
    "user.authentication.verify": (ClassUid.AUTHENTICATION, 6, SeverityId.INFORMATIONAL),
    "user.account.lock": (ClassUid.ACCOUNT_CHANGE, 9, SeverityId.MEDIUM),
    "user.account.unlock": (ClassUid.ACCOUNT_CHANGE, 12, SeverityId.LOW),
    "user.account.update_password": (ClassUid.ACCOUNT_CHANGE, 3, SeverityId.LOW),
    "user.account.reset_password": (ClassUid.ACCOUNT_CHANGE, 4, SeverityId.MEDIUM),
    "user.lifecycle.create": (ClassUid.ACCOUNT_CHANGE, 1, SeverityId.MEDIUM),
    "user.lifecycle.delete.initiated": (ClassUid.ACCOUNT_CHANGE, 6, SeverityId.MEDIUM),
    "user.mfa.factor.deactivate": (ClassUid.ACCOUNT_CHANGE, 11, SeverityId.HIGH),
    "user.mfa.factor.activate": (ClassUid.ACCOUNT_CHANGE, 10, SeverityId.LOW),
    "user.account.privilege.grant": (ClassUid.USER_ACCESS_MANAGEMENT, 1, SeverityId.HIGH),
    "user.account.privilege.revoke": (ClassUid.USER_ACCESS_MANAGEMENT, 2, SeverityId.LOW),
    "group.user_membership.add": (ClassUid.GROUP_MANAGEMENT, 3, SeverityId.MEDIUM),
    "group.user_membership.remove": (ClassUid.GROUP_MANAGEMENT, 4, SeverityId.LOW),
    "application.user_membership.add": (ClassUid.ENTITY_MANAGEMENT, 6, SeverityId.LOW),
    "system.api_token.create": (ClassUid.ACCOUNT_CHANGE, 1, SeverityId.HIGH),
    "system.api_token.revoke": (ClassUid.ACCOUNT_CHANGE, 6, SeverityId.LOW),
}

_ADMIN_HINTS = ("admin", "superuser", "org_admin", "super_admin")


@register
class OktaMapper(Mapper):
    source = "okta.system"
    product_name = "Okta System Log"
    vendor_name = "Okta"

    def map(self, record: RawLogRecord) -> Optional[OcsfEvent]:
        payload = record.payload or {}
        event_type = payload.get("eventType")
        if not event_type:
            raise NormalizationError("okta record without eventType", record)

        outcome = payload.get("outcome") or {}
        result = str(outcome.get("result") or "").upper()
        actor_raw = payload.get("actor") or {}
        client = payload.get("client") or {}
        geo = ((client.get("geographicalContext") or {}))
        targets = payload.get("target") or []
        debug = ((payload.get("debugContext") or {}).get("debugData") or {})

        class_uid, activity_id, severity = _EVENT_MAP.get(
            str(event_type), (ClassUid.ENTITY_MANAGEMENT, 99, SeverityId.INFORMATIONAL)
        )

        if result in {"FAILURE", "DENY"}:
            status_id = StatusId.FAILURE
            severity = max(severity, SeverityId.LOW)
        elif result == "SUCCESS":
            status_id = StatusId.SUCCESS
        else:
            status_id = StatusId.OTHER

        target_user = next(
            (t for t in targets if str(t.get("type", "")).lower() == "user"), None
        )
        target_group = next(
            (t for t in targets if str(t.get("type", "")).lower() in {"usergroup", "group"}), None
        )
        privileges = _privileges(debug, targets)
        if privileges and any(hint in " ".join(privileges).lower() for hint in _ADMIN_HINTS):
            severity = max(severity, SeverityId.HIGH)

        user_agent = (client.get("userAgent") or {})
        event = OcsfEvent(
            class_uid=class_uid,
            activity_id=activity_id,
            status_id=status_id,
            status_detail=outcome.get("reason"),
            severity_id=severity,
            time=parse_time(payload.get("published")) or record.received_at,
            actor=Actor(
                user=User(
                    name=actor_raw.get("alternateId") or actor_raw.get("displayName"),
                    uid=actor_raw.get("id"),
                    email_addr=actor_raw.get("alternateId")
                    if "@" in str(actor_raw.get("alternateId") or "")
                    else None,
                    type=actor_raw.get("type"),
                ),
                session=Session(
                    uid=(payload.get("authenticationContext") or {}).get("externalSessionId"),
                    is_mfa=_mfa(payload),
                    is_remote=True,
                ),
                app_name=user_agent.get("rawUserAgent"),
            ),
            user=User(
                name=target_user.get("alternateId") or target_user.get("displayName"),
                uid=target_user.get("id"),
                email_addr=target_user.get("alternateId")
                if "@" in str(target_user.get("alternateId") or "")
                else None,
                type="User",
                groups=[Group(name=target_group.get("displayName"), uid=target_group.get("id"))]
                if target_group
                else [],
            )
            if target_user
            else None,
            src_endpoint=Endpoint(
                ip=client.get("ipAddress"),
                domain=(payload.get("securityContext") or {}).get("domain"),
                location=Location(
                    country=geo.get("country"),
                    city=geo.get("city"),
                    region=(geo.get("geolocation") or {}).get("region") or geo.get("state"),
                    asn=(payload.get("securityContext") or {}).get("asNumber"),
                    isp=(payload.get("securityContext") or {}).get("isp"),
                )
                if geo or payload.get("securityContext")
                else None,
            ),
            dst_endpoint=Endpoint(svc_name="okta", hostname="okta.com"),
            device=Device(
                type=user_agent.get("os") and "User Device" or None,
                os=None,
                hostname=client.get("device"),
            ),
            group=Group(
                name=target_group.get("displayName"),
                uid=target_group.get("id"),
                privileges=privileges,
            )
            if target_group
            else (Group(name="okta-admin", privileges=privileges) if privileges else None),
            is_mfa=_mfa(payload),
            logon_type=(payload.get("authenticationContext") or {}).get("credentialType"),
            resources=[
                Resource(uid=t.get("id"), name=t.get("displayName") or t.get("alternateId"),
                         type=t.get("type"))
                for t in targets
                if str(t.get("type", "")).lower() in {"appinstance", "apitoken", "app"}
            ],
            metadata={
                "uid": payload.get("uuid"),
                "log_name": "okta.system",
                "labels": ["threat-suspicious"]
                if (payload.get("securityContext") or {}).get("isProxy")
                else [],
            },
            unmapped={
                "eventType": event_type,
                "displayMessage": payload.get("displayMessage"),
                "legacyEventType": payload.get("legacyEventType"),
                "privileges": privileges,
                "isProxy": (payload.get("securityContext") or {}).get("isProxy"),
                "threatSuspected": debug.get("threatSuspected"),
            },
            message=payload.get("displayMessage") or str(event_type),
        )
        return event


def _mfa(payload: Dict[str, Any]) -> Optional[bool]:
    context = payload.get("authenticationContext") or {}
    if "authenticationStep" in context and str(payload.get("eventType", "")).endswith("auth_via_mfa"):
        return True
    factor = (context.get("credentialProvider") or context.get("credentialType") or "")
    if factor:
        return str(factor).upper() not in {"PASSWORD", "OKTA_CREDENTIAL_PROVIDER"}
    return None


def _privileges(debug: Dict[str, Any], targets: Any) -> list:
    raw = debug.get("privilegeGranted") or debug.get("privileges") or ""
    if isinstance(raw, str) and raw:
        return [item.strip() for item in raw.split(",") if item.strip()]
    if isinstance(raw, list):
        return [str(item) for item in raw]
    return []
