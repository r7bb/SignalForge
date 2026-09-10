"""AWS CloudTrail -> OCSF."""

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

#: eventName -> (class_uid, activity_id, severity_id)
_EVENT_MAP: Dict[str, Any] = {
    "ConsoleLogin": (ClassUid.AUTHENTICATION, 1, SeverityId.INFORMATIONAL),
    "AssumeRole": (ClassUid.AUTHENTICATION, 3, SeverityId.LOW),
    "AssumeRoleWithSAML": (ClassUid.AUTHENTICATION, 3, SeverityId.LOW),
    "GetSessionToken": (ClassUid.AUTHENTICATION, 3, SeverityId.LOW),
    "CreateAccessKey": (ClassUid.ACCOUNT_CHANGE, 1, SeverityId.HIGH),
    "CreateLoginProfile": (ClassUid.ACCOUNT_CHANGE, 1, SeverityId.HIGH),
    "UpdateLoginProfile": (ClassUid.ACCOUNT_CHANGE, 4, SeverityId.HIGH),
    "CreateUser": (ClassUid.ACCOUNT_CHANGE, 1, SeverityId.MEDIUM),
    "DeleteUser": (ClassUid.ACCOUNT_CHANGE, 6, SeverityId.MEDIUM),
    "DeactivateMFADevice": (ClassUid.ACCOUNT_CHANGE, 11, SeverityId.HIGH),
    "EnableMFADevice": (ClassUid.ACCOUNT_CHANGE, 10, SeverityId.LOW),
    "AttachUserPolicy": (ClassUid.USER_ACCESS_MANAGEMENT, 1, SeverityId.HIGH),
    "AttachRolePolicy": (ClassUid.USER_ACCESS_MANAGEMENT, 1, SeverityId.HIGH),
    "PutUserPolicy": (ClassUid.USER_ACCESS_MANAGEMENT, 1, SeverityId.HIGH),
    "DetachUserPolicy": (ClassUid.USER_ACCESS_MANAGEMENT, 2, SeverityId.MEDIUM),
    "AddUserToGroup": (ClassUid.GROUP_MANAGEMENT, 3, SeverityId.HIGH),
    "RemoveUserFromGroup": (ClassUid.GROUP_MANAGEMENT, 4, SeverityId.LOW),
    "GetObject": (ClassUid.DATASTORE_ACTIVITY, 1, SeverityId.INFORMATIONAL),
    "ListObjects": (ClassUid.DATASTORE_ACTIVITY, 4, SeverityId.INFORMATIONAL),
    "ListObjectsV2": (ClassUid.DATASTORE_ACTIVITY, 4, SeverityId.INFORMATIONAL),
    "PutObject": (ClassUid.DATASTORE_ACTIVITY, 5, SeverityId.INFORMATIONAL),
    "DeleteObject": (ClassUid.DATASTORE_ACTIVITY, 7, SeverityId.LOW),
    "GetSecretValue": (ClassUid.DATASTORE_ACTIVITY, 1, SeverityId.MEDIUM),
    "Decrypt": (ClassUid.DATASTORE_ACTIVITY, 9, SeverityId.LOW),
    "StopLogging": (ClassUid.API_ACTIVITY, 3, SeverityId.CRITICAL),
    "DeleteTrail": (ClassUid.API_ACTIVITY, 4, SeverityId.CRITICAL),
    "PutBucketPolicy": (ClassUid.API_ACTIVITY, 3, SeverityId.HIGH),
}

#: Write-ish API verbs fall back to API Activity with these activity ids.
_VERB_ACTIVITY = {
    "Create": 1, "Put": 3, "Update": 3, "Modify": 3, "Delete": 4,
    "Get": 2, "List": 2, "Describe": 2,
}

_CRITICAL_RESOURCE_HINTS = ("prod", "payments", "secrets", "customer")


@register
class CloudTrailMapper(Mapper):
    source = "aws.cloudtrail"
    product_name = "AWS CloudTrail"
    vendor_name = "AWS"

    def map(self, record: RawLogRecord) -> Optional[OcsfEvent]:
        payload = record.payload or {}
        event_name = payload.get("eventName")
        if not event_name:
            raise NormalizationError("cloudtrail record without eventName", record)

        identity = payload.get("userIdentity") or {}
        request = payload.get("requestParameters") or {}
        response = payload.get("responseElements") or {}
        error_code = payload.get("errorCode")
        additional = payload.get("additionalEventData") or {}

        principal_name = (
            identity.get("userName")
            or (identity.get("sessionContext", {}).get("sessionIssuer", {}) or {}).get("userName")
            or identity.get("arn", "").rsplit("/", 1)[-1]
            or identity.get("principalId")
        )
        actor_user = User(
            name=principal_name,
            uid=identity.get("principalId"),
            domain=identity.get("accountId"),
            type=identity.get("type"),
            has_mfa=_as_bool(additional.get("MFAUsed")),
        )
        session_ctx = (identity.get("sessionContext") or {}).get("attributes") or {}
        session = Session(
            uid=payload.get("eventID"),
            issuer=(identity.get("sessionContext") or {}).get("sessionIssuer", {}).get("arn"),
            is_mfa=_as_bool(session_ctx.get("mfaAuthenticated")),
            created_time=parse_time(session_ctx.get("creationDate")),
        )

        class_uid, activity_id, severity = self._classify(str(event_name))

        # ConsoleLogin carries its outcome in additionalEventData/responseElements.
        login_result = (
            response.get("ConsoleLogin") or additional.get("ConsoleLogin") or additional.get("LoginTo")
        )
        if error_code:
            status_id = StatusId.FAILURE
        elif isinstance(login_result, str) and login_result.lower() == "failure":
            status_id = StatusId.FAILURE
        else:
            status_id = StatusId.SUCCESS
        if status_id == StatusId.FAILURE and class_uid == ClassUid.AUTHENTICATION:
            severity = max(severity, SeverityId.LOW)

        target_user = None
        if request.get("userName"):
            target_user = User(name=request.get("userName"), type="User")

        event = OcsfEvent(
            class_uid=class_uid,
            activity_id=activity_id,
            status_id=status_id,
            status_code=error_code,
            status_detail=payload.get("errorMessage"),
            severity_id=severity,
            time=parse_time(payload.get("eventTime")) or record.received_at,
            actor=Actor(
                user=actor_user,
                session=session,
                invoked_by=payload.get("sourceIdentity") or identity.get("invokedBy"),
                app_name=payload.get("userAgent"),
            ),
            user=target_user,
            src_endpoint=Endpoint(
                ip=payload.get("sourceIPAddress"),
                domain=payload.get("sourceIPAddress") if _looks_like_service(payload) else None,
            ),
            dst_endpoint=Endpoint(
                svc_name=payload.get("eventSource"),
                hostname=payload.get("eventSource"),
                domain=payload.get("awsRegion"),
            ),
            device=Device(
                type="Cloud Service",
                uid=payload.get("recipientAccountId"),
                region=payload.get("awsRegion"),
            ),
            api=Api(
                operation=str(event_name),
                service=ApiService(name=payload.get("eventSource")),
                request=ApiRequest(uid=payload.get("requestID")),
                response=ApiResponse(error=error_code, message=payload.get("errorMessage")),
                version=payload.get("eventVersion"),
            ),
            http_request=HttpRequest(user_agent=payload.get("userAgent")) if payload.get("userAgent") else None,
            group=Group(name=request.get("groupName")) if request.get("groupName") else None,
            is_mfa=_first_not_none(
                _as_bool(session_ctx.get("mfaAuthenticated")), _as_bool(additional.get("MFAUsed"))
            ),
            logon_type="AWS Console" if event_name == "ConsoleLogin" else None,
            resources=self._resources(payload, request, response),
            metadata={"uid": payload.get("eventID"), "log_name": "cloudtrail",
                      "labels": _labels(payload)},
            unmapped={
                "readOnly": payload.get("readOnly"),
                "managementEvent": payload.get("managementEvent"),
                "eventCategory": payload.get("eventCategory"),
                "requestParameters": request or None,
                "policyArn": request.get("policyArn"),
            },
            message="%s %s by %s" % (
                payload.get("eventSource", "aws"), event_name, principal_name or "unknown"
            ),
        )
        return event

    @staticmethod
    def _classify(event_name: str):
        if event_name in _EVENT_MAP:
            return _EVENT_MAP[event_name]
        for verb, activity_id in _VERB_ACTIVITY.items():
            if event_name.startswith(verb):
                severity = SeverityId.LOW if activity_id in (1, 3, 4) else SeverityId.INFORMATIONAL
                return ClassUid.API_ACTIVITY, activity_id, severity
        return ClassUid.API_ACTIVITY, 99, SeverityId.INFORMATIONAL

    @staticmethod
    def _resources(payload: Dict[str, Any], request: Dict[str, Any], response: Dict[str, Any]):
        resources = []
        for item in payload.get("resources") or []:
            name = item.get("ARN") or item.get("arn")
            resources.append(
                Resource(
                    uid=name,
                    name=(name or "").rsplit("/", 1)[-1] or None,
                    type=item.get("type"),
                    criticality="critical"
                    if any(hint in (name or "").lower() for hint in _CRITICAL_RESOURCE_HINTS)
                    else None,
                )
            )
        bucket = request.get("bucketName")
        if bucket:
            resources.append(
                Resource(
                    uid="arn:aws:s3:::%s" % bucket,
                    name=bucket,
                    type="AWS::S3::Bucket",
                    criticality="critical"
                    if any(hint in bucket.lower() for hint in _CRITICAL_RESOURCE_HINTS)
                    else "medium",
                    data_classification=request.get("key"),
                )
            )
        key_id = ((response.get("accessKey") or {}) if isinstance(response.get("accessKey"), dict) else {}).get(
            "accessKeyId"
        )
        if key_id:
            resources.append(Resource(uid=key_id, name=key_id, type="AWS::IAM::AccessKey",
                                      criticality="high"))
        return resources


def _labels(payload: Dict[str, Any]):
    labels = []
    if payload.get("readOnly") is False:
        labels.append("write")
    if payload.get("managementEvent"):
        labels.append("management")
    if (payload.get("userIdentity") or {}).get("type") == "Root":
        labels.append("root-account")
    return labels


def _looks_like_service(payload: Dict[str, Any]) -> bool:
    ip = str(payload.get("sourceIPAddress") or "")
    return ip.endswith(".amazonaws.com")


def _as_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "yes", "1"}


def _first_not_none(*values: Any) -> Optional[bool]:
    for value in values:
        if value is not None:
            return value
    return None
