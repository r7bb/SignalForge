"""Normalization: every source lands in the same schema."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from signalforge.models.ocsf import ClassUid, RawLogRecord, StatusId
from signalforge.normalize import NormalizationError, normalize, normalize_many, registry


def linux(line: str, source: str = "linux.sshd", tenant: str = "acme") -> RawLogRecord:
    return RawLogRecord(
        source=source,
        raw=line,
        tenant=tenant,
        received_at=datetime(2026, 9, 10, 14, 0, tzinfo=timezone.utc),
    )


def test_registry_has_every_shipped_source() -> None:
    assert set(registry.sources) == {"linux", "aws.cloudtrail", "okta.system", "app"}
    assert {entry["source"] for entry in registry.describe()} == set(registry.sources)


# ------------------------------------------------------------------ linux ----
def test_sshd_failure() -> None:
    event = normalize(
        linux(
            "Sep 10 13:41:02 web-01 sshd[2311]: Failed password for alex from 10.0.4.82 port 55212 ssh2"
        )
    )
    assert (event.class_uid, event.activity_id) == (ClassUid.AUTHENTICATION, 1)
    assert event.status_id == StatusId.FAILURE
    assert event.principal == "alex@example.com"  # identity resolution
    assert event.actor.user.name == "alex"  # source value preserved
    assert event.source_ip == "10.0.4.82"
    assert event.src_endpoint.port == 55212
    assert event.hostname == "web-01"
    assert event.auth_protocol == "Password"
    assert event.time == datetime(2026, 9, 10, 13, 41, 2, tzinfo=timezone.utc)


def test_sshd_success_and_publickey_is_treated_as_mfa() -> None:
    event = normalize(
        linux(
            "Sep 10 13:42:10 web-01 sshd[1]: Accepted publickey for alex from 10.0.4.82 port 1 ssh2"
        )
    )
    assert event.status_id == StatusId.SUCCESS
    assert event.is_mfa is True


def test_sshd_invalid_user_is_flagged() -> None:
    event = normalize(
        linux("Sep 10 13:44:00 web-01 sshd[1]: Invalid user admin from 185.220.101.7")
    )
    assert event.status_id == StatusId.FAILURE
    assert event.unmapped["invalid_user"] is True
    assert event.source_ip == "185.220.101.7"


def test_sshd_logoff() -> None:
    event = normalize(
        linux(
            "Sep 10 13:50:00 web-01 sshd[1]: pam_unix(sshd:session): session closed for user alex"
        )
    )
    assert event.activity_id == 2
    assert event.activity_name == "Logoff"


def test_sudo_command_becomes_process_activity() -> None:
    event = normalize(
        linux(
            "Sep 10 13:43:01 web-01 sudo: alex : TTY=pts/0 ; PWD=/home/alex ; "
            "USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
            source="linux.sudo",
        )
    )
    assert event.class_uid == ClassUid.PROCESS_ACTIVITY
    assert event.actor.process.cmd_line == "/usr/bin/cat /etc/shadow"
    assert event.unmapped["elevated"] is True


def test_usermod_privileged_group_is_high_severity() -> None:
    event = normalize(
        linux(
            "Sep 10 13:43:30 web-01 usermod[9001]: add 'alex' to group 'sudo'",
            source="linux.usermod",
        )
    )
    assert event.class_uid == ClassUid.GROUP_MANAGEMENT
    assert event.group.type == "Privileged"
    assert event.target_principal == "alex@example.com"


def test_auditd_execve() -> None:
    event = normalize(
        RawLogRecord(
            source="linux.auditd",
            tenant="acme",
            payload={
                "audit_type": "EXECVE",
                "exe": "/usr/bin/vim",
                "cmdline": "/usr/bin/vim /etc/sudoers",
                "auid_name": "alex",
                "pid": 42,
            },
        )
    )
    assert event.class_uid == ClassUid.PROCESS_ACTIVITY
    assert event.actor.process.name == "/usr/bin/vim"
    assert event.actor.process.pid == 42


def test_unknown_linux_program_is_a_normalization_error() -> None:
    with pytest.raises(NormalizationError):
        normalize(linux("Sep 10 13:00:00 web-01 chronyd[1]: clock stepped"))


def test_unknown_source_is_a_normalization_error() -> None:
    with pytest.raises(NormalizationError):
        normalize(RawLogRecord(source="windows.security", payload={"EventID": 4625}))


# -------------------------------------------------------------- cloudtrail ---
def test_cloudtrail_console_login_without_mfa() -> None:
    event = normalize(
        RawLogRecord(
            source="aws.cloudtrail",
            tenant="acme",
            payload={
                "eventTime": "2026-09-10T13:00:00Z",
                "eventName": "ConsoleLogin",
                "eventSource": "signin.amazonaws.com",
                "sourceIPAddress": "185.220.101.7",
                "userIdentity": {"type": "IAMUser", "userName": "alex"},
                "responseElements": {"ConsoleLogin": "Success"},
                "additionalEventData": {"MFAUsed": "No"},
                "eventID": "e-1",
            },
        )
    )
    assert event.class_uid == ClassUid.AUTHENTICATION
    assert event.status_id == StatusId.SUCCESS
    assert event.is_mfa is False
    assert event.logon_type == "AWS Console"
    assert event.api.operation == "ConsoleLogin"


def test_cloudtrail_saml_login_is_marked_federated() -> None:
    event = normalize(
        RawLogRecord(
            source="aws.cloudtrail",
            payload={
                "eventTime": "2026-09-10T13:00:00Z",
                "eventName": "ConsoleLogin",
                "userIdentity": {"type": "SAMLUser", "userName": "dana"},
                "responseElements": {"ConsoleLogin": "Success"},
                "additionalEventData": {
                    "MFAUsed": "No",
                    "SamlProviderArn": "arn:aws:iam::1:saml-provider/okta",
                },
            },
        )
    )
    assert event.logon_type == "SAML"


def test_cloudtrail_access_key_creation_captures_the_key_resource() -> None:
    event = normalize(
        RawLogRecord(
            source="aws.cloudtrail",
            payload={
                "eventTime": "2026-09-10T13:44:00Z",
                "eventName": "CreateAccessKey",
                "eventSource": "iam.amazonaws.com",
                "sourceIPAddress": "10.0.4.82",
                "userIdentity": {"type": "IAMUser", "userName": "alex"},
                "requestParameters": {"userName": "alex"},
                "responseElements": {"accessKey": {"accessKeyId": "AKIAEXAMPLE"}},
                "readOnly": False,
            },
        )
    )
    assert (event.class_uid, event.activity_id) == (ClassUid.ACCOUNT_CHANGE, 1)
    assert "AKIAEXAMPLE" in [resource.name for resource in event.resources]
    assert "write" in event.metadata.labels


def test_cloudtrail_error_code_is_a_failure() -> None:
    event = normalize(
        RawLogRecord(
            source="aws.cloudtrail",
            payload={
                "eventTime": "2026-09-10T13:44:00Z",
                "eventName": "StopLogging",
                "userIdentity": {"type": "IAMUser", "userName": "alex"},
                "errorCode": "AccessDenied",
            },
        )
    )
    assert event.status_id == StatusId.FAILURE
    assert event.status_code == "AccessDenied"


def test_cloudtrail_unknown_operation_falls_back_to_api_activity() -> None:
    event = normalize(
        RawLogRecord(
            source="aws.cloudtrail",
            payload={
                "eventTime": "2026-09-10T13:00:00Z",
                "eventName": "UpdateSomethingNew",
                "userIdentity": {"type": "IAMUser", "userName": "alex"},
            },
        )
    )
    assert event.class_uid == ClassUid.API_ACTIVITY
    assert event.activity_id == 3  # Update


def test_cloudtrail_without_event_name_is_rejected() -> None:
    with pytest.raises(NormalizationError):
        normalize(
            RawLogRecord(source="aws.cloudtrail", payload={"eventTime": "2026-09-10T13:00:00Z"})
        )


# -------------------------------------------------------------------- okta ---
def test_okta_privilege_grant_carries_target_and_geo() -> None:
    event = normalize(
        RawLogRecord(
            source="okta.system",
            tenant="acme",
            payload={
                "published": "2026-09-10T13:43:10Z",
                "eventType": "user.account.privilege.grant",
                "outcome": {"result": "SUCCESS"},
                "actor": {"alternateId": "root@example.com", "id": "a1", "type": "User"},
                "target": [{"type": "User", "alternateId": "alex@example.com", "id": "u2"}],
                "client": {
                    "ipAddress": "185.220.101.7",
                    "geographicalContext": {"country": "NL", "city": "Amsterdam"},
                },
                "debugContext": {"debugData": {"privilegeGranted": "Super administrator"}},
                "securityContext": {"isProxy": True, "asNumber": 204915},
            },
        )
    )
    assert event.class_uid == ClassUid.USER_ACCESS_MANAGEMENT
    assert event.principal == "root@example.com"
    assert event.target_principal == "alex@example.com"
    assert event.src_endpoint.location.country == "NL"
    assert event.src_endpoint.location.asn == 204915
    assert "threat-suspicious" in event.metadata.labels


def test_okta_failure_outcome() -> None:
    event = normalize(
        RawLogRecord(
            source="okta.system",
            payload={
                "published": "2026-09-10T13:00:00Z",
                "eventType": "user.session.start",
                "outcome": {"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
                "actor": {"alternateId": "alex@example.com"},
                "client": {"ipAddress": "10.0.4.82"},
            },
        )
    )
    assert event.status_id == StatusId.FAILURE
    assert event.status_detail == "INVALID_CREDENTIALS"


# --------------------------------------------------------------------- app ---
def test_app_role_change() -> None:
    event = normalize(
        RawLogRecord(
            source="app.audit",
            tenant="acme",
            payload={
                "timestamp": "2026-09-10T13:43:00Z",
                "action": "role_change",
                "user": "alex@example.com",
                "target_user": "alex@example.com",
                "new_role": "admin",
                "ip": "10.0.4.82",
                "session_id": "s-77",
            },
        )
    )
    assert event.class_uid == ClassUid.USER_ACCESS_MANAGEMENT
    assert event.session_uid == "s-77"
    assert event.user.type == "Admin"


def test_app_service_account_is_typed_as_service() -> None:
    event = normalize(
        RawLogRecord(
            source="app.audit",
            payload={
                "timestamp": "2026-09-10T13:43:00Z",
                "action": "api_key_created",
                "user": "ci-deploy@example.com",
                "is_service_account": True,
            },
        )
    )
    assert event.actor.user.type == "Service"


def test_app_data_access_captures_resource_criticality() -> None:
    event = normalize(
        RawLogRecord(
            source="app.audit",
            payload={
                "timestamp": "2026-09-10T13:46:00Z",
                "action": "data_export",
                "user": "alex@example.com",
                "resource": "customer-records",
                "resource_criticality": "critical",
                "record_count": 48000,
            },
        )
    )
    assert event.class_uid == ClassUid.DATASTORE_ACTIVITY
    assert event.resources[0].criticality == "critical"
    assert event.unmapped["record_count"] == 48000


def test_app_http_error_status_is_a_failure() -> None:
    event = normalize(
        RawLogRecord(
            source="app.audit",
            payload={
                "timestamp": "2026-09-10T13:46:00Z",
                "action": "api_request",
                "user": "alex@example.com",
                "status_code": 403,
            },
        )
    )
    assert event.status_id == StatusId.FAILURE
    assert event.api.response.code == 403


# ------------------------------------------------------------------- batch ---
def test_normalize_many_separates_failures_from_events() -> None:
    records = [
        linux(
            "Sep 10 13:41:02 web-01 sshd[1]: Failed password for alex from 10.0.4.82 port 1 ssh2"
        ),
        linux("Sep 10 13:00:00 web-01 chronyd[1]: clock stepped"),
        RawLogRecord(source="nope.unknown", payload={}),
    ]
    events, failures = normalize_many(records)
    assert len(events) == 1
    assert len(failures) == 2
    assert all(isinstance(reason, str) and reason for _, reason in failures)


def test_identity_resolution_unifies_sources() -> None:
    principals = {
        normalize(
            linux(
                "Sep 10 13:41:02 web-01 sshd[1]: Failed password for alex from 10.0.4.82 port 1 ssh2"
            )
        ).principal,
        normalize(
            RawLogRecord(
                source="app.audit",
                payload={
                    "timestamp": "2026-09-10T13:43:00Z",
                    "action": "login",
                    "user": "alex@example.com",
                },
            )
        ).principal,
        normalize(
            RawLogRecord(
                source="aws.cloudtrail",
                payload={
                    "eventTime": "2026-09-10T13:44:00Z",
                    "eventName": "CreateAccessKey",
                    "userIdentity": {"type": "IAMUser", "principalId": "AIDAEXAMPLEALEX"},
                },
            )
        ).principal,
    }
    assert principals == {"alex@example.com"}
