"""OCSF event model: classification, dedup keys, observables, flattening."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from signalforge.models.fields import is_known_field, ocsf_field_paths
from signalforge.models.ocsf import (
    Actor,
    ClassUid,
    Device,
    Endpoint,
    OcsfEvent,
    RawLogRecord,
    Resource,
    SeverityId,
    StatusId,
    User,
    flatten_event,
)


def make_event(**overrides) -> OcsfEvent:
    payload = {
        "class_uid": ClassUid.AUTHENTICATION,
        "activity_id": 1,
        "status_id": StatusId.FAILURE,
        "time": datetime(2026, 9, 10, 13, 41, tzinfo=timezone.utc),
        "actor": Actor(user=User(name="alex", email_addr="alex@example.com")),
        "src_endpoint": Endpoint(ip="10.0.4.82", port=55212),
        "device": Device(hostname="web-01"),
        "sf_tenant": "acme",
    }
    payload.update(overrides)
    return OcsfEvent(**payload)


def test_classification_is_derived_from_class_and_activity() -> None:
    event = make_event()
    assert event.class_name == "Authentication"
    assert event.category_uid == 3
    assert event.category_name == "Identity & Access Management"
    assert event.activity_name == "Logon"
    assert event.type_uid == 300201
    assert event.type_name == "Authentication: Logon"
    assert event.status == "Failure"
    assert event.severity == "Informational"


def test_principal_prefers_email_then_name() -> None:
    assert make_event().principal == "alex@example.com"
    bare = make_event(actor=Actor(user=User(name="root")))
    assert bare.principal == "root"
    assert make_event(actor=None).principal is None


def test_dedup_key_is_content_addressed() -> None:
    first = make_event()
    second = make_event()
    # Same content, different ingest identity -> same key.
    assert first.sf_event_id != second.sf_event_id
    assert first.sf_dedup_key == second.sf_dedup_key

    assert make_event(src_endpoint=Endpoint(ip="10.0.4.99")).sf_dedup_key != first.sf_dedup_key
    later = make_event(time=datetime(2026, 9, 10, 13, 42, tzinfo=timezone.utc))
    assert later.sf_dedup_key != first.sf_dedup_key
    assert make_event(sf_tenant="other").sf_dedup_key != first.sf_dedup_key


def test_dedup_key_ignores_ingest_metadata() -> None:
    base = make_event()
    other = make_event()
    other.sf_ingested_at = base.sf_ingested_at + timedelta(hours=3)
    assert other.compute_dedup_key() == base.compute_dedup_key()


def test_observables_are_derived_and_deduplicated() -> None:
    event = make_event().derive_observables()
    event.derive_observables()
    values = [(observable.type, observable.value) for observable in event.observables]
    assert ("ip", "10.0.4.82") in values
    assert ("user", "alex@example.com") in values
    assert ("hostname", "web-01") in values
    assert len(values) == len(set(values))


def test_naive_timestamps_are_treated_as_utc() -> None:
    event = make_event(time=datetime(2026, 9, 10, 13, 41))
    assert event.time.tzinfo is timezone.utc


def test_flatten_expands_nested_objects_and_collapses_lists() -> None:
    event = make_event(
        resources=[
            Resource(name="customer-records", criticality="critical"),
            Resource(name="internal-wiki", criticality="low"),
        ]
    )
    flat = flatten_event(event)
    assert flat["actor.user.name"] == "alex"
    assert flat["src_endpoint.port"] == 55212
    # A list of objects is addressable both by index and collapsed.
    assert flat["resources[0].name"] == "customer-records"
    assert set(flat["resources.criticality"]) == {"critical", "low"}


def test_flatten_accepts_plain_dicts() -> None:
    flat = flatten_event({"actor": {"user": {"name": "dana"}}, "tags": ["a", "b"]})
    assert flat["actor.user.name"] == "dana"
    assert flat["tags"] == ["a", "b"]


def test_severity_and_status_names_are_filled() -> None:
    event = make_event(status_id=StatusId.SUCCESS, severity_id=SeverityId.HIGH)
    assert event.status == "Success"
    assert event.severity == "High"
    assert event.is_failure is False


def test_raw_record_key_is_stable() -> None:
    first = RawLogRecord(source="linux.sshd", raw="line", tenant="acme")
    second = RawLogRecord(source="linux.sshd", raw="line", tenant="acme")
    assert first.key() == second.key()
    assert first.key() != RawLogRecord(source="linux.sshd", raw="other").key()


def test_field_introspection_covers_the_schema() -> None:
    paths = ocsf_field_paths()
    for path in ("actor.user.name", "src_endpoint.ip", "device.os.name", "api.operation"):
        assert path in paths
    assert is_known_field("unmapped.anything_at_all")
    assert not is_known_field("src_endpoint.adress")


@pytest.mark.parametrize(
    ("class_uid", "activity_id", "expected"),
    [
        (ClassUid.ACCOUNT_CHANGE, 11, "MFA Factor Disable"),
        (ClassUid.USER_ACCESS_MANAGEMENT, 1, "Assign Privileges"),
        (ClassUid.DATASTORE_ACTIVITY, 1, "Read"),
        (ClassUid.PROCESS_ACTIVITY, 1, "Launch"),
        (ClassUid.AUTHENTICATION, 99, "Other"),
    ],
)
def test_activity_names(class_uid: int, activity_id: int, expected: str) -> None:
    assert OcsfEvent(class_uid=class_uid, activity_id=activity_id).activity_name == expected
