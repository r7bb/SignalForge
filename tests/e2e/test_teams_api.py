"""The queue workflow over HTTP, as the dashboard will drive it.

One incident, two analysts and a lead: route it, claim it, fail to steal it,
transfer it with a reason, and close it with the right authority.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator

import pytest

pytestmark = pytest.mark.e2e

fastapi_testclient = pytest.importorskip("fastapi.testclient")


@pytest.fixture
def client(monkeypatch, tmp_path) -> Iterator[Any]:
    monkeypatch.setenv("SIGNALFORGE_BOOTSTRAP_TENANT", "acme")
    monkeypatch.setenv("SIGNALFORGE_BOOTSTRAP_ADMIN_EMAIL", "admin@signalforge.local")
    monkeypatch.setenv("SIGNALFORGE_BOOTSTRAP_ADMIN_PASSWORD", "test-password")
    monkeypatch.setenv("SIGNALFORGE_RESPONSE_DENYLIST_PATH", str(tmp_path / "denylist.txt"))

    from signalforge.config import reset_settings_cache

    reset_settings_cache()
    from app.main import create_app

    with fastapi_testclient.TestClient(create_app()) as test_client:
        yield test_client


def sign_in(client: Any, email: str, password: str = "test-password") -> Dict[str, str]:
    response = client.post(
        "/api/v1/auth/login", json={"email": email, "password": password, "tenant": "acme"}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer %s" % response.json()["access_token"]}


@pytest.fixture
def admin(client) -> Dict[str, str]:
    return sign_in(client, "admin@signalforge.local")


@pytest.fixture
def analysts(client, admin) -> Dict[str, Dict[str, str]]:
    """Two analysts and a responder, signed in."""
    for email, role in (
        ("dana@acme.test", "analyst"),
        ("sam@acme.test", "analyst"),
        ("rio@acme.test", "responder"),
    ):
        created = client.post(
            "/api/v1/auth/users",
            headers=admin,
            json={"email": email, "password": "test-password", "role": role},
        )
        assert created.status_code in (200, 201), created.text
    return {
        "dana": sign_in(client, "dana@acme.test"),
        "sam": sign_in(client, "sam@acme.test"),
        "rio": sign_in(client, "rio@acme.test"),
    }


@pytest.fixture
def incident_key(client, admin) -> str:
    """Drive a scenario through ingestion until an incident exists."""
    response = client.post(
        "/api/v1/lab/simulate", headers=admin, json={"scenario": "account_compromise"}
    )
    assert response.status_code == 200, response.text
    incidents = client.get("/api/v1/incidents", headers=admin).json()
    assert incidents, "the scenario should have opened an incident"
    return incidents[0]["key"]


def test_team_crud_and_membership(client, admin) -> None:
    created = client.post(
        "/api/v1/teams",
        headers=admin,
        json={"name": "Cloud Security", "description": "Cloud estate", "is_default": True},
    )
    assert created.status_code == 201, created.text
    assert created.json()["slug"] == "cloud-security"

    duplicate = client.post("/api/v1/teams", headers=admin, json={"name": "Cloud Security"})
    assert duplicate.status_code == 409

    member = client.post(
        "/api/v1/teams/cloud-security/members",
        headers=admin,
        json={"user": "admin@signalforge.local", "role": "lead"},
    )
    assert member.status_code == 201, member.text

    listed = client.get("/api/v1/teams", headers=admin).json()
    assert listed["count"] == 1
    assert listed["teams"][0]["members"][0]["role"] == "lead"

    mine = client.get("/api/v1/teams/mine", headers=admin).json()
    assert [team["slug"] for team in mine["teams"]] == ["cloud-security"]
    assert mine["teams"][0]["is_lead"] is True

    unknown = client.get("/api/v1/teams/nope", headers=admin)
    assert unknown.status_code == 404


def test_creating_a_team_needs_admin(client, analysts) -> None:
    forbidden = client.post("/api/v1/teams", headers=analysts["dana"], json={"name": "Rogue"})
    assert forbidden.status_code == 403


def test_queue_journey(client, admin, analysts, incident_key) -> None:
    client.post("/api/v1/teams", headers=admin, json={"name": "Identity"})
    client.post("/api/v1/teams", headers=admin, json={"name": "Cloud Security"})

    # Route it into the Identity queue (admin action for now; routing rules land later).
    moved = client.post(
        "/api/v1/incidents/%s/transfer" % incident_key,
        headers=admin,
        json={"team": "identity", "reason": "authentication chain, identity owns it"},
    )
    assert moved.status_code == 200, moved.text
    assert moved.json()["team_slug"] == "identity"

    queue = client.get("/api/v1/teams/identity/queue", headers=admin).json()
    assert [item["key"] for item in queue["incidents"]] == [incident_key]
    assert queue["incidents"][0]["owner"] is None

    # Dana claims it.
    claimed = client.post(
        "/api/v1/incidents/%s/claim" % incident_key, headers=analysts["dana"], json={}
    )
    assert claimed.status_code == 200, claimed.text
    assert claimed.json()["owner"] == "dana@acme.test"
    assert claimed.json()["acknowledged_at"] is not None
    version = claimed.json()["version"]

    # Sam cannot take it from her.
    stolen = client.post(
        "/api/v1/incidents/%s/claim" % incident_key, headers=analysts["sam"], json={}
    )
    assert stolen.status_code == 409, stolen.text
    assert "already claimed" in stolen.json()["detail"]

    # A stale version is rejected rather than silently overwriting.
    stale = client.post(
        "/api/v1/incidents/%s/status" % incident_key,
        headers=analysts["dana"],
        json={"status": "triaged", "expected_version": version - 1},
    )
    assert stale.status_code == 409
    assert "moved on" in stale.json()["detail"]

    triaged = client.post(
        "/api/v1/incidents/%s/status" % incident_key,
        headers=analysts["dana"],
        json={"status": "triaged", "expected_version": version},
    )
    assert triaged.status_code == 200, triaged.text

    # "My work" shows it for Dana and not for Sam.
    dana_work = client.get("/api/v1/incidents?mine=true", headers=analysts["dana"]).json()
    assert [item["key"] for item in dana_work] == [incident_key]
    assert client.get("/api/v1/incidents?mine=true", headers=analysts["sam"]).json() == []

    # Park it, which needs both a reason and a wake-up time.
    wake = (datetime.now(tz=timezone.utc) + timedelta(hours=4)).isoformat()
    incomplete = client.post(
        "/api/v1/incidents/%s/status" % incident_key,
        headers=analysts["dana"],
        json={"status": "waiting", "reason": "waiting on the account owner"},
    )
    assert incomplete.status_code == 409
    assert "wake-up time" in incomplete.json()["detail"]

    parked = client.post(
        "/api/v1/incidents/%s/status" % incident_key,
        headers=analysts["dana"],
        json={
            "status": "waiting",
            "reason": "waiting on the account owner",
            "waiting_until": wake,
        },
    )
    assert parked.status_code == 200, parked.text
    assert parked.json()["waiting_until"] is not None

    # Back to investigating, then containment - which an analyst may not do.
    client.post(
        "/api/v1/incidents/%s/status" % incident_key,
        headers=analysts["dana"],
        json={"status": "investigating"},
    )
    refused = client.post(
        "/api/v1/incidents/%s/status" % incident_key,
        headers=analysts["dana"],
        json={"status": "contained"},
    )
    assert refused.status_code == 403, refused.text
    assert "responder" in refused.json()["detail"]

    contained = client.post(
        "/api/v1/incidents/%s/status" % incident_key,
        headers=analysts["rio"],
        json={"status": "contained"},
    )
    assert contained.status_code == 200, contained.text

    # The whole journey is in the audit trail.
    trail = client.get("/api/v1/incidents/%s/audit" % incident_key, headers=admin).json()
    actions = [entry["action"] for entry in trail["entries"]]
    for expected in ("incident.transferred", "incident.claimed", "incident.status_changed"):
        assert expected in actions, "%s missing from %s" % (expected, actions)


def test_transfer_demands_a_reason(client, admin, incident_key) -> None:
    client.post("/api/v1/teams", headers=admin, json={"name": "Identity"})
    response = client.post(
        "/api/v1/incidents/%s/transfer" % incident_key,
        headers=admin,
        json={"team": "identity", "reason": ""},
    )
    assert response.status_code == 422, response.text


def test_unclaim_returns_work_to_the_queue(client, admin, analysts, incident_key) -> None:
    client.post("/api/v1/teams", headers=admin, json={"name": "Identity"})
    client.post(
        "/api/v1/incidents/%s/transfer" % incident_key,
        headers=admin,
        json={"team": "identity", "reason": "identity owns authentication"},
    )
    client.post("/api/v1/incidents/%s/claim" % incident_key, headers=analysts["dana"], json={})

    released = client.post(
        "/api/v1/incidents/%s/unclaim" % incident_key,
        headers=analysts["dana"],
        json={"reason": "end of shift"},
    )
    assert released.status_code == 200, released.text
    assert released.json()["owner"] is None

    queue = client.get("/api/v1/teams/identity/queue?unclaimed_only=true", headers=admin).json()
    assert [item["key"] for item in queue["incidents"]] == [incident_key]


def test_handover_report(client, admin, analysts, incident_key) -> None:
    client.post("/api/v1/teams", headers=admin, json={"name": "Identity"})
    client.post(
        "/api/v1/incidents/%s/transfer" % incident_key,
        headers=admin,
        json={"team": "identity", "reason": "identity owns authentication"},
    )
    client.post("/api/v1/incidents/%s/claim" % incident_key, headers=analysts["dana"], json={})

    report = client.get("/api/v1/teams/identity/handover", headers=admin).json()
    assert report["open_incidents"] == 1
    assert report["unclaimed"] == 0
    row = report["incidents"][0]
    assert row["owner"] == "dana@acme.test"
    assert row["last_action"], "the handover needs the most recent action"


def test_a_queue_with_open_work_cannot_be_deleted(client, admin, incident_key) -> None:
    client.post("/api/v1/teams", headers=admin, json={"name": "Identity"})
    client.post(
        "/api/v1/incidents/%s/transfer" % incident_key,
        headers=admin,
        json={"team": "identity", "reason": "identity owns authentication"},
    )
    blocked = client.delete("/api/v1/teams/identity", headers=admin)
    assert blocked.status_code == 409
    assert "still owns" in blocked.json()["detail"]


# ------------------------------------------------------------------ routing
def test_routing_table_is_exposed(client, admin) -> None:
    listed = client.get("/api/v1/routing", headers=admin).json()
    assert listed["enabled"] is True
    assert listed["count"] >= 1
    # Evaluation order is part of the contract: priority ascending.
    priorities = [rule["priority"] for rule in listed["rules"]]
    assert priorities == sorted(priorities)
    assert listed["errors"] == [], "the shipped routing table must be clean"
    assert listed["rules"][-1]["is_catch_all"], "the catch-all evaluates last"


def test_routing_preview_explains_the_decision(client, admin) -> None:
    preview = client.post(
        "/api/v1/routing/preview",
        headers=admin,
        json={"tactics": ["credential_access"], "risk_score": 88},
    ).json()
    assert preview["via"] == "rule"
    assert preview["team"] == "identity"
    assert preview["matched"]["id"].startswith("route-identity")
    # Every rule is reported with its verdict, not just the winner.
    assert any(entry["matched"] for entry in preview["evaluated"])
    assert len(preview["evaluated"]) == len(
        client.get("/api/v1/routing", headers=admin).json()["rules"]
    )


def test_routing_preview_for_an_existing_incident(client, admin, incident_key) -> None:
    preview = client.post(
        "/api/v1/routing/preview", headers=admin, json={"incident": incident_key}
    ).json()
    assert preview["team"], "an incident must resolve to some queue"

    missing = client.post("/api/v1/routing/preview", headers=admin, json={"incident": "INC-9999"})
    assert missing.status_code == 404


def test_a_new_incident_is_routed_on_creation(client, admin) -> None:
    """End to end: teams exist, a scenario fires, the incident lands in a queue."""
    for name, default in (("SOC Triage", True), ("Identity", False)):
        client.post("/api/v1/teams", headers=admin, json={"name": name, "is_default": default})

    client.post("/api/v1/lab/simulate", headers=admin, json={"scenario": "account_compromise"})
    incidents = client.get("/api/v1/incidents", headers=admin).json()
    assert incidents
    routed = [item for item in incidents if item["team_slug"]]
    assert routed, "auto-routing should have placed at least one incident"

    # The decision is auditable.
    trail = client.get("/api/v1/incidents/%s/audit" % routed[0]["key"], headers=admin).json()[
        "entries"
    ]
    assert any(entry["action"] == "incident.routed" for entry in trail)
