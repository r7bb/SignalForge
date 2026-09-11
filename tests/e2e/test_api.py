"""End-to-end tests through the FastAPI application.

These exercise the API exactly as the dashboard does: sign in, ingest, look at
the incident, request and approve a response, and confirm that a caller cannot
read another tenant's data.
"""

from __future__ import annotations

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

    application = create_app()
    with fastapi_testclient.TestClient(application) as test_client:
        yield test_client


def sign_in(
    client: Any,
    email: str = "admin@signalforge.local",
    password: str = "test-password",
    tenant: str = "acme",
) -> Dict[str, str]:
    response = client.post(
        "/api/v1/auth/login", json={"email": email, "password": password, "tenant": tenant}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer %s" % response.json()["access_token"]}


def scenario_records() -> list:
    from signalforge.lab import TelemetryGenerator

    generator = TelemetryGenerator(tenant="acme", seed=13)
    return [
        {
            "source": record.source,
            "payload": record.payload,
            "raw": record.raw,
            "received_at": record.received_at.isoformat(),
        }
        for record in generator.account_compromise()
    ]


# --------------------------------------------------------------- basics ------
def test_health_and_root_need_no_token(client: Any) -> None:
    assert client.get("/api/v1/health").status_code == 200
    assert client.get("/api/v1/health/live").json()["status"] == "alive"
    body = client.get("/").json()
    assert body["name"] == "SignalForge"

    ready = client.get("/api/v1/health/ready").json()
    assert ready["status"] == "ready", ready


def test_metrics_endpoint_is_exposed(client: Any) -> None:
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "signalforge" in response.text


def test_openapi_document_is_generated(client: Any) -> None:
    schema = client.get("/openapi.json").json()
    assert schema["info"]["title"] == "SignalForge API"
    assert "/api/v1/incidents" in schema["paths"]


# ------------------------------------------------------------------ auth -----
def test_protected_routes_require_a_token(client: Any) -> None:
    assert client.get("/api/v1/incidents").status_code == 401
    assert client.get("/api/v1/alerts").status_code == 401
    assert client.post("/api/v1/events/ingest", json={"records": []}).status_code == 401


def test_bad_credentials_are_rejected(client: Any) -> None:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@signalforge.local", "password": "wrong", "tenant": "acme"},
    )
    assert response.status_code == 401


def test_invalid_token_is_rejected(client: Any) -> None:
    response = client.get("/api/v1/incidents", headers={"Authorization": "Bearer nonsense"})
    assert response.status_code == 401


def test_me_reports_the_principal(client: Any) -> None:
    headers = sign_in(client)
    body = client.get("/api/v1/auth/me", headers=headers).json()
    assert body["email"] == "admin@signalforge.local"
    assert body["tenant"] == "acme"
    assert body["role"] == "admin"


def test_refresh_issues_a_new_access_token(client: Any) -> None:
    login = client.post(
        "/api/v1/auth/login",
        json={
            "email": "admin@signalforge.local",
            "password": "test-password",
            "tenant": "acme",
        },
    ).json()
    refreshed = client.post("/api/v1/auth/refresh", json={"refresh_token": login["refresh_token"]})
    assert refreshed.status_code == 200
    assert refreshed.json()["access_token"]


# ------------------------------------------------------- the whole journey ---
def test_ingest_to_incident_to_response(client: Any) -> None:
    headers = sign_in(client)

    ingest = client.post(
        "/api/v1/events/ingest", json={"records": scenario_records()}, headers=headers
    )
    assert ingest.status_code == 202, ingest.text
    body = ingest.json()
    assert body["events"] > 0
    assert body["alerts"] > 0
    assert body["incident_keys"]

    # The alert queue is populated and ordered by risk.
    alerts = client.get("/api/v1/alerts", headers=headers).json()
    assert alerts
    assert alerts[0]["risk_score"] >= alerts[-1]["risk_score"]

    # The incident carries a risk score, an ATT&CK path and a timeline.
    incidents = client.get("/api/v1/incidents", headers=headers).json()
    assert incidents
    reference = incidents[0]["key"]

    detail = client.get("/api/v1/incidents/%s" % reference, headers=headers).json()
    assert detail["risk_score"] > 0
    assert detail["alerts"]
    assert detail["timeline"]
    assert detail["suggested_playbooks"]
    assert [step["name"] for step in detail["tactics"]]

    attack = client.get("/api/v1/incidents/%s/attack" % reference, headers=headers).json()
    assert attack["tactics"]

    # Workflow: NEW -> TRIAGED is allowed, NEW -> CONTAINED is not.
    allowed = client.get("/api/v1/incidents/%s/transitions" % reference, headers=headers).json()
    assert "triaged" in allowed["allowed"]

    bad = client.post(
        "/api/v1/incidents/%s/status" % reference, json={"status": "contained"}, headers=headers
    )
    assert bad.status_code == 409

    good = client.post(
        "/api/v1/incidents/%s/status" % reference,
        json={"status": "triaged", "reason": "looks real"},
        headers=headers,
    )
    assert good.status_code == 200
    assert good.json()["status"] == "triaged"

    noted = client.post(
        "/api/v1/incidents/%s/notes" % reference,
        json={"body": "Confirmed with the account owner."},
        headers=headers,
    )
    assert noted.status_code == 200
    assert noted.json()["notes"]

    # Response: request, then approve (the admin here is a different actor than
    # the requester only because approval by the requester is blocked - assert it).
    requested = client.post(
        "/api/v1/response/incidents/%s/actions" % reference,
        json={"playbook": "revoke_sessions"},
        headers=headers,
    )
    assert requested.status_code == 201, requested.text
    action = requested.json()
    assert action["status"] == "pending_approval"

    self_approval = client.post(
        "/api/v1/response/actions/%s/approve" % action["id"], json={}, headers=headers
    )
    assert self_approval.status_code == 409, "the requester must not approve their own action"

    # A second responder approves it.
    client.post(
        "/api/v1/auth/users",
        json={
            "email": "responder@acme.io",
            "password": "responder-password",
            "role": "responder",
        },
        headers=headers,
    )
    responder_headers = sign_in(client, "responder@acme.io", "responder-password")
    approved = client.post(
        "/api/v1/response/actions/%s/approve" % action["id"], json={}, headers=responder_headers
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "executed"
    assert approved.json()["result"]["dry_run"] is True

    audit = client.get("/api/v1/incidents/%s/audit" % reference, headers=headers).json()
    actions = [entry["action"] for entry in audit["entries"]]
    assert "response.executed" in actions
    assert "incident.status_changed" in actions


# ---------------------------------------------------------------- tenancy ----
def test_reading_another_tenant_is_forbidden(client: Any) -> None:
    headers = sign_in(client)
    client.post("/api/v1/events/ingest", json={"records": scenario_records()}, headers=headers)
    incidents = client.get("/api/v1/incidents", headers=headers).json()
    reference = incidents[0]["key"]

    # An explicit cross-tenant query parameter is refused...
    assert client.get("/api/v1/incidents?tenant=globex", headers=headers).status_code == 403
    assert client.get("/api/v1/alerts?tenant=globex", headers=headers).status_code == 403

    # ...and so is reading a real incident that belongs to somebody else.
    from signalforge.auth import AuthService
    from signalforge.storage import db as dbm

    auth = AuthService(dbm.get_session_factory())
    auth.create_user(
        tenant="globex", email="analyst@globex.io", password="globex-password", role="analyst"
    )
    other_headers = sign_in(client, "analyst@globex.io", "globex-password", tenant="globex")

    forbidden = client.get("/api/v1/incidents/%s" % reference, headers=other_headers)
    assert forbidden.status_code == 403
    assert client.get("/api/v1/incidents", headers=other_headers).json() == []


def test_role_hierarchy_is_enforced(client: Any) -> None:
    admin_headers = sign_in(client)
    client.post(
        "/api/v1/auth/users",
        json={
            "email": "viewer@acme.io",
            "password": "viewer-password",
            "role": "viewer",
        },
        headers=admin_headers,
    )
    viewer_headers = sign_in(client, "viewer@acme.io", "viewer-password")

    # A viewer may read...
    assert client.get("/api/v1/incidents", headers=viewer_headers).status_code == 200
    # ...but not ingest, or manage users.
    assert (
        client.post(
            "/api/v1/events/ingest", json={"records": scenario_records()}, headers=viewer_headers
        ).status_code
        == 403
    )
    assert client.get("/api/v1/auth/users", headers=viewer_headers).status_code == 403


# ------------------------------------------------------------- detections ----
def test_detection_registry_and_linter(client: Any) -> None:
    headers = sign_in(client)

    rules = client.get("/api/v1/detections", headers=headers).json()
    assert rules
    ids = {rule["id"] for rule in rules}
    assert "sf-auth-0001" in ids
    assert "sf-corr-0003" in ids

    lint = client.get("/api/v1/detections/lint", headers=headers).json()
    assert lint["ok"] is True, lint["errors"]
    assert lint["tested_rules"] == lint["rule_count"] + lint["correlation_count"]

    detail = client.get("/api/v1/detections/sf-auth-0001", headers=headers).json()
    assert detail["stateful"] is True
    assert detail["timeframe_seconds"] == 300
    assert detail["tests"]
    assert detail["opensearch_query"]["query"]
    assert any(item["id"] == "sf-corr-0003" for item in detail["referenced_by"])

    versions = client.get("/api/v1/detections/sf-auth-0001/versions", headers=headers).json()
    assert versions["current_revision"] >= 1
    assert versions["versions"]

    assert client.get("/api/v1/detections/does-not-exist", headers=headers).status_code == 404


def test_retro_hunt_finds_stored_events(client: Any) -> None:
    headers = sign_in(client)
    client.post("/api/v1/events/ingest", json={"records": scenario_records()}, headers=headers)

    hunt = client.post(
        "/api/v1/detections/retro-hunt",
        json={"rule_id": "sf-auth-0001", "earliest": None},
        headers=headers,
    )
    assert hunt.status_code == 200, hunt.text
    body = hunt.json()
    assert body["total"] > 0
    assert body["groups"]


# ------------------------------------------------------------------ search ---
def test_event_search_and_timeline(client: Any) -> None:
    headers = sign_in(client)
    client.post("/api/v1/events/ingest", json={"records": scenario_records()}, headers=headers)

    search = client.post(
        "/api/v1/events/search",
        json={"principal": "alex@example.com", "size": 100},
        headers=headers,
    )
    assert search.status_code == 200
    assert search.json()["total"] > 0

    failures = client.post("/api/v1/events/search", json={"status_id": 2}, headers=headers).json()
    assert failures["total"] > 0

    timeline = client.get(
        "/api/v1/events/timeline?principal=alex@example.com&minutes=1440", headers=headers
    ).json()
    times = [event["time"] for event in timeline["events"]]
    assert times == sorted(times)

    assert client.get("/api/v1/events/timeline", headers=headers).status_code == 400


def test_overview_and_mitre_stats(client: Any) -> None:
    headers = sign_in(client)
    client.post("/api/v1/events/ingest", json={"records": scenario_records()}, headers=headers)

    overview = client.get("/api/v1/stats/overview", headers=headers).json()
    assert overview["events_today"] > 0
    assert overview["alerts_total"] > 0
    assert overview["top_rules"]

    mitre = client.get("/api/v1/stats/mitre", headers=headers).json()
    covered = {entry["tactic"]: entry for entry in mitre["tactics"]}
    assert covered["credential_access"]["rules"] > 0

    # Ascending, as the README documents them: 0-29 informational ... 90-100 critical.
    bands = client.get("/api/v1/stats/risk-bands", headers=headers).json()["bands"]
    assert [band["name"] for band in bands] == [
        "informational",
        "low",
        "medium",
        "high",
        "critical",
    ]
    assert bands[0]["min"] == 0
    assert bands[-1]["min"] == 90
    assert bands[-1]["max"] == 100


# --------------------------------------------------------------------- lab ---
def test_lab_scenarios_can_be_replayed(client: Any) -> None:
    headers = sign_in(client)
    scenarios = client.get("/api/v1/lab/scenarios", headers=headers).json()["scenarios"]
    assert any(item["name"] == "account_compromise" for item in scenarios)

    run = client.post("/api/v1/lab/simulate", json={"scenario": "brute_force"}, headers=headers)
    assert run.status_code == 200, run.text
    body = run.json()
    assert body["records"] > 0
    assert "sf-auth-0001" in body["detections_fired"]

    assert (
        client.post("/api/v1/lab/simulate", json={"scenario": "nope"}, headers=headers).status_code
        == 404
    )


# ------------------------------------------------------------ supply chain ---
def test_sbom_ingest_and_impact(client: Any) -> None:
    headers = sign_in(client)
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "component": {
                "bom-ref": "root",
                "type": "application",
                "name": "Production API",
                "version": "3.2.0",
            }
        },
        "components": [
            {
                "bom-ref": "lib",
                "type": "library",
                "name": "library-x",
                "version": "2.4.1",
                "purl": "pkg:pypi/library-x@2.4.1",
            },
        ],
        "dependencies": [{"ref": "root", "dependsOn": ["lib"]}],
    }
    ingest = client.post(
        "/api/v1/sbom/ingest",
        json={"document": document, "criticality": "critical"},
        headers=headers,
    )
    assert ingest.status_code == 201, ingest.text
    assert ingest.json()["components"] == 1

    advisory = client.post(
        "/api/v1/sbom/vulnerabilities",
        json={
            "vuln_id": "CVE-2026-31337",
            "package_name": "library-x",
            "ecosystem": "pypi",
            "affected_range": ">=2.4.0 <2.4.2",
            "fixed_version": "2.4.2",
            "severity": "high",
            "cvss_score": 8.1,
        },
        headers=headers,
    )
    assert advisory.status_code == 201
    assert advisory.json()["affected_applications"] == ["Production API"]

    impact = client.get(
        "/api/v1/sbom/vulnerabilities/CVE-2026-31337/impact", headers=headers
    ).json()
    assert impact["applications"][0]["status"] == "affected"

    findings = client.get("/api/v1/sbom/findings", headers=headers).json()["findings"]
    assert findings[0]["vuln_id"] == "CVE-2026-31337"

    assert (
        client.get("/api/v1/sbom/vulnerabilities/CVE-1999-0001/impact", headers=headers).status_code
        == 404
    )
    assert (
        client.post(
            "/api/v1/sbom/ingest", json={"document": {"nope": True}}, headers=headers
        ).status_code
        == 422
    )


# ------------------------------------------------------------------ intel ----
def test_intel_lookup(client: Any) -> None:
    headers = sign_in(client)
    tor = client.get("/api/v1/intel/lookup?value=185.220.101.7&type=ip", headers=headers).json()
    assert tor["verdict"] == "anonymizer"

    internal = client.get("/api/v1/intel/lookup?value=10.0.4.82&type=ip", headers=headers).json()
    assert internal["is_internal"] is True

    providers = client.get("/api/v1/intel/providers", headers=headers).json()
    assert "static-feed" in providers["providers"]
