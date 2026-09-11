"""SBOM ingestion, version matching and impact analysis."""

from __future__ import annotations

from typing import Any, Dict

import pytest
from signalforge.sbom import (
    SbomParseError,
    SbomService,
    compare_versions,
    detect_format,
    is_fixed_by,
    matches_range,
    parse,
    split_purl,
)

pytestmark = pytest.mark.integration


def cyclonedx(app: str, library_version: str) -> Dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:5f1d-%s" % app,
        "version": 1,
        "metadata": {
            "component": {"bom-ref": "root", "type": "application", "name": app, "version": "3.2.0"}
        },
        "components": [
            {
                "bom-ref": "lib-x",
                "type": "library",
                "name": "library-x",
                "version": library_version,
                "purl": "pkg:pypi/library-x@%s" % library_version,
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            },
            {
                "bom-ref": "lib-y",
                "type": "library",
                "name": "library-y",
                "version": "1.0.0",
                "purl": "pkg:pypi/library-y@1.0.0",
            },
        ],
        "dependencies": [
            {"ref": "root", "dependsOn": ["lib-x"]},
            {"ref": "lib-x", "dependsOn": ["lib-y"]},
        ],
    }


def spdx(app: str) -> Dict[str, Any]:
    return {
        "spdxVersion": "SPDX-2.3",
        "name": app,
        "documentNamespace": "https://example.org/spdx/%s" % app,
        "documentDescribes": ["SPDXRef-App"],
        "packages": [
            {"SPDXID": "SPDXRef-App", "name": app, "versionInfo": "1.0.0"},
            {
                "SPDXID": "SPDXRef-lib",
                "name": "library-x",
                "versionInfo": "2.4.2",
                "licenseConcluded": "MIT",
                "externalRefs": [
                    {"referenceType": "purl", "referenceLocator": "pkg:pypi/library-x@2.4.2"}
                ],
            },
        ],
    }


# ---------------------------------------------------------------- versions ---
@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("2.4.1", "2.4.1", 0),
        ("2.4.1", "2.4.2", -1),
        ("2.10.0", "2.9.9", 1),
        ("v2.4.1", "2.4.1", 0),
        ("2.4.0-rc1", "2.4.0", -1),
        ("2.4.0-rc1", "2.4.0-rc2", -1),
        ("1.0", "1.0.0", 0),
        ("2.4.1+build9", "2.4.1", 0),
    ],
)
def test_version_comparison(left: str, right: str, expected: int) -> None:
    assert compare_versions(left, right) == expected


@pytest.mark.parametrize(
    ("version", "spec", "expected"),
    [
        ("2.4.1", ">=2.4.0 <2.4.2", True),
        ("2.4.2", ">=2.4.0 <2.4.2", False),
        ("2.3.9", ">=2.4.0 <2.4.2", False),
        ("3.0.0", ">2.0", True),
        ("1.2.3", "==1.2.3", True),
        ("1.2.4", "!=1.2.3", True),
        ("2.4.1", "*", True),
        ("2.4.0-rc1", ">=2.4.0 <2.4.2", False),  # a pre-release is below the release
    ],
)
def test_range_matching(version: str, spec: str, expected: bool) -> None:
    assert matches_range(version, spec) is expected


def test_fixed_version_check() -> None:
    assert is_fixed_by("2.4.2", "2.4.2")
    assert is_fixed_by("2.5.0", "2.4.2")
    assert not is_fixed_by("2.4.1", "2.4.2")


def test_purl_splitting() -> None:
    assert split_purl("pkg:pypi/library-x@2.4.1") == ("pypi", "library-x", "2.4.1")
    assert split_purl("pkg:npm/%40scope/pkg@1.0.0")[0] == "npm"


# ------------------------------------------------------------------ parsing --
def test_format_detection_and_parsing() -> None:
    assert detect_format(cyclonedx("api", "2.4.1")) == "cyclonedx"
    assert detect_format(spdx("api")) == "spdx"

    parsed = parse(cyclonedx("Production API", "2.4.1"))
    assert parsed.application == "Production API"
    assert parsed.component_count == 2
    direct = {component.name: component.direct for component in parsed.components}
    assert direct["library-x"] is True
    assert direct["library-y"] is False  # from the dependency graph

    spdx_parsed = parse(spdx("Batch pipeline"))
    assert spdx_parsed.format == "spdx"
    assert spdx_parsed.application == "Batch pipeline"
    assert spdx_parsed.components[0].name == "library-x"


def test_unrecognised_document_is_rejected() -> None:
    with pytest.raises(SbomParseError):
        parse({"not": "an sbom"})


# ------------------------------------------------------------------ service --
@pytest.fixture
def service(session_factory) -> SbomService:
    return SbomService(session_factory)


def test_ingest_and_impact_analysis(service: SbomService) -> None:
    service.ingest(
        tenant="acme",
        document=cyclonedx("Production API", "2.4.1"),
        environment="production",
        criticality="critical",
    )
    service.ingest(
        tenant="acme",
        document=cyclonedx("Internal dashboard", "2.4.1"),
        environment="production",
        criticality="medium",
    )
    service.ingest(
        tenant="acme",
        document=cyclonedx("Mobile backend", "2.4.2"),
        environment="production",
        criticality="high",
    )
    service.ingest(tenant="acme", document=spdx("Batch pipeline"))

    applications = {app["name"]: app for app in service.applications("acme")}
    assert set(applications) == {
        "Production API",
        "Internal dashboard",
        "Mobile backend",
        "Batch pipeline",
    }
    assert applications["Production API"]["components"] == 2

    result = service.add_vulnerability(
        tenant="acme",
        vuln_id="CVE-2026-31337",
        package_name="library-x",
        ecosystem="pypi",
        affected_range=">=2.4.0 <2.4.2",
        fixed_version="2.4.2",
        severity="high",
        cvss_score=8.1,
        title="Deserialisation flaw in library-x",
    )
    assert set(result["affected_applications"]) == {"Production API", "Internal dashboard"}

    impact = service.impact(tenant="acme", vuln_id="CVE-2026-31337")
    statuses = {row["application"]: row["status"] for row in impact["applications"]}
    assert statuses["Production API"] == "affected"
    assert statuses["Internal dashboard"] == "affected"
    assert statuses["Mobile backend"] == "unaffected"  # already on the fixed version
    assert statuses["Batch pipeline"] == "unaffected"  # ships 2.4.2 too
    # Affected applications sort first for triage.
    assert impact["applications"][0]["status"] == "affected"


def test_findings_and_stats(service: SbomService) -> None:
    service.ingest(
        tenant="acme", document=cyclonedx("Production API", "2.4.1"), criticality="critical"
    )
    service.add_vulnerability(
        tenant="acme",
        vuln_id="CVE-2026-31337",
        package_name="library-x",
        ecosystem="pypi",
        affected_range=">=2.4.0 <2.4.2",
        fixed_version="2.4.2",
        severity="high",
        cvss_score=8.1,
    )
    service.add_vulnerability(
        tenant="acme",
        vuln_id="CVE-2026-40001",
        package_name="library-y",
        ecosystem="pypi",
        affected_range="<1.1.0",
        fixed_version="1.1.0",
        severity="critical",
    )

    findings = service.findings("acme")
    assert len(findings) == 2
    assert findings[0]["severity"] == "critical"  # most severe first
    stats = service.stats("acme")
    assert stats["applications"] == 1
    assert stats["open_findings"] == 2
    assert stats["by_severity"]["critical"] == 1


def test_reingest_replaces_the_inventory(service: SbomService) -> None:
    service.ingest(tenant="acme", document=cyclonedx("Production API", "2.4.1"))
    service.add_vulnerability(
        tenant="acme",
        vuln_id="CVE-2026-31337",
        package_name="library-x",
        ecosystem="pypi",
        affected_range=">=2.4.0 <2.4.2",
        fixed_version="2.4.2",
        severity="high",
    )
    assert service.findings("acme")

    # The team upgrades and re-uploads the SBOM.
    service.ingest(tenant="acme", document=cyclonedx("Production API", "2.4.2"))
    assert service.findings("acme") == []
    assert service.applications("acme")[0]["open_vulnerabilities"] == 0


def test_tenants_do_not_see_each_other(service: SbomService) -> None:
    service.ingest(tenant="acme", document=cyclonedx("Production API", "2.4.1"))
    service.ingest(tenant="globex", document=cyclonedx("Their API", "2.4.1"))
    assert [app["name"] for app in service.applications("acme")] == ["Production API"]
    assert [app["name"] for app in service.applications("globex")] == ["Their API"]


def test_unknown_vulnerability_impact_is_reported_as_unknown(service: SbomService) -> None:
    assert service.impact(tenant="acme", vuln_id="CVE-1999-0001")["known"] is False
