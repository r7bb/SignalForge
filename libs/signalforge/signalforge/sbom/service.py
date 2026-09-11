"""SBOM ingestion and vulnerability impact analysis.

Answers the question the CISA SBOM guidance is really about: *when a new
vulnerability lands, which of my applications actually contain the affected
component?*  Ingest is idempotent per application (a new SBOM replaces the
previous inventory), and matching is done on ``(ecosystem, package, version
range)`` so a fixed version is reported as unaffected.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from sqlalchemy import select

from ..storage import db as dbm
from .parse import ParsedSbom, SbomParseError, parse, split_purl
from .versions import is_fixed_by, matches_range

log = logging.getLogger("signalforge.sbom")

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


class SbomService:
    def __init__(self, session_factory: Any) -> None:
        self.session_factory = session_factory

    # ------------------------------------------------------------------ #
    # Ingestion
    # ------------------------------------------------------------------ #
    def ingest(
        self,
        *,
        tenant: str,
        document: Dict[str, Any],
        application: Optional[str] = None,
        environment: str = "production",
        criticality: str = "medium",
        owner: Optional[str] = None,
        actor: str = "system",
    ) -> Dict[str, Any]:
        parsed: ParsedSbom = parse(document)
        app_name = application or parsed.application
        if not app_name:
            raise SbomParseError("cannot determine the application name; pass it explicitly")

        with self.session_factory() as session:
            app_row = session.scalars(
                select(dbm.Application).where(
                    dbm.Application.tenant == tenant, dbm.Application.name == app_name
                )
            ).first()
            if app_row is None:
                app_row = dbm.Application(
                    tenant=tenant,
                    name=app_name,
                    environment=environment,
                    criticality=criticality,
                    owner=owner,
                )
                session.add(app_row)
                session.flush()
            else:
                app_row.environment = environment or app_row.environment
                app_row.criticality = criticality or app_row.criticality
                app_row.owner = owner or app_row.owner

            # A new SBOM supersedes the previous inventory for this application.
            for previous in list(app_row.sboms):
                session.delete(previous)
            session.flush()

            sbom_row = dbm.Sbom(
                application_id=app_row.id,
                format=parsed.format,
                spec_version=parsed.spec_version,
                serial_number=parsed.serial_number,
                component_count=parsed.component_count,
            )
            session.add(sbom_row)
            session.flush()

            for component in parsed.components:
                component_row = self._upsert_component(session, component)
                session.add(
                    dbm.SbomComponent(
                        sbom_id=sbom_row.id,
                        component_id=component_row.id,
                        direct=component.direct,
                        scope=component.scope,
                    )
                )
            dbm.record_audit(
                session,
                tenant=tenant,
                actor=actor,
                action="sbom.ingested",
                entity_type="application",
                entity_id=app_row.id,
                detail=app_name,
                format=parsed.format,
                components=parsed.component_count,
            )
            session.commit()
            result = {
                "application": app_name,
                "application_id": app_row.id,
                "sbom_id": sbom_row.id,
                "format": parsed.format,
                "spec_version": parsed.spec_version,
                "components": parsed.component_count,
            }

        # Newly ingested components may already be covered by known advisories.
        result["matched_vulnerabilities"] = len(self.rematch(tenant=tenant))
        return result

    def _upsert_component(self, session: Any, component: Any) -> dbm.Component:
        row = session.scalars(
            select(dbm.Component).where(dbm.Component.purl == component.purl)
        ).first()
        if row is None:
            ecosystem, name, version = split_purl(component.purl)
            row = dbm.Component(
                purl=component.purl,
                name=component.name or name,
                version=component.version or version or "",
                ecosystem=component.ecosystem or ecosystem,
                licenses=list(component.licenses),
            )
            session.add(row)
            session.flush()
        elif component.licenses and not row.licenses:
            row.licenses = list(component.licenses)
        return row

    # ------------------------------------------------------------------ #
    # Vulnerabilities
    # ------------------------------------------------------------------ #
    def add_vulnerability(
        self,
        *,
        tenant: str,
        vuln_id: str,
        package_name: str,
        affected_range: str,
        ecosystem: Optional[str] = None,
        severity: str = "unknown",
        cvss_score: Optional[float] = None,
        fixed_version: Optional[str] = None,
        title: Optional[str] = None,
        references: Optional[Sequence[str]] = None,
        published_at: Optional[datetime] = None,
        actor: str = "system",
    ) -> Dict[str, Any]:
        """Record an advisory and immediately match it against every SBOM."""
        with self.session_factory() as session:
            row = session.scalars(
                select(dbm.Vulnerability).where(dbm.Vulnerability.vuln_id == vuln_id)
            ).first()
            if row is None:
                row = dbm.Vulnerability(vuln_id=vuln_id)
                session.add(row)
            row.title = title or row.title
            row.severity = severity
            row.cvss_score = cvss_score
            row.ecosystem = ecosystem
            row.package_name = package_name
            row.affected_range = affected_range
            row.fixed_version = fixed_version
            row.references = list(references or [])
            row.published_at = published_at or datetime.now(tz=timezone.utc)
            dbm.record_audit(
                session,
                tenant=tenant,
                actor=actor,
                action="vulnerability.recorded",
                entity_type="vulnerability",
                entity_id=row.id,
                detail=vuln_id,
                severity=severity,
                package=package_name,
            )
            session.commit()
            vuln_row_id = row.id

        affected = self._match_vulnerability(vuln_id)
        return {
            "vulnerability_id": vuln_row_id,
            "vuln_id": vuln_id,
            "affected_components": len(affected),
            "affected_applications": sorted({item["application"] for item in affected}),
        }

    def _match_vulnerability(self, vuln_id: str) -> List[Dict[str, Any]]:
        with self.session_factory() as session:
            vuln = session.scalars(
                select(dbm.Vulnerability).where(dbm.Vulnerability.vuln_id == vuln_id)
            ).first()
            if vuln is None:
                return []
            query = select(dbm.Component).where(dbm.Component.name == vuln.package_name)
            if vuln.ecosystem:
                query = query.where(dbm.Component.ecosystem == vuln.ecosystem)
            components = session.scalars(query).all()

            matched: List[Dict[str, Any]] = []
            for component in components:
                in_range = matches_range(component.version, vuln.affected_range)
                fixed = is_fixed_by(component.version, vuln.fixed_version)
                link = session.scalars(
                    select(dbm.ComponentVulnerability).where(
                        dbm.ComponentVulnerability.component_id == component.id,
                        dbm.ComponentVulnerability.vulnerability_id == vuln.id,
                    )
                ).first()
                if in_range and not fixed:
                    if link is None:
                        link = dbm.ComponentVulnerability(
                            component_id=component.id,
                            vulnerability_id=vuln.id,
                            status="affected",
                        )
                        session.add(link)
                    else:
                        link.status = "affected"
                    for app_name in self._applications_for_component(session, component.id):
                        matched.append(
                            {
                                "application": app_name,
                                "component": component.name,
                                "version": component.version,
                                "purl": component.purl,
                            }
                        )
                elif link is not None:
                    link.status = "fixed" if fixed else "not_affected"
            session.commit()
            return matched

    def rematch(self, *, tenant: Optional[str] = None) -> List[Dict[str, Any]]:
        """Re-run every advisory against the current inventory."""
        with self.session_factory() as session:
            vuln_ids = [row.vuln_id for row in session.scalars(select(dbm.Vulnerability)).all()]
        matched: List[Dict[str, Any]] = []
        for vuln_id in vuln_ids:
            matched.extend(self._match_vulnerability(vuln_id))
        return matched

    # ------------------------------------------------------------------ #
    # Queries
    # ------------------------------------------------------------------ #
    def impact(self, *, tenant: str, vuln_id: str) -> Dict[str, Any]:
        """ "Which applications contain it?" - affected vs unaffected, per app."""
        with self.session_factory() as session:
            vuln = session.scalars(
                select(dbm.Vulnerability).where(dbm.Vulnerability.vuln_id == vuln_id)
            ).first()
            if vuln is None:
                return {"vuln_id": vuln_id, "known": False, "applications": []}

            applications = session.scalars(
                select(dbm.Application).where(dbm.Application.tenant == tenant)
            ).all()
            rows: List[Dict[str, Any]] = []
            for app in applications:
                findings = []
                for sbom in app.sboms:
                    for link in sbom.components:
                        component = link.component
                        if component.name != vuln.package_name:
                            continue
                        if vuln.ecosystem and component.ecosystem != vuln.ecosystem:
                            continue
                        in_range = matches_range(component.version, vuln.affected_range)
                        fixed = is_fixed_by(component.version, vuln.fixed_version)
                        findings.append(
                            {
                                "component": component.name,
                                "version": component.version,
                                "purl": component.purl,
                                "direct": link.direct,
                                "affected": bool(in_range and not fixed),
                                "fixed_version": vuln.fixed_version,
                            }
                        )
                rows.append(
                    {
                        "application": app.name,
                        "environment": app.environment,
                        "criticality": app.criticality,
                        "owner": app.owner,
                        "status": "affected"
                        if any(f["affected"] for f in findings)
                        else ("unaffected" if findings else "not_present"),
                        "findings": findings,
                    }
                )
            return {
                "vuln_id": vuln.vuln_id,
                "known": True,
                "title": vuln.title,
                "severity": vuln.severity,
                "cvss_score": vuln.cvss_score,
                "package": vuln.package_name,
                "ecosystem": vuln.ecosystem,
                "affected_range": vuln.affected_range,
                "fixed_version": vuln.fixed_version,
                "references": list(vuln.references or []),
                "applications": sorted(
                    rows, key=lambda row: (row["status"] != "affected", row["application"])
                ),
            }

    def applications(self, tenant: str) -> List[Dict[str, Any]]:
        with self.session_factory() as session:
            rows = session.scalars(
                select(dbm.Application).where(dbm.Application.tenant == tenant)
            ).all()
            out = []
            for app in rows:
                component_count = sum(len(sbom.components) for sbom in app.sboms)
                out.append(
                    {
                        "id": app.id,
                        "name": app.name,
                        "environment": app.environment,
                        "criticality": app.criticality,
                        "owner": app.owner,
                        "components": component_count,
                        "sbom_format": app.sboms[0].format if app.sboms else None,
                        "ingested_at": app.sboms[0].ingested_at if app.sboms else None,
                        "open_vulnerabilities": len(self._app_vulnerabilities(session, app)),
                    }
                )
            return sorted(out, key=lambda row: row["name"])

    def components(
        self, *, tenant: str, application: str, search: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        with self.session_factory() as session:
            app = session.scalars(
                select(dbm.Application).where(
                    dbm.Application.tenant == tenant, dbm.Application.name == application
                )
            ).first()
            if app is None:
                return []
            out = []
            for sbom in app.sboms:
                for link in sbom.components:
                    component = link.component
                    if search and search.lower() not in component.name.lower():
                        continue
                    out.append(
                        {
                            "name": component.name,
                            "version": component.version,
                            "purl": component.purl,
                            "ecosystem": component.ecosystem,
                            "licenses": list(component.licenses or []),
                            "direct": link.direct,
                        }
                    )
            return sorted(out, key=lambda row: row["name"])

    def findings(self, tenant: str) -> List[Dict[str, Any]]:
        """Every open (application, component, vulnerability) triple."""
        with self.session_factory() as session:
            applications = session.scalars(
                select(dbm.Application).where(dbm.Application.tenant == tenant)
            ).all()
            out: List[Dict[str, Any]] = []
            for app in applications:
                for entry in self._app_vulnerabilities(session, app):
                    out.append({"application": app.name, "criticality": app.criticality, **entry})
            return sorted(
                out,
                key=lambda row: (-SEVERITY_ORDER.get(row["severity"], 0), row["application"]),
            )

    def stats(self, tenant: str) -> Dict[str, Any]:
        findings = self.findings(tenant)
        by_severity: Dict[str, int] = {}
        for finding in findings:
            by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
        applications = self.applications(tenant)
        return {
            "applications": len(applications),
            "components": sum(app["components"] for app in applications),
            "open_findings": len(findings),
            "by_severity": by_severity,
            "affected_applications": sorted({f["application"] for f in findings}),
        }

    # ------------------------------------------------------------------ #
    @staticmethod
    def _applications_for_component(session: Any, component_id: str) -> List[str]:
        links = session.scalars(
            select(dbm.SbomComponent).where(dbm.SbomComponent.component_id == component_id)
        ).all()
        names = []
        for link in links:
            sbom = session.get(dbm.Sbom, link.sbom_id)
            if sbom is None:
                continue
            app = session.get(dbm.Application, sbom.application_id)
            if app is not None and app.name not in names:
                names.append(app.name)
        return names

    @staticmethod
    def _app_vulnerabilities(session: Any, app: dbm.Application) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for sbom in app.sboms:
            for link in sbom.components:
                rows = session.scalars(
                    select(dbm.ComponentVulnerability).where(
                        dbm.ComponentVulnerability.component_id == link.component_id,
                        dbm.ComponentVulnerability.status == "affected",
                    )
                ).all()
                for row in rows:
                    vuln = session.get(dbm.Vulnerability, row.vulnerability_id)
                    if vuln is None:
                        continue
                    out.append(
                        {
                            "vuln_id": vuln.vuln_id,
                            "title": vuln.title,
                            "severity": vuln.severity,
                            "cvss_score": vuln.cvss_score,
                            "component": link.component.name,
                            "version": link.component.version,
                            "purl": link.component.purl,
                            "direct": link.direct,
                            "fixed_version": vuln.fixed_version,
                        }
                    )
        return out
