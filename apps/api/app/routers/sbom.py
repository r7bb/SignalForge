"""Software supply chain: SBOM ingestion and vulnerability impact."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from signalforge.auth import Principal

from ..deps import get_state, require_analyst, tenant_scope
from ..schemas import SbomIngestRequest, VulnerabilityRequest
from ..state import AppState

router = APIRouter(prefix="/sbom", tags=["supply-chain"])


@router.post("/ingest", status_code=201)
async def ingest(
    payload: SbomIngestRequest,
    principal: Principal = Depends(require_analyst),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """Ingest a CycloneDX or SPDX document (auto-detected)."""
    return state.sbom.ingest(
        tenant=principal.tenant,
        document=payload.document,
        application=payload.application,
        environment=payload.environment,
        criticality=payload.criticality,
        owner=payload.owner,
        actor=principal.email,
    )


@router.post("/upload", status_code=201)
async def upload(
    file: UploadFile = File(...),
    application: Optional[str] = None,
    environment: str = "production",
    criticality: str = "medium",
    principal: Principal = Depends(require_analyst),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    import json

    raw = await file.read()
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=422, detail="file is not valid JSON") from exc
    return state.sbom.ingest(
        tenant=principal.tenant,
        document=document,
        application=application,
        environment=environment,
        criticality=criticality,
        actor=principal.email,
    )


@router.get("/applications")
async def applications(
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    return {"applications": state.sbom.applications(tenant)}


@router.get("/applications/{name}/components")
async def components(
    name: str,
    search: Optional[str] = None,
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    rows = state.sbom.components(tenant=tenant, application=name, search=search)
    if not rows:
        applications = {app["name"] for app in state.sbom.applications(tenant)}
        if name not in applications:
            raise HTTPException(status_code=404, detail="unknown application %r" % name)
    return {"application": name, "count": len(rows), "components": rows}


@router.post("/vulnerabilities", status_code=201)
async def add_vulnerability(
    payload: VulnerabilityRequest,
    principal: Principal = Depends(require_analyst),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """Record an advisory and immediately match it against every SBOM."""
    return state.sbom.add_vulnerability(
        tenant=principal.tenant,
        vuln_id=payload.vuln_id,
        package_name=payload.package_name,
        affected_range=payload.affected_range,
        ecosystem=payload.ecosystem,
        severity=payload.severity,
        cvss_score=payload.cvss_score,
        fixed_version=payload.fixed_version,
        title=payload.title,
        references=payload.references,
        actor=principal.email,
    )


@router.get("/vulnerabilities/{vuln_id}/impact")
async def impact(
    vuln_id: str,
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """ "Which applications contain it?" - affected, unaffected, not present."""
    result = state.sbom.impact(tenant=tenant, vuln_id=vuln_id)
    if not result.get("known"):
        raise HTTPException(status_code=404, detail="unknown vulnerability %r" % vuln_id)
    return result


@router.get("/findings")
async def findings(
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    return {"findings": state.sbom.findings(tenant)}


@router.get("/stats")
async def stats(
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    return state.sbom.stats(tenant)


@router.post("/rematch")
async def rematch(
    principal: Principal = Depends(require_analyst),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    matched = state.sbom.rematch(tenant=principal.tenant)
    return {"matched": len(matched), "results": matched}
