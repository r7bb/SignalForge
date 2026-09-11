"""Parse CycloneDX and SPDX SBOM documents into a common component list."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

PURL_RE = re.compile(r"^pkg:(?P<type>[^/]+)/(?P<rest>.+)$")


class SbomParseError(Exception):
    """The document is not a CycloneDX or SPDX SBOM we can read."""


@dataclass
class ParsedComponent:
    name: str
    version: str
    purl: str
    ecosystem: Optional[str] = None
    licenses: List[str] = field(default_factory=list)
    direct: bool = True
    scope: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class ParsedSbom:
    format: str  # cyclonedx | spdx
    spec_version: Optional[str]
    serial_number: Optional[str]
    application: Optional[str]
    application_version: Optional[str]
    components: List[ParsedComponent] = field(default_factory=list)

    @property
    def component_count(self) -> int:
        return len(self.components)


def detect_format(document: Dict[str, Any]) -> str:
    if not isinstance(document, dict):
        raise SbomParseError("SBOM must be a JSON object")
    if document.get("bomFormat") == "CycloneDX" or "components" in document:
        return "cyclonedx"
    if document.get("spdxVersion") or "packages" in document:
        return "spdx"
    raise SbomParseError(
        "unrecognised SBOM: expected CycloneDX (bomFormat/components) or SPDX "
        "(spdxVersion/packages)"
    )


def parse(document: Dict[str, Any]) -> ParsedSbom:
    kind = detect_format(document)
    return parse_cyclonedx(document) if kind == "cyclonedx" else parse_spdx(document)


# --------------------------------------------------------------------------- #
def parse_cyclonedx(document: Dict[str, Any]) -> ParsedSbom:
    metadata = document.get("metadata") or {}
    root = metadata.get("component") or {}
    direct_refs = _cyclonedx_direct_refs(document, root.get("bom-ref"))

    components: List[ParsedComponent] = []
    for entry in document.get("components") or []:
        name = entry.get("name")
        version = entry.get("version")
        if not name:
            continue
        purl = entry.get("purl") or _synthetic_purl(entry.get("type"), name, version)
        ref = entry.get("bom-ref") or purl
        components.append(
            ParsedComponent(
                name=str(name),
                version=str(version or ""),
                purl=purl,
                ecosystem=_ecosystem_from_purl(purl),
                licenses=_cyclonedx_licenses(entry),
                direct=(ref in direct_refs) if direct_refs else True,
                scope=entry.get("scope"),
            )
        )
    return ParsedSbom(
        format="cyclonedx",
        spec_version=document.get("specVersion"),
        serial_number=document.get("serialNumber"),
        application=root.get("name"),
        application_version=root.get("version"),
        components=components,
    )


def _cyclonedx_direct_refs(document: Dict[str, Any], root_ref: Optional[str]) -> set:
    """Components the root depends on directly, per the dependency graph."""
    if not root_ref:
        return set()
    for entry in document.get("dependencies") or []:
        if entry.get("ref") == root_ref:
            return {str(ref) for ref in entry.get("dependsOn") or []}
    return set()


def _cyclonedx_licenses(entry: Dict[str, Any]) -> List[str]:
    licenses: List[str] = []
    for item in entry.get("licenses") or []:
        if not isinstance(item, dict):
            continue
        license_obj = item.get("license") or {}
        value = license_obj.get("id") or license_obj.get("name") or item.get("expression")
        if value:
            licenses.append(str(value))
    return licenses


# --------------------------------------------------------------------------- #
def parse_spdx(document: Dict[str, Any]) -> ParsedSbom:
    packages = document.get("packages") or []
    describes = {str(ref) for ref in document.get("documentDescribes") or []}
    root_name = document.get("name")

    components: List[ParsedComponent] = []
    application = None
    application_version = None
    for entry in packages:
        name = entry.get("name")
        if not name:
            continue
        version = entry.get("versionInfo") or ""
        purl = _spdx_purl(entry) or _synthetic_purl(None, name, version)
        spdx_id = str(entry.get("SPDXID") or "")
        is_root = spdx_id in describes or (root_name and name == root_name)
        if is_root and application is None:
            application, application_version = str(name), str(version)
            continue
        components.append(
            ParsedComponent(
                name=str(name),
                version=str(version),
                purl=purl,
                ecosystem=_ecosystem_from_purl(purl),
                licenses=[
                    str(value)
                    for value in (entry.get("licenseConcluded"), entry.get("licenseDeclared"))
                    if value and value != "NOASSERTION"
                ],
                direct=bool(entry.get("primaryPackagePurpose") in (None, "APPLICATION", "LIBRARY")),
            )
        )
    return ParsedSbom(
        format="spdx",
        spec_version=document.get("spdxVersion"),
        serial_number=document.get("documentNamespace"),
        application=application or root_name,
        application_version=application_version,
        components=components,
    )


def _spdx_purl(entry: Dict[str, Any]) -> Optional[str]:
    for reference in entry.get("externalRefs") or []:
        if reference.get("referenceType") == "purl":
            return str(reference.get("referenceLocator"))
    return None


# --------------------------------------------------------------------------- #
def _synthetic_purl(kind: Optional[str], name: str, version: Optional[str]) -> str:
    """A stable identifier for components that ship without a purl."""
    ecosystem = (kind or "generic").lower()
    if version:
        return "pkg:%s/%s@%s" % (ecosystem, name, version)
    return "pkg:%s/%s" % (ecosystem, name)


def _ecosystem_from_purl(purl: Optional[str]) -> Optional[str]:
    if not purl:
        return None
    match = PURL_RE.match(purl)
    return match.group("type").lower() if match else None


def split_purl(purl: str) -> Tuple[Optional[str], str, Optional[str]]:
    """``pkg:pypi/requests@2.31.0`` -> ``("pypi", "requests", "2.31.0")``."""
    match = PURL_RE.match(purl or "")
    if not match:
        return None, purl, None
    ecosystem = match.group("type").lower()
    rest = match.group("rest").split("?", 1)[0].split("#", 1)[0]
    if "@" in rest:
        name, _, version = rest.rpartition("@")
    else:
        name, version = rest, None
    return ecosystem, name, version
