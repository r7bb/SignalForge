"""Software supply chain: SBOM ingestion and vulnerability impact analysis."""

from .parse import (
    ParsedComponent,
    ParsedSbom,
    SbomParseError,
    detect_format,
    parse,
    parse_cyclonedx,
    parse_spdx,
    split_purl,
)
from .service import SbomService
from .versions import compare_versions, is_fixed_by, matches_range, satisfies

__all__ = [
    "ParsedComponent",
    "ParsedSbom",
    "SbomParseError",
    "SbomService",
    "compare_versions",
    "detect_format",
    "is_fixed_by",
    "matches_range",
    "parse",
    "parse_cyclonedx",
    "parse_spdx",
    "satisfies",
    "split_purl",
]
