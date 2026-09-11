"""Threat-intelligence enrichment.

Providers are tried in order and their answers merged:

1. :class:`InternalClassifier` - is the address internal or external, which
   network does it belong to?  No network calls, always available.
2. :class:`StaticFeedProvider` - a checked-in feed
   (``schemas/intel/static_feed.json``) so the demo and the test suite have
   deterministic, reputable-looking data without scraping anything.
3. :class:`HttpFeedProvider` - optional HTTP lookup against a feed you are
   authorised to query, disabled by default, with retry/backoff and a circuit
   breaker so a slow provider degrades the enrichment rather than the pipeline.

Every lookup is cached (see :mod:`signalforge.enrich.cache`), and a provider
failure yields a ``degraded`` verdict instead of an exception - enrichment is
additive context, never a gate on detection.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from ..config import Settings, get_settings
from ..models.ocsf import Enrichment
from .cache import Cache, get_cache

log = logging.getLogger("signalforge.enrich.intel")

VERDICT_MALICIOUS = "malicious"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_ANONYMIZER = "anonymizer"
VERDICT_BENIGN = "benign"
VERDICT_UNKNOWN = "unknown"
VERDICT_DEGRADED = "degraded"

#: Verdict -> the risk-context signal it implies.
VERDICT_CONTEXT = {
    VERDICT_MALICIOUS: "known_malicious_indicator",
    VERDICT_ANONYMIZER: "anonymizing_infrastructure",
}


@dataclass
class IndicatorReport:
    value: str
    type: str
    verdict: str = VERDICT_UNKNOWN
    score: int = 0  # 0-100 confidence that this is bad
    providers: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    country: Optional[str] = None
    is_internal: Optional[bool] = None
    network: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    references: List[str] = field(default_factory=list)
    cached: bool = False

    @property
    def is_bad(self) -> bool:
        return self.verdict in {VERDICT_MALICIOUS, VERDICT_SUSPICIOUS, VERDICT_ANONYMIZER}

    def to_dict(self) -> Dict[str, Any]:
        return {key: value for key, value in self.__dict__.items() if value is not None}

    def to_enrichment(self) -> Enrichment:
        return Enrichment(
            name="threat_intel",
            provider=",".join(self.providers) or "internal",
            value=self.verdict,
            data=self.to_dict(),
        )


class Provider:
    name = "provider"

    def lookup(self, value: str, type_: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError


class InternalClassifier(Provider):
    """Internal/external classification from the configured network list."""

    name = "internal"

    def __init__(self, networks: Sequence[str]) -> None:
        self.networks = []
        for network in networks:
            try:
                self.networks.append(ipaddress.ip_network(network, strict=False))
            except ValueError:
                log.warning("ignoring invalid internal network %r", network)

    def lookup(self, value: str, type_: str) -> Optional[Dict[str, Any]]:
        if type_ != "ip":
            return None
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return None
        for network in self.networks:
            if address in network:
                return {
                    "is_internal": True,
                    "network": str(network),
                    "verdict": VERDICT_BENIGN,
                    "score": 0,
                    "categories": ["internal"],
                }
        return {"is_internal": False, "categories": ["external"]}


class StaticFeedProvider(Provider):
    """Deterministic feed checked into the repository."""

    name = "static-feed"

    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self._data: Optional[Dict[str, Any]] = None

    @property
    def data(self) -> Dict[str, Any]:
        if self._data is None:
            candidates = [self.path, Path(__file__).resolve().parents[4] / self.path]
            self._data = {"indicators": {}, "networks": {}}
            for candidate in candidates:
                if candidate.exists():
                    with candidate.open("r", encoding="utf-8") as handle:
                        self._data = json.load(handle)
                    break
            else:
                log.warning("static intel feed not found", extra={"path": str(self.path)})
        return self._data

    def lookup(self, value: str, type_: str) -> Optional[Dict[str, Any]]:
        indicators = self.data.get("indicators") or {}
        entry = indicators.get(value)
        if entry is None and type_ == "ip":
            entry = self._match_network(value)
        if entry is None:
            return None
        return {
            "verdict": entry.get("verdict", VERDICT_SUSPICIOUS),
            "score": int(entry.get("score", 50)),
            "categories": list(entry.get("categories") or []),
            "asn": entry.get("asn"),
            "asn_org": entry.get("asn_org"),
            "country": entry.get("country"),
            "first_seen": entry.get("first_seen"),
            "last_seen": entry.get("last_seen"),
            "references": list(entry.get("references") or []),
        }

    def _match_network(self, value: str) -> Optional[Dict[str, Any]]:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return None
        for cidr, entry in (self.data.get("networks") or {}).items():
            try:
                if address in ipaddress.ip_network(cidr, strict=False):
                    return entry
            except ValueError:
                continue
        return None


class HttpFeedProvider(Provider):
    """Optional HTTP provider with retry, backoff and a circuit breaker."""

    name = "http-feed"

    def __init__(
        self,
        url: str,
        api_key: Optional[str] = None,
        *,
        timeout: float = 3.0,
        max_attempts: int = 3,
        failure_threshold: int = 5,
        cooldown_seconds: int = 60,
    ) -> None:
        self.url = url
        self.api_key = api_key
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self._failures = 0
        self._open_until = 0.0

    @property
    def circuit_open(self) -> bool:
        return time.monotonic() < self._open_until

    def lookup(self, value: str, type_: str) -> Optional[Dict[str, Any]]:
        if self.circuit_open:
            return {"verdict": VERDICT_DEGRADED, "categories": ["provider-circuit-open"]}
        import httpx

        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer %s" % self.api_key
        last_error: Optional[Exception] = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                response = httpx.get(
                    self.url,
                    params={"indicator": value, "type": type_},
                    headers=headers,
                    timeout=self.timeout,
                )
                if response.status_code == 404:
                    self._failures = 0
                    return None
                if response.status_code == 429 or response.status_code >= 500:
                    raise RuntimeError("provider returned %d" % response.status_code)
                response.raise_for_status()
                self._failures = 0
                payload = response.json()
                return {
                    "verdict": payload.get("verdict", VERDICT_UNKNOWN),
                    "score": int(payload.get("score", 0)),
                    "categories": list(payload.get("categories") or []),
                    "asn": payload.get("asn"),
                    "asn_org": payload.get("asn_org"),
                    "country": payload.get("country"),
                    "first_seen": payload.get("first_seen"),
                    "last_seen": payload.get("last_seen"),
                    "references": list(payload.get("references") or []),
                }
            except Exception as exc:
                last_error = exc
                if attempt < self.max_attempts:
                    time.sleep(0.2 * (2 ** (attempt - 1)) * (0.5 + random.random()))
        self._failures += 1
        if self._failures >= self.failure_threshold:
            self._open_until = time.monotonic() + self.cooldown_seconds
            log.error("intel provider circuit opened", extra={"cooldown": self.cooldown_seconds})
        log.warning("intel lookup failed", extra={"error": str(last_error), "indicator": value})
        return {"verdict": VERDICT_DEGRADED, "categories": ["provider-error"]}


class ThreatIntelService:
    """Cached, multi-provider indicator lookups."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        *,
        cache: Optional[Cache] = None,
        providers: Optional[Sequence[Provider]] = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.cache = cache or get_cache(self.settings)
        if providers is not None:
            self.providers: List[Provider] = list(providers)
        else:
            self.providers = [
                InternalClassifier(self.settings.internal_networks),
                StaticFeedProvider(self.settings.intel_feed_path),
            ]
            if self.settings.intel_http_enabled and self.settings.intel_http_url:
                self.providers.append(
                    HttpFeedProvider(self.settings.intel_http_url, self.settings.intel_http_api_key)
                )

    # ------------------------------------------------------------------ #
    def lookup(self, value: str, type_: str = "ip") -> IndicatorReport:
        cache_key = "%s:%s" % (type_, value)
        cached = self.cache.get(cache_key)
        if cached is not None:
            report = IndicatorReport(**cached)
            report.cached = True
            return report

        report = IndicatorReport(value=value, type=type_)
        for provider in self.providers:
            try:
                answer = provider.lookup(value, type_)
            except Exception as exc:
                log.warning("provider raised", extra={"provider": provider.name, "error": str(exc)})
                continue
            if not answer:
                continue
            report.providers.append(provider.name)
            self._merge(report, answer)

        if report.verdict == VERDICT_UNKNOWN and report.is_internal:
            report.verdict = VERDICT_BENIGN
        self.cache.set(cache_key, report.to_dict())
        return report

    @staticmethod
    def _merge(report: IndicatorReport, answer: Dict[str, Any]) -> None:
        verdict = answer.get("verdict")
        if verdict and _verdict_rank(verdict) > _verdict_rank(report.verdict):
            report.verdict = verdict
        report.score = max(report.score, int(answer.get("score") or 0))
        for category in answer.get("categories") or []:
            if category not in report.categories:
                report.categories.append(category)
        for field_name in (
            "asn",
            "asn_org",
            "country",
            "first_seen",
            "last_seen",
            "is_internal",
            "network",
        ):
            value = answer.get(field_name)
            if value is not None and getattr(report, field_name, None) in (None, ""):
                setattr(report, field_name, value)
        for reference in answer.get("references") or []:
            if reference not in report.references:
                report.references.append(reference)

    # ------------------------------------------------------------------ #
    def verdict(self, value: Optional[str], type_: str = "ip") -> Optional[str]:
        """Convenience hook for the detection engine's context builder."""
        if not value:
            return None
        report = self.lookup(value, type_)
        return report.verdict

    def enrich_event(self, event: Any) -> List[Enrichment]:
        """Look up every observable on an event and attach the results."""
        enrichments: List[Enrichment] = []
        for observable in getattr(event, "observables", []) or []:
            if observable.type not in {"ip", "domain", "url", "file_hash"}:
                continue
            report = self.lookup(observable.value, observable.type)
            if report.verdict in {VERDICT_UNKNOWN, VERDICT_BENIGN} and not report.categories:
                continue
            enrichment = report.to_enrichment()
            enrichment.name = "threat_intel:%s" % observable.type
            enrichments.append(enrichment)
        existing = {(e.name, e.value) for e in getattr(event, "enrichments", [])}
        for enrichment in enrichments:
            if (enrichment.name, enrichment.value) not in existing:
                event.enrichments.append(enrichment)
        return enrichments

    def enrich_alert(self, alert: Any) -> List[Enrichment]:
        """Attach intel to an alert and reflect a hit in its risk factors."""
        enrichments: List[Enrichment] = []
        for value, type_ in ((alert.source_ip, "ip"),):
            if not value:
                continue
            report = self.lookup(value, type_)
            if report.verdict in {VERDICT_UNKNOWN}:
                continue
            enrichment = report.to_enrichment()
            enrichments.append(enrichment)
            alert.enrichments.append(enrichment)
            if report.is_bad:
                factor = "threat intel: %s (%s)" % (
                    report.verdict,
                    ", ".join(report.categories) or "no category",
                )
                if factor not in alert.risk_factors:
                    alert.risk_factors.append(factor)
        return enrichments

    @property
    def cache_stats(self) -> Dict[str, int]:
        return self.cache.stats


_RANK = {
    VERDICT_UNKNOWN: 0,
    VERDICT_DEGRADED: 1,
    VERDICT_BENIGN: 2,
    VERDICT_ANONYMIZER: 3,
    VERDICT_SUSPICIOUS: 4,
    VERDICT_MALICIOUS: 5,
}


def _verdict_rank(verdict: str) -> int:
    return _RANK.get(verdict, 0)


_SERVICE: Optional[ThreatIntelService] = None


def get_intel_service(
    settings: Optional[Settings] = None, *, refresh: bool = False
) -> ThreatIntelService:
    global _SERVICE
    if _SERVICE is None or refresh:
        _SERVICE = ThreatIntelService(settings)
    return _SERVICE


def reset_intel_service() -> None:
    global _SERVICE
    _SERVICE = None
