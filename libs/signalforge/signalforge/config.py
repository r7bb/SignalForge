"""Runtime configuration.

Every service reads the same settings object so that a single ``.env`` file (or
a set of container environment variables) drives the whole platform.  Anything
infrastructure-backed has an in-process fallback so the test suite and a laptop
demo can run without Kafka/OpenSearch/Redis.
"""

from __future__ import annotations

from functools import lru_cache
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SIGNALFORGE_",
        env_file=(".env", ".env.local"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: str = "local"
    debug: bool = False

    # --- Event bus -------------------------------------------------------
    # "kafka" talks to Redpanda/Kafka; "memory" uses the in-process bus.
    bus_backend: str = "memory"
    kafka_bootstrap_servers: str = "localhost:19092"
    kafka_client_id: str = "signalforge"
    topic_raw: str = "sf.logs.raw"
    topic_normalized: str = "sf.events.normalized"
    topic_alerts: str = "sf.alerts"
    topic_dlq: str = "sf.dlq"
    consumer_group: str = "signalforge"
    max_poll_records: int = 500

    # --- Security event store --------------------------------------------
    # "opensearch" or "memory".
    event_store_backend: str = "memory"
    opensearch_url: str = "http://localhost:9200"
    opensearch_user: Optional[str] = None
    opensearch_password: Optional[str] = None
    opensearch_verify_certs: bool = False
    opensearch_index_prefix: str = "sf-events"
    opensearch_bulk_size: int = 500
    opensearch_request_timeout: int = 20

    # --- Relational metadata store ---------------------------------------
    database_url: str = "sqlite+pysqlite:///./signalforge.db"
    database_echo: bool = False
    #: Run ``alembic upgrade head`` when a service opens the database.
    #: Convenient for the compose stack and local runs; turn it off where a
    #: deployment applies migrations as a separate, ordered step (and in the
    #: test suite, which builds each throwaway database straight from the
    #: models -- see ``tests/integration/test_migrations.py`` for the check
    #: that the two stay in agreement).
    db_auto_migrate: bool = True
    #: Where the Alembic tree lives. ``None`` resolves it relative to the
    #: repository root, which is right for both a source checkout and the
    #: container images (they copy ``migrations/`` alongside the library).
    migrations_path: Optional[str] = None

    # --- Cache / broker ---------------------------------------------------
    redis_url: Optional[str] = None  # None -> in-process cache
    celery_broker_url: Optional[str] = None
    celery_result_backend: Optional[str] = None

    # --- Detection --------------------------------------------------------
    detections_path: str = "detections"
    detection_min_level: str = "low"
    alert_dedup_window_seconds: int = 300

    # --- Incident routing -------------------------------------------------
    #: Routing rules (``routing/*.yml``) deciding which queue a new incident
    #: lands in. A missing directory, or no matching rule, means the incident
    #: goes to the tenant's default queue.
    routing_path: str = "routing"
    #: Route incidents automatically as they are opened. Off leaves every new
    #: incident unrouted for a human to place.
    routing_enabled: bool = True

    # --- Correlation / risk ----------------------------------------------
    correlation_window_seconds: int = 900
    incident_dedup_window_seconds: int = 1800
    risk_critical_threshold: int = 90
    risk_high_threshold: int = 70

    # --- Enrichment -------------------------------------------------------
    intel_feed_path: str = "schemas/intel/static_feed.json"
    intel_cache_ttl_seconds: int = 3600
    intel_http_enabled: bool = False
    intel_http_url: Optional[str] = None
    intel_http_api_key: Optional[str] = None
    internal_networks: List[str] = Field(
        default_factory=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]
    )

    # --- Auth -------------------------------------------------------------
    jwt_secret: str = "dev-only-change-me"
    jwt_algorithm: str = "HS256"
    access_token_ttl_seconds: int = 3600
    refresh_token_ttl_seconds: int = 604800
    bootstrap_admin_email: str = "admin@signalforge.local"
    bootstrap_admin_password: str = "signalforge"
    bootstrap_tenant: str = "acme"

    # --- Response ---------------------------------------------------------
    response_require_approval: bool = True
    response_dry_run: bool = True
    response_denylist_path: str = "var/denylist.txt"

    # --- Telemetry --------------------------------------------------------
    otel_enabled: bool = False
    otel_exporter_endpoint: Optional[str] = None
    metrics_port: int = 9464
    log_level: str = "INFO"

    @field_validator("internal_networks", mode="before")
    @classmethod
    def _split_networks(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @property
    def use_kafka(self) -> bool:
        return self.bus_backend.lower() == "kafka"

    @property
    def use_opensearch(self) -> bool:
        return self.event_store_backend.lower() == "opensearch"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """Test helper - drop the cached settings singleton."""
    get_settings.cache_clear()
