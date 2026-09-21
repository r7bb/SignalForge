"""Notification channels and dispatch."""

from .channels import (
    Channel,
    LogChannel,
    MemoryChannel,
    SlackChannel,
    WebhookChannel,
    build_channels,
)
from .dispatcher import MAX_ATTEMPTS, RETRY_BACKOFF_SECONDS, NotificationService
from .models import (
    URGENT_KINDS,
    DeliveryResult,
    DeliveryStatus,
    DispatchReport,
    Notification,
    NotificationKind,
)

__all__ = [
    "MAX_ATTEMPTS",
    "RETRY_BACKOFF_SECONDS",
    "URGENT_KINDS",
    "Channel",
    "DeliveryResult",
    "DeliveryStatus",
    "DispatchReport",
    "LogChannel",
    "MemoryChannel",
    "Notification",
    "NotificationKind",
    "NotificationService",
    "SlackChannel",
    "WebhookChannel",
    "build_channels",
]
