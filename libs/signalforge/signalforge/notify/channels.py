"""Where a notification goes.

Every channel is the same shape, so adding email or PagerDuty later is a class
rather than a change to the dispatcher. The default is ``log``: a deployment
that has configured nothing still leaves a record that somebody should have
been told, which is more useful than silence.

Nothing here retries. A channel reports success or failure and the dispatcher
owns the retry policy - otherwise two layers back off against each other and
the effective interval is anybody's guess.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Protocol

from .models import DeliveryResult, DeliveryStatus, Notification

logger = logging.getLogger("signalforge.notify")


class Channel(Protocol):
    """A delivery target."""

    name: str

    def send(self, notification: Notification) -> DeliveryResult:  # pragma: no cover - protocol
        ...


class LogChannel:
    """Write the notification to the service log.

    The fallback, and genuinely useful: in a demo or a deployment without a
    webhook, "nobody was told" and "nobody could have been told" look identical
    without this.
    """

    name = "log"

    def send(self, notification: Notification) -> DeliveryResult:
        logger.info(
            "notification",
            extra={
                "kind": notification.kind.value,
                "recipient": notification.recipient_email,
                "incident": notification.incident_key,
                "subject": notification.subject,
                "urgent": notification.urgent,
            },
        )
        return DeliveryResult(notification.id, self.name, DeliveryStatus.SENT)


class MemoryChannel:
    """Collects notifications in a list. Used by the tests."""

    name = "memory"

    def __init__(self, fail_on: Optional[str] = None) -> None:
        self.sent: List[Notification] = []
        #: Substring of a subject that should fail, for exercising retry.
        self.fail_on = fail_on
        self.attempts = 0

    def send(self, notification: Notification) -> DeliveryResult:
        self.attempts += 1
        if self.fail_on and self.fail_on in notification.subject:
            return DeliveryResult(
                notification.id, self.name, DeliveryStatus.FAILED, "configured to fail"
            )
        self.sent.append(notification)
        return DeliveryResult(notification.id, self.name, DeliveryStatus.SENT)

    def clear(self) -> None:
        self.sent.clear()
        self.attempts = 0


class WebhookChannel:
    """POST the notification as JSON to a configured URL.

    Deliberately generic rather than Slack-shaped: a JSON body any receiver can
    read is more useful than one vendor's message format, and a Slack incoming
    webhook is one adapter away (see :class:`SlackChannel`).
    """

    name = "webhook"

    def __init__(self, url: str, timeout: float = 5.0, headers: Optional[Dict[str, str]] = None):
        self.url = url
        self.timeout = timeout
        self.headers = {"content-type": "application/json", **(headers or {})}

    def payload(self, notification: Notification) -> Dict[str, Any]:
        return notification.to_dict()

    def send(self, notification: Notification) -> DeliveryResult:
        import httpx

        try:
            response = httpx.post(
                self.url,
                json=self.payload(notification),
                headers=self.headers,
                timeout=self.timeout,
            )
        except Exception as exc:  # network, DNS, timeout
            return DeliveryResult(
                notification.id,
                self.name,
                DeliveryStatus.FAILED,
                "%s: %s" % (type(exc).__name__, exc),
            )
        if response.status_code >= 400:
            return DeliveryResult(
                notification.id,
                self.name,
                DeliveryStatus.FAILED,
                "HTTP %d: %s" % (response.status_code, response.text[:200]),
            )
        return DeliveryResult(notification.id, self.name, DeliveryStatus.SENT)


class SlackChannel(WebhookChannel):
    """A Slack incoming webhook, which wants ``{"text": ...}``."""

    name = "slack"

    def payload(self, notification: Notification) -> Dict[str, Any]:
        prefix = "🔴" if notification.urgent else "•"
        lines = ["%s *%s*" % (prefix, notification.subject), notification.body]
        if notification.incident_key:
            lines.append("_%s_" % notification.incident_key)
        return {"text": "\n".join(lines)}


def build_channels(settings: Any) -> List[Channel]:
    """Construct the channels named in ``notify_channels``.

    An unknown or unconfigured name is skipped with a warning rather than
    raising: a typo in a channel list should not stop a service booting.
    """
    names = [
        name.strip().lower()
        for name in (getattr(settings, "notify_channels", "") or "").split(",")
        if name.strip()
    ]
    channels: List[Channel] = []
    for name in names:
        if name == "log":
            channels.append(LogChannel())
        elif name in ("webhook", "slack"):
            url = getattr(settings, "notify_webhook_url", None)
            if not url:
                logger.warning(
                    "notification channel needs a webhook URL; skipping",
                    extra={"channel": name},
                )
                continue
            channels.append(SlackChannel(url) if name == "slack" else WebhookChannel(url))
        else:
            logger.warning("unknown notification channel", extra={"channel": name})
    return channels


def describe(channels: List[Channel]) -> str:
    return ", ".join(channel.name for channel in channels) or "none"


def json_body(notification: Notification) -> str:
    """Helper for adapters that want the payload as a string."""
    return json.dumps(notification.to_dict(), sort_keys=True)
