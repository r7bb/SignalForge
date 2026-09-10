"""Timestamp parsing helpers shared by the normalizers."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

_SYSLOG_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$")
_MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


def utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def parse_time(value: Any, *, reference: Optional[datetime] = None) -> Optional[datetime]:
    """Parse the timestamp shapes SignalForge ingests.

    Accepts datetimes, epoch seconds/millis (int, float or numeric string),
    ISO-8601 (including a trailing ``Z``) and RFC3164 syslog stamps such as
    ``Sep 10 13:41:02`` which carry no year - those are resolved against
    ``reference`` (default: now), rolling back a year if that would put the
    event in the future.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return ensure_utc(value)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _from_epoch(float(value))
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if re.fullmatch(r"\d{9,14}(\.\d+)?", text):
        return _from_epoch(float(text))
    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        return ensure_utc(datetime.fromisoformat(candidate))
    except ValueError:
        pass
    match = _SYSLOG_RE.match(text)
    if match:
        ref = ensure_utc(reference or utcnow())
        month = _MONTHS[match.group(1)]
        parsed = datetime(
            ref.year, month, int(match.group(2)), int(match.group(3)),
            int(match.group(4)), int(match.group(5)), tzinfo=timezone.utc,
        )
        if parsed - ref > timedelta(days=1):
            parsed = parsed.replace(year=ref.year - 1)
        return parsed
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z"):
        try:
            return ensure_utc(datetime.strptime(text, fmt))
        except ValueError:
            continue
    return None


def _from_epoch(value: float) -> datetime:
    # Heuristic: values large enough to be milliseconds (or micro/nanos) get scaled.
    if value > 1e17:
        value /= 1e9
    elif value > 1e14:
        value /= 1e6
    elif value > 1e11:
        value /= 1e3
    return datetime.fromtimestamp(value, tz=timezone.utc)
