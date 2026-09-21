"""``@mention`` parsing.

Two forms are accepted, because analysts type both:

* ``@dana`` - the local part of an address, resolved when it is unambiguous
  inside the tenant;
* ``@dana@acme.test`` - the full address, always unambiguous.

Unresolved handles are **returned rather than swallowed**. A mention that
matched nobody is worth telling the author about: silently dropping it means
they believe they notified someone who was never told.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Sequence, Tuple

#: ``@name`` or ``@name@domain.tld``. Trailing punctuation is left outside the
#: match so "ask @dana, please" resolves to "dana".
#:
#: The lookbehind matters: without it, a bare address in prose ("the account
#: dana@acme.test was disabled") matches "@acme.test" as a handle, which then
#: fails to resolve and tells the author that somebody they never mentioned
#: could not be found. A mention has to start a word.
MENTION_RE = re.compile(
    r"(?<![A-Za-z0-9._%+\-])@([A-Za-z0-9._%+\-]+(?:@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})?)",
)


@dataclass
class MentionResult:
    #: Emails of users the handles resolved to, in first-seen order.
    resolved: List[str] = field(default_factory=list)
    #: Handles that matched nobody, or matched more than one person.
    unresolved: List[str] = field(default_factory=list)
    #: Handles that matched several people, kept separately so the caller can
    #: explain *why* they were not resolved.
    ambiguous: Dict[str, List[str]] = field(default_factory=dict)

    @property
    def any_unresolved(self) -> bool:
        return bool(self.unresolved)


def extract_handles(body: str) -> List[str]:
    """Every ``@handle`` in the text, de-duplicated, in order."""
    seen: Dict[str, None] = {}
    for match in MENTION_RE.finditer(body or ""):
        seen.setdefault(match.group(1).rstrip(".,;:!?"), None)
    return list(seen)


def resolve_mentions(body: str, candidates: Sequence[str]) -> MentionResult:
    """Match handles against a tenant's user emails.

    ``candidates`` is every email in the tenant. Resolution is exact-email
    first, then a unique local-part match; a local part shared by two people is
    reported ambiguous rather than guessed at.
    """
    result = MentionResult()
    if not body:
        return result

    by_email = {email.lower(): email for email in candidates}
    by_local: Dict[str, List[str]] = {}
    for email in candidates:
        by_local.setdefault(email.split("@", 1)[0].lower(), []).append(email)

    for handle in extract_handles(body):
        key = handle.lower()
        if key in by_email:
            _append_unique(result.resolved, by_email[key])
            continue
        matches = by_local.get(key, [])
        if len(matches) == 1:
            _append_unique(result.resolved, matches[0])
        elif len(matches) > 1:
            result.ambiguous[handle] = sorted(matches)
            result.unresolved.append(handle)
        else:
            result.unresolved.append(handle)
    return result


def render_note(body: str, resolved: Iterable[str]) -> List[Tuple[str, bool]]:
    """Split a body into ``(text, is_mention)`` segments for display.

    Returned as segments rather than HTML so the caller decides how to render
    and nothing here can inject markup.
    """
    known = {email.lower() for email in resolved}
    known |= {email.split("@", 1)[0].lower() for email in resolved}

    segments: List[Tuple[str, bool]] = []
    cursor = 0
    for match in MENTION_RE.finditer(body or ""):
        handle = match.group(1).rstrip(".,;:!?")
        if handle.lower() not in known:
            continue
        if match.start() > cursor:
            segments.append((body[cursor : match.start()], False))
        segments.append(("@" + handle, True))
        cursor = match.start() + 1 + len(handle)
    if cursor < len(body or ""):
        segments.append((body[cursor:], False))
    return segments


def _append_unique(target: List[str], value: str) -> None:
    if value not in target:
        target.append(value)
