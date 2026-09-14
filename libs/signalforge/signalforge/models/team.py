"""Teams: the queues incidents are routed to before anybody claims them.

An incident belongs to a *team* first and a *person* second. That ordering is
the point: work that nobody has picked up is still visibly somebody's, which is
what stops an incident quietly ageing in an unassigned pile over a weekend.

Team membership carries its own role (``lead`` or ``member``) that is separate
from the global role on :class:`~signalforge.auth.security.Principal`. A lead is
trusted with their own team's incidents - notably closing one as a false
positive - without being handed tenant-wide admin.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field

from .ocsf import utcnow

#: Membership roles, least to most privileged.
TEAM_ROLES = ("member", "lead")

_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def normalise_slug(value: str) -> str:
    """``"Cloud Security"`` -> ``"cloud-security"``."""
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    if not slug:
        raise ValueError("team slug cannot be empty")
    if not _SLUG_RE.match(slug):
        raise ValueError("invalid team slug %r" % value)
    return slug


class TeamMember(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    team_id: str
    user_id: str
    email: str = ""
    full_name: Optional[str] = None
    #: member | lead
    role: str = "member"
    joined_at: datetime = Field(default_factory=utcnow)

    @property
    def is_lead(self) -> bool:
        return self.role == "lead"


class Team(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant: str = "default"
    slug: str
    name: str
    description: Optional[str] = None
    #: The fallback queue when no routing rule matches. One per tenant.
    is_default: bool = False
    members: List[TeamMember] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    #: Populated by the service for queue views; not stored on the row.
    open_incidents: int = 0
    unclaimed_incidents: int = 0

    @property
    def leads(self) -> List[TeamMember]:
        return [member for member in self.members if member.is_lead]

    def is_lead(self, user_id: str) -> bool:
        return any(m.user_id == user_id and m.is_lead for m in self.members)

    def includes(self, user_id: str) -> bool:
        return any(m.user_id == user_id for m in self.members)
