"""Relationships between incidents.

Three relationships, each with different directionality, because conflating
them loses the thing that makes a link useful:

``related_to``
    Symmetric. "These two are connected" reads the same from either end, so it
    is stored once and presented from both.
``duplicate_of``
    Directional, and the one a merge records. A points at B means A is the
    copy; B is the case that survives.
``caused_by``
    Directional. A caused_by B means B came first. Read from B's end it is
    ``led_to``, which is why the inverse has its own label rather than being
    rendered backwards.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Dict, Optional

from pydantic import BaseModel, ConfigDict, Field

from .ocsf import utcnow


class LinkRelationship(str, Enum):
    RELATED_TO = "related_to"
    DUPLICATE_OF = "duplicate_of"
    CAUSED_BY = "caused_by"


#: How each relationship reads from the other end. A symmetric relationship is
#: its own inverse; a directional one gets a label that is true in reverse
#: rather than the same word pointing the wrong way.
INVERSE_LABEL: Dict[LinkRelationship, str] = {
    LinkRelationship.RELATED_TO: "related_to",
    LinkRelationship.DUPLICATE_OF: "duplicated_by",
    LinkRelationship.CAUSED_BY: "led_to",
}

SYMMETRIC = frozenset({LinkRelationship.RELATED_TO})


def is_symmetric(relationship: LinkRelationship) -> bool:
    return relationship in SYMMETRIC


def inverse_label(relationship: LinkRelationship) -> str:
    return INVERSE_LABEL[relationship]


class IncidentLink(BaseModel):
    """One edge, as the API presents it from a particular incident's side."""

    model_config = ConfigDict(extra="allow")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    #: The incident on the other end, from the point of view of the caller.
    other_key: str
    other_title: str = ""
    other_status: str = ""
    #: The relationship as it reads *from the caller's side*: an incident that
    #: is the target of a ``duplicate_of`` link reports ``duplicated_by``.
    relationship: str
    reason: Optional[str] = None
    created_by: str = "system"
    created_at: datetime = Field(default_factory=utcnow)
    #: False when the stored row points the other way and this is the
    #: reverse reading of it.
    outgoing: bool = True
