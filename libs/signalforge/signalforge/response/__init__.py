"""Approval-gated response automation for isolated lab environments."""

from .playbooks import (
    PLAYBOOKS,
    LabAdapter,
    Playbook,
    PlaybookResult,
    ResponseContext,
    ResponseError,
    execute,
    get_playbook,
    list_playbooks,
    suggest_target,
)
from .service import ResponseService

__all__ = [
    "PLAYBOOKS",
    "LabAdapter",
    "Playbook",
    "PlaybookResult",
    "ResponseContext",
    "ResponseError",
    "ResponseService",
    "execute",
    "get_playbook",
    "list_playbooks",
    "suggest_target",
]
