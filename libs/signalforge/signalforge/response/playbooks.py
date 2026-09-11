"""Approval-gated response playbooks.

Design constraints, deliberately conservative:

* **Nothing runs without an analyst.**  A playbook is *requested* by the
  platform and stays ``pending_approval`` until a human with the responder role
  approves it.  ``SIGNALFORGE_RESPONSE_REQUIRE_APPROVAL=false`` exists for
  automated tests only and is logged loudly.
* **Dry run by default.**  With ``SIGNALFORGE_RESPONSE_DRY_RUN=true`` (the
  default) a playbook reports exactly what it *would* do and changes nothing.
* **Lab targets only.**  Every playbook acts on resources the platform itself
  owns: the local denylist file, the lab application's own accounts/sessions
  and its own API tokens, via an explicit adapter.  There is no vendor
  integration that could reach a production system by accident.
* **Everything is audited.**  Request, approval/rejection and execution each
  write an audit row and an incident timeline entry.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from ..config import Settings, get_settings

log = logging.getLogger("signalforge.response")


class ResponseError(Exception):
    """Invalid playbook request (unknown playbook, missing target, bad state)."""


@dataclass
class PlaybookResult:
    ok: bool
    message: str
    dry_run: bool = True
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"ok": self.ok, "message": self.message, "dry_run": self.dry_run, "data": self.data}


@dataclass
class Playbook:
    """A named, documented containment action."""

    name: str
    title: str
    description: str
    #: What the action touches, for the approval prompt in the UI.
    target_kind: str  # account | session | token | ip | container | none
    #: Roles allowed to approve it.
    approver_roles: Sequence[str] = ("responder", "admin")
    reversible: bool = True
    handler: Optional[Callable[[ResponseContext], PlaybookResult]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "target_kind": self.target_kind,
            "approver_roles": list(self.approver_roles),
            "reversible": self.reversible,
        }


@dataclass
class ResponseContext:
    """Everything a handler is allowed to see."""

    playbook: str
    target: Optional[str]
    params: Dict[str, Any]
    settings: Settings
    actor: str
    incident_key: Optional[str] = None
    adapter: Optional[LabAdapter] = None

    @property
    def dry_run(self) -> bool:
        return bool(self.settings.response_dry_run)


class LabAdapter:
    """Adapter over the isolated lab environment.

    The default implementation only manipulates state SignalForge itself owns:
    an on-disk denylist and an in-memory account/session/token registry that
    the bundled lab application reads.  Swap it for a real adapter only in an
    environment you are authorised to act on.
    """

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()
        self.disabled_accounts: List[str] = []
        self.revoked_sessions: List[str] = []
        self.revoked_tokens: List[str] = []
        self.isolated_containers: List[str] = []
        self.revoked_privileges: List[str] = []

    # -- account / session / token ----------------------------------------
    def disable_account(self, account: str) -> Dict[str, Any]:
        self.disabled_accounts.append(account)
        return {"account": account, "state": "disabled"}

    def revoke_sessions(self, account: str) -> Dict[str, Any]:
        self.revoked_sessions.append(account)
        return {"account": account, "state": "sessions_revoked"}

    def revoke_token(self, token_id: str) -> Dict[str, Any]:
        self.revoked_tokens.append(token_id)
        return {"token_id": token_id, "state": "revoked"}

    def revoke_privileges(self, account: str, role: Optional[str] = None) -> Dict[str, Any]:
        self.revoked_privileges.append(account)
        return {"account": account, "role": role, "state": "privileges_revoked"}

    def isolate_container(self, container: str) -> Dict[str, Any]:
        self.isolated_containers.append(container)
        return {"container": container, "state": "network_isolated"}

    # -- denylist ---------------------------------------------------------
    @property
    def denylist_path(self) -> Path:
        return Path(self.settings.response_denylist_path)

    def add_to_denylist(self, address: str) -> Dict[str, Any]:
        ipaddress.ip_address(address)  # validate; raises ValueError for junk
        path = self.denylist_path
        path.parent.mkdir(parents=True, exist_ok=True)
        existing = self.read_denylist()
        if address in existing:
            return {"address": address, "state": "already_present", "count": len(existing)}
        with path.open("a", encoding="utf-8") as handle:
            handle.write("%s\n" % address)
        return {"address": address, "state": "denied", "count": len(existing) + 1}

    def read_denylist(self) -> List[str]:
        path = self.denylist_path
        if not path.exists():
            return []
        with path.open("r", encoding="utf-8") as handle:
            return [line.strip() for line in handle if line.strip()]


# --------------------------------------------------------------------------- #
# Handlers
# --------------------------------------------------------------------------- #
def _require_target(context: ResponseContext) -> str:
    if not context.target:
        raise ResponseError("playbook %r requires a target" % context.playbook)
    return context.target


def _disable_account(context: ResponseContext) -> PlaybookResult:
    account = _require_target(context)
    if context.dry_run:
        return PlaybookResult(
            True, "would disable lab account %s" % account, True, {"account": account}
        )
    data = context.adapter.disable_account(account) if context.adapter else {}
    return PlaybookResult(True, "disabled lab account %s" % account, False, data)


def _revoke_sessions(context: ResponseContext) -> PlaybookResult:
    account = _require_target(context)
    if context.dry_run:
        return PlaybookResult(
            True, "would revoke active lab sessions for %s" % account, True, {"account": account}
        )
    data = context.adapter.revoke_sessions(account) if context.adapter else {}
    return PlaybookResult(True, "revoked lab sessions for %s" % account, False, data)


def _revoke_api_token(context: ResponseContext) -> PlaybookResult:
    token = _require_target(context)
    if context.dry_run:
        return PlaybookResult(
            True, "would revoke lab API token %s" % token, True, {"token_id": token}
        )
    data = context.adapter.revoke_token(token) if context.adapter else {}
    return PlaybookResult(True, "revoked lab API token %s" % token, False, data)


def _revoke_privileges(context: ResponseContext) -> PlaybookResult:
    account = _require_target(context)
    role = context.params.get("role")
    if context.dry_run:
        return PlaybookResult(
            True,
            "would remove role %s from %s" % (role or "elevated", account),
            True,
            {"account": account, "role": role},
        )
    data = context.adapter.revoke_privileges(account, role) if context.adapter else {}
    return PlaybookResult(True, "removed elevated role from %s" % account, False, data)


def _deny_ip(context: ResponseContext) -> PlaybookResult:
    address = _require_target(context)
    try:
        ipaddress.ip_address(address)
    except ValueError as exc:
        raise ResponseError("%r is not an IP address" % address) from exc
    if context.dry_run:
        return PlaybookResult(
            True, "would add %s to the local denylist" % address, True, {"address": address}
        )
    data = context.adapter.add_to_denylist(address) if context.adapter else {}
    return PlaybookResult(True, "added %s to the local denylist" % address, False, data)


def _isolate_container(context: ResponseContext) -> PlaybookResult:
    container = _require_target(context)
    if context.dry_run:
        return PlaybookResult(
            True,
            "would isolate disposable lab container %s" % container,
            True,
            {"container": container},
        )
    data = context.adapter.isolate_container(container) if context.adapter else {}
    return PlaybookResult(True, "isolated lab container %s" % container, False, data)


def _contain_account(context: ResponseContext) -> PlaybookResult:
    """Composite playbook: sessions, then privileges, then the account."""
    account = _require_target(context)
    steps: List[Dict[str, Any]] = []
    for step in (_revoke_sessions, _revoke_privileges, _disable_account):
        result = step(context)
        steps.append(
            {
                "step": step.__name__.strip("_"),
                "message": result.message,
                "ok": result.ok,
                "data": result.data,
            }
        )
        if not result.ok:
            return PlaybookResult(
                False,
                "containment stopped at %s" % step.__name__,
                context.dry_run,
                {"steps": steps},
            )
    verb = "would contain" if context.dry_run else "contained"
    return PlaybookResult(
        True, "%s lab account %s" % (verb, account), context.dry_run, {"steps": steps}
    )


def _notify_only(context: ResponseContext) -> PlaybookResult:
    return PlaybookResult(
        True,
        "notification recorded for %s" % (context.incident_key or context.target or "incident"),
        context.dry_run,
        {"channel": context.params.get("channel", "audit-log")},
    )


PLAYBOOKS: Dict[str, Playbook] = {
    playbook.name: playbook
    for playbook in [
        Playbook(
            name="disable_account",
            title="Disable lab account",
            description="Disables the account in the isolated lab identity store.",
            target_kind="account",
            handler=_disable_account,
        ),
        Playbook(
            name="revoke_sessions",
            title="Revoke lab sessions",
            description="Invalidates the account's active sessions in the lab application.",
            target_kind="account",
            handler=_revoke_sessions,
        ),
        Playbook(
            name="revoke_api_token",
            title="Revoke lab API token",
            description="Invalidates a token issued by the lab application.",
            target_kind="token",
            handler=_revoke_api_token,
        ),
        Playbook(
            name="revoke_privileges",
            title="Remove elevated role",
            description="Removes an elevated role granted in the lab identity store.",
            target_kind="account",
            handler=_revoke_privileges,
        ),
        Playbook(
            name="deny_ip",
            title="Add IP to local denylist",
            description="Appends the address to SignalForge's own denylist file.",
            target_kind="ip",
            handler=_deny_ip,
        ),
        Playbook(
            name="isolate_container",
            title="Isolate disposable lab container",
            description="Detaches a disposable lab container from its network.",
            target_kind="container",
            reversible=True,
            handler=_isolate_container,
        ),
        Playbook(
            name="contain_account",
            title="Contain lab account (composite)",
            description=(
                "Revokes sessions, removes elevated roles and disables the lab account, "
                "in that order."
            ),
            target_kind="account",
            approver_roles=("admin",),
            handler=_contain_account,
        ),
        Playbook(
            name="notify_only",
            title="Notify, take no action",
            description="Records a notification on the incident without touching anything.",
            target_kind="none",
            approver_roles=("analyst", "responder", "admin"),
            handler=_notify_only,
        ),
    ]
}


def get_playbook(name: str) -> Playbook:
    playbook = PLAYBOOKS.get(name)
    if playbook is None:
        raise ResponseError(
            "unknown playbook %r (available: %s)" % (name, ", ".join(sorted(PLAYBOOKS)))
        )
    return playbook


def list_playbooks() -> List[Dict[str, Any]]:
    return [playbook.to_dict() for playbook in PLAYBOOKS.values()]


def execute(
    name: str,
    *,
    target: Optional[str],
    params: Optional[Dict[str, Any]] = None,
    actor: str,
    incident_key: Optional[str] = None,
    settings: Optional[Settings] = None,
    adapter: Optional[LabAdapter] = None,
) -> PlaybookResult:
    """Run an *already approved* playbook.  Approval is enforced by the service."""
    settings = settings or get_settings()
    playbook = get_playbook(name)
    if playbook.handler is None:  # pragma: no cover - all playbooks ship a handler
        raise ResponseError("playbook %r has no handler" % name)
    context = ResponseContext(
        playbook=name,
        target=target,
        params=dict(params or {}),
        settings=settings,
        actor=actor,
        incident_key=incident_key,
        adapter=adapter or LabAdapter(settings),
    )
    log.info(
        "executing playbook",
        extra={
            "playbook": name,
            "target": target,
            "actor": actor,
            "dry_run": context.dry_run,
            "incident": incident_key,
        },
    )
    return playbook.handler(context)


def suggest_target(playbook_name: str, incident: Any) -> Optional[str]:
    """Best default target for a playbook, given an incident."""
    playbook = get_playbook(playbook_name)
    if playbook.target_kind == "account":
        return getattr(incident, "principal", None)
    if playbook.target_kind == "ip":
        ips = getattr(incident, "source_ips", None) or []
        return ips[0] if ips else None
    if playbook.target_kind == "container":
        hosts = getattr(incident, "hostnames", None) or []
        return hosts[0] if hosts else None
    return None
