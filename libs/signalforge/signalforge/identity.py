"""Identity resolution across log sources.

The same human appears as ``alex`` in ``sshd``, ``alex@example.com`` in the
application audit log and ``AIDAEXAMPLE`` in CloudTrail.  Correlation groups by
principal, so unless those are reconciled a cross-source attack chain silently
falls apart into three unrelated alerts.

The mapping is declarative (``schemas/identities.yml``) and applied during
normalization: the canonical email lands in ``actor.user.email_addr`` /
``user.email_addr`` while the source's own value is left untouched, so
``OcsfEvent.principal`` becomes stable across sources without losing fidelity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class Identity:
    email: str
    display_name: Optional[str] = None
    uid: Optional[str] = None
    aliases: List[str] = field(default_factory=list)
    department: Optional[str] = None
    is_service_account: bool = False
    criticality: Optional[str] = None


class IdentityResolver:
    def __init__(self, identities: Optional[Dict[str, Any]] = None) -> None:
        self._by_alias: Dict[str, Identity] = {}
        for email, payload in (identities or {}).items():
            payload = payload or {}
            identity = Identity(
                email=email,
                display_name=payload.get("display_name"),
                uid=str(payload["uid"]) if payload.get("uid") else None,
                aliases=[str(alias) for alias in (payload.get("aliases") or [])],
                department=payload.get("department"),
                is_service_account=bool(payload.get("service_account")),
                criticality=payload.get("criticality"),
            )
            for alias in {email, *identity.aliases, *([identity.uid] if identity.uid else [])}:
                self._by_alias[str(alias).lower()] = identity

    def resolve(self, value: Optional[str]) -> Optional[Identity]:
        if not value:
            return None
        return self._by_alias.get(str(value).lower())

    def canonical_email(self, value: Optional[str]) -> Optional[str]:
        identity = self.resolve(value)
        if identity:
            return identity.email
        # An address is already canonical.
        return value if value and "@" in value else None

    @property
    def size(self) -> int:
        return len({identity.email for identity in self._by_alias.values()})


def load_identities(path: Optional[str] = None) -> IdentityResolver:
    candidates = [Path(path)] if path else []
    candidates += [
        Path("schemas/identities.yml"),
        Path(__file__).resolve().parents[3] / "schemas" / "identities.yml",
    ]
    for candidate in candidates:
        if candidate and candidate.exists():
            with candidate.open("r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
            return IdentityResolver(data.get("identities") or {})
    return IdentityResolver()


@lru_cache(maxsize=1)
def get_resolver() -> IdentityResolver:
    return load_identities()


def reset_resolver_cache() -> None:
    get_resolver.cache_clear()
