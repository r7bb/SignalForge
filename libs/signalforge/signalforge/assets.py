"""Asset / identity criticality inventory.

Risk scoring needs to know that ``prod-payments-db`` matters more than a
developer laptop.  The inventory is a small YAML file (see
``schemas/assets.yml``) so it can live in git next to the detections; anything
unknown falls back to a medium criticality of 5/10.
"""

from __future__ import annotations

import fnmatch
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

DEFAULT_CRITICALITY = 5

CRITICALITY_SCORES: Dict[str, int] = {
    "low": 3,
    "medium": 5,
    "high": 8,
    "critical": 10,
}


class AssetInventory:
    def __init__(self, data: Optional[Dict[str, Any]] = None) -> None:
        data = data or {}
        self.hosts: Dict[str, str] = dict(data.get("hosts") or {})
        self.users: Dict[str, str] = dict(data.get("users") or {})
        self.resources: Dict[str, str] = dict(data.get("resources") or {})
        self.networks: Dict[str, str] = dict(data.get("networks") or {})
        self.service_accounts = set(data.get("service_accounts") or [])
        self.load_test_accounts = set(data.get("load_test_accounts") or [])

    @staticmethod
    def _lookup(table: Dict[str, str], value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        needle = value.lower()
        if needle in table:
            return table[needle]
        for pattern, level in table.items():
            if fnmatch.fnmatch(needle, pattern):
                return level
        return None

    def host_level(self, hostname: Optional[str]) -> Optional[str]:
        return self._lookup(self.hosts, hostname)

    def user_level(self, user: Optional[str]) -> Optional[str]:
        return self._lookup(self.users, user)

    def resource_level(self, resource: Optional[str]) -> Optional[str]:
        return self._lookup(self.resources, resource)

    def is_service_account(self, user: Optional[str]) -> bool:
        return bool(user) and any(
            fnmatch.fnmatch(user.lower(), pattern) for pattern in self.service_accounts
        )

    def is_load_test_account(self, user: Optional[str]) -> bool:
        return bool(user) and any(
            fnmatch.fnmatch(user.lower(), pattern) for pattern in self.load_test_accounts
        )

    def criticality_score(
        self,
        hostname: Optional[str] = None,
        user: Optional[str] = None,
        resource: Optional[str] = None,
    ) -> int:
        levels = [
            self.host_level(hostname),
            self.user_level(user),
            self.resource_level(resource),
        ]
        scores = [CRITICALITY_SCORES[lvl] for lvl in levels if lvl in CRITICALITY_SCORES]
        return max(scores) if scores else DEFAULT_CRITICALITY


def load_inventory(path: Optional[str] = None) -> AssetInventory:
    candidates = [Path(path)] if path else []
    candidates += [
        Path("schemas/assets.yml"),
        Path(__file__).resolve().parents[3] / "schemas" / "assets.yml",
    ]
    for candidate in candidates:
        if candidate and candidate.exists():
            with candidate.open("r", encoding="utf-8") as handle:
                return AssetInventory(yaml.safe_load(handle) or {})
    return AssetInventory()


@lru_cache(maxsize=1)
def get_inventory() -> AssetInventory:
    return load_inventory()


def reset_inventory_cache() -> None:
    get_inventory.cache_clear()
