"""Roles for terminals: a name and a list of tool patterns (botrbac_cli.patterns).

Each person has their own roles (`owner` is `person:<email>`, which leaves room for a
workspace owner later). Three built-in roles are always there and cannot be changed.
"""

import json
import secrets
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

from botrbac_cli.patterns import PatternError, is_tool_id, validate_all

ROLES_KEY = "term:roles:{email}"
TOOLS_KEY = "term:tools:{email}"
MAX_ROLES = 50
MAX_NAME = 60
MAX_SEEN_TOOLS = 500
DEFAULT_OFFLINE_DAYS = 7
MAX_OFFLINE_DAYS = 30


class RoleError(ValueError):
    """A role that cannot be saved; the message is shown to the person."""


@dataclass(frozen=True)
class Role:
    id: str
    name: str
    patterns: list[str]
    offline_days: int = DEFAULT_OFFLINE_DAYS
    builtin: bool = False
    owner: str = ""
    updated_at: float = 0.0
    description: str = ""

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "patterns": list(self.patterns),
            "offline_days": self.offline_days,
            "builtin": self.builtin,
        }


READ_ONLY = "read-only"
FULL = "full"
NO_TOOLS = "none"
BUILTIN: dict[str, Role] = {
    READ_ONLY: Role(
        READ_ONLY,
        "Read-only",
        ["*/read*", "*/get*", "*/list*", "*/search*"],
        builtin=True,
        description=(
            "Tools whose names start with read, get, list or search. This goes by the "
            "name only: check what each server's tools really do."
        ),
    ),
    FULL: Role(FULL, "Full access", ["*"], builtin=True, description="Every tool."),
    NO_TOOLS: Role(NO_TOOLS, "No tools", [], builtin=True, description="Blocks every tool."),
}
# What a new terminal gets. A terminal whose role was deleted gets No tools instead.
DEFAULT_ROLE = READ_ONLY


@dataclass
class TerminalRoles:
    store: Any
    clock: Callable[[], float] = field(default=time.time)

    def _key(self, email: str) -> str:
        return ROLES_KEY.format(email=email)

    def all(self, email: str) -> list[Role]:
        custom: list[Role] = []
        for raw in self.store.hgetall(self._key(email)).values():
            role = _load(raw)
            if role is not None:
                custom.append(role)
        custom.sort(key=lambda r: r.name.lower())
        return [*BUILTIN.values(), *custom]

    def get(self, email: str, role_id: str | None) -> Role | None:
        if not role_id:
            return None
        if role_id in BUILTIN:
            return BUILTIN[role_id]
        raw = self.store.hget(self._key(email), role_id)
        return _load(raw) if raw else None

    def effective(self, email: str, role_id: str | None) -> Role:
        """The role a terminal runs with. No role set means the default (Read-only). A
        role that is set but cannot be found (deleted, or a record that fails its
        signature check) means No tools: never a different set than the person chose."""
        if not role_id:
            return BUILTIN[DEFAULT_ROLE]
        return self.get(email, role_id) or BUILTIN[NO_TOOLS]

    def save(
        self,
        email: str,
        role_id: str | None,
        name: str,
        patterns: list[str],
        offline_days: int = DEFAULT_OFFLINE_DAYS,
    ) -> Role:
        name = " ".join(name.split())
        if not name or len(name) > MAX_NAME:
            raise RoleError(f"Give the role a name of 1 to {MAX_NAME} characters.")
        if role_id in BUILTIN:
            raise RoleError("Built-in roles cannot be changed. Make a new role instead.")
        try:
            checked = validate_all(patterns)
        except PatternError as exc:
            raise RoleError(str(exc)) from None
        if not 1 <= offline_days <= MAX_OFFLINE_DAYS:
            raise RoleError(f"Offline grace must be 1 to {MAX_OFFLINE_DAYS} days.")
        existing = self.all(email)
        if any(r.name.lower() == name.lower() and r.id != role_id for r in existing):
            raise RoleError(f"You already have a role called {name!r}.")
        if role_id:
            if self.get(email, role_id) is None:
                raise RoleError("That role no longer exists.")
        else:
            if len(existing) - len(BUILTIN) >= MAX_ROLES:
                raise RoleError(f"You can have at most {MAX_ROLES} roles.")
            role_id = "r_" + secrets.token_hex(6)
        role = Role(
            id=role_id,
            name=name,
            patterns=checked,
            offline_days=offline_days,
            owner=f"person:{email}",
            updated_at=self.clock(),
        )
        self.store.hset(self._key(email), role_id, json.dumps(asdict(role)))
        return role

    def delete(self, email: str, role_id: str) -> bool:
        if role_id in BUILTIN or self.get(email, role_id) is None:
            return False
        self.store.hdel(self._key(email), role_id)
        return True

    # ---- tools the person's terminals have seen (feeds the tool picker) ----------

    def note_tools(self, email: str, tools: list[str]) -> None:
        key = TOOLS_KEY.format(email=email)
        known = self.store.hgetall(key)
        now = str(int(self.clock()))
        for tool in tools:
            if not isinstance(tool, str) or not is_tool_id(tool):
                continue
            if tool not in known and len(known) >= MAX_SEEN_TOOLS:
                continue
            if tool not in known:
                self.store.hset(key, tool, now)
                known[tool] = now

    def seen_tools(self, email: str) -> dict[str, list[str]]:
        """server -> sorted tool names."""
        grouped: dict[str, list[str]] = {}
        for tool in self.store.hgetall(TOOLS_KEY.format(email=email)):
            server, _, name = tool.partition("/")
            grouped.setdefault(server, []).append(name)
        return {server: sorted(names) for server, names in sorted(grouped.items())}


def _load(raw: str) -> Role | None:
    try:
        data = json.loads(raw)
        return Role(
            id=str(data["id"]),
            name=str(data["name"]),
            patterns=[str(p) for p in data.get("patterns") or []],
            offline_days=int(data.get("offline_days") or DEFAULT_OFFLINE_DAYS),
            owner=str(data.get("owner") or ""),
            updated_at=float(data.get("updated_at") or 0),
        )
    except (ValueError, KeyError, TypeError):
        return None
