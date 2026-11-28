"""Named roles: a named part of the owner's allowed files, with its own ceiling.

A connected app already has a level (read only, read and edit, full) and reaches
everything on its owner's allowlist. A named role is narrower. The owner defines it on
the dashboard: a name, a level, and which allowlisted items it covers. An agent uses it
by connecting to `/mcp/role/<slug>` instead of `/mcp`.

A role only ever narrows the connection it is used through:

- the level is the lower of the connection's level and the role's;
- the files are the allowlist entries the role lists, so an item taken off the allowlist
  is gone from every role, and a role can never reach what the allowlist does not hold;
- only the tools for this person's own Drive files are offered (policy.AGENT_ROLE_TOOLS).
  The mailbox, pairing, webhooks, access requests and other people's shared files are
  not part of a role.

A role that does not exist, or whose record cannot be read, refuses the call: a missing
record is never treated as "no narrowing".

An app that signs in through a role's address gets a connection for that role only
(mcp_oauth.py records the role on the grant). Its tokens are refused on plain `/mcp` and
on every other role, and an app connected to plain `/mcp` is refused on a role's
address. So the role holds against someone who has copied the token, not only against an
agent configured with the address. Pre-shared `API_TOKENS` are not connections and
cannot be bound: on a role's address they are narrowed, and they still work on `/mcp`.
"""

import json
import logging
import re
from collections.abc import Collection, Iterable
from contextvars import ContextVar
from dataclasses import dataclass, field, replace

import anyio.to_thread
from starlette.types import ASGIApp, Receive, Scope, Send

from .audit import audit_auth_failure
from .auth import ROLE_PATH_PARAM, current_principal
from .auth import ROLE_SLUG as SLUG
from .config import Role
from .store import AGENT_ROLES_KEY, KeyValueStore, utc_now

logger = logging.getLogger(__name__)

__all__ = ["ROLE_PATH_PARAM", "SLUG"]
_ITEM_ID = re.compile(r"^[A-Za-z0-9_-]{1,200}$")
MAX_NAME = 40
MAX_ROLES = 20
MAX_ROLE_ITEMS = 200

# Lowest first. A role's level is a ceiling: the call runs at the lower of the two.
_LEVELS: tuple[Role, ...] = (Role.VIEWER, Role.EDITOR, Role.ADMIN)


def narrowed(level: Role, ceiling: Role | str) -> Role:
    """The lower of a connection's level and a role's. An unknown ceiling is read only."""
    try:
        cap = Role(ceiling)
    except ValueError:
        cap = Role.VIEWER
    return _LEVELS[min(_LEVELS.index(Role(level)), _LEVELS.index(cap))]


def slugify(name: str) -> str:
    """`Research Reader` -> `research-reader`. Empty when nothing usable is left."""
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")[:32].strip("-")
    return slug if SLUG.fullmatch(slug) else ""


class AgentRoleError(Exception):
    """A role could not be saved. The message is written for the owner."""


@dataclass(frozen=True)
class AgentRole:
    slug: str
    name: str
    level: str
    items: tuple[str, ...]
    created_at: str = field(default_factory=utc_now)

    def to_json(self) -> str:
        return json.dumps(
            {
                "slug": self.slug,
                "name": self.name,
                "level": self.level,
                "items": list(self.items),
                "created_at": self.created_at,
            },
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, raw: str) -> "AgentRole":
        data = json.loads(raw)
        slug = str(data["slug"])
        if SLUG.fullmatch(slug) is None:
            raise ValueError("bad role slug")
        level = str(data.get("level", ""))
        items = data.get("items") or []
        if not isinstance(items, list):
            raise ValueError("bad role items")
        return cls(
            slug=slug,
            name=str(data.get("name") or slug)[:MAX_NAME],
            # Anything unreadable is the lowest level, never the highest.
            level=level if level in {r.value for r in _LEVELS} else Role.VIEWER.value,
            items=tuple(str(i) for i in items if _ITEM_ID.fullmatch(str(i)))[:MAX_ROLE_ITEMS],
            created_at=str(data.get("created_at", "")),
        )


class AgentRoles:
    """One person's named roles: a hash of AgentRole records, keyed by slug."""

    def __init__(self, store: KeyValueStore, key: str = AGENT_ROLES_KEY):
        self.store = store
        self.key = key

    def all(self) -> list[AgentRole]:
        roles: list[AgentRole] = []
        for slug, raw in self.store.hgetall(self.key).items():
            try:
                role = AgentRole.from_json(raw)
            except (ValueError, KeyError, TypeError):
                continue
            # A record filed under another slug is not that role.
            if role.slug == slug:
                roles.append(role)
        return sorted(roles, key=lambda r: r.name.lower())

    def get(self, slug: str) -> AgentRole | None:
        if SLUG.fullmatch(slug or "") is None:
            return None
        raw = self.store.hget(self.key, slug)
        if not raw:
            return None
        try:
            role = AgentRole.from_json(raw)
        except (ValueError, KeyError, TypeError):
            return None
        return role if role.slug == slug else None

    def save(
        self,
        name: str,
        level: str,
        items: Iterable[str],
        allowlisted: Collection[str],
        slug: str = "",
    ) -> AgentRole:
        """Create the role, or replace the one with the same slug. `allowlisted` is the
        owner's allowlist right now: a role can only list items that are on it.

        With `slug`, that existing role is changed and `name` is only what it is called:
        the slug is the role's address and what its connections are bound to, so a rename
        never moves it."""
        name = " ".join(name.split())[:MAX_NAME]
        if slug:
            if self.get(slug) is None:
                raise AgentRoleError("That role no longer exists.")
            if not slugify(name):
                raise AgentRoleError("Give the role a name with letters or numbers.")
            clash = next(
                (
                    r
                    for r in self.all()
                    if r.slug != slug and slugify(name) in (r.slug, slugify(r.name))
                ),
                None,
            )
            if clash is not None:
                raise AgentRoleError(f"You already have a role called {clash.name}.")
        else:
            slug = slugify(name)
        if not slug:
            raise AgentRoleError("Give the role a name with letters or numbers.")
        if level not in {r.value for r in _LEVELS}:
            raise AgentRoleError("Choose what this role may do.")
        chosen = tuple(dict.fromkeys(i for i in items if i in allowlisted))
        if not chosen:
            raise AgentRoleError("Choose at least one allowed file or folder for this role.")
        if len(chosen) > MAX_ROLE_ITEMS:
            raise AgentRoleError(f"A role can list at most {MAX_ROLE_ITEMS} items.")
        existing = self.get(slug)
        if existing is None and len(self.store.hgetall(self.key)) >= MAX_ROLES:
            raise AgentRoleError(f"You can have at most {MAX_ROLES} roles. Delete one first.")
        role = AgentRole(slug=slug, name=name, level=level, items=chosen)
        if existing is not None:
            role = replace(role, created_at=existing.created_at)
        self.store.hset(self.key, slug, role.to_json())
        return role

    def delete(self, slug: str) -> bool:
        if self.get(slug) is None:
            return False
        self.store.hdel(self.key, slug)
        return True


# The named role this call runs under, or None for a call to plain `/mcp`.
current_agent_role: ContextVar[AgentRole | None] = ContextVar("current_agent_role", default=None)


class AgentRoleMiddleware:
    """Runs inside the bearer middleware. For `/mcp/role/<slug>` it loads that role from
    the caller's own account and narrows the call to it, or refuses the request."""

    def __init__(self, app: ASGIApp, roles: AgentRoles):
        self.app = app
        self.roles = roles

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        slug = (scope.get("path_params") or {}).get(ROLE_PATH_PARAM)
        principal = current_principal.get()
        bound = None if principal is None else principal.bound_role
        # A connection works only at the address it was approved for: a role's on that
        # role, a plain one on `/mcp`. API tokens (no grant) are not connections.
        connection = principal is not None and principal.grant_id is not None
        if bound != slug and (connection or bound is not None):
            audit_auth_failure("role_mismatch", str(scope.get("path", ""))[:200])
            await _refused(
                send,
                "role_mismatch",
                "This connection was approved for another address. Sign in again from this one.",
            )
            return
        if slug is None:
            await self.app(scope, receive, send)
            return
        role: AgentRole | None = None
        if principal is not None:
            try:
                # The store read uses the caller's account (current_actor is copied in).
                role = await anyio.to_thread.run_sync(self.roles.get, str(slug))
            except Exception:
                logger.warning("could not read a named role; refusing the call", exc_info=True)
        if principal is None or role is None:
            audit_auth_failure("unknown_role", str(scope.get("path", ""))[:200])
            await _refused(
                send,
                "unknown_role",
                "This account has no role with that name. Roles are made in Settings.",
            )
            return
        reset_principal = current_principal.set(
            replace(principal, role=narrowed(principal.role, role.level), agent_role=role.slug)
        )
        reset_role = current_agent_role.set(role)
        try:
            await self.app(scope, receive, send)
        finally:
            current_agent_role.reset(reset_role)
            current_principal.reset(reset_principal)


async def _refused(send: Send, error: str, message: str) -> None:
    # 403, not 404: an MCP client reads 404 on its endpoint as an expired session.
    body = json.dumps({"error": error, "message": message}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 403,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"cache-control", b"no-store"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
