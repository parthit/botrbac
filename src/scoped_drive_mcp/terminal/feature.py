"""Bot RBAC Terminal's dashboard pages."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import anyio.to_thread
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from ..audit import audit_owner
from ..auth import current_actor
from .roles import BUILTIN, DEFAULT_OFFLINE_DAYS, RoleError, TerminalRoles

Handler = Callable[[Request], Awaitable[Response]]
FormHandler = Callable[[Request, Any], Awaitable[Response]]

# Every key this feature writes starts with this, so it never touches existing records.
KEY_PREFIX = "term:"


@dataclass
class Kit:
    """The dashboard helpers these pages use (all defined in dashboard.py)."""

    owner_only: Callable[[Handler], Handler]
    csrf_protected: Callable[[FormHandler], Handler]
    render: Callable[..., Response]
    flash: Callable[[Request, str, str], None]


async def _run(fn: Callable[..., Any], *args: Any) -> Any:
    return await anyio.to_thread.run_sync(lambda: fn(*args))


def _me() -> str:
    email = current_actor.get()
    assert email, "owner_only sets the actor"
    return email


@dataclass
class TerminalFeature:
    store: Any
    roles: TerminalRoles = field(init=False)

    def __post_init__(self) -> None:
        self.roles = TerminalRoles(self.store)

    def page_routes(self, kit: Kit) -> list[Route]:
        render = kit.render

        async def overview(request: Request) -> Response:
            return render(request, "terminal.html", terminals=[])

        async def roles_page(request: Request) -> Response:
            roles = await _run(self.roles.all, _me())
            return render(request, "terminal_roles.html", roles=roles)

        async def role_edit(request: Request) -> Response:
            email = _me()
            role_id = request.path_params.get("role_id")
            role = None
            if role_id:
                role = await _run(self.roles.get, email, role_id)
                if role is None:
                    return render(request, "error.html", 404, message="Page not found.")
            seen = await _run(self.roles.seen_tools, email)
            return render(
                request,
                "terminal_role.html",
                role=role,
                seen=seen,
                default_offline=DEFAULT_OFFLINE_DAYS,
            )

        async def role_save(request: Request, _form: Any) -> Response:
            email = _me()
            form = await request.form()
            role_id = str(form.get("role_id") or "") or None
            typed = str(form.get("patterns") or "").splitlines()
            ticked = [str(v) for v in form.getlist("tool")]
            try:
                days = int(str(form.get("offline_days") or DEFAULT_OFFLINE_DAYS))
            except ValueError:
                days = 0
            try:
                role = await _run(
                    self.roles.save,
                    email,
                    role_id,
                    str(form.get("name") or ""),
                    ticked + typed,
                    days,
                )
            except RoleError as exc:
                kit.flash(request, "error", str(exc))
                back = f"/terminal/roles/{role_id}" if role_id else "/terminal/roles/new"
                return RedirectResponse(back, status_code=303)
            audit_owner("terminal_role_saved", role=role.id)
            kit.flash(request, "ok", f"Saved {role.name}.")
            return RedirectResponse("/terminal/roles", status_code=303)

        async def role_delete(request: Request, _form: Any) -> Response:
            role_id = request.path_params["role_id"]
            if await _run(self.roles.delete, _me(), role_id):
                audit_owner("terminal_role_deleted", role=role_id)
                kit.flash(
                    request,
                    "ok",
                    "Role deleted. Terminals that used it now have no tools until you give "
                    "them a role.",
                )
            else:
                kit.flash(request, "error", "That role cannot be deleted.")
            return RedirectResponse("/terminal/roles", status_code=303)

        own = kit.owner_only
        csrf = kit.csrf_protected
        return [
            Route("/terminal", own(overview), methods=["GET"]),
            Route("/terminal/roles", own(roles_page), methods=["GET"]),
            Route("/terminal/roles/new", own(role_edit), methods=["GET"]),
            Route("/terminal/roles/save", csrf(role_save), methods=["POST"]),
            Route("/terminal/roles/{role_id}", own(role_edit), methods=["GET"]),
            Route("/terminal/roles/{role_id}/delete", csrf(role_delete), methods=["POST"]),
        ]


__all__ = ["BUILTIN", "Kit", "TerminalFeature"]
