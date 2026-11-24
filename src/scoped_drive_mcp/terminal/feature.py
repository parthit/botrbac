"""Bot RBAC Terminal's dashboard pages."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import anyio.to_thread
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from ..audit import audit_owner
from ..auth import current_actor
from ..ratelimit import allow, ip_identity
from .device import DeviceError, Terminals, normalize_user_code
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


async def _run(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    return await anyio.to_thread.run_sync(lambda: fn(*args, **kwargs))


def _me() -> str:
    email = current_actor.get()
    assert email, "owner_only sets the actor"
    return email


API_WINDOW = 600
# Per address, per 10 minutes. A login polls every 5 seconds for up to 10 minutes
# (120 polls), so token calls get room for a few logins behind one address.
DEVICE_LIMIT = 30
TOKEN_LIMIT = 600
# Per signed-in person, per 10 minutes: approving or refusing codes on /device.
APPROVE_LIMIT = 30


async def _body(request: Request) -> dict[str, Any]:
    """JSON or a form, as OAuth clients send either. Anything else is empty."""
    kind = request.headers.get("content-type", "")
    try:
        if kind.startswith("application/json"):
            data = await request.json()
            return data if isinstance(data, dict) else {}
        form = await request.form()
        return {k: str(v) for k, v in form.items()}
    except Exception:  # noqa: BLE001 - a malformed body is just empty
        return {}


def _oauth_error(code: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": code}, status_code=status, headers={"cache-control": "no-store"})


def _too_many() -> JSONResponse:
    # Not RFC 8628's slow_down: that tells a client to poll more slowly, not to wait.
    return JSONResponse(
        {"error": "rate_limited"},
        status_code=429,
        headers={"cache-control": "no-store", "retry-after": "60"},
    )


@dataclass
class TerminalFeature:
    store: Any
    base_url: str | None = None
    signed_in: Callable[[str], bool] = lambda _email: True
    roles: TerminalRoles = field(init=False)
    terminals: Terminals = field(init=False)

    def __post_init__(self) -> None:
        self.roles = TerminalRoles(self.store)
        self.terminals = Terminals(self.store, self.roles, self.signed_in)

    # ---- API (no cookies; mounted outside the dashboard) -----------------------

    def api_routes(self) -> list[Route]:
        def limited(request: Request, name: str, limit: int) -> bool:
            return not allow(self.store, name, ip_identity(request.scope), limit, API_WINDOW)

        async def device(request: Request) -> Response:
            if limited(request, "termdevice", DEVICE_LIMIT):
                return _too_many()
            data = await _body(request)
            started = await _run(self.terminals.start, data)
            base = (self.base_url or str(request.base_url)).rstrip("/")
            started["verification_uri"] = f"{base}/device"
            started["verification_uri_complete"] = f"{base}/device?code={started['user_code']}"
            return JSONResponse(started, headers={"cache-control": "no-store"})

        async def token(request: Request) -> Response:
            if limited(request, "termtoken", TOKEN_LIMIT):
                return _too_many()
            data = await _body(request)
            grant = str(data.get("grant_type") or "")
            if grant == "urn:ietf:params:oauth:grant-type:device_code":
                try:
                    issued = await _run(self.terminals.poll, str(data.get("device_code") or ""))
                except DeviceError as exc:
                    return _oauth_error(exc.code)
            elif grant == "refresh_token":
                issued = await _run(self.terminals.refresh, str(data.get("refresh_token") or ""))
                if issued is None:
                    return _oauth_error("invalid_grant")
            else:
                return _oauth_error("unsupported_grant_type")
            return JSONResponse(issued, headers={"cache-control": "no-store"})

        return [
            Route("/api/terminal/device", device, methods=["POST"]),
            Route("/api/terminal/token", token, methods=["POST"]),
        ]

    def page_routes(self, kit: Kit) -> list[Route]:
        render = kit.render

        async def overview(request: Request) -> Response:
            email = _me()
            terminals = await _run(self.terminals.for_person, email)
            roles = await _run(self.roles.all, email)
            names = {r.id: r.name for r in roles}
            return render(
                request, "terminal.html", terminals=terminals, roles=roles, role_names=names
            )

        async def device_page(request: Request) -> Response:
            email = _me()
            code = normalize_user_code(request.query_params.get("code") or "")
            found = await _run(self.terminals.pending, code) if code else None
            roles = await _run(self.roles.all, email)
            return render(
                request,
                "terminal_device.html",
                code=code,
                typed=request.query_params.get("code") or "",
                found=found[1] if found else None,
                roles=roles,
            )

        async def device_decide(request: Request, form: Any) -> Response:
            email = _me()
            code = str(form.get("code") or "")
            action = request.path_params["action"]
            if action not in ("approve", "deny"):
                return render(request, "error.html", 404, message="Page not found.")
            if not allow(self.store, "termapprove", email, APPROVE_LIMIT, API_WINDOW):
                kit.flash(request, "error", "Too many codes tried. Wait a few minutes.")
                return RedirectResponse("/device", status_code=303)
            if action == "deny":
                if await _run(self.terminals.deny, code):
                    kit.flash(request, "ok", "Login refused. The terminal was not connected.")
                else:
                    kit.flash(request, "error", "That code has expired or was already used.")
                return RedirectResponse("/terminal", status_code=303)
            try:
                terminal = await _run(
                    self.terminals.approve,
                    email,
                    code,
                    str(form.get("role_id") or ""),
                    str(form.get("name") or ""),
                )
            except ValueError as exc:
                kit.flash(request, "error", str(exc))
                return RedirectResponse("/terminal", status_code=303)
            if terminal is None:
                kit.flash(request, "error", "That code has expired. Run botrbac login again.")
                return RedirectResponse("/device", status_code=303)
            audit_owner("terminal_connected", terminal=terminal.id, role=terminal.role_id)
            kit.flash(request, "ok", f"Connected {terminal.name}. You can close this page.")
            return RedirectResponse("/terminal", status_code=303)

        async def terminal_act(request: Request, form: Any) -> Response:
            email = _me()
            tid = request.path_params["terminal_id"]
            action = request.path_params["action"]
            if action == "revoke":
                done = await _run(self.terminals.revoke, email, tid)
                message = "Terminal disconnected. Its agents can no longer use Bot RBAC tools."
            elif action == "rename":
                name = " ".join(str(form.get("name") or "").split())[:80]
                done = bool(name) and bool(await _run(self.terminals.update, email, tid, name=name))
                message = "Renamed."
            elif action == "role":
                role = await _run(self.roles.get, email, str(form.get("role_id") or ""))
                done = role is not None and bool(
                    await _run(self.terminals.update, email, tid, role_id=role.id)
                )
                message = "Role changed. The terminal picks it up the next time it checks in."
            else:
                done, message = False, ""
            if done:
                audit_owner(f"terminal_{action}", terminal=tid)
                kit.flash(request, "ok", message)
            else:
                kit.flash(request, "error", "That terminal could not be changed.")
            return RedirectResponse("/terminal", status_code=303)

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
            Route("/device", own(device_page), methods=["GET"]),
            Route("/device/{action:str}", csrf(device_decide), methods=["POST"]),
            Route("/terminal/t/{terminal_id}/{action}", csrf(terminal_act), methods=["POST"]),
            Route("/terminal/roles", own(roles_page), methods=["GET"]),
            Route("/terminal/roles/new", own(role_edit), methods=["GET"]),
            Route("/terminal/roles/save", csrf(role_save), methods=["POST"]),
            Route("/terminal/roles/{role_id}", own(role_edit), methods=["GET"]),
            Route("/terminal/roles/{role_id}/delete", csrf(role_delete), methods=["POST"]),
        ]


__all__ = ["BUILTIN", "Kit", "TerminalFeature"]
