"""Bot RBAC Terminal's dashboard pages."""

import csv
import hashlib
import io
import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import anyio.to_thread
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route

from ..audit import audit_owner
from ..auth import current_actor, extract_token
from ..ratelimit import allow, ip_identity
from .device import DeviceError, Terminal, Terminals, normalize_user_code
from .ingest import IngestError, TerminalActivity
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


def epoch_iso(value: Any) -> str:
    """Seconds since 1970 as ISO 8601, for the dashboard's `when` filter."""
    try:
        return datetime.fromtimestamp(float(value), UTC).isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


def _me() -> str:
    email = current_actor.get()
    assert email, "owner_only sets the actor"
    return email


# Unauthenticated API calls (device codes, token polls) per address.
API_LIMIT = 60
API_WINDOW = 600
# Calls by one signed-in terminal (policy checks and audit batches).
TERMINAL_LIMIT = 240
MAX_BODY = 2 * 1024 * 1024
MAX_UNGUARDED = 50
ACTIVITY_PAGE = 100


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


@dataclass
class TerminalFeature:
    store: Any
    base_url: str | None = None
    signed_in: Callable[[str], bool] = lambda _email: True
    roles: TerminalRoles = field(init=False)
    terminals: Terminals = field(init=False)
    activity: TerminalActivity = field(init=False)

    def __post_init__(self) -> None:
        self.roles = TerminalRoles(self.store)
        self.terminals = Terminals(self.store, self.roles, self.signed_in)
        self.activity = TerminalActivity(self.store)

    def policy_for(self, terminal: Terminal) -> dict[str, Any]:
        """What the CLI enforces: this terminal's role, every role it may narrow to with
        --role, and sessions revoked on the website."""
        email = terminal.email
        role = self.roles.effective(email, terminal.role_id)
        body: dict[str, Any] = {
            "email": email,
            "terminal": {"id": terminal.id, "name": terminal.name},
            "role": role.public(),
            "roles": [r.public() for r in self.roles.all(email)],
            "revoked_sessions": self.activity.revoked_sessions(email),
        }
        digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        body["version"] = digest[:16]
        body["issued_at"] = time.time()
        return body

    # ---- API (no cookies; mounted outside the dashboard) -----------------------

    def api_routes(self) -> list[Route]:
        def limited(request: Request) -> bool:
            return not allow(
                self.store, "termapi", ip_identity(request.scope), API_LIMIT, API_WINDOW
            )

        async def device(request: Request) -> Response:
            if limited(request):
                return _oauth_error("slow_down", 429)
            data = await _body(request)
            started = await _run(self.terminals.start, data)
            base = (self.base_url or str(request.base_url)).rstrip("/")
            started["verification_uri"] = f"{base}/device"
            started["verification_uri_complete"] = f"{base}/device?code={started['user_code']}"
            return JSONResponse(started, headers={"cache-control": "no-store"})

        async def token(request: Request) -> Response:
            if limited(request):
                return _oauth_error("slow_down", 429)
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

        async def caller(request: Request) -> Terminal | Response:
            raw = extract_token(request.headers.get("authorization"))
            terminal = await _run(self.terminals.resolve, raw) if raw else None
            if terminal is None:
                return JSONResponse(
                    {"error": "invalid_token"},
                    status_code=401,
                    headers={"www-authenticate": 'Bearer error="invalid_token"'},
                )
            if not allow(self.store, "termcall", terminal.id, TERMINAL_LIMIT, API_WINDOW):
                return JSONResponse({"error": "rate_limited"}, status_code=429)
            return terminal

        async def policy(request: Request) -> Response:
            terminal = await caller(request)
            if isinstance(terminal, Response):
                return terminal
            await _run(self.terminals.update, terminal.email, terminal.id, last_seen=time.time())
            body = await _run(self.policy_for, terminal)
            return JSONResponse(body, headers={"cache-control": "no-store"})

        async def audit(request: Request) -> Response:
            terminal = await caller(request)
            if isinstance(terminal, Response):
                return terminal
            if int(request.headers.get("content-length") or 0) > MAX_BODY:
                return JSONResponse({"error": "too_large"}, status_code=413)
            data = await _body(request)
            try:
                result = await _run(
                    self.activity.add, terminal.email, terminal.id, terminal.name, data.get("rows")
                )
            except IngestError as exc:
                return JSONResponse({"error": "invalid_request", "message": str(exc)}, 400)
            tools = data.get("tools")
            if isinstance(tools, list):
                await _run(self.roles.note_tools, terminal.email, tools[:500])
            changes: dict[str, Any] = {"last_seen": time.time()}
            queued = data.get("queued")
            if isinstance(queued, int) and queued >= 0:
                changes["queued"] = min(queued, 10**9)
            unguarded = data.get("unguarded")
            if isinstance(unguarded, list):
                changes["unguarded"] = sorted(
                    {str(u)[:64] for u in unguarded if isinstance(u, str) and u.strip()}
                )[:MAX_UNGUARDED]
            await _run(self.terminals.update, terminal.email, terminal.id, **changes)
            return JSONResponse(result)

        return [
            Route("/api/terminal/device", device, methods=["POST"]),
            Route("/api/terminal/token", token, methods=["POST"]),
            Route("/api/terminal/policy", policy, methods=["GET"]),
            Route("/api/terminal/audit", audit, methods=["POST"]),
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
            if action == "deny":
                await _run(self.terminals.deny, code)
                kit.flash(request, "ok", "Login refused. The terminal was not connected.")
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
                kit.flash(request, "ok", "Role deleted. Terminals that used it are now read-only.")
            else:
                kit.flash(request, "error", "That role cannot be deleted.")
            return RedirectResponse("/terminal/roles", status_code=303)

        def filtered(request: Request, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
            q = request.query_params
            if q.get("terminal"):
                rows = [r for r in rows if r.get("terminal_id") == q["terminal"]]
            if q.get("agent"):
                rows = [r for r in rows if r.get("agent") == q["agent"]]
            if q.get("blocked") == "1":
                rows = [r for r in rows if r.get("decision") == "deny"]
            return rows

        async def activity_page(request: Request) -> Response:
            email = _me()
            rows = await _run(self.activity.recent, email)
            terminals = await _run(self.terminals.for_person, email)
            agents = sorted({r["agent"] for r in rows if r.get("agent")})
            shown = filtered(request, rows)
            try:
                limit = max(ACTIVITY_PAGE, min(int(request.query_params.get("show") or 0), 2000))
            except ValueError:
                limit = ACTIVITY_PAGE
            return render(
                request,
                "terminal_activity.html",
                rows=shown[:limit],
                more=len(shown) > limit,
                limit=limit,
                total=len(rows),
                terminals=terminals,
                agents=agents,
                q=request.query_params,
                export_query=request.url.query,
            )

        async def activity_export(request: Request) -> Response:
            rows = filtered(request, await _run(self.activity.recent, _me()))
            fields = [
                "ts", "terminal", "terminal_id", "agent", "tool", "decision", "reason",
                "role", "session_id", "parent_session_id", "via", "event_id", "received",
            ]  # fmt: skip
            if request.query_params.get("format") == "jsonl":
                text = "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in rows)
                kind, ext = "application/x-ndjson", "jsonl"
            else:
                out = io.StringIO()
                writer = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                for r in rows:
                    # A cell starting with = + - @ would run as a formula in a spreadsheet.
                    writer.writerow(
                        {k: ("'" + v if isinstance(v, str) and v[:1] in "=+-@" else v)
                         for k, v in r.items()}
                    )  # fmt: skip
                text, kind, ext = out.getvalue(), "text/csv", "csv"
            return PlainTextResponse(
                text,
                media_type=kind,
                headers={
                    "content-disposition": f'attachment; filename="terminal-activity.{ext}"',
                    "cache-control": "no-store",
                },
            )

        async def session_page(request: Request) -> Response:
            tree = await _run(self.activity.session, _me(), request.path_params["session_id"])
            if tree is None:
                return render(request, "error.html", 404, message="Session not found.")
            return render(request, "terminal_session.html", tree=tree)

        async def session_revoke(request: Request, _form: Any) -> Response:
            sid = request.path_params["session_id"]
            if await _run(self.activity.session, _me(), sid) is None:
                return render(request, "error.html", 404, message="Session not found.")
            await _run(self.activity.revoke_session, _me(), sid)
            audit_owner("terminal_session_revoked", session=sid)
            kit.flash(
                request,
                "ok",
                "Session revoked. It and everything started under it are blocked the next "
                "time the terminal checks in (within about a minute while online).",
            )
            return RedirectResponse(f"/terminal/sessions/{sid}", status_code=303)

        own = kit.owner_only
        csrf = kit.csrf_protected
        return [
            Route("/terminal", own(overview), methods=["GET"]),
            Route("/device", own(device_page), methods=["GET"]),
            Route("/device/{action:str}", csrf(device_decide), methods=["POST"]),
            Route("/terminal/t/{terminal_id}/{action}", csrf(terminal_act), methods=["POST"]),
            Route("/terminal/roles", own(roles_page), methods=["GET"]),
            Route("/terminal/activity", own(activity_page), methods=["GET"]),
            Route("/terminal/activity/export", own(activity_export), methods=["GET"]),
            Route("/terminal/sessions/{session_id}", own(session_page), methods=["GET"]),
            Route("/terminal/sessions/{session_id}/revoke", csrf(session_revoke), methods=["POST"]),
            Route("/terminal/roles/new", own(role_edit), methods=["GET"]),
            Route("/terminal/roles/save", csrf(role_save), methods=["POST"]),
            Route("/terminal/roles/{role_id}", own(role_edit), methods=["GET"]),
            Route("/terminal/roles/{role_id}/delete", csrf(role_delete), methods=["POST"]),
        ]


__all__ = ["BUILTIN", "Kit", "TerminalFeature"]
