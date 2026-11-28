"""Bot RBAC Terminal's dashboard pages."""

import csv
import hashlib
import io
import json
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import anyio.to_thread
from starlette.requests import Request
from starlette.responses import (
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from starlette.routing import Route

from botrbac_cli import chain, sealing, signing
from botrbac_cli.api import DEFAULT_SERVER

from ..audit import audit_owner
from ..auth import current_actor, extract_token
from ..ratelimit import allow, ip_identity
from . import export as otlp_export
from . import identity
from .coverage import clean_coverage, unhooked
from .device import DeviceError, Terminal, Terminals, normalize_user_code
from .ingest import RETENTION_DAYS, RETENTION_MAX_ROWS, IngestError, TerminalActivity
from .provenance import FIELDS as PROVENANCE_FIELDS
from .provenance import SEALED_FIELDS
from .roles import BUILTIN, DEFAULT_OFFLINE_DAYS, RoleError, TerminalRoles
from .webhook import AuditWebhook, WebhookError

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


API_WINDOW = 600
# Per address, per 10 minutes. A login polls every 5 seconds for up to 10 minutes
# (120 polls), so token calls get room for a few logins behind one address.
DEVICE_LIMIT = 30
TOKEN_LIMIT = 600
# Per signed-in person, per 10 minutes: approving or refusing codes on /device.
APPROVE_LIMIT = 30
# ... and looking codes up on /device (a hit shows the other computer's name).
LOOKUP_LIMIT = 60
# Calls by one signed-in terminal (policy checks and audit batches).
TERMINAL_LIMIT = 240
MAX_BODY = 2 * 1024 * 1024
MAX_UNGUARDED = 50
ACTIVITY_PAGE = 100
_TEMPLATES = Path(__file__).resolve().parent.parent / "templates"
SETUP_MD = _TEMPLATES / "terminal_setup.md"
INSTALL_SH = _TEMPLATES / "terminal_install.sh"
# A site address that is safe to bake into a shell script and markdown as is.
_SAFE_SITE = re.compile(r"^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$")
AGENTS = (
    ("claude-code", "Claude Code"),
    ("cursor", "Cursor"),
    ("codex", "Codex"),
    ("gemini", "Gemini CLI"),
)


WEBHOOK_ERRORS = {
    "invalid_webhook_url": "Use an https address on port 443, with no user, query or fragment.",
    "webhook_host_unknown": "That host could not be found.",
    "webhook_host_not_public": "That host is on a private network. Use a public https address.",
    "webhook_disabled": "This site has no ENCRYPTION_KEY, so it cannot send audit webhooks.",
    "": "That webhook could not be saved.",
}


def safe_site(base: str) -> str:
    base = base.rstrip("/")
    return base if _SAFE_SITE.fullmatch(base) else DEFAULT_SERVER


def install_command(base: str, agent: str = "claude-code") -> str:
    return f"curl -fsSL {safe_site(base)}/terminal/install.sh | sh -s -- --agent {agent}"


def install_script(base: str) -> str:
    """/terminal/install.sh with this site's address filled in."""
    return INSTALL_SH.read_text(encoding="utf-8").replace("{{ server }}", safe_site(base))


def login_command(base: str) -> str:
    """`botrbac login`, with --server only when this site is not the CLI's default."""
    base = safe_site(base)
    return "botrbac login" if base == DEFAULT_SERVER else f"botrbac login --server {base}"


def setup_markdown(base: str) -> str:
    """The setup steps a coding agent follows (/terminal/setup.md), for this site."""
    base = safe_site(base)
    text = SETUP_MD.read_text(encoding="utf-8")
    return text.replace("{{ server }}", base).replace("{{ login }}", login_command(base))


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


async def _read_capped(request: Request, limit: int) -> bytes | None:
    """The body, or None when it is (or claims to be) larger than `limit`. Counted while
    streaming, so a chunked request without Content-Length is capped too."""
    try:
        if int(request.headers.get("content-length") or 0) > limit:
            return None
    except ValueError:
        return None
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


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
    # ENCRYPTION_KEY: policies are signed with a key derived from it, and recorded
    # commands are sealed to another. None: unsigned, and commands are never recorded.
    signing_secret: str | None = None
    # TERMINAL_ACTIVITY_DAYS and TERMINAL_ACTIVITY_MAX_ROWS.
    activity_days: int = RETENTION_DAYS
    activity_max_rows: int = RETENTION_MAX_ROWS
    roles: TerminalRoles = field(init=False)
    terminals: Terminals = field(init=False)
    activity: TerminalActivity = field(init=False)
    webhook: AuditWebhook = field(init=False)

    def __post_init__(self) -> None:
        self._signing_key = (
            signing.key_from_secret(self.signing_secret) if self.signing_secret else None
        )
        self._command_key = (
            sealing.key_from_secret(self.signing_secret) if self.signing_secret else None
        )
        self.roles = TerminalRoles(self.store)
        self.terminals = Terminals(self.store, self.roles, self.signed_in)
        self.activity = TerminalActivity(
            self.store, retention_days=self.activity_days, max_rows=self.activity_max_rows
        )
        self.webhook = AuditWebhook(self.store, self.signing_secret)

    def site(self, request: Request) -> str:
        return safe_site(self.base_url or str(request.base_url))

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
        if self._command_key is not None and self.activity.records_commands(email):
            # "Record commands" is on: the CLI seals what agents run to this key.
            body["command_key"] = sealing.public_key_text(self._command_key)
        digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        body["version"] = digest[:16]
        body["issued_at"] = time.time()
        if self._signing_key is not None:
            # The CLI checks this against the key it pinned at login, so an edited
            # policy cache on the computer blocks every tool instead of widening a role.
            body["signature"] = signing.sign(self._signing_key, body)
        return body

    def command_key_for(self, email: str) -> Any:
        """The key that opens this person's sealed commands, while recording is on."""
        if self._command_key is None or not self.activity.records_commands(email):
            return None
        return self._command_key

    def open_commands(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Copies of `rows` with each sealed command, description and task opened, for
        the owner's eyes only. One that will not open (ENCRYPTION_KEY changed) says so
        with `<field>_unreadable`."""
        out = []
        for row in rows:
            event_id = str(row.get("event_id", ""))
            fields = [("command", event_id)] + [(n, f"{event_id}:{n}") for n in SEALED_FIELDS]
            for name, aad in fields:
                sealed = row.get(name)
                if not sealed:
                    continue
                text = None
                if self._command_key is not None:
                    try:
                        text = sealing.open_sealed(self._command_key, aad, sealed)
                    except sealing.SealError:
                        text = None
                row = {**row, name: text, f"{name}_unreadable": text is None}
            out.append(row)
        return out

    def open_tree(self, tree: dict[str, Any]) -> dict[str, Any]:
        """A session tree (TerminalActivity.session) with each start row opened."""
        return {
            **tree,
            "start": self.open_commands([tree["start"]])[0],
            "children": [self.open_tree(c) for c in tree.get("children") or []],
        }

    def checkpoint_for(self, email: str, terminal_id: str) -> dict[str, Any] | None:
        """The newest chained row accepted from this terminal, signed with the policy
        key (integrity.py, botrbac_cli.chain). None before its first chained row."""
        tip = self.activity.chains.tip(email, terminal_id)
        if tip is None:
            return None
        body = chain.checkpoint_body(terminal_id, tip[0], tip[1], time.time())
        if self._signing_key is not None:
            body["signature"] = signing.sign(self._signing_key, body)
        return body

    @property
    def policy_key(self) -> str | None:
        """The public key the CLI pins at login, or None when policies are not signed."""
        if self._signing_key is None:
            return None
        return signing.public_key_text(self._signing_key)

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
            if data.get("public_key"):
                # This terminal's signing key: kept at login, or at the first refresh of
                # a terminal that has none. Never replaced (terminal.identity).
                added = await _run(
                    self.terminals.register_key, issued["terminal_id"], data.get("public_key")
                )
                if added:
                    via = "login" if grant != "refresh_token" else "refresh"
                    await _run(
                        self.terminals.touch,
                        issued["terminal_id"],
                        key_registered={"at": time.time(), "via": via},
                    )
                    audit_owner("terminal_key_registered", terminal=issued["terminal_id"], via=via)
            if self.policy_key:
                issued["policy_key"] = self.policy_key
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
            await _run(self.terminals.touch, terminal.id, last_seen=time.time())
            body = await _run(self.policy_for, terminal)
            return JSONResponse(body, headers={"cache-control": "no-store"})

        async def audit(request: Request) -> Response:
            terminal = await caller(request)
            if isinstance(terminal, Response):
                return terminal
            raw = await _read_capped(request, MAX_BODY)
            if raw is None:
                return JSONResponse({"error": "too_large"}, status_code=413)
            public_key = await _run(self.terminals.public_key, terminal.id)
            try:
                signed = await _run(
                    identity.verify_batch,
                    self.store,
                    public_key,
                    terminal.id,
                    request.headers,
                    raw,
                    time.time(),
                )
            except identity.SignatureRejected as exc:
                return JSONResponse({"error": exc.code}, status_code=401)
            try:
                data = json.loads(raw or b"{}")
            except ValueError:
                data = None
            if not isinstance(data, dict):
                return JSONResponse({"error": "invalid_request"}, status_code=400)
            command_key = await _run(self.command_key_for, terminal.email)
            # The role and policy the site has for this terminal now: `grant` is built
            # from these, not from the role names the computer wrote into its rows.
            policy = await _run(self.policy_for, terminal)
            assigned = {"role": policy["role"]["name"], "policy_version": policy["version"]}
            stored: list[dict[str, Any]] = []
            try:
                result = await _run(
                    self.activity.add,
                    terminal.email,
                    terminal.id,
                    terminal.name,
                    data.get("rows"),
                    command_key,
                    stamp=identity.stamper(terminal, signed, stored, assigned),
                )
            except IngestError as exc:
                return JSONResponse({"error": "invalid_request", "message": str(exc)}, 400)
            if stored:
                # Best effort, short timeout; never fails the upload (terminal.webhook).
                await _run(self.webhook.deliver, terminal.email, stored, command_key)
            tools = data.get("tools")
            if isinstance(tools, list):
                await _run(self.roles.note_tools, terminal.email, tools[:500])
            changes: dict[str, Any] = {"last_seen": time.time()}
            queued = data.get("queued")
            if isinstance(queued, int) and queued >= 0:
                changes["queued"] = min(queued, 10**9)
            hooks = data.get("hooks")
            if isinstance(hooks, dict):
                changes["hook_missing"] = sorted(
                    str(agent)[:40]
                    for agent, status in list(hooks.items())[:10]
                    if status in ("missing", "disabled")
                )
            unguarded = data.get("unguarded")
            if isinstance(unguarded, list):
                changes["unguarded"] = sorted(
                    {str(u)[:64] for u in unguarded if isinstance(u, str) and u.strip()}
                )[:MAX_UNGUARDED]
            coverage = clean_coverage(data.get("coverage"))
            if coverage is not None:
                changes["coverage"] = coverage
            await _run(self.terminals.touch, terminal.id, **changes)
            checkpoint = await _run(self.checkpoint_for, terminal.email, terminal.id)
            if checkpoint is not None:
                result = {**result, "checkpoint": checkpoint}
            return JSONResponse(result)

        async def checkpoint(request: Request) -> Response:
            terminal = await caller(request)
            if isinstance(terminal, Response):
                return terminal
            body = await _run(self.checkpoint_for, terminal.email, terminal.id)
            return JSONResponse({"checkpoint": body}, headers={"cache-control": "no-store"})

        async def setup_md(request: Request) -> Response:
            text = await _run(setup_markdown, self.site(request))
            return PlainTextResponse(
                text, media_type="text/markdown", headers={"cache-control": "no-cache"}
            )

        async def install_sh(request: Request) -> Response:
            text = await _run(install_script, self.site(request))
            return PlainTextResponse(
                text, media_type="text/x-shellscript", headers={"cache-control": "no-cache"}
            )

        return [
            # Public: the instructions a coding agent reads to set a computer up.
            Route("/terminal/setup.md", setup_md, methods=["GET"]),
            Route("/terminal/install.sh", install_sh, methods=["GET"]),
            Route("/api/terminal/device", device, methods=["POST"]),
            Route("/api/terminal/token", token, methods=["POST"]),
            Route("/api/terminal/policy", policy, methods=["GET"]),
            Route("/api/terminal/audit", audit, methods=["POST"]),
            Route("/api/terminal/checkpoint", checkpoint, methods=["GET"]),
        ]

    def page_routes(self, kit: Kit) -> list[Route]:
        render = kit.render

        async def overview(request: Request) -> Response:
            email = _me()
            terminals = await _run(self.terminals.for_person, email)
            roles = await _run(self.roles.all, email)
            names = {r.id: r.name for r in roles}
            chains = await _run(self.activity.chains.summary, email)
            site = self.site(request)
            return render(
                request,
                "terminal.html",
                terminals=terminals,
                roles=roles,
                role_names=names,
                chains=chains,
                site=site,
                login_cmd=login_command(site),
                agents=AGENTS,
                install_cmds={a: install_command(site, a) for a, _ in AGENTS},
                unhooked=unhooked,
            )

        async def device_page(request: Request) -> Response:
            email = _me()
            code = normalize_user_code(request.query_params.get("code") or "")
            if code and not allow(self.store, "termlookup", email, LOOKUP_LIMIT, API_WINDOW):
                kit.flash(request, "error", "Too many codes tried. Wait a few minutes.")
                code = ""
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
            email = _me()
            roles = await _run(self.roles.all, email)
            terminals = await _run(self.terminals.for_person, email)
            used: dict[str, int] = {}
            for t in terminals:
                used[t.role_id] = used.get(t.role_id, 0) + 1
            return render(
                request,
                "terminal_roles.html",
                roles=roles,
                used=used,
                has_terminals=bool(terminals),
            )

        async def role_edit(request: Request) -> Response:
            email = _me()
            role_id = request.path_params.get("role_id")
            role = None
            if role_id:
                role = await _run(self.roles.get, email, role_id)
                if role is None:
                    return render(request, "error.html", 404, message="Page not found.")
            return await role_form(request, email, role)

        async def role_form(
            request: Request,
            email: str,
            role: Any,
            error: str = "",
            typed: dict[str, Any] | None = None,
        ) -> Response:
            """The role page. After a refused save it shows the error next to the
            patterns and keeps everything the person typed and ticked."""
            seen = await _run(self.roles.seen_tools, email)
            return render(
                request,
                "terminal_role.html",
                400 if error else 200,
                role=role,
                seen=seen,
                default_offline=DEFAULT_OFFLINE_DAYS,
                error=error,
                typed=typed,
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
                existing = await _run(self.roles.get, email, role_id) if role_id else None
                if role_id and existing is None:
                    kit.flash(request, "error", str(exc))
                    return RedirectResponse("/terminal/roles", status_code=303)
                typed_form = {
                    "name": str(form.get("name") or "")[:200],
                    "patterns": "\n".join(typed)[:20_000],
                    "ticked": ticked[:500],
                    "offline_days": str(form.get("offline_days") or "")[:4],
                }
                typed_form["field"] = exc.field or "form"
                return await role_form(request, email, existing, str(exc), typed_form)
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

        def wanted(request: Request) -> Callable[[dict[str, Any]], bool]:
            q = request.query_params

            def keep(r: dict[str, Any]) -> bool:
                if q.get("terminal") and r.get("terminal_id") != q["terminal"]:
                    return False
                if q.get("agent") and r.get("agent") != q["agent"]:
                    return False
                if q.get("blocked") == "1" and r.get("decision") != "deny":
                    return False
                return all(r.get(k) == q[k] for k in ("prompt_id", "agent_session_id") if q.get(k))

            return keep

        def filtered(request: Request, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
            keep = wanted(request)
            return [r for r in rows if keep(r)]

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
            recording = await _run(self.activity.records_commands, email)
            hook = await _run(self.webhook.get, email)
            return render(
                request,
                "terminal_activity.html",
                delegation=identity.chain_text,
                webhook=hook,
                can_webhook=self.webhook.ready,
                rows=self.open_commands(shown[:limit]),
                recording=recording,
                can_record=self._command_key is not None,
                more=len(shown) > limit,
                limit=limit,
                total=len(rows),
                terminals=terminals,
                agents=agents,
                q=request.query_params,
                export_query=request.url.query,
            )

        async def activity_export(request: Request) -> Response:
            # Everything kept (TERMINAL_ACTIVITY_DAYS), newest received first, read and
            # sent a chunk at a time: not just the rows the Activity page shows.
            keep = wanted(request)
            source = self.activity.everything(_me())
            fields = [
                "ts", "terminal", "terminal_id", "agent", "tool", "command",
                "command_error", "decision", "reason", "role", "session_id",
                "parent_session_id", "via", "event_id", "received", "seq", "chain",
                "row_hash", "signed", "subject", "actor", "grant", "policy_version",
                *PROVENANCE_FIELDS,
            ]  # fmt: skip
            fmt = request.query_params.get("format")
            if fmt == "otlp":
                # One OTLP/JSON document: read what is kept, then build it. Unlike CSV
                # and JSONL this holds every kept row in memory (at most
                # TERMINAL_ACTIVITY_MAX_ROWS), accepted for one owner-only download.
                rows = self.open_commands([r for r in source if keep(r)])
                body = otlp_export.otlp_logs(rows, self.site(request))
                return PlainTextResponse(
                    json.dumps(body, separators=(",", ":")),
                    media_type="application/json",
                    headers={
                        "content-disposition": 'attachment; filename="terminal-activity.otlp.json"',
                        "cache-control": "no-store",
                    },
                )
            jsonl = fmt == "jsonl"

            def lines() -> Any:
                if not jsonl:
                    out = io.StringIO()
                    csv.DictWriter(out, fieldnames=fields).writeheader()
                    yield out.getvalue()
                for r in source:
                    if not keep(r):
                        continue
                    (r,) = self.open_commands([r])
                    if jsonl:
                        yield json.dumps(r, separators=(",", ":")) + "\n"
                        continue
                    out = io.StringIO()
                    writer = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore")
                    # The delegation fields are objects: JSON in their cells.
                    r = {k: json.dumps(v) if isinstance(v, dict) else v for k, v in r.items()}
                    # A cell starting with = + - @ would run as a formula in a spreadsheet.
                    writer.writerow(
                        {k: ("'" + v if isinstance(v, str) and v and v[0] in "=+-@\t\r" else v)
                         for k, v in r.items()}
                    )  # fmt: skip
                    yield out.getvalue()

            kind, ext = ("application/x-ndjson", "jsonl") if jsonl else ("text/csv", "csv")
            return StreamingResponse(
                lines(),
                media_type=kind,
                headers={
                    "content-disposition": f'attachment; filename="terminal-activity.{ext}"',
                    "cache-control": "no-store",
                },
            )

        async def checkpoints_export(request: Request) -> Response:
            """Each terminal's latest signed checkpoint, and the key to check them with."""
            email = _me()
            terminals = await _run(self.terminals.for_person, email)
            chains = await _run(self.activity.chains.summary, email)
            out = []
            for t in terminals:
                body = await _run(self.checkpoint_for, email, t.id)
                state = chains.get(t.id) or {}
                out.append(
                    {
                        "terminal": t.name,
                        "terminal_id": t.id,
                        "checkpoint": body,
                        "chain": {
                            k: state.get(k) for k in ("start", "missing", "forks", "unchained")
                        },
                    }
                )
            text = json.dumps(
                {"policy_key": self.policy_key, "generated_at": time.time(), "terminals": out},
                indent=2,
            )
            return PlainTextResponse(
                text,
                media_type="application/json",
                headers={
                    "content-disposition": 'attachment; filename="terminal-checkpoints.json"',
                    "cache-control": "no-store",
                },
            )

        async def record_commands(request: Request, form: Any) -> Response:
            on = str(form.get("record") or "") == "1"
            if on and self._command_key is None:
                kit.flash(request, "error", "This site has no ENCRYPTION_KEY, so it cannot.")
                return RedirectResponse("/terminal/activity", status_code=303)
            await _run(self.activity.set_records_commands, _me(), on)
            audit_owner("terminal_record_commands", on="1" if on else "0")
            kit.flash(
                request,
                "ok",
                "Recording commands. Each computer starts the next time it checks in "
                "(within about a minute while online)."
                if on
                else "Commands are no longer recorded. Ones already recorded stay until "
                "they age out of the log.",
            )
            return RedirectResponse("/terminal/activity", status_code=303)

        async def webhook_save(request: Request, form: Any) -> Response:
            email = _me()
            back = RedirectResponse("/terminal/activity#audit-webhook", status_code=303)
            if str(form.get("action") or "") == "remove":
                if await _run(self.webhook.clear, email):
                    audit_owner("terminal_webhook_removed")
                    kit.flash(request, "ok", "Audit webhook removed. Nothing more is sent.")
                return back
            url = str(form.get("url") or "").strip()
            include = str(form.get("include_commands") or "") == "1"
            rotate = str(form.get("rotate") or "") == "1"
            try:
                secret = await _run(self.webhook.save, email, url, include, rotate)
            except WebhookError as exc:
                kit.flash(request, "error", WEBHOOK_ERRORS.get(str(exc), WEBHOOK_ERRORS[""]))
                return back
            audit_owner("terminal_webhook_saved", commands="1" if include else "0")
            if secret is None:
                kit.flash(request, "ok", "Audit webhook saved. The secret is unchanged.")
                return back
            # Shown on this page only, once: it is stored encrypted and never shown again.
            page = render(
                request,
                "terminal_webhook_secret.html",
                url=url,
                secret=secret,
                include_commands=include,
            )
            page.headers["cache-control"] = "no-store"
            return page

        async def session_page(request: Request) -> Response:
            tree = await _run(self.activity.session, _me(), request.path_params["session_id"])
            if tree is None:
                return render(request, "error.html", 404, message="Session not found.")
            return render(request, "terminal_session.html", tree=self.open_tree(tree))

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
            Route("/terminal/activity/checkpoints", own(checkpoints_export), methods=["GET"]),
            Route("/terminal/activity/record", csrf(record_commands), methods=["POST"]),
            Route("/terminal/activity/webhook", csrf(webhook_save), methods=["POST"]),
            Route("/terminal/sessions/{session_id}", own(session_page), methods=["GET"]),
            Route("/terminal/sessions/{session_id}/revoke", csrf(session_revoke), methods=["POST"]),
            Route("/terminal/roles/new", own(role_edit), methods=["GET"]),
            Route("/terminal/roles/save", csrf(role_save), methods=["POST"]),
            Route("/terminal/roles/{role_id}", own(role_edit), methods=["GET"]),
            Route("/terminal/roles/{role_id}/delete", csrf(role_delete), methods=["POST"]),
        ]


__all__ = ["BUILTIN", "Kit", "TerminalFeature"]
