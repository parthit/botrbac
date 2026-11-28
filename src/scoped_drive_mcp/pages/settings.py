"""Settings pages: connected assistants and their roles, pairing with people (the
bridge), the wake webhook, and the /files and /sharing hubs that pick a tab's page.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from ..agent_roles import AgentRole, AgentRoleError
from ..audit import app_tag, audit_owner
from ..auth import current_actor
from ..bridge import MailboxError
from ..mcp_oauth import APP_ROLES
from ..policy import FEATURES
from .common import ROLE_LABELS, WAKE_HOME, describe_mime
from .kit import FormHandler, Handler, Kit

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SettingsPages:
    """What dashboard.py needs from this module: the handlers it routes to, and
    the helpers other page modules call."""

    files_page: Handler
    sharing_hub: Handler
    settings_page: Handler
    moved: Callable[..., Handler]
    bridge_webhook: FormHandler
    bridge_decide: FormHandler
    oauth_grant_role: FormHandler
    oauth_grant_features: FormHandler
    role_save: FormHandler
    role_delete: FormHandler
    oauth_grant_rename: FormHandler
    revoke_oauth_grant: FormHandler
    revoke_all: FormHandler


def settings_pages(
    kit: Kit,
    *,
    drive_row_connected: Callable[[list[dict[str, Any]]], bool],
    browse: Handler,
    access: Handler,
    notion_files: Handler,
    onedrive_files: Handler,
    sharing: Handler,
    shared_overview: Handler,
) -> SettingsPages:
    ctx = kit.ctx
    settings = kit.settings
    render = kit.render
    flash = kit.flash
    action_done = kit.action_done
    blocking = kit.blocking
    safe_next = kit.safe_next

    def assistant_rows(email: str, links: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """Connected assistants with their wake-up, for Settings. Two connections can share
        a name (two "Cursor"s), so each row also says which of your assistants it is
        paired with, when it was added and last used, and a short id that never changes."""
        box = ctx.mailbox
        grants = ctx.mcp_oauth.list_grants(email) if ctx.mcp_oauth else []
        if links is None:
            links = box.list_links(email)["links"] if box is not None else []
        # Who each assistant talks to: your own assistants it is paired with (a grant
        # can be in several pairings). Other people's assistants never reach yours.
        names = {g.id: f"{g.client_name} …{g.id[-5:]}" for g in grants}
        mates: dict[str, list[dict[str, Any]]] = {}
        for link in links:
            status = link["status"]
            if not link.get("same_account"):
                continue
            if status not in ("active", "pending_approval"):
                continue
            (grant_a, grant_b), (label_a, label_b) = link["grant_ids"], link["assistants"]
            for me, other, label in ((grant_a, grant_b, label_b), (grant_b, grant_a, label_a)):
                mates.setdefault(str(me), []).append(
                    {
                        "name": names.get(str(other), label),
                        "pending": status == "pending_approval",
                    }
                )
        entries = ctx.allowlist.entries()
        role_items: dict[str, int] = {}
        if ctx.agent_roles is not None:
            role_items = {
                r.slug: sum(1 for i in r.items if i in entries) for r in ctx.agent_roles.all()
            }

        def reach(slug: str | None) -> int:
            return role_items.get(slug, 0) if slug else len(entries)

        wake_on = box is not None and bool(box.get_webhook(email, "").get("available"))
        # One row per (pairing, assistant): an assistant in two pairings has two senders.
        missing_rows = box.missing_wakeups(email) if wake_on else []
        rows = []
        for g in grants:
            rows.append(
                {
                    "id": g.id,
                    "short_id": g.id[-5:],
                    "name": g.client_name,
                    "app_name": g.app_name or g.client_name,
                    "renamed": g.renamed,
                    "agent_role": g.agent_role,
                    "created_at": g.created_at,
                    "last_used": g.last_used,
                    "paired_with": ", ".join(m["name"] for m in mates.get(g.id, [])) or None,
                    "mates": mates.get(g.id, []),
                    "hook": box.get_webhook(email, g.id) if wake_on else None,
                    "role": g.role,
                    "legacy_full": g.legacy_full,
                    "features": g.features,
                    # How many allowed items it reaches: the whole Allowed list, or only
                    # its named role's part of it.
                    "reach": reach(g.agent_role),
                }
            )
        return {
            "assistants": rows,
            "wake_on": wake_on,
            # Left from when mail from other people existed. It is never woken now; the
            # page only offers to move it to an assistant or remove it.
            "account_hook": box.get_webhook(email, "") if wake_on else None,
            "missing_wakeups": missing_rows,
        }

    async def bridge_page(request: Request) -> Response:
        if ctx.mailbox is None:
            return render(request, "error.html", 404, message="Pairing is not configured.")
        email = str(request.session.get("owner") or "")
        data = await blocking(ctx.mailbox.list_links, email)
        data["missing_wakeups"] = await blocking(ctx.mailbox.missing_wakeups, email)
        # Approving a pairing lets that person's assistant read the Sharing list, so each
        # card that asks for approval says what that list holds right now.
        ext = ctx.ext_allowlist
        data["sharing_on"] = ext is not None
        data["shared_items"] = []
        data["visible_to"] = {}
        if ext is not None:
            entries = await blocking(ext.entries)
            ordered = sorted(entries.values(), key=lambda e: e.granted_at, reverse=True)
            # A new person is never named on an item yet: approving shows them only what
            # is shared with everyone paired.
            data["shared_items"] = [e for e in ordered if e.for_everyone and not e.expired()]
            # Each person you share with: exactly what their assistant can read now.
            for link in data["links"]:
                peer = link.get("peer_email")
                if peer and not link.get("same_account"):
                    data["visible_to"][peer] = [e for e in ordered if e.readable_by(peer)]
        data["drops_on"] = ctx.drops is not None
        data["drops_off"] = await blocking(ctx.drops.off_list) if ctx.drops is not None else set()
        return render(request, "bridge.html", tab="people", **data)

    async def settings_page(request: Request) -> Response:
        email = str(request.session.get("owner") or "")

        def gather() -> dict[str, Any]:
            entries = ctx.allowlist.entries()
            roles = ctx.agent_roles.all() if ctx.agent_roles is not None else []
            return {
                "rows": ctx.connection_rows(),
                **assistant_rows(email),
                "roles_on": ctx.agent_roles is not None,
                "mailbox_feature": ctx.mailbox is not None,
                "shared_feature": ctx.shared_with_me is not None,
                # Each role with the items it still reaches: one taken off the allowlist
                # stays on the record but no longer counts.
                "roles": [{"role": r, "live": [i for i in r.items if i in entries]} for r in roles],
                "allowed_items": sorted(entries.values(), key=lambda e: e.name.lower()),
            }

        data = await blocking(gather)
        return render(
            request,
            "settings.html",
            mcp_url=f"{settings.app_base_url}/mcp",
            role_url_base=f"{settings.app_base_url}/mcp/role/",
            describe_mime=describe_mime,
            drive_connected=drive_row_connected(data["rows"]),
            next="/settings",
            missing=settings.missing_settings(),
            store_kind=getattr(ctx.store, "kind", "custom"),
            root_folder_id=ctx.visible_root_folder_id(),
            picker_ready=settings.picker_configured,
            env_token_set=bool(
                settings.env_bot_refresh_token and current_actor.get() == settings.owner_email
            ),
            **data,
        )

    async def files_page(request: Request) -> Response:
        request.state.allow_count = len(await blocking(ctx.allowlist.entries))
        request.state.notion_tab = ctx.notion is not None
        request.state.onedrive_tab = ctx.onedrive is not None
        if request.query_params.get("tab") == "notion" and ctx.notion is not None:
            # Notion does not need Google Drive, so this tab works without it.
            return await notion_files(request)
        if request.query_params.get("tab") == "onedrive" and ctx.onedrive is not None:
            return await onedrive_files(request)
        if request.query_params.get("tab") == "allowed":
            return await access(request)
        return await browse(request)

    async def sharing_hub(request: Request) -> Response:
        tab = request.query_params.get("tab") or "people"
        if tab == "by-me":
            return await sharing(request)
        if tab == "with-me":
            return await shared_overview(request)
        if tab == "mailbox":
            return await mailbox_page(request)
        return await bridge_page(request)

    async def mailbox_page(request: Request) -> Response:
        """What your own assistants sent each other. Read-only: nothing is marked read."""
        if ctx.mailbox is None:
            return render(request, "error.html", 404, message="The Mailbox is not set up.")
        email = str(request.session.get("owner") or "")
        messages = await blocking(ctx.mailbox.owner_messages, email)
        return render(request, "mailbox.html", tab="mailbox", messages=messages)

    def moved(path: str, **extra: str) -> Handler:
        """An old address. Keep its query string so bookmarks and links still land."""

        async def go(request: Request) -> Response:
            params = [(k, v) for k, v in request.query_params.multi_items() if k not in extra]
            params = [*extra.items(), *params]
            target = path + (f"?{urlencode(params)}" if params else "")
            return RedirectResponse(target, status_code=308)

        return go

    def _bridge_act(
        request: Request,
        link_id: str,
        action: str,
        purge: bool = False,
        expect_peer: str | None = None,
    ) -> str:
        email = str(request.session.get("owner") or "")
        if action == "cancel":
            ctx.mailbox.cancel_invite(email, link_id)
            return "Invite cancelled. That code no longer works."
        if action == "dismiss":
            ctx.mailbox.dismiss(email, link_id)
            return "Removed from your list."
        if action == "purge":
            count = ctx.mailbox.delete_messages(email, link_id)["purged_messages"]
            return f"Deleted {count} stored message{'' if count == 1 else 's'} for both of you."
        if action == "revoke":
            peer = next(
                (
                    link["peer_email"]
                    for link in ctx.mailbox.list_links(email)["links"]
                    if link["link_id"] == link_id
                ),
                None,
            )
            same = next(
                (
                    link.get("same_account", False)
                    for link in ctx.mailbox.list_links(email)["links"]
                    if link["link_id"] == link_id
                ),
                False,
            )
            ctx.mailbox.revoke(email, link_id, purge)
            if not same:
                message = (
                    "Pairing turned off. Neither of you can read the other's Sharing list "
                    "through it any more."
                )
                if peer and ctx.mailbox.is_linked(email, peer):
                    message += f" You still have another active pairing with {peer}."
                return message
            message = "Pairing turned off. Your two assistants can no longer message each other."
            if purge:
                return message + " Stored messages were deleted."
            return message + " Messages already delivered stay readable until they expire."
        same = next(
            (
                link.get("same_account", False)
                for link in ctx.mailbox.list_links(email)["links"]
                if link["link_id"] == link_id
            ),
            False,
        )
        # Approving another person is approving that account. The form names the account
        # the page showed, and the approval is refused if someone else is joined by now.
        if action == "approve" and not same and not expect_peer:
            raise MailboxError(
                "peer_changed",
                "Reload the page and check who is asking before you approve.",
            )
        result = ctx.mailbox.decide(
            email, link_id, action, expect_peer if action == "approve" else None
        )
        if same and result["status"] == "active":
            return "Approved. Your two assistants can message each other now."
        if action == "deny" or result["status"] == "revoked":
            return "Pairing declined. Nothing is shared through it."
        if result["status"] == "active":
            return "You approved. You can now share documents with each other."
        return "You approved. Nothing is shared until the other person approves."

    async def bridge_decide(request: Request, form: dict[str, str]) -> Response:
        if ctx.mailbox is None:
            return render(request, "error.html", 404, message="The mailbox is not configured.")
        link_id = request.path_params["link_id"]
        action = request.path_params["action"]
        if action not in ("approve", "deny", "revoke", "cancel", "dismiss", "purge"):
            return render(request, "error.html", 404, message="That page is not available.")
        purge = form.get("purge") == "on"
        try:
            message = await blocking(
                _bridge_act, request, link_id, action, purge, form.get("peer") or None
            )
        except MailboxError as exc:
            flash(request, "error", exc.message)
        else:
            # Pairings decide who can read the Sharing list, so every change is on record.
            audit_owner(f"pairing_{action}", link=link_id, purge="1" if purge else None)
            flash(request, "ok", message)
        return RedirectResponse("/sharing?tab=people", status_code=303)

    async def bridge_webhook(request: Request, form: dict[str, str]) -> Response:
        if ctx.mailbox is None:
            return render(request, "error.html", 404, message="The mailbox is not configured.")
        email = str(request.session.get("owner") or "")
        back = safe_next(form.get("next") or WAKE_HOME)
        # "account" (or "" from older pages) is the account-wide slot, left from when mail
        # from other people existed; otherwise one of this person's connected apps.
        raw_app = (form.get("app") or "").strip()
        app = "" if raw_app == "account" else raw_app
        from_app = (form.get("from_app") or "").strip()
        from_app = "" if from_app == "account" else from_app
        action = form.get("action")
        grants = await blocking(ctx.mcp_oauth.list_grants, email) if ctx.mcp_oauth else []
        ids = {g.id for g in grants}
        if (app and app not in ids) or (from_app and from_app not in ids):
            return action_done(request, "error", "That app is not connected.", back)
        if action in (None, "", "save") and not app:
            # The account slot never fires: mail only goes between your own assistants,
            # each to its own wake-up. Make the person say which assistant it starts.
            return action_done(
                request, "error", "Choose which assistant this wake-up starts.", back
            )
        if action == "primary":
            return action_done(
                request,
                "error",
                "Mail from other people is turned off, so there is nothing to answer.",
                back,
            )
        # A failed test wake still changes what the page shows (the last wake), so the
        # settings page refreshes those sections even when the test reports an error.
        changed: bool | None = None
        try:
            if action == "remove":
                await blocking(ctx.mailbox.clear_webhook, email, app)
                kind, message = "ok", "Wake-up removed. Mail still waits for check_messages."
            elif action == "test":
                result = await blocking(ctx.mailbox.test_webhook, email, app)
                changed = True
                if result.get("ok"):
                    kind, message = (
                        "ok",
                        f"Test wake sent (HTTP {result.get('http')}). The assistant should "
                        "start in a few seconds and find no new mail.",
                    )
                else:
                    code = f" (HTTP {result['http']})" if result.get("http") else ""
                    kind, message = (
                        "error",
                        f"Test wake failed{code}: {result.get('error')}. Check the URL and "
                        "key in the assistant that gave them to you, then save them again.",
                    )
            elif action == "move":
                await blocking(ctx.mailbox.move_webhook, email, app, from_app)
                kind, message = "ok", "Wake-up moved to that assistant. Its key moved with it."
            else:
                enabled = form.get("enabled", "true") != "false"
                await blocking(
                    ctx.mailbox.set_webhook,
                    email,
                    form.get("url") or "",
                    sender_key=form.get("sender_key") or None,
                    auth_scheme=form.get("auth_scheme") or "bearer",
                    enabled=enabled,
                    app=app,
                )
                kind, message = "ok", "Wake-up saved. Use Send test wake to check it works."
        except MailboxError as exc:
            kind, message, changed = "error", exc.message, False
        else:
            if action != "test":
                # Never the URL or key: which app's wake-up changed, and how.
                audit_owner(
                    f"webhook_{action or 'save'}",
                    app=app_tag(app) if app else None,
                    from_app=app_tag(from_app) if from_app else None,
                )
        return action_done(request, kind, message, back, changed=changed)

    async def oauth_grant_role(request: Request, form: dict[str, str]) -> Response:
        """The owner changes what one of their connected apps may do."""
        email = str(request.session.get("owner") or "")
        grant_id = form.get("grant_id") or ""
        role = form.get("role") or ""
        back = "/settings#assistants"
        if ctx.mcp_oauth is None or role not in APP_ROLES:
            return action_done(request, "error", "Choose what this app may do.", back)
        if not await blocking(ctx.mcp_oauth.set_role, grant_id, email, role):
            return action_done(request, "error", "That app is not connected.", back)
        names = {g.id: g.client_name for g in ctx.mcp_oauth.list_grants(email)}
        audit_owner(
            "oauth_role", grant=grant_id[-5:], role=role, client=names.get(grant_id, "an app")
        )
        return action_done(
            request, "ok", f"Saved. Its next call runs as {ROLE_LABELS[role]}.", back
        )

    async def oauth_grant_features(request: Request, form: dict[str, str]) -> Response:
        """The owner switches the Mailbox or Shared with me on or off for one app."""
        email = str(request.session.get("owner") or "")
        grant_id = form.get("grant_id") or ""
        back = "/settings#assistants"
        if ctx.mcp_oauth is None:
            return action_done(request, "error", "That app is not connected.", back)
        # Only the parts the form showed change; one it didn't show (that part isn't
        # set up on this server) keeps its saved value, so it isn't switched off unseen.
        shown = set((form.get("features_shown") or "").split(","))
        current = await blocking(ctx.mcp_oauth.features_of, grant_id)
        features = {
            name: form.get(f"feature_{name}") == "on" if name in shown else current[name]
            for name in FEATURES
        }
        if not await blocking(ctx.mcp_oauth.set_features, grant_id, email, features):
            return action_done(request, "error", "That app is not connected.", back)
        names = {g.id: g.client_name for g in ctx.mcp_oauth.list_grants(email)}
        audit_owner(
            "oauth_features",
            grant=grant_id[-5:],
            client=names.get(grant_id, "an app"),
            off=",".join(n for n, on in features.items() if not on) or "-",
        )
        return action_done(request, "ok", "Saved. Its next call uses these settings.", back)

    async def role_save(request: Request, form: dict[str, str]) -> Response:
        """The owner creates a named role, or replaces the one with the same name."""
        back = "/settings#roles"
        if ctx.agent_roles is None:
            return action_done(request, "error", "Roles are not set up on this server.", back)
        items = [str(v) for v in (await request.form()).getlist("item")]

        def save() -> AgentRole:
            return ctx.agent_roles.save(
                form.get("name") or "", form.get("level") or "", items, ctx.allowlist.entries()
            )

        try:
            role = await blocking(save)
        except AgentRoleError as exc:
            return action_done(request, "error", str(exc), back)
        # The scope guard caches each role's part of the list.
        ctx.on_allowlist_change()
        audit_owner("role_save", name=role.name, level=role.level, count=str(len(role.items)))
        return action_done(
            request, "ok", f"Saved the role {role.name}. Its next call uses these files.", back
        )

    async def role_delete(request: Request, form: dict[str, str]) -> Response:
        back = "/settings#roles"
        slug = form.get("slug") or ""
        role = None if ctx.agent_roles is None else await blocking(ctx.agent_roles.get, slug)
        if role is None or not await blocking(ctx.agent_roles.delete, slug):
            return action_done(request, "error", "That role was not found.", back)
        ctx.on_allowlist_change()
        audit_owner("role_delete", name=role.name)
        return action_done(
            request, "ok", "Deleted the role. Agents using its address are refused.", back
        )

    async def oauth_grant_rename(request: Request, form: dict[str, str]) -> Response:
        """The owner gives one of their connected apps a name of their own ("Grok Bot"
        instead of the "Cursor" it registered as). Empty goes back to the app's name."""
        email = str(request.session.get("owner") or "")
        grant_id = form.get("grant_id") or ""
        back = f"/settings#app-{grant_id}" if grant_id else "/settings#assistants"
        if ctx.mcp_oauth is None:
            return action_done(request, "error", "That app is not connected.", back)
        before = {g.id: g.client_name for g in await blocking(ctx.mcp_oauth.list_grants, email)}
        shown = await blocking(ctx.mcp_oauth.set_label, grant_id, email, form.get("name"))
        if shown is None:
            return action_done(request, "error", "That app is not connected.", back)
        if ctx.mailbox is not None:
            try:
                await blocking(ctx.mailbox.relabel_assistant, email, grant_id, shown)
            except Exception:  # noqa: BLE001 - the new name is saved either way
                kit.logger.warning("relabel_pairings_failed", exc_info=True)
        old = before.get(grant_id, "an app")
        if shown != old:
            audit_owner("oauth_rename", grant=grant_id[-5:], client=old, label=shown)
        return action_done(request, "ok", f"Saved. It is now called {shown}.", back)

    async def revoke_oauth_grant(request: Request, form: dict[str, str]) -> Response:
        grant_id = form.get("grant_id") or ""
        if ctx.mcp_oauth is None or not await blocking(
            ctx.mcp_oauth.revoke, grant_id, email=str(request.session.get("owner") or "")
        ):
            return action_done(
                request, "error", "That connection was not found.", "/settings#assistants"
            )
        audit_owner("oauth_revoke", app=app_tag(grant_id))
        return action_done(
            request,
            "ok",
            "Disconnected the assistant. Its tokens no longer work.",
            "/settings#assistants",
        )

    def _revoke_everything(email: str) -> tuple[int, int, int]:
        """Every connected app and terminal of `email`, and approvals not yet used.
        Ending an app also ends its pairings with your other assistants and deletes its
        wake-up (mcp_oauth.on_revoke). Pairings with other people, and what is on Files
        and Sharing, are left as they are: those are people, not assistants.
        Returns (apps, terminals, failed)."""
        apps = terminals = failed = 0
        if ctx.mcp_oauth is not None:
            apps, failed = ctx.mcp_oauth.revoke_all(email)
        feature = getattr(ctx, "terminal", None)
        if feature is not None:
            for terminal in feature.terminals.for_person(email):
                try:
                    if feature.terminals.revoke(email, terminal.id):
                        terminals += 1
                except Exception:
                    failed += 1
                    logger.warning("revoke_all: one terminal failed")
        return apps, terminals, failed

    async def revoke_all(request: Request, form: dict[str, str]) -> Response:
        """The emergency stop: disconnect every assistant at once."""
        email = str(request.session.get("owner") or "")
        apps, terminals, failed = await blocking(_revoke_everything, email)
        audit_owner(
            "revoke_all",
            "error" if failed else "allow",
            apps=str(apps),
            terminals=str(terminals),
            failed=str(failed) if failed else None,
        )
        parts = [f"{apps} app{'' if apps == 1 else 's'}"]
        if terminals:
            parts.append(f"{terminals} terminal{'' if terminals == 1 else 's'}")
        if failed:
            return action_done(
                request,
                "error",
                f"Disconnected {' and '.join(parts)}, but {failed} could not be disconnected "
                "right now. Try again in a moment.",
                "/settings#assistants",
            )
        return action_done(
            request,
            "ok",
            f"Disconnected {' and '.join(parts)}. Their tokens no longer work; "
            "each one has to sign in and be allowed again.",
            "/settings#assistants",
        )

    return SettingsPages(
        files_page=files_page,
        sharing_hub=sharing_hub,
        settings_page=settings_page,
        moved=moved,
        bridge_webhook=bridge_webhook,
        bridge_decide=bridge_decide,
        oauth_grant_role=oauth_grant_role,
        oauth_grant_features=oauth_grant_features,
        role_save=role_save,
        role_delete=role_delete,
        oauth_grant_rename=oauth_grant_rename,
        revoke_oauth_grant=revoke_oauth_grant,
        revoke_all=revoke_all,
    )
