"""Admin pages: /admin and its two maintenance actions, for OWNER_EMAIL only."""

from dataclasses import dataclass
from typing import Any

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from ..audit import audit_owner
from ..auth import current_actor
from ..humanize import parse_ts
from ..store import SignedStore, sign_existing_records
from .kit import FormHandler, Handler, Kit


@dataclass(frozen=True)
class AdminPages:
    """What dashboard.py needs from this module: the handlers it routes to, and
    the helpers other page modules call."""

    admin_page: Handler
    admin_sign_records: FormHandler
    admin_revoke_legacy: FormHandler


def admin_pages(kit: Kit) -> AdminPages:
    ctx = kit.ctx
    settings = kit.settings
    oauth = kit.oauth
    logger = kit.logger
    session_user = kit.session_user
    remember_pending = kit.remember_pending
    render = kit.render
    flash = kit.flash
    blocking = kit.blocking

    async def admin_page(request: Request) -> Response:
        email = session_user(request)
        if email != settings.owner_email:
            return render(request, "error.html", 404, message="Page not found.")
        reset = current_actor.set(email)
        try:
            await remember_pending(request)
            people = await blocking(_directory_rows)
        finally:
            current_actor.reset(reset)
        signing = None
        if isinstance(ctx.store, SignedStore):
            signing = {"required": ctx.store.require}
        legacy = sum(1 for person in people if person["legacy"])
        return render(request, "admin.html", people=people, signing=signing, legacy=legacy)

    async def admin_revoke_legacy(request: Request, form: dict[str, str]) -> Response:
        """Revoke and delete every stored full-Drive (or unstamped) token, for everyone.

        Those tokens are already never used. This removes them from the store and asks
        Google to end them, so a copy of the store cannot be used to reach anyone's Drive.
        Each person reconnects with per-file access when they next visit."""
        if session_user(request) != settings.owner_email or ctx.directory is None:
            return render(request, "error.html", 404, message="Page not found.")

        def run() -> tuple[int, int]:
            assert ctx.directory is not None
            done = failed = 0
            for person in ctx.directory.known_users():
                vault = ctx.directory.vault_for(person)
                record = vault.legacy_owner()
                if not record:
                    continue
                try:
                    ok = oauth.revoke(record["t"])
                except Exception:
                    logger.exception("revoking an old Drive connection failed")
                    ok = False
                if not ok:
                    # Kept so the next run can try again. It is never used meanwhile.
                    failed += 1
                    continue
                current = vault.legacy_owner()
                if current and current.get("t") == record["t"]:
                    vault.clear_owner()
                ctx.forget_drive(person)
                done += 1
            return done, failed

        done, failed = await blocking(run)
        audit_owner("revoke_legacy_drive", count=str(done), failed=str(failed))
        if failed:
            flash(
                request,
                "error",
                f"Revoked {done}. Google didn’t confirm {failed}; those are kept (and still "
                "unused). Run this again.",
            )
        else:
            flash(
                request,
                "ok",
                f"Revoked {done} old full-Drive connection{'' if done == 1 else 's'}."
                if done
                else "No old full-Drive connections are stored.",
            )
        return RedirectResponse("/admin", status_code=303)

    async def admin_sign_records(request: Request, form: dict[str, str]) -> Response:
        """Sign the allowlist, app and pairing records saved before records were signed."""
        if session_user(request) != settings.owner_email or ctx.directory is None:
            return render(request, "error.html", 404, message="Page not found.")
        if isinstance(ctx.store, SignedStore) and ctx.store.require:
            # Signing is for records from before. Once unsigned ones are ignored, signing
            # whatever is in the store would bring back one that was planted since.
            flash(
                request,
                "error",
                "REQUIRE_SIGNED_RECORDS is on, so nothing was signed. Unsigned records are "
                "ignored now.",
            )
            return RedirectResponse("/admin", status_code=303)

        def run() -> tuple[int, int]:
            people = ctx.directory.known_users()
            everyone = list(dict.fromkeys([*people, settings.owner_email or ""]))
            # First the two records whose older form says less than it should: an
            # approval that does not name who joined, and an app with no written role.
            if ctx.mailbox is not None:
                known = [e for e in everyone if e]
                ctx.mailbox.seal_ended_pairings(known)
                ctx.mailbox.bind_legacy_approvals(known)
            unpinned = 0
            if ctx.mcp_oauth is not None:
                _pinned, unpinned = ctx.mcp_oauth.pin_legacy_roles()
            signed, failed = sign_existing_records(ctx.store, people, settings.owner_email)
            return signed, failed + unpinned

        signed, failed = await blocking(run)
        audit_owner("sign_records", count=str(signed), failed=str(failed))
        if failed:
            flash(
                request,
                "error",
                f"Signed {signed}, but {failed} could not be signed because they changed "
                "at that moment or the store refused. Run this again, and keep "
                "REQUIRE_SIGNED_RECORDS=0 until it reports none left.",
            )
        else:
            flash(
                request,
                "ok",
                f"Signed {signed} stored record{'' if signed == 1 else 's'}. Every record "
                "this server knows of is now signed."
                if signed
                else "Every record this server knows of was already signed.",
            )
        return RedirectResponse("/admin", status_code=303)

    def _directory_rows() -> list[dict[str, Any]]:
        if ctx.directory is None:
            return []
        rows: list[dict[str, Any]] = []
        for person in ctx.directory.known_users():
            grants = ctx.mcp_oauth.list_grants(person) if ctx.mcp_oauth else []
            # The sign-in index is newer than some accounts, so its date can be later
            # than an app the person connected. Show the earliest date we know of.
            known = [ctx.directory.created_at(person), *(g.created_at for g in grants)]
            moments = [(parse_ts(v), v) for v in known if v]
            earliest = min((m for m in moments if m[0] is not None), default=None)
            rows.append(
                {
                    "email": person,
                    "created_at": earliest[1] if earliest else None,
                    "grants": grants,
                    "legacy": ctx.directory.vault_for(person).legacy_owner() is not None,
                }
            )
        return rows

    return AdminPages(
        admin_page=admin_page,
        admin_sign_records=admin_sign_records,
        admin_revoke_legacy=admin_revoke_legacy,
    )
