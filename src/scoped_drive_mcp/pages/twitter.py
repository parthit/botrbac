"""X (Twitter) pages: connecting (X's OAuth 2.0 with PKCE), disconnecting, and
Files → From X, where the person allows the accounts and lists assistants may read.

/connect/twitter and /connect/twitter/disconnect are routed through pages/connections.py
like every other service; it calls `start` and `disconnect` here.
"""

import hmac
import secrets
from dataclasses import dataclass
from typing import Any

from itsdangerous import BadSignature
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from ..audit import audit_owner
from ..auth import current_actor
from ..policy import PayloadToolError
from ..twitter_client import (
    POST_SCOPES,
    READ_SCOPES,
    WRITE_SCOPE,
    TwitterApiError,
    TwitterOAuthError,
    can_post,
    normalize_scopes,
    pkce_pair,
    scopes_acceptable,
)
from .common import STATE_MAX_AGE
from .kit import FormHandler, Handler, Kit

BACK = "/files?tab=twitter"


@dataclass(frozen=True)
class TwitterPages:
    start: Handler
    disconnect: Handler
    twitter_callback: Handler
    twitter_files: Handler
    twitter_allow: FormHandler
    twitter_remove: FormHandler


def twitter_pages(kit: Kit) -> TwitterPages:
    ctx = kit.ctx
    serializer = kit.serializer
    refused = kit.refused
    render = kit.render
    flash = kit.flash
    action_done = kit.action_done
    blocking = kit.blocking

    def requested_scopes() -> tuple[str, ...]:
        return POST_SCOPES if ctx.twitter_post else READ_SCOPES

    async def start(request: Request) -> Response:
        """Send the signed-in person to X's consent screen. The state is signed, expires,
        is tied to this browser (nonce) and names the account it is for. The PKCE
        verifier stays in this browser's session; only its hash goes to X."""
        nonce = secrets.token_urlsafe(24)
        verifier, challenge = pkce_pair()
        request.session["twitter_nonce"] = nonce
        request.session["twitter_verifier"] = verifier
        state = serializer.dumps(
            {"flow": "twitter", "nonce": nonce, "who": current_actor.get() or ""}
        )
        url = ctx.twitter.oauth.authorization_url(state, challenge, requested_scopes())
        return RedirectResponse(url, status_code=303)

    async def twitter_callback(request: Request) -> Response:
        if ctx.twitter is None:
            return render(request, "error.html", 404, message="Unknown connection.")
        params = request.query_params
        nonce = request.session.pop("twitter_nonce", None)
        verifier = request.session.pop("twitter_verifier", None)
        request.session.pop("oauth_next", None)
        retry_actions = [
            {"label": "Back to Settings", "href": "/settings#services", "primary": True},
        ]
        if params.get("error"):
            cancelled = params.get("error") == "access_denied"
            return render(
                request,
                "error.html",
                400,
                title="You didn’t connect X" if cancelled else "X isn’t connected",
                message=(
                    "You cancelled on X’s screen, so nothing changed."
                    if cancelled
                    else "X didn’t finish connecting. Nothing changed."
                ),
                actions=retry_actions,
            )
        try:
            data = serializer.loads(params.get("state", ""), max_age=STATE_MAX_AGE)
        except BadSignature:
            data = None
        email = current_actor.get() or ""
        if (
            not isinstance(data, dict)
            or data.get("flow") != "twitter"
            or not nonce
            or not verifier
            or not hmac.compare_digest(str(nonce), str(data.get("nonce", "")))
            or str(data.get("who") or "") != email
        ):
            audit_owner("twitter_connect", "deny", reason="bad_state")
            return render(
                request,
                "error.html",
                400,
                title="X connection expired",
                message="That X connection didn’t start here, or took too long. Try again.",
                actions=retry_actions,
            )
        code = params.get("code")
        if not code:
            return render(request, "error.html", 400, message="X did not return a code.")
        try:
            tokens = await blocking(ctx.twitter.oauth.exchange_code, code, str(verifier))
        except TwitterOAuthError as exc:
            return render(
                request,
                "error.html",
                502,
                title="X isn’t connected",
                message=f"Connecting X failed: {exc}.",
                actions=retry_actions,
            )
        granted = normalize_scopes(tokens.scopes)
        if not scopes_acceptable(granted, requested_scopes()):
            # Not stored, and ended at X: it is either missing what reading needs, or
            # carries more than this deployment asked for.
            await blocking(ctx.twitter.oauth.revoke, tokens.access_token)
            if tokens.refresh_token:
                await blocking(ctx.twitter.oauth.revoke, tokens.refresh_token, "refresh_token")
            audit_owner("twitter_connect", "deny", reason="scopes")
            return render(
                request,
                "error.html",
                400,
                title="X isn’t connected",
                message=(
                    "X gave Bot RBAC different access than it asks for, so the connection "
                    "was not kept. Try again, and approve everything X’s screen lists."
                ),
                actions=retry_actions,
            )
        try:
            account = await blocking(ctx.twitter.account_for, tokens.access_token)
        except (TwitterApiError, PayloadToolError):
            return render(
                request,
                "error.html",
                502,
                title="X isn’t connected",
                message=(
                    "X didn’t say which account this is. Try again in a minute. If it keeps "
                    "happening, this deployment’s X app may not have API access."
                ),
                actions=retry_actions,
            )
        previous = await blocking(ctx.twitter_record)
        if previous is None or previous.get("user_id") != account.user_id:
            # The list is kept only when the same X account reconnects.
            await blocking(ctx.twitter.clear)
        await blocking(
            ctx.vault.set_twitter,
            tokens.access_token,
            tokens.refresh_token,
            email,
            tokens.expires_at,
            account.user_id,
            account.username,
            " ".join(sorted(granted)),
        )
        audit_owner("twitter_connect", connection="twitter")
        if WRITE_SCOPE in granted:
            done = (
                "X is connected. Now allow the accounts and lists your assistants may read. "
                "Assistants you let edit can post for you."
            )
        else:
            done = "X is connected. Now allow the accounts and lists your assistants may read."
        flash(request, "ok", done)
        return RedirectResponse(BACK, status_code=303)

    async def disconnect(request: Request) -> Response:
        record = await blocking(ctx.twitter_record)
        await blocking(ctx.vault.clear_twitter)
        # The list belongs to that X account; a later connection starts empty.
        await blocking(ctx.twitter.clear)
        confirmed = True
        if record and ctx.twitter.oauth is not None:
            for key, hint in (("t", "access_token"), ("r", "refresh_token")):
                if record.get(key):
                    ok = await blocking(ctx.twitter.oauth.revoke, record[key], hint)
                    confirmed = ok and confirmed
        audit_owner("twitter_disconnect", connection="twitter")
        if confirmed:
            flash(request, "ok", "X is disconnected. Assistants can no longer reach it.")
        else:
            flash(
                request,
                "error",
                "X is disconnected here, but X didn’t confirm it ended the connection. On "
                "X, open Settings → Security and account access → Apps and sessions → "
                "Connected apps, and remove Bot RBAC to be sure.",
            )
        return RedirectResponse("/settings#services", status_code=303)

    async def twitter_files(request: Request) -> Response:
        """Files → From X: what assistants may read, and the account's own lists."""

        def gather() -> dict[str, Any]:
            record = ctx.twitter_record()
            allowed = sorted(ctx.twitter.allowlist.entries().values(), key=lambda e: e.name.lower())
            out: dict[str, Any] = {
                "twitter_connected": record is not None,
                "twitter_can_post": ctx.twitter_post and can_post(record),
                "account": (record or {}).get("username") or "",
                "allowed": allowed,
                "own_lists": [],
                "twitter_error": None,
            }
            if record is None:
                return out
            try:
                out["own_lists"] = ctx.twitter.owned_lists()
            except PayloadToolError as exc:
                out["twitter_error"] = str(exc.payload.get("message") or "X refused.")
            except TwitterApiError:
                out["twitter_error"] = "X didn’t list your lists. Reload the page in a minute."
            return out

        data = await blocking(gather)
        return render(request, "twitter.html", next=BACK, **data)

    async def twitter_allow(request: Request, form: dict[str, str]) -> Response:
        if ctx.twitter is None:
            return refused(request, 404, "X is not set up on this server.")
        raw = (form.get("source") or "").strip()
        try:
            entry = await blocking(ctx.twitter.allow, raw)
        except PayloadToolError as exc:
            return action_done(request, "error", str(exc.payload.get("message")), BACK)
        except TwitterApiError:
            return action_done(request, "error", "X didn’t answer. Try again.", BACK)
        if entry is None:
            return action_done(
                request,
                "error",
                "X doesn’t show Bot RBAC that account or list. Type an @handle, an x.com "
                "account link, or a list link (x.com/i/lists/…).",
                BACK,
                changed=False,
            )
        audit_owner("twitter_allow", source=entry.id, name=entry.name)
        return action_done(request, "ok", f"Allowed “{entry.name}” for your assistants.", BACK)

    async def twitter_remove(request: Request, form: dict[str, str]) -> Response:
        if ctx.twitter is None:
            return refused(request, 404, "X is not set up on this server.")
        entry = await blocking(ctx.twitter.remove, form.get("source", ""))
        if entry is None:
            return action_done(request, "ok", "That was not allowed.", BACK, changed=False)
        audit_owner("twitter_remove", source=entry.id, name=entry.name)
        return action_done(
            request, "ok", f"Removed “{entry.name}”. Assistants can no longer read it.", BACK
        )

    return TwitterPages(
        start=start,
        disconnect=disconnect,
        twitter_callback=twitter_callback,
        twitter_files=twitter_files,
        twitter_allow=twitter_allow,
        twitter_remove=twitter_remove,
    )
