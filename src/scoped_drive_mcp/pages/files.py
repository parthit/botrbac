"""Files pages: the overview at /, the Drive browser and search, the Allowed list,
the Google Picker session, and allow/remove for one item or a batch.
"""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from ..access import PENDING
from ..auth import current_actor
from ..drive_client import FOLDER_MIME, SHORTCUT_MIME, DriveNotFoundError
from ..errors import report_exception
from ..grants import OWNER_FIELDS, GrantError, GrantService
from ..oauth import OAuthError
from ..scope import InvalidInputError, clean_search_text, parents_clause, validate_drive_id
from .common import (
    BATCH_ACTIONS,
    BATCH_LIMIT,
    COVER_CHECK_LIMIT,
    LIST_FIELDS,
    MAX_BREADCRUMBS,
    SEARCH_PAGE,
    OwnerNotConnectedError,
    _dupes,
    browse_pager,
    describe_mime,
    fetch_parents,
    icon_kind,
    normalize_page_token,
)
from .kit import FormHandler, Handler, Kit


@dataclass(frozen=True)
class FilePages:
    """What dashboard.py needs from this module: the handlers it routes to, and
    the helpers other page modules call."""

    home: Handler
    browse: Handler
    access: Handler
    picker_session: Handler
    grant: FormHandler
    revoke: FormHandler
    files_batch: FormHandler
    picked: Callable[[Request, str, str, str], Awaitable[Response]]
    still_covered: Callable[..., Awaitable[str | None]]


# Items taken from one visit to Google's full-page picker.
PICK_LIMIT = 100


def file_pages(kit: Kit) -> FilePages:
    ctx = kit.ctx
    settings = kit.settings
    peer_requests = kit.peer_requests
    logger = kit.logger
    signed_in_user = kit.signed_in_user
    remember_pending = kit.remember_pending
    render = kit.render
    render_plain = kit.render_plain
    flash = kit.flash
    action_done = kit.action_done
    wants_json = kit.wants_json
    blocking = kit.blocking
    safe_next = kit.safe_next
    refresh_access_token = kit.refresh_access_token

    async def home(request: Request) -> Response:
        # Logged-out visitors get the public page linked from the Google consent screen.
        email = await signed_in_user(request)
        if not email:
            return render_plain("home.html")
        reset = current_actor.set(email)
        try:
            await remember_pending(request)
            return await overview(request)
        finally:
            current_actor.reset(reset)

    async def overview(request: Request) -> Response:
        def gather() -> dict[str, Any]:
            entries = ctx.allowlist.entries()
            bot = ctx.bot_status()
            return {
                "bot": bot,
                "owner_connected": ctx.owner_connected(),
                # Step 2 done for this person. Browse, Allow and Sharing need it, even
                # when the deployment's own bot token (bot.connected) is set.
                "drive_connected": ctx.drive_connected(),
                "connections": ctx.connection_rows(),
                "allow_count": len(entries),
                "grants": (ctx.mcp_oauth.list_grants(current_actor.get()) if ctx.mcp_oauth else []),
                "missing_wakeups": (
                    ctx.mailbox.missing_wakeups(str(current_actor.get() or ""))
                    if ctx.mailbox is not None
                    else []
                ),
                **people_summary(str(current_actor.get() or "")),
                "first_reads": ctx.first_reads.recent() if ctx.first_reads else [],
            }

        data = await blocking(gather)
        return render(
            request,
            "overview.html",
            missing=settings.missing_settings(),
            store_kind=getattr(ctx.store, "kind", "custom"),
            root_folder_id=ctx.visible_root_folder_id(),
            mcp_url=f"{settings.app_base_url}/mcp",
            picker_ready=settings.picker_configured,
            env_token_set=bool(
                settings.env_bot_refresh_token and current_actor.get() == settings.owner_email
            ),
            **data,
        )

    def people_summary(email: str) -> dict[str, Any]:
        """Mailbox and Shared with me counts for Overview. Store reads only, no Drive call."""
        mailbox = None
        if ctx.mailbox is not None and email:
            try:
                mailbox = ctx.mailbox.summary(email)
            except Exception:
                logger.exception("mailbox summary failed")
        shared = None
        if ctx.shared_with_me is not None and email:
            try:
                people = ctx.shared_with_me.overview(email)
                shared = {
                    "people": len(people),
                    "item_count": sum(p.item_count for p in people),
                }
            except Exception:
                logger.exception("shared with me summary failed")
        return {"mailbox_summary": mailbox, "shared_summary": shared}

    def browse_data(folder: str, q: str | None, page_token: str | None) -> dict[str, Any]:
        drive, token = ctx.owner_drive_and_token()
        # drive.file cannot files.get("root") until the app has opened My Drive.
        # The alias still works in a parents query, which is enough to list files
        # this app created or the user picked.
        root_id = ctx.owner_root_id(drive, token)
        entries = ctx.allowlist.entries()
        shared = ctx.ext_ids()
        crumbs: list[dict[str, str]] = []
        # The nearest allowed folder at or above the one being browsed, and its id so
        # the breadcrumb can offer to remove that folder's own entry.
        covered_by: str | None = None
        covered_id: str | None = None
        # The nearest folder on the Sharing list above the one being browsed. Everything
        # inside it is readable by paired people's assistants, as the guest guard allows.
        shared_by: str | None = None
        shared_id: str | None = None
        next_token: str | None = None
        more_matches = False
        current: dict[str, Any] | None = None
        at_top = not q and folder == "root"
        if q:
            term = clean_search_text(q)
            query = f"trashed=false and name contains '{term}'"
            resp = drive.list_files(query, fields=LIST_FIELDS, page_size=SEARCH_PAGE)
            items = resp.get("files", [])
            more_matches = bool(resp.get("nextPageToken"))
        else:
            if folder == "root":
                folder_id = root_id or "root"
            else:
                folder_id = validate_drive_id(folder, "folder")
            if folder_id == "root" or folder_id == root_id:
                # My Drive itself: its name and place are known, so no lookup.
                current = {
                    "id": folder_id,
                    "name": "My Drive",
                    "mimeType": FOLDER_MIME,
                    "parents": [],
                }
            else:
                try:
                    current = drive.get_file(folder_id, fields=OWNER_FIELDS)
                except DriveNotFoundError:
                    raise InvalidInputError("folder not found in your Drive") from None
                if current.get("mimeType") != FOLDER_MIME:
                    raise InvalidInputError("that is not a folder")
            node: dict[str, Any] | None = current
            seen: set[str] = set()
            while node is not None and len(crumbs) < MAX_BREADCRUMBS:
                nid = str(node["id"])
                if nid in seen:
                    break
                seen.add(nid)
                name = "My Drive" if nid == root_id or nid == "root" else str(node.get("name", ""))
                crumbs.insert(0, {"id": "root" if nid == root_id else nid, "name": name})
                if covered_by is None and nid in entries:
                    covered_by, covered_id = name, nid
                if shared_by is None and nid in shared:
                    shared_by, shared_id = name, nid
                parents = node.get("parents") or []
                if nid == root_id or nid == "root" or not parents:
                    break
                try:
                    node = drive.get_file(str(parents[0]), fields=OWNER_FIELDS)
                except DriveNotFoundError:
                    node = None
            if at_top:
                # Google opens a file to this app only once it is picked (drive.file), and
                # picked files can sit anywhere in the Drive, not just in My Drive's top
                # level. So the top of Files lists everything the app can open: the
                # picked items and the files it created, each with Allow and Share.
                # That "everything" is bounded by the OAuth scope, which is always
                # drive.file: a wider token is refused at connect and on every refresh.
                query = "trashed=false"
            else:
                query = f"{parents_clause([folder_id])} and trashed=false"
            resp = drive.list_files(
                query,
                fields=LIST_FIELDS,
                page_size=kit.browse_page_size(),
                page_token=page_token,
                # Folders first, then by name, across every page (not just within one).
                order_by="folder,name",
            )
            items = resp.get("files", [])
            # Drive's parents filter can echo a file that merely mentions the folder.
            # The alias "root" is not the id Drive returns on a file, so it cannot be
            # used for that check.
            if not at_top and folder_id != "root":
                items = [i for i in items if folder_id in (i.get("parents") or [])]
            next_token = resp.get("nextPageToken")
        items.sort(key=lambda i: (i.get("mimeType") != FOLDER_MIME, str(i.get("name", "")).lower()))

        # Folder metadata looked up while working out search results and shortcut
        # targets. Many results share folders, so each folder is fetched once.
        metas: dict[str, dict[str, Any] | None] = {}
        if current is not None:
            metas[str(current["id"])] = current

        lookups = [0]

        class _OutOfLookups(Exception):
            pass

        def meta_of(fid: str) -> dict[str, Any] | None:
            if fid not in metas:
                if lookups[0] >= kit.search_lookups():
                    raise _OutOfLookups
                lookups[0] += 1
                try:
                    metas[fid] = drive.get_file(fid, fields=OWNER_FIELDS)
                except DriveNotFoundError:
                    metas[fid] = None
            return metas[fid]

        def lineage(item: dict[str, Any]) -> list[tuple[str, str]] | None:
            """(id, name) of the folders above `item`, nearest first, up to My Drive.
            Follows the first parent, as the breadcrumbs do. None when the page's lookup
            budget ran out before reaching the top, so the answer would be a guess."""
            out: list[tuple[str, str]] = []
            seen_ids = {str(item.get("id", ""))}
            parents = item.get("parents") or []
            try:
                while parents and len(out) < MAX_BREADCRUMBS:
                    pid = str(parents[0])
                    if pid in seen_ids or pid == root_id or pid == "root":
                        break
                    seen_ids.add(pid)
                    node_meta = meta_of(pid)
                    if node_meta is None:
                        break
                    out.append((pid, str(node_meta.get("name", ""))))
                    parents = node_meta.get("parents") or []
            except _OutOfLookups:
                return None
            return out

        def nearest(chain: list[tuple[str, str]], ids: Any) -> tuple[str, str] | None:
            return next(((fid, name) for fid, name in chain if fid in ids), None)

        # In a folder view every row sits under the same folders, so the folder-level
        # answer applies. Search results come from anywhere, so each works out its own.
        folder_cover = (covered_id, covered_by) if covered_by and covered_id else None
        folder_share = (shared_id, shared_by) if shared_by and shared_id else None
        # Removed from Bot RBAC: left out of My Drive's list and search, the two places a
        # picked item shows up on its own. Inside a folder everything is still listed.
        hidden = ctx.hidden.ids() if ctx.hidden is not None and (q or folder == "root") else set()
        hidden_count = sum(1 for item in items if str(item["id"]) in hidden)
        rows = []
        for item in items:
            iid = str(item["id"])
            if iid in hidden:
                continue
            mime = str(item.get("mimeType", ""))
            is_shortcut = mime == SHORTCUT_MIME
            path: str | None = None
            unsure = False
            if q or at_top:
                # Search results, and the top of Files (every picked item, wherever it
                # sits in the Drive), come from anywhere: each row works out its own
                # folders, so an item inside an allowed folder shows as allowed here too.
                chain = lineage(item)
                if chain is None:
                    # Too many folders to look up on one page: don't guess the status.
                    unsure, cover, share, parent_id = True, None, None, None
                else:
                    cover = nearest(chain, entries) or folder_cover
                    share = nearest(chain, shared) or folder_share
                    if q:
                        path = " / ".join(["My Drive", *(name for _, name in reversed(chain))])
                        parent_id = chain[0][0] if chain else "root"
                    else:
                        parent_id = None
            else:
                cover, share = folder_cover, folder_share
                parent_id = None
            # A shortcut is not on the lists itself: Allow stores its target. So the row
            # shows the target's state, and Remove / Stop sharing act on the target.
            acts_on = iid
            target: dict[str, Any] | None = None
            if is_shortcut:
                target_id = str((item.get("shortcutDetails") or {}).get("targetId") or "")
                try:
                    target_meta = meta_of(target_id) if target_id else None
                except _OutOfLookups:
                    target_meta, unsure = None, True
                tchain = lineage(target_meta) if target_meta is not None else None
                if target_meta is not None and tchain is None:
                    unsure = True
                if unsure and target_id:
                    # Out of lookups: still act on the target (Allow stores the target),
                    # but don't guess its folder state from the shortcut's own folder.
                    acts_on, cover, share = target_id, None, None
                if target_meta is not None and tchain is not None:
                    # The row's state is the target's, and that is known.
                    acts_on, unsure = target_id, False
                    cover = nearest(tchain, entries)
                    share = nearest(tchain, shared)
                    item_parents = [str(p) for p in item.get("parents") or []]
                    target_parents = [str(p) for p in target_meta.get("parents") or []]
                    target = {
                        "id": target_id,
                        "name": str(target_meta.get("name", "")),
                        "folder": tchain[0][1] if tchain else "My Drive",
                        "elsewhere": not set(item_parents) & set(target_parents),
                    }
            rows.append(
                {
                    "id": iid,
                    "acts_on": acts_on,
                    "name": str(item.get("name", "")),
                    "is_folder": mime == FOLDER_MIME,
                    "is_shortcut": is_shortcut,
                    "target": target,
                    "kind": describe_mime(mime),
                    "icon": icon_kind(mime),
                    "modified": item.get("modifiedTime"),
                    "link": item.get("webViewLink"),
                    "path": path,
                    "parent_id": parent_id,
                    "unsure": unsure,
                    "granted": acts_on in entries,
                    "covered_by": cover[1] if cover else None,
                    "ext_shared": acts_on in shared,
                    "shared_by": share[1] if share else None,
                }
            )
        return {
            "rows": rows,
            # Same-named rows ("Untitled document" three times) show when each changed.
            "dupes": _dupes(rows),
            "crumbs": crumbs,
            "covered_by": covered_by,
            "covered_id": covered_id,
            "shared_by": shared_by,
            "current": current,
            "current_granted": current is not None and str(current["id"]) in entries,
            "is_root": current is not None
            and (
                str(current["id"]) == root_id or (root_id is None and str(current["id"]) == "root")
            ),
            "next_token": next_token,
            "more_matches": more_matches,
            "hidden_count": hidden_count,
            "drive_error": False,
        }

    async def browse(request: Request) -> Response:
        folder = request.query_params.get("folder") or "root"
        q = (request.query_params.get("q") or "").strip()[:200] or None
        page_token = normalize_page_token(request.query_params.get("page"))
        prev = [
            token
            for token in (
                normalize_page_token(item) for item in request.query_params.getlist("prev")
            )
            if token
        ]
        request_id = request.query_params.get("request") or None
        picking = None
        if request_id:
            picking = await blocking(ctx.requests.get, request_id)
            if picking is None or picking.status != PENDING:
                picking = None
        # Choosing the one item to share for a paired person's described request.
        peer_picking = None
        peer_id = request.query_params.get("peer_request") or None
        if peer_id and peer_requests is not None:
            peer_picking = await blocking(
                peer_requests.get, str(current_actor.get() or ""), peer_id
            )
            if peer_picking is None or peer_picking.status != PENDING or peer_picking.text is None:
                peer_picking = None
        if peer_picking is not None:
            picking = None
        try:
            data = await blocking(browse_data, folder, q, page_token)
        except (InvalidInputError, OwnerNotConnectedError):
            raise
        except Exception as exc:
            # The picker has to stay on the page. A Drive failure used to replace the
            # whole screen, which also removed the only way to approve a file.
            report_exception(exc, where="browse")
            if page_token:
                # Most often a page link that went stale (Back, or a bookmark). Show the
                # folder's first page instead of an error.
                first = {"folder": folder}
                if q:
                    first["q"] = q
                if picking:
                    first["request"] = picking.id
                if peer_picking:
                    first["peer_request"] = peer_picking.id
                return RedirectResponse(f"/files?{urlencode(first)}", status_code=303)
            data = {
                "rows": [],
                "crumbs": [{"id": "root", "name": "My Drive"}],
                "covered_by": None,
                "covered_id": None,
                "shared_by": None,
                "current": {"id": "root", "name": "My Drive", "mimeType": FOLDER_MIME},
                "current_granted": False,
                "is_root": True,
                "next_token": None,
                "drive_error": True,
            }
        here = request.url.path + ("?" + request.url.query if request.url.query else "")
        pager = browse_pager(
            folder,
            q=q,
            request_id=picking.id if picking else None,
            page=page_token,
            prev=prev,
            next_token=data.get("next_token"),
        )
        if peer_picking:
            keep_peer = "&" + urlencode({"peer_request": peer_picking.id})
            pager = {k: (v + keep_peer if v else v) for k, v in pager.items()}
        email = str(current_actor.get() or "")
        has_pairing = bool(
            ctx.mailbox is not None
            and ctx.ext_allowlist is not None
            and await blocking(ctx.mailbox.active_peers, email)
        )
        return render(
            request,
            "browse.html",
            has_pairing=has_pairing,
            q=q,
            folder=folder,
            picking=picking,
            peer_picking=peer_picking,
            here=here,
            picker_ready=settings.picker_configured,
            **pager,
            **data,
        )

    async def picker_session(request: Request) -> Response:
        if not settings.picker_configured:
            return JSONResponse({"error": "picker_not_configured"}, status_code=404)
        record = await blocking(ctx.vault.owner)
        if not record or not record.get("t"):
            return JSONResponse({"error": "sign_in_required"}, status_code=401)
        assert settings.google_oauth_client_id is not None
        assert settings.google_oauth_client_secret is not None
        try:
            token = await blocking(
                refresh_access_token,
                settings.google_oauth_client_id.get_secret_value(),
                settings.google_oauth_client_secret.get_secret_value(),
                record["t"],
            )
        except OAuthError as exc:
            logger.warning("picker token not issued: %s", exc)
            return JSONResponse({"error": str(exc)}, status_code=502)
        return JSONResponse(
            {
                "access_token": token,
                "api_key": settings.google_picker_api_key,
                "app_id": settings.google_cloud_project_number,
            }
        )

    async def grant(request: Request, form: dict[str, str]) -> Response:
        file_id = validate_drive_id(form.get("file_id"))
        next_url = safe_next(form.get("next"))
        try:
            entry = await blocking(ctx.grants().grant, file_id)
        except GrantError as exc:
            return action_done(request, "error", str(exc), next_url)
        await unhide(file_id, entry.id)
        what = f"\u201c{entry.name}\u201d"
        if entry.id != file_id:
            what += ", the shortcut\u2019s target,"
        return action_done(
            request,
            "ok",
            f"Allowed {what} for the assistant.",
            next_url,
            extra=await allow_count_extra(request),
        )

    async def revoke(request: Request, form: dict[str, str]) -> Response:
        file_id = validate_drive_id(form.get("file_id"))
        next_url = safe_next(form.get("next"))
        grants = ctx.grants()
        entry = await blocking(ctx.allowlist.get, file_id)
        try:
            await blocking(grants.revoke, file_id)
        except GrantError as exc:
            gone = await blocking(lambda: ctx.allowlist.get(file_id) is None)
            return action_done(
                request,
                "error",
                str(exc),
                next_url,
                changed=gone,
                extra=await allow_count_extra(request) if gone else None,
            )
        root = ctx.visible_root_folder_id()
        extra = {root: "the folder set on the server"} if root else None
        cover = await still_covered(grants, file_id, extra)
        name = (entry.name if entry else "") or "it"
        if cover is None:
            message = f"Removed “{name}”. The assistant can no longer use it."
        elif cover:
            message = (
                f"Removed “{name}”, but the assistant can still use it "
                f"because “{cover}” is allowed."
            )
        else:
            message = (
                f"Removed “{name}”. If a folder above it is allowed, "
                "the assistant can still use it through that folder."
            )
        return action_done(request, "ok", message, next_url, extra=await allow_count_extra(request))

    async def unhide(*file_ids: str) -> None:
        """Picking or allowing an item again brings it back onto Files."""
        if ctx.hidden is not None:
            for fid in set(file_ids):
                await blocking(ctx.hidden.unhide, fid)

    async def picked(request: Request, picked_ids: str, next_url: str, request_id: str) -> Response:
        """Allow what came back from Google's full-page picker (pages/signin.py), the same
        way ui.js does after the in-page picker: each item through GrantService.grant,
        then the request it was picked for, if any. `current_actor` is already set."""
        try:
            ids = list(
                dict.fromkeys(
                    validate_drive_id(part.strip())
                    for part in picked_ids.split(",")
                    if part.strip()
                )
            )
        except InvalidInputError:
            flash(request, "error", "Google returned something that is not a Drive item.")
            return RedirectResponse(next_url, status_code=303)
        if not ids:
            flash(
                request,
                "error",
                "Nothing came back from Google’s file picker, so nothing changed. "
                "Choose the files on Google’s page, then Select.",
            )
            return RedirectResponse(next_url, status_code=303)
        skipped = len(ids) - PICK_LIMIT
        names: list[str] = []
        errors: list[str] = []
        for file_id in ids[:PICK_LIMIT]:
            try:
                entry = await blocking(ctx.grants().grant, file_id)
            except GrantError as exc:
                errors.append(str(exc))
                continue
            await unhide(file_id, entry.id)
            names.append(entry.name or entry.id)
        if len(names) == 1:
            flash(request, "ok", f"Allowed \u201c{names[0]}\u201d for the assistant.")
        elif names:
            flash(request, "ok", f"Allowed {len(names)} items for the assistant.")
        if errors:
            flash(request, "error", errors[0])
        if skipped > 0:
            flash(request, "error", f"Only the first {PICK_LIMIT} items were added. Pick the rest.")
        if request_id and names:
            req = await blocking(ctx.requests.get, request_id)
            if req is not None:
                try:
                    entry = await blocking(ctx.grants().approve, req, ids[0])
                    flash(
                        request,
                        "ok",
                        f"Approved: shared \u201c{entry.name}\u201d with the assistant.",
                    )
                except GrantError as exc:
                    flash(request, "error", str(exc))
                return RedirectResponse(f"/requests/{quote(req.id)}", status_code=303)
        return RedirectResponse(next_url, status_code=303)

    def plural(n: int, one: str = "item", many: str = "items") -> str:
        return f"{n} {one if n == 1 else many}"

    async def files_batch(request: Request, form: dict[str, str]) -> Response:
        """One action on several ticked items: the action bar on Files and Sharing.

        Each item goes through the same GrantService call as its own row button, so the
        allowlist checks, audit records and cache invalidation are unchanged. An item the
        action does not apply to (Remove on an item that is not allowed) is skipped.
        """
        action = form.get("action") or ""
        next_url = safe_next(form.get("next") or "/files")
        if action not in BATCH_ACTIONS:
            return action_done(request, "error", "Choose what to do with the items.", next_url)
        raw = (await request.form()).getlist("file_id")
        try:
            ids = list(dict.fromkeys(validate_drive_id(str(v)) for v in raw))
        except InvalidInputError:
            # Only a hand-made request carries one: the page renders real ids. Refuse the
            # whole batch rather than act on part of it.
            return action_done(
                request, "error", "One of the ticked items is not a Drive item.", next_url
            )
        if not ids:
            return action_done(request, "error", "Tick at least one item first.", next_url)
        if len(ids) > BATCH_LIMIT:
            return action_done(
                request, "error", f"Choose at most {BATCH_LIMIT} items at a time.", next_url
            )
        if action in ("share", "unshare") and ctx.ext_allowlist is None:
            return action_done(request, "error", "Sharing is not set up on this server.", next_url)
        own = ctx.grants()
        ext = ctx.ext_grants() if ctx.ext_allowlist is not None else None

        def run() -> tuple[int, list[str], list[str], list[str]]:
            done = 0
            errors: list[str] = []
            names: list[str] = []
            # Ids actually taken off a list, for the folder check below. Skipped items
            # (Remove on something that was not allowed) must not be reported on.
            changed: list[str] = []
            hidden = ctx.hidden

            def unhide(*fids: str) -> None:
                if hidden is not None:
                    for one in set(fids):
                        hidden.unhide(one)

            for fid in ids:
                try:
                    if action == "allow":
                        entry = own.grant(fid)
                        names.append(entry.name)
                        unhide(fid, entry.id)
                    elif action == "share":
                        assert ext is not None
                        entry = ext.grant(fid)
                        names.append(entry.name)
                        unhide(fid, entry.id)
                    elif action == "remove":
                        entry = ctx.allowlist.get(fid)
                        if entry is None:
                            continue
                        names.append(entry.name)
                        own.revoke(fid)
                        changed.append(fid)
                    elif action == "unshare":
                        assert ext is not None and ctx.ext_allowlist is not None
                        entry = ctx.ext_allowlist.get(fid)
                        if entry is None:
                            continue
                        names.append(entry.name)
                        ext.revoke(fid)
                        changed.append(fid)
                    else:  # forget: off both lists, then off this list
                        mine = ctx.allowlist.get(fid)
                        theirs = ctx.ext_allowlist.get(fid) if ctx.ext_allowlist else None
                        listed = mine or theirs
                        if listed is not None and listed.name:
                            names.append(listed.name)
                        if mine is not None:
                            own.revoke(fid)
                        shared = ctx.ext_allowlist
                        if ext is not None and shared is not None and shared.get(fid) is not None:
                            ext.revoke(fid)
                        if hidden is not None:
                            hidden.hide(fid)
                    done += 1
                except GrantError as exc:
                    errors.append(str(exc))
            return done, errors, names, changed

        done, errors, names, changed = await blocking(run)
        if action == "remove":
            # Same check as one row's Remove, bounded: an allowed folder above an item
            # still includes it, so the message must not say the item is unreachable.
            root = ctx.visible_root_folder_id()
            extra = {root: "the folder set on the server"} if root else None
        else:
            extra = None
        # still: the folder that still covers each removed item. unknown: removed items
        # whose folders were not checked, because Drive did not answer ("") or the batch
        # was past COVER_CHECK_LIMIT. Then the message must not say they are unreachable.
        still: list[str] = []
        unknown = 0
        checker = own if action == "remove" else ext if action == "unshare" else None
        if checker is not None:
            unknown = max(0, len(changed) - COVER_CHECK_LIMIT)
            for fid in changed[:COVER_CHECK_LIMIT]:
                cover = await still_covered(checker, fid, extra)
                if cover:
                    still.append(cover)
                elif cover == "":
                    unknown += 1
        what = f"\u201c{names[0]}\u201d" if done == 1 and names else plural(done)
        message = {
            "allow": f"Allowed {what} for your assistants.",
            "remove": f"Removed {what}. Your assistants can no longer use "
            f"{'it' if done == 1 else 'them'}.",
            "share": f"Shared {what} with the assistants of people you are paired with.",
            "unshare": f"Stopped sharing {what}. Paired people\u2019s assistants can no longer "
            f"read {'it' if done == 1 else 'them'}.",
            "forget": f"Removed {what} from Bot RBAC. No assistant can open "
            f"{'it' if done == 1 else 'them'}. Google still lists Bot RBAC as able to open "
            f"{'it' if done == 1 else 'them'} until you remove the app in your Google Account.",
        }[action]
        if unknown and not still:
            # Same wording as one row's Remove when Drive could not be asked.
            them = "it" if done == 1 else "them"
            if action == "remove":
                message = (
                    f"Removed {what}. If a folder above {them} is allowed, your assistants "
                    f"can still use {them} through that folder."
                )
            else:
                message = (
                    f"Stopped sharing {what}. If a folder above {them} is on your Sharing "
                    f"list, paired people\u2019s assistants can still read {them} through it."
                )
        if still:
            folders = ", ".join(f"\u201c{c}\u201d" for c in dict.fromkeys(still))
            stays = "stays" if len(set(still)) == 1 else "stay"
            if action == "remove":
                message = (
                    f"Removed {what}, but your assistants can still use "
                    f"{len(still)} of them through {folders}, "
                    f"which {stays} allowed."
                    if done > 1
                    else f"Removed {what}, but your assistants can still use it because "
                    f"{folders} is allowed."
                )
            else:
                message += f" Still readable through {folders}, which {stays} shared."
        if errors:
            first = errors[0].replace("allowlist", "list")
            failed = plural(len(errors))
            if done:
                message += f" {failed} could not be changed: {first}"
            else:
                return action_done(
                    request, "error", f"{failed} could not be changed: {first}", next_url
                )
        if done == 0:
            return action_done(
                request, "error", "None of the ticked items needed that change.", next_url
            )
        return action_done(request, "ok", message, next_url)

    async def allow_count_extra(request: Request) -> dict[str, int] | None:
        """The new number for the Allowed tab, so ui.js can update it without a reload."""
        if not wants_json(request):
            return None
        return {"allow_count": len(await blocking(ctx.allowlist.entries))}

    async def still_covered(
        grants: GrantService, file_id: str, extra: dict[str, str] | None = None
    ) -> str | None:
        """Name of an allowed folder that still includes `file_id`.

        None means no folder on the list includes it. An empty string means Drive could
        not be asked; only the wording depends on this, so the completed removal is not
        turned into an error, and the message does not claim the item is unreachable.
        """
        try:
            found = await blocking(grants.covering_entry, file_id, extra)
        except Exception as exc:
            report_exception(exc, where="covering_entry")
            return ""
        return found[1] if found else None

    async def access(request: Request) -> Response:
        def gather() -> dict[str, Any]:
            return {
                "entries": ctx.allowlist.entries(),
                "bot": ctx.bot_status(),
                "drive_connected": ctx.drive_connected(),
            }

        data = await blocking(gather)
        rows = sorted(data["entries"].values(), key=lambda e: e.granted_at, reverse=True)

        def entry_status() -> tuple[dict[str, str], set[str]]:
            # covered: an entry inside another allowed folder. Removing it alone changes
            # nothing, so the list says so. needs_pick: Google opens a file to this app
            # only once it is picked (drive.file); an entry from an older connection
            # stays on the list but can't be opened until it is picked again.
            # One pass for both, with each level of folder lookups run in parallel.
            # Bounded, since each check walks up the folder tree.
            if not data["drive_connected"] or not rows:
                return {}, set()
            try:
                drive = ctx.owner_drive()
            except Exception:
                return {}, set()
            ids = [entry.id for entry in rows[:COVER_CHECK_LIMIT]]
            failed = [0]

            def fetch(batch: list[str]) -> dict[str, dict[str, Any] | None | Exception]:
                found = fetch_parents(drive, batch)
                failed[0] += sum(isinstance(v, Exception) for v in found.values())
                return found

            try:
                covers, not_found = ctx.grants().entry_status(ids, fetch)
            except Exception:
                logger.exception("allowed list status check failed")
                return {}, set()
            if failed[0]:
                # Those items get no note rather than a guess. Logged so a burst of rate
                # limits or Drive errors shows up instead of quietly hiding the notes.
                logger.warning("allowed list status check: %d Drive lookups failed", failed[0])
            if len(rows) < 2:
                # One entry can't be inside another. The walk above still ran, because
                # it also finds the entries Drive no longer opens (needs_pick).
                covers = {}
            return {fid: c[1] for fid, c in covers.items() if c[0] != fid}, not_found

        covered, needs_pick = await blocking(entry_status)
        return render(
            request,
            "access.html",
            covered=covered,
            needs_pick=needs_pick,
            picker_ready=settings.picker_configured,
            rows=rows,
            root_folder_id=ctx.visible_root_folder_id(),
            describe_mime=describe_mime,
            bot=data["bot"],
            drive_connected=data["drive_connected"],
        )

    return FilePages(
        home=home,
        browse=browse,
        access=access,
        picker_session=picker_session,
        grant=grant,
        revoke=revoke,
        files_batch=files_batch,
        picked=picked,
        still_covered=still_covered,
    )
