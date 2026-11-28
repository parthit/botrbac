"""Owner-side grant and revoke (server allowlist).

Grant and revoke change the allowlist. The dashboard never passes a bot address, so a tick
does not create a Drive permission. Revoke still deletes a permission id already stored on
an older entry.
"""

from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from .access import APPROVED, DENIED, AccessRequest, AccessRequests
from .audit import audit_owner
from .drive_client import FOLDER_MIME, SHORTCUT_MIME, DriveNotFoundError, OwnerDriveClient
from .scope import validate_drive_id
from .store import ACCESS_EDIT, ACCESS_READ, AllowEntry, Allowlist

OWNER_FIELDS = "id,name,mimeType,parents,trashed,webViewLink,shortcutDetails"
# Bounds for covering_entry's walk up the folder tree (levels, and folders looked at).
MAX_COVER_DEPTH = 25
MAX_COVER_NODES = 200


class GrantError(Exception):
    """A grant or revoke could not be completed; the message is safe to show the owner."""


@dataclass(frozen=True)
class ApprovalOption:
    id: str
    name: str
    mime_type: str
    label: str


def _live(entry: AllowEntry) -> bool:
    """Whether an entry still lets someone in: not ended, and not naming nobody."""
    if entry.expired():
        return False
    return entry.for_everyone or bool(entry.audience)


class _Keep:
    """Leave this field as it is (set_audience's expires_at)."""


KEEP = _Keep()


class GrantService:
    def __init__(
        self,
        owner_drive: Callable[[], OwnerDriveClient],
        allowlist: Allowlist,
        requests: AccessRequests,
        on_change: Callable[[], None] = lambda: None,
        audience: str | None = None,
        audit_actions: tuple[str, str] = ("grant", "revoke"),
    ):
        self._owner_drive = owner_drive
        self.allowlist = allowlist
        self.requests = requests
        self._on_change = on_change
        # Stamped on new entries. Set for the external list (who may read the item).
        self.audience = audience
        # Activity-log names for grant and revoke, so the external list does not log
        # as if the person's own assistant were given access.
        self._grant_action, self._revoke_action = audit_actions

    def owner_drive(self) -> OwnerDriveClient:
        return self._owner_drive()

    def owner_meta(self, file_id: str) -> dict[str, Any] | None:
        validate_drive_id(file_id)
        try:
            return self.owner_drive().get_file(file_id, fields=OWNER_FIELDS)
        except DriveNotFoundError:
            return None

    def grant(
        self,
        file_id: str,
        *,
        request_id: str | None = None,
        audience: str | tuple[str, ...] | None = None,
        expires_at: str | None = None,
    ) -> AllowEntry:
        """Add an item. On the Sharing list, `audience` (default: everyone paired) and
        `expires_at` say who may read it and until when. For an item already on the list,
        a given audience or expiry is applied with set_audience; without them it keeps
        what it has."""
        meta = self.owner_meta(file_id)
        if meta is None:
            raise GrantError("That item was not found in your Drive.")
        if meta.get("mimeType") == SHORTCUT_MIME:
            target = (meta.get("shortcutDetails") or {}).get("targetId")
            if not target:
                raise GrantError("That shortcut has no target.")
            meta = self.owner_meta(str(target))
            if meta is None:
                raise GrantError("The shortcut's target was not found in your Drive.")
        if meta.get("trashed"):
            raise GrantError("That item is in the trash.")
        item_id = str(meta["id"])
        existing = self.allowlist.get(item_id)
        if existing is not None:
            if self.audience is not None and (audience is not None or expires_at is not None):
                return self.set_audience(
                    item_id,
                    audience
                    if audience is not None
                    # An item that names nobody stays that way; never widen it to everyone.
                    else (existing.audience if existing.audience is not None else self.audience),
                    expires_at if expires_at is not None else KEEP,
                )
            if request_id and not existing.request_id:
                updated = replace(existing, request_id=request_id)
                self.allowlist.add(updated)
                return updated
            return existing
        if item_id == self.my_drive_root_id():
            raise GrantError("Your whole My Drive cannot be shared; pick folders or files in it.")
        chosen = self._audience_for(audience)
        if isinstance(chosen, tuple) and not chosen:
            raise GrantError("Choose at least one person, or share the item with everyone.")
        entry = AllowEntry(
            id=item_id,
            name=str(meta.get("name", "")),
            mime_type=str(meta.get("mimeType", "")),
            permission_id=None,  # only entries from the old bot-account mode carry one
            request_id=request_id,
            audience=chosen,
            expires_at=expires_at if self.audience is not None else None,
        )
        self.allowlist.add(entry)
        self._on_change()
        self._access_changed(item_id)
        audit_owner(self._grant_action, file_id=item_id, request_id=request_id)
        return entry

    def _audience_for(self, audience: str | tuple[str, ...] | None) -> str | tuple[str, ...] | None:
        if self.audience is None:
            return None
        if isinstance(audience, tuple):
            return tuple(sorted({a.strip().lower() for a in audience if a.strip()}))
        return self.audience

    def set_audience(
        self,
        file_id: str,
        audience: str | tuple[str, ...],
        expires_at: "str | None | _Keep" = None,
        access: "str | _Keep" = None,  # type: ignore[assignment]
    ) -> AllowEntry:
        """Sharing list only: change who may read an item, and until when. `expires_at`
        None clears the end date; KEEP leaves it as it is. An empty tuple is refused; use
        revoke to stop sharing with everyone."""
        if self.audience is None:
            raise GrantError("Only items on your Sharing list have an audience.")
        validate_drive_id(file_id)
        entry = self.allowlist.get(file_id)
        if entry is None:
            raise GrantError("That item is not on your Sharing list.")
        chosen = self._audience_for(audience)
        if isinstance(chosen, tuple) and not chosen:
            raise GrantError("Choose at least one person, or stop sharing the item.")
        until = entry.expires_at if isinstance(expires_at, _Keep) else (expires_at or None)
        if access is None or isinstance(access, _Keep):
            mode = entry.access
        elif access in (ACCESS_READ, ACCESS_EDIT):
            mode = access
        else:
            raise GrantError("Choose read or edit.")
        updated = replace(entry, audience=chosen, expires_at=until, access=mode)
        self.allowlist.add(updated)
        self._on_change()
        who = ",".join(chosen) if isinstance(chosen, tuple) else "everyone"
        audit_owner(
            "share_audience", file_id=file_id, audience=who, expires_at=until or "", access=mode
        )
        return updated

    def _access_changed(self, item_id: str) -> None:
        """The owner changed what the assistant may use, so an earlier denial for this
        item stops holding back new requests. The Sharing list is about other people's
        assistants and leaves those denials alone."""
        if self.audience is None:
            self.requests.clear_denials(item_id)

    def revoke(self, file_id: str) -> None:
        validate_drive_id(file_id)
        entry = self.allowlist.get(file_id)
        if entry is None:
            raise GrantError("That item is not in the allowlist.")
        self.allowlist.remove(file_id)
        self._on_change()
        self._access_changed(file_id)
        if entry.permission_id:
            try:
                self.owner_drive().delete_permission(file_id, entry.permission_id)
            except DriveNotFoundError:
                pass
            except Exception as exc:
                audit_owner(
                    self._revoke_action, "error", file_id=file_id, reason=type(exc).__name__
                )
                raise GrantError(
                    "Removed from the allowlist, but Google did not remove the bot's sharing. "
                    "Remove the bot from this item's Share dialog in Drive."
                ) from None
        audit_owner(self._revoke_action, file_id=file_id)

    def covering_entry(
        self, file_id: str, extra: dict[str, str] | None = None
    ) -> tuple[str, str] | None:
        """The nearest folder above `file_id` that is on this list, as (id, name).

        A folder on the list includes what is inside it, so after removing an item's own
        entry it can still be reachable through one of its folders. This walks every
        parent chain, the same way the scope guard does, so the dashboard can say so
        instead of claiming the item is gone. `extra` adds ids that count as allowed
        without being on the list (the server's root folder), mapped to a display name.
        Only a live entry counts: one that has ended, or names nobody, gives no access, so
        the walk goes on past it to a folder further up that still does.
        """
        entries = {fid: e for fid, e in self.allowlist.entries().items() if _live(e)}
        drive = self.owner_drive()
        seen: set[str] = {file_id}
        frontier = [file_id]
        for _ in range(MAX_COVER_DEPTH):
            next_frontier: list[str] = []
            for fid in frontier:
                try:
                    meta = drive.get_file(fid, fields="id,parents")
                except DriveNotFoundError:
                    continue
                for parent in meta.get("parents") or []:
                    pid = str(parent)
                    if pid in seen:
                        continue
                    seen.add(pid)
                    if pid in entries:
                        return pid, entries[pid].name or pid
                    if extra and pid in extra:
                        return pid, extra[pid]
                    next_frontier.append(pid)
            if not next_frontier or len(seen) > MAX_COVER_NODES:
                return None
            frontier = next_frontier
        return None

    def entry_status(
        self,
        file_ids: list[str],
        fetch_many: Callable[[list[str]], dict[str, dict[str, Any] | None | Exception]],
    ) -> tuple[dict[str, tuple[str, str]], set[str]]:
        """covering_entry for many ids at once, plus which ids Drive no longer opens.

        Same walk as covering_entry (every parent chain, nearest live entry, the same
        bounds), but the list is read once and the walks advance level by level together,
        so each level is one `fetch_many` call (the caller can run those lookups in
        parallel) and a folder shared by several walks is looked up once.

        `fetch_many` maps each id to its metadata ("id,parents"), None when Drive says
        not found, or the exception it raised. Returns ({id: (cover id, cover name)},
        {ids not found}). An id whose own lookup failed gets neither answer.
        """
        entries = {fid: e for fid, e in self.allowlist.entries().items() if _live(e)}
        metas: dict[str, dict[str, Any] | None | Exception] = {}

        def fetch(ids: set[str]) -> None:
            missing = [i for i in ids if i not in metas]
            if missing:
                metas.update(fetch_many(missing))

        fetch(set(file_ids))
        not_found = {fid for fid in file_ids if metas.get(fid) is None}
        covers: dict[str, tuple[str, str]] = {}
        # One walk per id: (seen, frontier). A walk leaves the dict when it ends.
        walks = {fid: ({fid}, [fid]) for fid in file_ids}
        for _ in range(MAX_COVER_DEPTH):
            if not walks:
                break
            # This level's folders, in one batch (the first level is already fetched).
            fetch({node for _, frontier in walks.values() for node in frontier})
            next_walks: dict[str, tuple[set[str], list[str]]] = {}
            for fid, (seen, frontier) in walks.items():
                next_frontier: list[str] = []
                found: tuple[str, str] | None = None
                for node in frontier:
                    meta = metas.get(node)
                    if not isinstance(meta, dict):
                        continue
                    for parent in meta.get("parents") or []:
                        pid = str(parent)
                        if pid in seen:
                            continue
                        seen.add(pid)
                        if pid in entries:
                            found = (pid, entries[pid].name or pid)
                            break
                        next_frontier.append(pid)
                    if found:
                        break
                if found:
                    covers[fid] = found
                elif next_frontier and len(seen) <= MAX_COVER_NODES:
                    next_walks[fid] = (seen, next_frontier)
            walks = next_walks
        return covers, not_found

    # ---- access request decisions --------------------------------------

    def approval_options(self, req: AccessRequest) -> list[ApprovalOption]:
        """For a file request: the item itself, plus its parent folder if the owner can see it
        (and it is not the owner's My Drive root, which cannot be shared)."""
        if not req.file_id:
            return []
        meta = self.owner_meta(req.file_id)
        if meta is None:
            return []
        root_id = self.my_drive_root_id()
        item_id = str(meta["id"])
        options: list[ApprovalOption] = []
        # The item itself is not an option when it is My Drive. Sharing it would
        # give the bot the owner's whole drive; grant() refuses that too.
        if meta.get("mimeType") == SHORTCUT_MIME:
            # Approving a shortcut allows what it points to (see grant), which can be a
            # folder with another name. So the option shows the target, not the shortcut.
            target_id = (meta.get("shortcutDetails") or {}).get("targetId")
            target = self.owner_meta(str(target_id)) if target_id else None
            if target is not None and str(target["id"]) != root_id:
                options.append(
                    ApprovalOption(
                        id=str(target["id"]),
                        name=str(target.get("name", "")),
                        mime_type=str(target.get("mimeType", "")),
                        label="Allow what this shortcut points to",
                    )
                )
        elif item_id != root_id:
            options.append(
                ApprovalOption(
                    id=item_id,
                    name=str(meta.get("name", "")),
                    mime_type=str(meta.get("mimeType", "")),
                    label="Allow just this item",
                )
            )
        for parent_id in meta.get("parents") or []:
            if parent_id == root_id:
                continue
            parent = self.owner_meta(str(parent_id))
            if parent is None or parent.get("mimeType") != FOLDER_MIME:
                continue
            options.append(
                ApprovalOption(
                    id=str(parent["id"]),
                    name=str(parent.get("name", "")),
                    mime_type=FOLDER_MIME,
                    label="Allow its whole folder",
                )
            )
            break
        return options

    def my_drive_root_id(self) -> str | None:
        try:
            return str(self.owner_drive().get_file("root", fields="id")["id"])
        except DriveNotFoundError:
            return None

    def approve(self, req: AccessRequest, target_id: str) -> AllowEntry:
        if req.status != "pending":
            raise GrantError(f"This request was already {req.status}.")
        validate_drive_id(target_id)
        if req.file_id:
            allowed = {o.id for o in self.approval_options(req)}
            # No safe option (item missing, or it is My Drive itself): the approval page
            # sends the owner to Browse to pick a substitute. A visible file or its
            # parent is still the only thing that may be approved for that request.
            if allowed and target_id not in allowed:
                raise GrantError("Pick the requested item or its parent folder.")
        entry = self.grant(target_id, request_id=req.id)
        self.requests.decide(req, APPROVED, granted_id=entry.id, granted_name=entry.name)
        audit_owner("approve_request", request_id=req.id, file_id=entry.id)
        return entry

    def deny(self, req: AccessRequest) -> None:
        if req.status != "pending":
            raise GrantError(f"This request was already {req.status}.")
        self.requests.decide(req, DENIED)
        audit_owner("deny_request", request_id=req.id, file_id=req.file_id)
