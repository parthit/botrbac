"""Services a signed-in person can connect, one consent step each.

Signing in (step 1) only proves who someone is. Each entry here is a separate,
explicit step 2: the person chooses **Connect**, Google (or later, another provider)
shows the wider permission, and the refresh token that comes back is stored for that
person. Google Drive is the first connection; Notion and OneDrive are optional (each
offered only when its OAuth client is configured, see notion.py and onedrive.py).
Adding another service means adding an entry here, a token slot for it, and the tools
that use it; the sign-in step does not change.
"""

from collections.abc import Iterable
from dataclasses import dataclass, replace

from .drive_client import ACCEPTABLE_SCOPES, DRIVE_FILE_SCOPE
from .onedrive_client import ALLOWED_SCOPES as ONEDRIVE_ALLOWED_SCOPES
from .onedrive_client import REQUIRED_SCOPE as ONEDRIVE_REQUIRED_SCOPE
from .onedrive_client import SCOPES as ONEDRIVE_SCOPES


@dataclass(frozen=True)
class Connection:
    key: str
    """URL-safe id, used in `/connect/{key}`."""
    name: str
    """What the person sees, e.g. "Google Drive"."""
    provider: str
    """Who runs the consent screen: "google", "notion" or "microsoft"."""
    scopes: tuple[str, ...]
    """Scopes requested in addition to the sign-in scopes."""
    required_scope: str
    """A token without this scope is refused and not stored."""
    allowed_scopes: frozenset[str]
    """An allowlist: a token that carries any scope outside it is refused, revoked and
    not stored. Includes the sign-in scopes, which come back on the same token."""
    summary: str
    """One line on what connecting allows."""
    disclosure: str
    """Shown right before the connect button, as Google's policy asks."""

    def scopes_too_wide(self, granted: Iterable[str]) -> bool:
        """True when Google granted anything outside `allowed_scopes`."""
        return not set(granted) <= self.allowed_scopes


GOOGLE_DRIVE = Connection(
    key="google_drive",
    name="Google Drive",
    provider="google",
    scopes=(DRIVE_FILE_SCOPE,),
    required_scope=DRIVE_FILE_SCOPE,
    allowed_scopes=ACCEPTABLE_SCOPES,
    summary="Only the Google Drive files and folders you pick.",
    disclosure=(
        "Google will ask you to let Bot RBAC see, edit, create, and delete only the "
        "specific Google Drive files you use with this app. That means files you pick in "
        "Google's file picker and files the app creates. Google keeps the rest of your "
        "Drive closed to Bot RBAC. An assistant still reaches only the items you allow."
    ),
)

NOTION = Connection(
    key="notion",
    name="Notion",
    provider="notion",
    # Notion has no scopes: its consent screen asks which pages to share instead.
    scopes=(),
    required_scope="",
    allowed_scopes=frozenset(),
    summary="Only the Notion pages you pick, and only to read.",
    disclosure=(
        "Notion will ask which pages to share with Bot RBAC. Bot RBAC can read only those "
        "pages and what is inside them, and never edits Notion. An assistant still reaches "
        "only the pages you allow on Files."
    ),
)

# What Notion's card says on a deployment that turned page creation on
# (NOTION_ALLOW_CREATE). Shown in place of NOTION; everything else is the same.
NOTION_WITH_CREATE = replace(
    NOTION,
    summary="Only the Notion pages you pick: to read, and to add new pages under them.",
    disclosure=(
        "Notion will ask which pages to share with Bot RBAC. Bot RBAC can read only those "
        "pages and what is inside them. An assistant you let edit can also add a new page "
        "under one. Bot RBAC never changes or deletes existing Notion pages. An assistant "
        "still reaches only the pages you allow on Files."
    ),
)

ONEDRIVE = Connection(
    key="onedrive",
    name="OneDrive",
    provider="microsoft",
    scopes=ONEDRIVE_SCOPES,
    required_scope=ONEDRIVE_REQUIRED_SCOPE,
    allowed_scopes=ONEDRIVE_ALLOWED_SCOPES,
    summary="Only the OneDrive files and folders you allow.",
    disclosure=(
        "Microsoft will ask you to let Bot RBAC read and edit your OneDrive files and see "
        "your name. Microsoft can't limit that to some files, so Bot RBAC holds "
        "assistants to the files and folders you allow on Files. Only assistants you let "
        "edit can add files and folders there or change and rename what is inside; none "
        "can delete, move or share anything."
    ),
)

CONNECTIONS: dict[str, Connection] = {c.key: c for c in (GOOGLE_DRIVE, NOTION, ONEDRIVE)}


def get_connection(key: str | None) -> Connection | None:
    if not key:
        return None
    return CONNECTIONS.get(key)
