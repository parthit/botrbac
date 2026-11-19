"""Services a signed-in person can connect, one consent step each.

Signing in (step 1) only proves who someone is. Each entry here is a separate,
explicit step 2: the person chooses **Connect**, Google (or later, another provider)
shows the wider permission, and the refresh token that comes back is stored for that
person. Google Drive is the first connection. Adding another service means adding an
entry here, a token slot for it, and the tools that use it; the sign-in step does not
change.
"""

from dataclasses import dataclass

from .drive_client import DRIVE_SCOPE


@dataclass(frozen=True)
class Connection:
    key: str
    """URL-safe id, used in `/connect/{key}`."""
    name: str
    """What the person sees, e.g. "Google Drive"."""
    provider: str
    """Who runs the consent screen. Only "google" exists today."""
    scopes: tuple[str, ...]
    """Scopes requested in addition to the sign-in scopes."""
    required_scope: str
    """A token without this scope is refused and not stored."""
    summary: str
    """One line on what connecting allows."""
    disclosure: str
    """Shown right before the connect button, as Google's policy asks."""


GOOGLE_DRIVE = Connection(
    key="google_drive",
    name="Google Drive",
    provider="google",
    scopes=(DRIVE_SCOPE,),
    required_scope=DRIVE_SCOPE,
    summary="Files and folders in your Google Drive.",
    disclosure=(
        "Google will ask you to let Bot RBAC see, edit, create, and delete your Google "
        "Drive files. That is the whole Drive, so you can browse it here and approve "
        "requests. An assistant still reaches only the files and folders you allow, "
        "and every call is checked against that list."
    ),
)

CONNECTIONS: dict[str, Connection] = {c.key: c for c in (GOOGLE_DRIVE,)}


def get_connection(key: str | None) -> Connection | None:
    if not key:
        return None
    return CONNECTIONS.get(key)
