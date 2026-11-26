"""The dashboard helpers every page module uses.

`build_dashboard` (dashboard.py) makes one `Kit` and hands it to each group of pages, so
the page modules never import dashboard.py, which imports them.
"""

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from itsdangerous import URLSafeTimedSerializer
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from ..config import Settings
from ..oauth import OAuthClient
from ..peer_requests import PeerRequestService

if TYPE_CHECKING:
    from ..dashboard import DashboardContext

Handler = Callable[[Request], Awaitable[Response]]
FormHandler = Callable[[Request, dict[str, str]], Awaitable[Response]]


@dataclass(frozen=True)
class Kit:
    """What `build_dashboard` shares with the pages (all defined in dashboard.py).

    The route wrappers (`safely`, `owner_only`, `csrf_protected`) are not here: the route
    table in `build_dashboard` applies them, so every route's checks are read in one place.
    """

    ctx: "DashboardContext"
    settings: Settings
    oauth: OAuthClient
    serializer: URLSafeTimedSerializer
    # Requests between paired people. None wherever Sharing is off.
    peer_requests: PeerRequestService | None
    # dashboard.py's logger, so log records keep its name.
    logger: logging.Logger
    session_user: Callable[[Request], str | None]
    # The same check run in a worker thread: what an async handler awaits.
    signed_in_user: Callable[[Request], Awaitable[str | None]]
    remember_pending: Callable[[Request], Awaitable[None]]
    connect_redirect: Callable[[Request], RedirectResponse]
    refused: Callable[..., Response]
    render: Callable[..., HTMLResponse]
    render_plain: Callable[..., HTMLResponse]
    flash: Callable[[Request, str, str], None]
    action_done: Callable[..., Response]
    wants_json: Callable[[Request], bool]
    blocking: Callable[..., Awaitable[Any]]
    safe_next: Callable[[str | None], str]
    # Read from dashboard.py on each call, never copied: tests replace BROWSE_PAGE_SIZE,
    # SEARCH_LOOKUPS, SHARED_SEARCH_LIMIT and refresh_access_token on that module.
    browse_page_size: Callable[[], int]
    search_lookups: Callable[[], int]
    shared_search_limit: Callable[[], int]
    refresh_access_token: Callable[..., str]
