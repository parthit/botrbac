"""Bot RBAC Terminal's dashboard pages."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

Handler = Callable[[Request], Awaitable[Response]]
Render = Callable[..., Response]

# Every key this feature writes starts with this, so it never touches existing records.
KEY_PREFIX = "term:"


@dataclass
class TerminalFeature:
    def page_routes(self, owner_only: Callable[[Handler], Handler], render: Render) -> list[Route]:
        async def overview(request: Request) -> Response:
            return render(request, "terminal.html", terminals=[])

        return [Route("/terminal", owner_only(overview), methods=["GET"])]
