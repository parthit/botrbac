"""Who sees the Terminal beta, and its dashboard pages."""

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
    """`everyone` is TERMINAL_ENABLED; `allowed` checks the Edge Config beta list."""

    everyone: bool
    allowed: Callable[[str], bool]

    def enabled_for(self, email: str | None) -> bool:
        if not email:
            return False
        if self.everyone:
            return True
        try:
            return bool(self.allowed(email))
        except Exception:  # noqa: BLE001 - a flag read failing means off
            return False

    def page_routes(
        self,
        owner_only: Callable[[Handler], Handler],
        render: Render,
        current_email: Callable[[Request], str | None],
    ) -> list[Route]:
        """Dashboard pages. People outside the beta get the ordinary 404 page."""

        def gated(handler: Handler) -> Handler:
            async def wrapped(request: Request) -> Response:
                if not self.enabled_for(current_email(request)):
                    return render(request, "error.html", 404, message="Page not found.")
                return await handler(request)

            return wrapped

        async def overview(request: Request) -> Response:
            return render(request, "terminal.html", terminals=[])

        return [Route("/terminal", owner_only(gated(overview)), methods=["GET"])]
