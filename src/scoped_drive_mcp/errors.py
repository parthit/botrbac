"""A single place for unexpected errors.

`report_exception` logs the traceback. Assign `sink` to a callable
`(exc, where) -> None` if you later add an error tracker. Nothing here phones
home, and no paid service is wired up.
"""

import logging
from collections.abc import Callable

logger = logging.getLogger(__name__)

sink: Callable[[BaseException, str], None] | None = None


def report_exception(exc: BaseException, *, where: str) -> None:
    logger.exception("unhandled error in %s", where)
    hook = sink
    if hook is None:
        return
    try:
        hook(exc, where)
    except Exception:
        logger.warning("error sink failed in %s", where)
