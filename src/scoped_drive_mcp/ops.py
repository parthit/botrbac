"""Operational endpoints: readiness and scheduled housekeeping.

* `GET /health/ready` says whether this instance can reach its store. `/health` stays a
  pure liveness check (the process answers), so a store outage does not make a platform
  restart instances that are fine.
* `GET /internal/sweep` runs the clean-up jobs. A Vercel cron calls it once a day
  (`crons` in vercel.json) with `Authorization: Bearer $CRON_SECRET`. Every job also
  runs opportunistically inside ordinary requests; the cron is what makes clean-up
  happen on a deployment nobody happens to be writing to.

Neither endpoint says anything about configuration, counts or errors in its body: those
go to the log.
"""

import hmac
import logging
import threading
import time
from collections.abc import Callable, Mapping

import anyio.to_thread
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from .errors import report_exception

logger = logging.getLogger(__name__)

READY_PATH = "/health/ready"
SWEEP_PATH = "/internal/sweep"
# The readiness answer is reused for this long, so the public route cannot be used to
# make this instance send the store a request per call.
READY_TTL = 5.0
# Vercel recommends at least 16 characters; a shorter one is treated as not set.
MIN_CRON_SECRET = 16

SweepJob = Callable[[], int | None]


def readiness_route(
    ping: Callable[[], object], *, clock: Callable[[], float] = time.monotonic
) -> Route:
    """`ping` makes one cheap store read and raises if the store cannot be reached."""
    lock = threading.Lock()
    state: dict[str, float | bool] = {"at": float("-inf"), "ok": False}

    def check() -> bool:
        with lock:
            if clock() - float(state["at"]) < READY_TTL:
                return bool(state["ok"])
            try:
                ping()
                ok = True
            except Exception as exc:  # noqa: BLE001 - any failure means "not ready"
                # The driver's message can carry the connection URL: the type is enough.
                logger.warning("readiness check failed (%s)", type(exc).__name__)
                ok = False
            state["at"], state["ok"] = clock(), ok
            return ok

    async def ready(_: Request) -> JSONResponse:
        if await anyio.to_thread.run_sync(check):
            return JSONResponse({"status": "ok"})
        return JSONResponse({"status": "unavailable"}, status_code=503)

    return Route(READY_PATH, ready, methods=["GET"])


def usable_cron_secret(secret: str | None) -> str | None:
    secret = (secret or "").strip()
    return secret if len(secret) >= MIN_CRON_SECRET else None


def run_sweep(jobs: Mapping[str, SweepJob]) -> tuple[dict[str, int | None], list[str]]:
    """Run every job. One failing is reported and does not stop the others. Returns what
    each job removed (None when it does not count) and the names of the ones that failed."""
    done: dict[str, int | None] = {}
    failed: list[str] = []
    for name, job in jobs.items():
        try:
            done[name] = job()
        except Exception as exc:  # noqa: BLE001 - reported; the next job still runs
            report_exception(exc, where=f"sweep:{name}")
            failed.append(name)
    return done, failed


def sweep_route(secret: str, jobs: Mapping[str, SweepJob]) -> Route:
    expected = f"Bearer {secret}".encode()

    async def sweep(request: Request) -> JSONResponse:
        sent = (request.headers.get("authorization") or "").encode()
        if not hmac.compare_digest(sent, expected):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        done, failed = await anyio.to_thread.run_sync(run_sweep, jobs)
        logger.info("sweep finished: removed=%s failed=%s", done, failed)
        # A failed run shows as a failed cron invocation; the body still says nothing more.
        if failed:
            return JSONResponse({"status": "failed"}, status_code=500)
        return JSONResponse({"status": "ok"})

    return Route(SWEEP_PATH, sweep, methods=["GET"])
