"""Readiness and the scheduled clean-up route (src/scoped_drive_mcp/ops.py)."""

import json
from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from scoped_drive_mcp import ops
from scoped_drive_mcp.server import build_app
from scoped_drive_mcp.store import MemoryStore
from tests.conftest import FakeClock, build_tree, make_settings

SECRET = "cron-secret-for-tests-0123456789"  # noqa: S105 - a test value
ROOT = Path(__file__).resolve().parents[1]


class DownStore(MemoryStore):
    """A store that stops answering reads when `down` is set."""

    down = False
    reads = 0

    def get(self, key: str) -> str | None:
        type(self).reads += 1
        if self.down:
            raise ConnectionError("postgresql://user:hunter2@db.example/prod is unreachable")
        return super().get(key)


def app_with(store=None, **settings):
    return build_app(make_settings(**settings), build_tree(), store=store or MemoryStore())


# ---- readiness ----


def test_ready_reads_the_store_and_health_does_not() -> None:
    store = DownStore()
    DownStore.reads = 0
    c = TestClient(app_with(store))
    assert c.get("/health").json() == {"status": "ok"}
    assert DownStore.reads == 0
    r = c.get("/health/ready")
    assert r.status_code == 200 and r.json() == {"status": "ok"}
    assert DownStore.reads == 1


def test_ready_is_503_when_the_store_is_down_and_says_nothing_else(caplog) -> None:
    store = DownStore()
    store.down = True
    c = TestClient(app_with(store))
    r = c.get("/health/ready")
    assert r.status_code == 503 and r.json() == {"status": "unavailable"}
    # Liveness is unaffected: the process is fine, so nothing should restart it.
    assert c.get("/health").status_code == 200
    # The driver's message (it can hold the connection URL) reaches neither body nor log.
    assert "hunter2" not in r.text and "hunter2" not in caplog.text
    assert "ConnectionError" in caplog.text


def test_ready_answer_is_reused_for_a_few_seconds() -> None:
    clock = FakeClock()
    calls: list[int] = []
    route = ops.readiness_route(lambda: calls.append(1), clock=clock)
    c = TestClient(Starlette(routes=[route]))
    for _ in range(20):
        assert c.get("/health/ready").status_code == 200
    assert len(calls) == 1
    clock.advance(ops.READY_TTL + 1)
    c.get("/health/ready")
    assert len(calls) == 2


# ---- scheduled clean-up ----


def test_sweep_route_does_not_exist_without_a_usable_secret() -> None:
    for settings in ({}, {"cron_secret": "short"}, {"cron_secret": "   "}):
        c = TestClient(app_with(**settings), follow_redirects=False)
        r = c.get("/internal/sweep", headers={"Authorization": "Bearer short"})
        # Falls through to the dashboard like any unknown path: not a clean-up run.
        assert r.status_code in (303, 404) and "status" not in r.text


@pytest.mark.parametrize(
    "header",
    [None, "", "Bearer", "Bearer wrong-secret-of-the-same-length!", SECRET, f"bearer {SECRET}"],
)
def test_sweep_needs_the_exact_bearer(header) -> None:
    ran: list[str] = []
    route = ops.sweep_route(SECRET, {"job": lambda: ran.append("x") or 1})
    c = TestClient(Starlette(routes=[route]))
    headers = {} if header is None else {"Authorization": header}
    assert c.get("/internal/sweep", headers=headers).status_code == 401
    assert (
        c.post("/internal/sweep", headers={"Authorization": f"Bearer {SECRET}"}).status_code == 405
    )
    assert ran == []


def test_sweep_runs_every_job_even_when_one_fails(caplog) -> None:
    ran: list[str] = []

    def broken() -> int:
        raise RuntimeError("blob store is away")

    jobs = {
        "first": lambda: ran.append("first") or 3,
        "broken": broken,
        "uncounted": lambda: ran.append("uncounted"),
    }
    c = TestClient(Starlette(routes=[ops.sweep_route(SECRET, jobs)]))
    with caplog.at_level("INFO"):
        r = c.get("/internal/sweep", headers={"Authorization": f"Bearer {SECRET}"})
    assert ran == ["first", "uncounted"]
    # The cron run shows as failed; the body carries no detail.
    assert r.status_code == 500 and r.json() == {"status": "failed"}
    assert "sweep:broken" in caplog.text and "'first': 3" in caplog.text


def test_app_sweep_runs_with_the_configured_secret() -> None:
    c = TestClient(app_with(cron_secret=SECRET))
    assert c.get("/internal/sweep").status_code == 401
    r = c.get("/internal/sweep", headers={"Authorization": f"Bearer {SECRET}"})
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_vercel_cron_calls_the_sweep_route() -> None:
    config = json.loads((ROOT / "vercel.json").read_text())
    assert [job["path"] for job in config["crons"]] == [ops.SWEEP_PATH]
    # Hobby projects may run a cron once a day at most.
    minute, hour, *rest = config["crons"][0]["schedule"].split()
    assert minute.isdigit() and hour.isdigit() and rest == ["*", "*", "*"]


def test_app_sweep_fails_the_run_when_held_files_cannot_be_swept() -> None:
    """The cron's held-file job is the forced sweep: not skipped because an upload swept
    recently, and a Blob store that cannot be listed is a failed run, not a quiet 200."""
    from tests.test_drop_pieces import FakeBlob

    blob = FakeBlob()
    app = build_app(
        make_settings(cron_secret=SECRET), build_tree(), store=MemoryStore(), blob_api=blob
    )
    c = TestClient(app)
    good = {"Authorization": f"Bearer {SECRET}"}
    assert c.get("/internal/sweep", headers=good).status_code == 200
    assert c.get("/internal/sweep", headers=good).status_code == 200
    assert blob.lists == 2  # both runs listed the store; neither was gated

    def away(*args, **kwargs):
        raise RuntimeError("blob store is away")

    blob.list = away  # type: ignore[method-assign]
    r = c.get("/internal/sweep", headers=good)
    assert r.status_code == 500 and r.json() == {"status": "failed"}
