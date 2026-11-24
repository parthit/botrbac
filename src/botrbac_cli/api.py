"""The website's /api/terminal endpoints, with token refresh."""

import contextlib
import time
from collections.abc import Iterator
from typing import Any

import httpx

from . import __version__, state

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
TIMEOUT = 10.0


class NotLoggedIn(Exception):
    pass


class ApiError(Exception):
    def __init__(self, status: int, code: str):
        super().__init__(f"{status} {code}")
        self.status = status
        self.code = code


class Api:
    """`client` is injectable so tests can talk to the app in-process."""

    def __init__(self, server: str | None = None, client: httpx.Client | None = None):
        creds = state.read_json("credentials.json", {}) or {}
        self.server = (server or creds.get("server") or "").rstrip("/")
        self.client = client or httpx.Client(timeout=TIMEOUT)

    # ---- login -------------------------------------------------------------------

    def start_login(self, hostname: str, os_name: str) -> dict[str, Any]:
        r = self.client.post(
            f"{self.server}/api/terminal/device",
            json={"hostname": hostname, "os": os_name, "version": __version__},
        )
        if r.status_code != 200:
            raise ApiError(r.status_code, _code(r))
        return r.json()

    def poll_login(self, device_code: str) -> dict[str, Any] | str:
        """Tokens, or the RFC 8628 error code to act on."""
        r = self.client.post(
            f"{self.server}/api/terminal/token",
            data={"grant_type": DEVICE_GRANT, "device_code": device_code},
        )
        if r.status_code == 200:
            self._save(r.json())
            return r.json()
        return _code(r)

    def _save(self, issued: dict[str, Any]) -> None:
        state.write_json(
            "credentials.json",
            {
                "server": self.server,
                "access_token": issued["access_token"],
                "refresh_token": issued["refresh_token"],
                "expires_at": time.time() + int(issued.get("expires_in") or 3600) - 60,
                "terminal_id": issued.get("terminal_id"),
            },
            private=True,
        )

    # ---- authenticated calls -----------------------------------------------------

    def _token(self, force_refresh: bool = False) -> str:
        creds = _creds()
        if not creds.get("refresh_token"):
            raise NotLoggedIn("Not logged in. Run: botrbac login")
        if not force_refresh and time.time() < float(creds.get("expires_at") or 0):
            return str(creds["access_token"])
        # Several gateways (one per agent) share these credentials, and each refresh
        # token works once. Refresh one at a time, and use what another process got.
        with _refresh_lock():
            latest = _creds()
            if latest.get("refresh_token") != creds.get("refresh_token") and time.time() < float(
                latest.get("expires_at") or 0
            ):
                return str(latest["access_token"])
            r = self.client.post(
                f"{self.server}/api/terminal/token",
                data={"grant_type": "refresh_token", "refresh_token": latest["refresh_token"]},
            )
            if r.status_code != 200:
                if _code(r) == "invalid_grant":
                    again = _creds()
                    if again.get("refresh_token") != latest.get("refresh_token"):
                        return str(again["access_token"])
                    raise NotLoggedIn(
                        "This terminal was disconnected on the website. Run: botrbac login"
                    )
                raise ApiError(r.status_code, _code(r))
            self._save(r.json())
            return str(r.json()["access_token"])

    def _call(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        for attempt in (0, 1):
            headers = {"Authorization": f"Bearer {self._token(force_refresh=attempt == 1)}"}
            r = self.client.request(method, f"{self.server}{path}", headers=headers, **kwargs)
            if r.status_code == 401 and attempt == 0:
                continue
            if r.status_code != 200:
                raise ApiError(r.status_code, _code(r))
            return r.json()
        raise ApiError(401, "invalid_token")

    def policy(self) -> dict[str, Any]:
        return self._call("GET", "/api/terminal/policy")

    def send_audit(self, body: dict[str, Any]) -> dict[str, Any]:
        return self._call("POST", "/api/terminal/audit", json=body)


def _creds() -> dict[str, Any]:
    return state.read_json("credentials.json", {}) or {}


@contextlib.contextmanager
def _refresh_lock() -> Iterator[None]:
    """An exclusive lock across processes (POSIX); without fcntl, no lock."""
    with open(state.home() / ".refresh.lock", "a") as handle:
        try:
            import fcntl
        except ImportError:  # Windows
            yield
            return
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def _code(r: httpx.Response) -> str:
    try:
        return str(r.json().get("error") or r.status_code)
    except ValueError:
        return str(r.status_code)
