"""Shared setup for the Terminal tests."""

from scoped_drive_mcp.server import build_app
from tests.conftest import OWNER_EMAIL, make_settings


def terminal_app(world, memstore, oauth, **overrides):
    settings = make_settings(root_folder_id=None, allowlist_cache_ttl=0, **overrides)
    return build_app(
        settings,
        world.as_user(OWNER_EMAIL),
        store=memstore,
        owner_drive_factory=lambda token: world.as_user(OWNER_EMAIL),
        oauth=oauth,
    )


DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


def connect_terminal(c, role_id: str = "read-only", name: str = "laptop") -> dict:
    """Run the whole device flow as the signed-in person. Returns the token response."""
    from tests import dash

    started = c.post("/api/terminal/device", json={"hostname": "laptop", "os": "Linux"}).json()
    page = c.get("/device", params={"code": started["user_code"]})
    assert page.status_code == 200, page.text
    token = dash.csrf(c, f"/device?code={started['user_code']}")
    r = c.post(
        "/device/approve",
        data={"csrf": token, "code": started["user_code"], "role_id": role_id, "name": name},
    )
    assert r.status_code == 303, r.text
    issued = c.post(
        "/api/terminal/token",
        data={"grant_type": DEVICE_GRANT, "device_code": started["device_code"]},
    )
    assert issued.status_code == 200, issued.text
    return issued.json()
