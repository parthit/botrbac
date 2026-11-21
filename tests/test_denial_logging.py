"""Phase 3: every refused guest read is logged on the owner's activity, and new readers show."""

import json

import pytest

from scoped_drive_mcp.store import KEY_PREFIX
from tests.conftest import EVE, OWNER_EMAIL
from tests.dash import client, csrf, login, post
from tests.test_external_sharing import _error, _pair
from tests.test_multi_user import CAROL, _app, _grok, _mcp


@pytest.fixture
def setup(world, memstore, oauth):
    """The owner shares one item and is paired with Eve. Carol has an account, unpaired."""
    app = _app(world, memstore, oauth)
    owner, eve, carol = client(app), client(app), client(app)
    login(owner)
    login(eve, "eve-code")
    login(carol, "carol-code")
    eve_token = _grok(eve, "Grok Eve")
    carol_token = _grok(carol, "Grok Carol")
    _pair(app, OWNER_EMAIL, EVE)
    assert post(owner, "/sharing/add", file_id="loose-doc").status_code == 303
    return app, owner, (eve, eve_token), (carol, carol_token)


def _owner_log(memstore) -> list[dict]:
    # The owner is the admin, so their activity is on the legacy key.
    return [json.loads(r) for r in memstore.lrange(f"{KEY_PREFIX}activity", 0, -1)]


def _guest_rows(memstore, guest: str) -> list[dict]:
    return [r for r in _owner_log(memstore) if r.get("guest") == guest]


def test_someone_not_paired_is_logged_once_an_hour(setup, memstore) -> None:
    _app_, _owner, _eve, (carol, token) = setup
    for _ in range(3):
        result = _mcp(carol, token, "read_shared_file", owner=OWNER_EMAIL, file_id="loose-doc")
        assert _error(result)["error"] == "not_linked"
    rows = [r for r in _guest_rows(memstore, CAROL) if r.get("reason") == "not_linked"]
    assert len(rows) == 1
    assert rows[0]["decision"] == "deny"
    assert rows[0]["tool"] == "read_shared_file"
    assert rows[0]["token_name"] == f"guest:{CAROL}"
    # Another tool is its own line.
    _mcp(carol, token, "list_shared_folder", owner=OWNER_EMAIL)
    tools = {r["tool"] for r in _guest_rows(memstore, CAROL) if r.get("reason") == "not_linked"}
    assert tools == {"read_shared_file", "list_shared_folder"}


def test_probing_an_address_with_no_account_writes_nothing(setup, memstore) -> None:
    _app_, _owner, _eve, (carol, token) = setup
    nobody = "nobody@example.com"
    result = _mcp(carol, token, "read_shared_file", owner=nobody, file_id="loose-doc")
    assert _error(result)["error"] == "not_linked"
    assert not [k for k in memstore._values if f"u:{nobody}:" in k]  # noqa: SLF001


def test_reading_your_own_share_as_a_guest_is_logged_on_your_log(setup, memstore) -> None:
    _app_, _owner, (eve, token), _carol = setup
    result = _mcp(eve, token, "read_shared_file", owner=EVE, file_id="loose-doc")
    assert _error(result)["error"] == "own_drive"
    eve_log = [json.loads(r) for r in memstore.lrange(f"{KEY_PREFIX}u:{EVE}:activity", 0, -1)]
    assert any(r.get("reason") == "own_drive" for r in eve_log)


def test_listing_what_is_shared_with_you_is_logged_for_the_owner(setup, memstore) -> None:
    _app_, _owner, (eve, token), _carol = setup
    listed = _mcp(eve, token, "list_shared_with_me")["structuredContent"]
    assert listed["people"][0]["owner"] == OWNER_EMAIL
    rows = [r for r in _guest_rows(memstore, EVE) if r["tool"] == "list_shared_with_me"]
    assert rows and rows[0]["decision"] == "allow"


def test_a_new_reader_shows_on_overview_once(setup) -> None:
    _app_, owner, (eve, token), _carol = setup
    assert "New readers" not in owner.get("/").text
    for _ in range(2):
        _mcp(eve, token, "read_shared_file", owner=OWNER_EMAIL, file_id="loose-doc")
    page = owner.get("/").text
    assert "New readers of what you share" in page
    assert page.count(f"<b>{EVE}</b>’s assistant read something") == 1

    cleared = owner.post("/first-reads/clear", data={"csrf": csrf(owner, "/")})
    assert cleared.status_code == 303
    assert "New readers" not in owner.get("/").text
    # A later read by the same person is not news again.
    _mcp(eve, token, "read_shared_file", owner=OWNER_EMAIL, file_id="loose-doc")
    assert "New readers" not in owner.get("/").text


def test_browsing_shared_with_me_yourself_is_not_a_new_reader(setup) -> None:
    from tests.test_shared_with_me import open_item

    _app_, owner, (eve, _token), _carol = setup
    opened = open_item(eve, "loose-doc")
    assert opened.status_code == 200
    assert "memo beta" in opened.text  # the person really read it, on the dashboard
    assert "New readers" not in owner.get("/").text


def test_activity_wording_for_refusals_and_listings(setup) -> None:
    _app_, owner, (eve, eve_token), (carol, carol_token) = setup
    _mcp(carol, carol_token, "read_shared_file", owner=OWNER_EMAIL, file_id="loose-doc")
    _mcp(eve, eve_token, "list_shared_with_me")
    page = owner.get("/activity").text
    assert "they aren’t paired with you" in page
    assert "listed what you share with them" in page


def test_a_malformed_owner_is_logged_on_the_callers_own_log(setup, memstore) -> None:
    _app_, _owner, (eve, token), _carol = setup
    result = _mcp(eve, token, "read_shared_file", owner="not an email", file_id="loose-doc")
    assert _error(result)["error"] == "invalid_input"
    eve_log = [json.loads(r) for r in memstore.lrange(f"{KEY_PREFIX}u:{EVE}:activity", 0, -1)]
    row = next(r for r in eve_log if r.get("reason") == "invalid_input")
    assert row["role"] != "guest" and row["token_name"]


def test_a_failed_first_read_notice_is_tried_again() -> None:
    from scoped_drive_mcp.store import FirstReads, MemoryStore

    class Flaky(MemoryStore):
        fail = True

        def lpush(self, key: str, value: str) -> None:
            if self.fail:
                raise RuntimeError("store down")
            super().lpush(key, value)

    store = Flaky()
    reads = FirstReads(store)
    with pytest.raises(RuntimeError):
        reads.add(EVE, "read_shared_file", "f1")
    store.fail = False
    assert reads.add(EVE, "read_shared_file", "f1") is True
    assert reads.add(EVE, "read_shared_file", "f1") is False
    assert [r["guest"] for r in reads.recent()] == [EVE]
