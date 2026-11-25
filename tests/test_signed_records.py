"""What someone who can read or write the store (but holds no key and no session) cannot do.

Records that decide access are signed (store.SignedStore) and bound to their key, a
pairing approval names the account and the kind of pairing it was given to, and parked
OAuth codes are sealed. Each test here was a working exploit in the security audit."""

import hashlib
import json

import pytest
from pydantic import ValidationError

from scoped_drive_mcp import mcp_oauth
from scoped_drive_mcp.drive_client import DRIVE_FILE_SCOPE as DRIVE_FILE
from scoped_drive_mcp.mcp_oauth import GRANTS_KEY, McpOAuth
from scoped_drive_mcp.server import build_app
from scoped_drive_mcp.store import (
    KEY_PREFIX,
    MemoryStore,
    SignedStore,
    TokenVault,
    sign_existing_records,
    signing_key,
)
from tests.conftest import BASE_URL, ENCRYPTION_KEY, EVE, OWNER_EMAIL, before_signing, make_settings
from tests.dash import MCP_HEADERS, client, csrf, login, post
from tests.test_mcp_oauth import GROK, auth_params, register
from tests.test_multi_user import CAROL, _accounts, _extend, _mcp
from tests.test_peer_edit import _editor_app


def _signed(require: bool = False) -> tuple[MemoryStore, SignedStore]:
    raw = MemoryStore()
    return raw, SignedStore(raw, signing_key(ENCRYPTION_KEY), require=require)


def _stored(memstore, key: str) -> str:
    return memstore.get(f"{KEY_PREFIX}{key}")


def _build(world, memstore, oauth, require: bool = True):
    """A multi-user app on `memstore`; `require` is REQUIRE_SIGNED_RECORDS."""
    _accounts(oauth)
    if CAROL not in world.roots:
        _extend(world)

    def drive_for(token: str):
        return world.as_user(token.removeprefix("rt-"))

    return build_app(
        make_settings(
            root_folder_id=None,
            google_oauth_refresh_token=None,
            allowlist_cache_ttl=0,
            require_signed_records=require,
        ),
        store=memstore,
        owner_drive_factory=drive_for,
        oauth=oauth,
        bot_drive_factory=drive_for,
    )


@pytest.fixture
def strict(world, memstore, oauth):
    app = _build(world, memstore, oauth)
    owner, eve = client(app), client(app)
    assert login(owner).status_code == 303
    assert login(eve, "eve-code").status_code == 303
    return app, owner, eve


def _pending_pairing(box, joiner: str = EVE) -> str:
    link = box.request_link(OWNER_EMAIL)
    box.request_link(joiner, link["invite_code"])
    return link["link_id"]


# ---- the signing layer ----


def test_signed_records_are_required_by_default_and_need_a_key() -> None:
    assert make_settings().require_signed_records is True
    # Without ENCRYPTION_KEY nothing is signed, so the default must not refuse to start...
    assert make_settings(encryption_key=None).encryption_key is None
    # ...but asking for signed records explicitly without a key is a configuration error.
    with pytest.raises(ValidationError, match="REQUIRE_SIGNED_RECORDS"):
        make_settings(encryption_key=None, require_signed_records=True)


def test_a_signed_record_cannot_be_changed_or_moved() -> None:
    raw, store = _signed()
    store.hset("allowlist", "f1", '{"id":"f1"}')
    store.set("oauth:at:abc", "grant-1", ex=60)
    store.set("activity_note", "plain")
    assert raw.hget("allowlist", "f1").startswith("s1.")
    assert raw.get("activity_note") == "plain"  # not a record that decides access
    assert store.hget("allowlist", "f1") == '{"id":"f1"}'
    assert store.hgetall("allowlist") == {"f1": '{"id":"f1"}'}
    assert store.get("oauth:at:abc") == "grant-1"

    # Changed in place.
    raw.hset("allowlist", "f1", raw.hget("allowlist", "f1").replace("f1", "f2"))
    assert store.hget("allowlist", "f1") is None and store.hgetall("allowlist") == {}
    # A real record copied to another field, another key, or another person's keys.
    store.hset("allowlist", "f1", '{"id":"f1"}')
    sealed = raw.hget("allowlist", "f1")
    raw.hset("allowlist", "other-file", sealed)
    raw.hset("ext_allowlist", "f1", sealed)
    raw.hset(f"u:{EVE}:allowlist", "f1", sealed)
    assert store.hgetall("allowlist") == {"f1": '{"id":"f1"}'}
    assert store.hgetall("ext_allowlist") == {}
    assert store.hgetall(f"u:{EVE}:allowlist") == {}
    raw.set("oauth:at:other", raw.get("oauth:at:abc"))
    assert store.get("oauth:at:other") is None
    assert store.refused >= 4


def test_a_refused_record_is_not_consumed() -> None:
    raw, strict_store = _signed(require=True)
    raw.set("oauth:rt:tok", "unsigned refresh token", ex=600)
    assert strict_store.getdel("oauth:rt:tok") is None
    assert raw.get("oauth:rt:tok") == "unsigned refresh token"
    strict_store.set("oauth:rt:good", "payload", ex=600)
    assert strict_store.getdel("oauth:rt:good") == "payload"
    assert raw.get("oauth:rt:good") is None


def test_a_drive_sign_in_moved_to_another_account_is_refused() -> None:
    kv = MemoryStore()
    TokenVault(kv, ENCRYPTION_KEY).set_owner("rt-owner", OWNER_EMAIL, DRIVE_FILE)
    assert TokenVault(kv, ENCRYPTION_KEY, expected=lambda: OWNER_EMAIL).owner()["t"] == "rt-owner"
    assert TokenVault(kv, ENCRYPTION_KEY, expected=lambda: EVE).owner() is None


def test_a_store_writer_cannot_add_an_app_and_an_allowlist_entry(world, memstore, oauth) -> None:
    """With write access to the store and nothing else, make up an app connection and an
    allowlist entry, then read a file nobody allowed."""
    app = _build(world, memstore, oauth)
    victim = client(app)
    assert login(victim).status_code == 303

    bearer = "store-writer-chosen-value"
    digest = hashlib.sha256(bearer.encode()).hexdigest()
    grant = {
        "id": "forged0001grant",
        "client_id": "x",
        "client_name": "x",
        "email": OWNER_EMAIL,
        "created_at": "",
        "access_hashes": [digest],
        "roles": True,
    }
    memstore.hset(KEY_PREFIX + "oauth:grants", grant["id"], json.dumps(grant))
    memstore.set(KEY_PREFIX + "oauth:role:" + grant["id"], "admin")
    memstore.set(
        KEY_PREFIX + "oauth:at:" + digest,
        json.dumps({"grant_id": grant["id"], "client_id": "x", "email": OWNER_EMAIL}),
    )
    folder = {
        "id": "owner-root",
        "name": "x",
        "mime_type": "application/vnd.google-apps.folder",
        "permission_id": None,
    }
    memstore.hset(KEY_PREFIX + "allowlist", "owner-root", json.dumps(folder))

    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"file_id": "priv-secret"}},
    }
    headers = {**MCP_HEADERS, "Authorization": f"Bearer {bearer}"}
    assert client(app).post("/mcp", json=body, headers=headers).status_code == 401
    # The person's own, real connection still works, and does not see the made-up folder.
    assert post(victim, "/grant", file_id="shared-doc").status_code in (303, 200)
    assert "owner-root" not in app.state.dashboard.allowlist.entries()


# ---- signing records saved before signing existed (the /admin action) ----


def test_older_records_are_signed_by_the_admin_action_not_by_reading_them() -> None:
    raw, store = _signed()
    raw.hset("allowlist", "old", '{"id":"old"}')
    grant = {"id": "g1", "access_hashes": ["aaa"], "refresh_hash": "rrr"}
    raw.hset("oauth:grants", "g1", json.dumps(grant))
    raw.set("oauth:role:g1", "editor")
    raw.set("oauth:at:aaa", "access", ex=60)
    raw.set("oauth:rt:rrr", "refresh", ex=600)
    raw.hset(f"bridge:user:{EVE}", "link1", "2026-01-01")
    raw.set("bridge:link:link1", '{"link_id":"link1","invite_code":"CODE"}')
    raw.set("bridge:invite:CODE", "link1", ex=600)
    raw.set("bridge:peer:link1", "s1.smith@example.com", ex=600)

    # Reading accepts them and leaves the store alone.
    assert store.hget("allowlist", "old") == '{"id":"old"}'
    assert store.get("bridge:peer:link1") == "s1.smith@example.com"  # not taken for signed
    assert raw.hget("allowlist", "old") == '{"id":"old"}'

    assert sign_existing_records(store, [EVE], OWNER_EMAIL) == (9, 0)
    assert sign_existing_records(store, [EVE], OWNER_EMAIL) == (0, 0)
    assert raw.get("oauth:at:aaa").startswith("s1.") and raw.get("oauth:rt:rrr").startswith("s1.")
    # A token keeps the time it had left.
    assert raw._values["oauth:at:aaa"][0] is not None

    _, strict_store = _signed(require=True)
    strict_store.inner = raw
    assert strict_store.hget("allowlist", "old") == '{"id":"old"}'
    assert strict_store.get("oauth:at:aaa") == "access"
    assert strict_store.get("bridge:peer:link1") == "s1.smith@example.com"
    raw.hset("allowlist", "forged", '{"id":"forged"}')
    assert "forged" not in strict_store.hgetall("allowlist")


def test_signing_a_record_does_not_undo_a_change_made_at_the_same_moment() -> None:
    """Signing is a compare-and-swap. A record removed or changed between the read and
    the write stays removed or changed, and is reported as not signed."""
    raw, store = _signed()
    raw.hset("allowlist", "f1", '{"id":"f1"}')
    raw.set("oauth:role:g1", "admin")
    read_hash, read_string = raw.hget, raw.get

    def hget_then_removed(key, field):
        value = read_hash(key, field)
        raw.hdel(key, field)  # the owner's "remove" lands here
        return value

    def get_then_lowered(key):
        value = read_string(key)
        if key == "oauth:role:g1":
            raw.set(key, "viewer")  # the owner's "read only" lands here
        return value

    raw.hget, raw.get = hget_then_removed, get_then_lowered
    assert store.sign_in_place("allowlist", "f1") == "failed"
    assert store.sign_in_place("oauth:role:g1") == "failed"
    raw.hget, raw.get = read_hash, read_string
    assert raw.hgetall("allowlist") == {}
    assert raw.get("oauth:role:g1") == "viewer"
    raw.hset("oauth:grants", "g1", '{"id":"g1"}')
    assert sign_existing_records(store, [], OWNER_EMAIL) == (2, 0)


@before_signing
def test_the_admin_can_sign_older_records_from_the_people_page(p2_app, memstore) -> None:
    c = client(p2_app)
    login(c)
    memstore.hset(KEY_PREFIX + "allowlist", "old-one", '{"id":"old-one","name":"n"}')
    page = c.get("/admin").text
    assert "Sign existing records" in page
    assert c.post("/admin/sign-records", data={"csrf": csrf(c)}).status_code == 303
    assert memstore.hget(KEY_PREFIX + "allowlist", "old-one").startswith("s1.")
    # A page that read the allowlist on the way may have signed it already.
    after = c.get("/admin").text
    assert "Signed 1 stored record." in after or "already signed" in after
    assert "Sign existing records" in after


def test_a_fresh_deployment_has_nothing_to_sign(p2_app) -> None:
    """Signing is required out of the box, so /admin offers no signing of older records."""
    c = client(p2_app)
    login(c)
    page = c.get("/admin").text
    assert "Sign existing records" not in page
    assert "an unsigned one is ignored (the default)" in page


def test_nothing_is_signed_once_unsigned_records_are_ignored(strict, memstore) -> None:
    app, owner, _eve = strict
    planted = '{"id":"priv-secret","name":"x","mime_type":"text/plain","permission_id":null}'
    memstore.hset(f"{KEY_PREFIX}allowlist", "priv-secret", planted)
    assert post(owner, "/admin/sign-records").status_code == 303
    assert memstore.hget(f"{KEY_PREFIX}allowlist", "priv-secret") == planted
    assert "priv-secret" not in app.state.dashboard.allowlist.entries()


# ---- pairings: deleting or swapping a record never adds access ----


def test_replacing_who_joined_a_pairing_does_not_inherit_its_approvals(strict, memstore) -> None:
    """The owner paired with Carol and both approved. Someone who can write to the store
    deletes the record of who joined and joins with the invite code themselves."""
    app, owner, eve = strict
    eve_token = _editor_app(eve, "Grok Eve")
    box = app.state.mailbox
    link = box.request_link(OWNER_EMAIL)
    box.request_link(CAROL, link["invite_code"])
    box.decide(OWNER_EMAIL, link["link_id"], "approve")
    box.decide(CAROL, link["link_id"], "approve")
    assert box.active_peers(OWNER_EMAIL) == [CAROL]
    assert post(owner, "/sharing/add", file_id="loose-doc").status_code == 303

    memstore.delete(f"{KEY_PREFIX}bridge:peer:{link['link_id']}")
    joined = _mcp(eve, eve_token, "request_link", invite_code=link["invite_code"])
    assert joined["isError"] is False, joined
    assert joined["structuredContent"]["status"] == "pending_approval"
    assert box.active_peers(OWNER_EMAIL) == []
    got = _mcp(eve, eve_token, "read_shared_file", owner=OWNER_EMAIL, file_id="loose-doc")
    assert got["isError"] is True


def test_a_pairing_that_was_turned_off_stays_off_without_its_marker(strict, memstore) -> None:
    box = strict[0].state.mailbox
    lid = _pending_pairing(box)
    box.decide(OWNER_EMAIL, lid, "approve")
    box.decide(EVE, lid, "approve")
    assert box.active_peers(OWNER_EMAIL) == [EVE]
    box.revoke(OWNER_EMAIL, lid)
    memstore.delete(f"{KEY_PREFIX}bridge:revoked:{lid}")
    assert box.active_peers(OWNER_EMAIL) == []
    assert box.list_links(OWNER_EMAIL)["links"][0]["status"] in ("revoked", "declined")


def test_a_pairing_turned_off_before_signing_stays_off_after_it(world, memstore, oauth) -> None:
    """Turned off by the code from before: only a marker says so, and both approvals are
    still there. The admin action must make that permanent, not sign the approvals."""
    loose = _build(world, memstore, oauth, require=False)
    owner = client(loose)
    assert login(owner).status_code == 303
    box = loose.state.mailbox
    lid = _pending_pairing(box)
    for side in ("a", "b"):
        box.store.hset(f"bridge:appr:{lid}", side, "2026-11-01T00:00:00+00:00")
    assert box.active_peers(OWNER_EMAIL) == [EVE]
    at = "2026-11-02T00:00:00+00:00"
    ended = json.dumps({"by": OWNER_EMAIL, "at": at, "how": "turned_off"})
    box.store.set(f"bridge:ended:{lid}", ended)
    box.store.set(f"bridge:revoked:{lid}", at)

    assert post(owner, "/admin/sign-records").status_code == 303
    assert box.store.hgetall(f"bridge:appr:{lid}") == {}
    assert json.loads(box.store.get(f"bridge:link:{lid}"))["ended_at"] == at

    strict_box = _build(world, memstore, oauth).state.mailbox
    memstore.delete(f"{KEY_PREFIX}bridge:revoked:{lid}")
    memstore.delete(f"{KEY_PREFIX}bridge:ended:{lid}")
    assert strict_box.active_peers(OWNER_EMAIL) == []


def test_an_approval_from_before_they_named_the_person_needs_binding_first(strict) -> None:
    box = strict[0].state.mailbox
    lid = _pending_pairing(box)
    for side in ("a", "b"):  # what an approval looked like before: a time and nothing else
        box.store.hset(f"bridge:appr:{lid}", side, "2026-01-01T00:00:00+00:00")
    assert box.active_peers(OWNER_EMAIL) == []
    box.strict = False
    assert box.active_peers(OWNER_EMAIL) == [EVE]
    assert box.bind_legacy_approvals([OWNER_EMAIL]) == 2
    box.strict = True
    assert box.active_peers(OWNER_EMAIL) == [EVE]


def test_an_approval_is_for_the_account_the_page_showed(strict, memstore) -> None:
    """Carol is waiting on the owner's page. Before the owner clicks, the record of who
    joined is replaced and Eve joins. The click must not approve Eve."""
    app, owner, _eve = strict
    box = app.state.mailbox
    link = box.request_link(OWNER_EMAIL)
    lid = link["link_id"]
    box.request_link(CAROL, link["invite_code"])
    page = owner.get("/sharing?tab=people").text
    assert f'name="peer" value="{CAROL}"' in page
    memstore.delete(f"{KEY_PREFIX}bridge:peer:{lid}")
    box.request_link(EVE, link["invite_code"])

    assert post(owner, f"/bridge/{lid}/approve", peer=CAROL).status_code == 303
    assert box.store.hgetall(f"bridge:appr:{lid}") == {}
    # A post that does not say who it is approving is refused too.
    assert post(owner, f"/bridge/{lid}/approve").status_code == 303
    assert box.store.hgetall(f"bridge:appr:{lid}") == {}
    assert post(owner, f"/bridge/{lid}/approve", peer=EVE).status_code == 303
    assert list(box.store.hgetall(f"bridge:appr:{lid}")) == ["a"]


def test_an_approval_is_stored_for_the_account_it_was_checked_against(strict) -> None:
    """Who joined is read once. If the record changes while the click is being handled,
    the approval names the account that was checked, so it does not count for the new one."""
    box = strict[0].state.mailbox
    lid = _pending_pairing(box, CAROL)
    real_peer, real_approval = box._peer, box._approval
    changed = []

    def approval_while_the_record_changes(*args):
        changed.append(True)  # from here on, the store says Eve is the one joined
        return real_approval(*args)

    box._peer = lambda link_id: EVE if changed else real_peer(link_id)
    box._approval = approval_while_the_record_changes
    try:
        box.decide(OWNER_EMAIL, lid, "approve", CAROL)
    finally:
        box._peer, box._approval = real_peer, real_approval
    assert changed
    assert box.store.hget(f"bridge:appr:{lid}", "a").split("|")[1] == CAROL


def test_a_pairing_of_your_own_assistants_cannot_become_one_with_someone_else(
    strict, memstore
) -> None:
    """The owner pairs two of their own assistants. Someone who can write to the store
    swaps the link record between its two earlier forms, replaces who joined, and joins
    as themselves. Neither their own Approve click nor the owner's may turn that into an
    active pairing with them."""
    app, owner, eve = strict
    box = app.state.mailbox
    grok = _editor_app(owner, "Grok One")
    claude = _editor_app(owner, "Claude Two")
    eve_token = _editor_app(eve, "Grok Eve")
    assert post(owner, "/sharing/add", file_id="loose-doc").status_code == 303

    made = _mcp(owner, grok, "request_link")["structuredContent"]
    lid, code = made["link_id"], made["invite_code"]
    two_people_form = _stored(memstore, f"bridge:link:{lid}")
    assert _mcp(owner, claude, "request_link", invite_code=code)["isError"] is False
    own_assistants_form = _stored(memstore, f"bridge:link:{lid}")
    assert '"same_account": true' in own_assistants_form

    memstore.set(f"{KEY_PREFIX}bridge:link:{lid}", two_people_form)
    memstore.delete(f"{KEY_PREFIX}bridge:peer:{lid}")
    assert _mcp(eve, eve_token, "request_link", invite_code=code)["isError"] is False
    memstore.set(f"{KEY_PREFIX}bridge:link:{lid}", own_assistants_form)

    # Eve's click, then the owner's click on a card that says "two of your own assistants".
    assert post(eve, f"/bridge/{lid}/approve").status_code == 303
    assert post(owner, f"/bridge/{lid}/approve").status_code == 303
    assert box.store.hgetall(f"bridge:appr:{lid}") == {}
    for form in (own_assistants_form, two_people_form):
        memstore.set(f"{KEY_PREFIX}bridge:link:{lid}", form)
        assert box.active_peers(OWNER_EMAIL) == []
        got = _mcp(eve, eve_token, "read_shared_file", owner=OWNER_EMAIL, file_id="loose-doc")
        assert got["isError"] is True


def test_an_approval_counts_only_for_the_kind_of_pairing_it_was_given_to(strict) -> None:
    box = strict[0].state.mailbox
    lid = _pending_pairing(box)
    record = box._link(lid)
    # Approvals that name Eve but were given to a pairing of one person's own assistants.
    for side in ("a", "b"):
        box.store.hset(f"bridge:appr:{lid}", side, f"2026-11-22T00:00:00+00:00|{EVE}|self")
    assert box._status(record) == "pending_approval"
    # The real thing still works, and says which kind it is for.
    box.decide(OWNER_EMAIL, lid, "approve", EVE)
    box.decide(EVE, lid, "approve", OWNER_EMAIL)
    assert box.store.hget(f"bridge:appr:{lid}", "a").endswith(f"|{EVE}|pair")
    assert box.active_peers(OWNER_EMAIL) == [EVE]


def test_approvals_stored_before_the_kind_was_added_keep_working(strict) -> None:
    """What the previous release wrote: a time and the account, no kind."""
    app, owner, _eve = strict
    box = app.state.mailbox
    # Two people.
    lid = _pending_pairing(box)
    for side in ("a", "b"):
        box.store.hset(f"bridge:appr:{lid}", side, f"2026-11-22T00:00:00+00:00|{EVE}")
    assert box.active_peers(OWNER_EMAIL) == [EVE]
    # One person's own two assistants: the account named is the creator's own.
    grok = _editor_app(owner, "Grok One")
    claude = _editor_app(owner, "Claude Two")
    made = _mcp(owner, grok, "request_link")["structuredContent"]
    own = made["link_id"]
    assert _mcp(owner, claude, "request_link", invite_code=made["invite_code"])["isError"] is False
    for side in ("a", "b"):
        box.store.hset(f"bridge:appr:{own}", side, f"2026-11-22T00:00:00+00:00|{OWNER_EMAIL}")
    assert box._status(box._link(own)) == "active"
    # Neither counts for the other kind of pairing.
    for side in ("a", "b"):
        box.store.hset(f"bridge:appr:{own}", side, f"2026-11-22T00:00:00+00:00|{EVE}")
        box.store.hset(f"bridge:appr:{lid}", side, f"2026-11-22T00:00:00+00:00|{OWNER_EMAIL}")
    assert box._status(box._link(own)) == "pending_approval"
    assert box.active_peers(OWNER_EMAIL) == []


# ---- connected apps: roles and access tokens ----


def _make_legacy_app(app, owner, memstore) -> tuple:
    """Connect an app, then make it look like one from before apps had roles: no flag on
    the grant and no role record."""
    token = _editor_app(owner, "Old app")
    oauth_server = app.state.dashboard.mcp_oauth
    grant_id = oauth_server.list_grants(OWNER_EMAIL)[0].id
    grant = json.loads(oauth_server.store.hget(GRANTS_KEY, grant_id))
    grant.pop("roles")
    oauth_server.store.hset(GRANTS_KEY, grant_id, json.dumps(grant))
    memstore.delete(f"{KEY_PREFIX}oauth:role:{grant_id}")
    return oauth_server, grant_id, token


def test_deleting_an_older_apps_role_records_does_not_make_it_full(strict, memstore) -> None:
    app, owner, _eve = strict
    oauth_server, grant_id, token = _make_legacy_app(app, owner, memstore)
    oauth_server.strict = False
    assert oauth_server.resolve_access(token).role.value == "admin"  # as it always was
    assert oauth_server.pin_legacy_roles() == (1, 0)  # the admin action writes that down
    oauth_server.strict = True
    assert oauth_server.resolve_access(token).role.value == "admin"
    memstore.delete(f"{KEY_PREFIX}oauth:role:{grant_id}")
    memstore.delete(f"{KEY_PREFIX}oauth:rolechosen:{grant_id}")
    assert oauth_server.resolve_access(token).role.value == "viewer"


def test_settings_still_says_an_older_app_is_full_only_because_it_is_old(strict, memstore) -> None:
    app, owner, _eve = strict
    oauth_server, grant_id, _token = _make_legacy_app(app, owner, memstore)
    oauth_server.strict = False
    memstore.delete(f"{KEY_PREFIX}oauth:rolechosen:{grant_id}")
    assert oauth_server.list_grants(OWNER_EMAIL)[0].legacy_full is True
    assert oauth_server.pin_legacy_roles() == (1, 0)
    assert oauth_server.list_grants(OWNER_EMAIL)[0].legacy_full is True
    assert oauth_server.set_role(grant_id, OWNER_EMAIL, "viewer") is True
    assert oauth_server.list_grants(OWNER_EMAIL)[0].legacy_full is False


def test_an_access_token_put_back_without_an_expiry_still_ends(
    strict, memstore, monkeypatch
) -> None:
    app, owner, _eve = strict
    token = _editor_app(owner, "Some app")
    key = f"{KEY_PREFIX}oauth:at:{hashlib.sha256(token.encode()).hexdigest()}"
    memstore.set(key, memstore.get(key))  # the same signed record, now with no expiry
    oauth_server = app.state.dashboard.mcp_oauth
    assert oauth_server.resolve_access(token) is not None
    later = mcp_oauth.time.time() + mcp_oauth.ACCESS_TTL + 1
    monkeypatch.setattr(mcp_oauth.time, "time", lambda: later)
    assert memstore.get(key) is not None
    assert oauth_server.resolve_access(token) is None


# ---- the code parked between Allow and the redirect ----


def test_the_code_parked_between_allow_and_the_redirect_cannot_be_read_from_the_store(
    strict, memstore
) -> None:
    _app_, owner, eve = strict
    client_id = register(eve, GROK, name="Some app").json()["client_id"]
    _verifier, params = auth_params(client_id, GROK)
    assert owner.get("/oauth/authorize", params=params).status_code == 200
    allowed = post(owner, "/oauth/authorize", decision="allow")
    assert allowed.status_code == 303 and "/oauth/continue" in allowed.headers["location"]
    parked = [
        value
        for key, (_expires, value) in memstore._values.items()
        if key.startswith(f"{KEY_PREFIX}oauth:bounce:")
    ]
    assert len(parked) == 1
    assert "code=" not in parked[0] and "http" not in parked[0]
    # The person's own browser still completes the hand-off.
    done = owner.get(allowed.headers["location"], follow_redirects=False)
    assert "code=" in (done.headers.get("location") or done.text)


def test_an_encrypted_parked_redirect_needs_the_key_and_a_plain_one_is_refused_with_it() -> None:
    url = "https://claude.ai/api/mcp/auth_callback?code=abc&state=s"
    with_key = McpOAuth(MemoryStore(), BASE_URL, OWNER_EMAIL, encryption_key=ENCRYPTION_KEY)
    ticket = with_key.park_completion(url, OWNER_EMAIL)
    without_key = McpOAuth(with_key.store, BASE_URL, OWNER_EMAIL)
    assert without_key.take_completion(ticket, OWNER_EMAIL) is None
    ticket = with_key.park_completion(url, OWNER_EMAIL)
    assert with_key.take_completion(ticket, OWNER_EMAIL) == url
    plain = without_key.park_completion(url, OWNER_EMAIL)
    assert with_key.take_completion(plain, OWNER_EMAIL) is None
