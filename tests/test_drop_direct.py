"""Held files the browser sends to and fetches from Vercel Blob itself, with URLs that
api/blob-sign.mjs signs (drop_storage.BlobSigner). Python still decides who may do what,
and the browser seals each piece with the file's own key, so Blob holds only ciphertext."""

import base64
import http.server
import json
import secrets
import shutil
import subprocess
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from scoped_drive_mcp import drop_storage
from scoped_drive_mcp.drop_storage import (
    BLOB_AT_REST,
    ENC_CLIENT,
    SEAL_OVERHEAD,
    BlobParts,
    HttpBlobSigner,
    SignerError,
    blob_signer_from_env,
    blob_store_host,
    signer_headers,
    signer_key,
    signer_url_from_env,
)
from scoped_drive_mcp.external import acting_as
from tests.conftest import EVE, OWNER_EMAIL
from tests.dash import client, csrf, login, mcp_call
from tests.test_drop_pieces import PIECE, FakeBlob, _start
from tests.test_drops import _drop_folders, _held
from tests.test_external_sharing import _pair
from tests.test_multi_user import _app
from tests.test_peer_edit import _editor_app

ROOT = Path(__file__).resolve().parent.parent


class FakeSigner:
    """Hands out fake presigned URLs; `fail` makes every call raise."""

    store_host: str | None = None

    def __init__(self) -> None:
        self.puts: list[tuple[str, int, int, int]] = []
        self.gets: list[tuple[str, int]] = []
        self.fail = False

    def sign_put(self, pathname: str, max_bytes: int, valid_for: int, ttl_days: int) -> dict:
        if self.fail:
            raise SignerError("signer answered 401")
        self.puts.append((pathname, max_bytes, valid_for, ttl_days))
        return {
            "url": f"https://vercel.com/api/blob/?pathname={pathname}&max={max_bytes}",
            "headers": {"x-vercel-blob-access": "private"},
        }

    def sign_get(self, pathname: str, valid_for: int) -> str:
        if self.fail:
            raise SignerError("signer unreachable")
        self.gets.append((pathname, valid_for))
        return f"https://store.private.blob.vercel-storage.com/{pathname}?sig=x"


class HeadBlob(FakeBlob):
    def __init__(self) -> None:
        super().__init__()
        self.heads = 0

    def head(self, pathname: str) -> int | None:
        self.heads += 1
        data = self.blobs.get(pathname)
        return None if data is None else len(data)


def _seal(key: str, path: str, data: bytes) -> bytes:
    """What ui.js does to a piece before it uploads it."""
    nonce = secrets.token_bytes(12)
    return b"\x01" + nonce + AESGCM(base64.b64decode(key)).encrypt(nonce, data, path.encode())


def _unseal(key: str, path: str, raw: bytes) -> bytes:
    """What ui.js does to a piece it fetched from Blob."""
    assert raw[:1] == b"\x01"
    return AESGCM(base64.b64decode(key)).decrypt(raw[1:13], raw[13:], path.encode())


def _blob_put(blob: HeadBlob, signed: dict, raw: bytes) -> None:
    """What a PUT to a presigned URL does: Blob stores the bytes as sent, refusing more
    than the URL allows and anything where a blob already is."""
    query = parse_qs(urlsplit(signed["url"]).query)
    assert query["pathname"] == [signed["path"]]
    assert len(raw) <= int(query["max"][0])
    assert signed["path"] not in blob.blobs
    blob.blobs[signed["path"]] = raw


def _browser_put(blob: HeadBlob, begun: dict, n: int, data: bytes) -> None:
    signed = begun["direct"][n]
    _blob_put(blob, signed, _seal(begun["key"], signed["path"], data))


@pytest.fixture
def blob(monkeypatch) -> HeadBlob:
    monkeypatch.setattr(drop_storage, "PIECE_BYTES", PIECE)
    return HeadBlob()


@pytest.fixture
def signer() -> FakeSigner:
    return FakeSigner()


def _paired(app):
    owner, eve = client(app), client(app)
    login(owner)
    login(eve, "eve-code")
    _editor_app(eve, "Grok Eve")
    _pair(app, OWNER_EMAIL, EVE)
    return app, owner, eve


@pytest.fixture
def setup(world, memstore, oauth, blob, signer, monkeypatch):
    """A Blob store and a signer: dashboard sends go straight to Blob."""
    return _paired(_app(world, memstore, oauth, blob_api=blob, blob_signer=signer))


def _direct_upload(c, blob: HeadBlob, data: bytes, *, skip: int | None = None) -> tuple:
    token, r = _start(c, len(data))
    assert r.status_code == 200, r.text
    begun = r.json()
    assert len(begun["direct"]) == begun["pieces"]
    for n in range(begun["pieces"]):
        if n != skip:
            _browser_put(blob, begun, n, data[n * PIECE : (n + 1) * PIECE])
    done = c.post(f"/shared/send/{begun['upload_id']}/finish", data={"csrf": token})
    return begun, done


def test_begin_hands_out_one_presigned_put_per_piece(setup, blob, signer) -> None:
    app, owner, eve = setup
    data = b"0123456789abcdefghijklmnopqrstu"  # 31 bytes: 4 pieces, the last 7
    begun, done = _direct_upload(eve, blob, data)
    assert done.status_code == 200 and done.json()["ok"] is True, done.text
    # Each URL allows exactly its sealed piece's size, a short while, and Blob's own expiry.
    assert [p[1] - SEAL_OVERHEAD for p in signer.puts] == [8, 8, 8, 7]
    assert {p[2] for p in signer.puts} == {15 * 60}
    assert {p[3] for p in signer.puts} == {2}
    [row] = _held(app)
    assert row["enc"] == ENC_CLIENT and row["store"] == "blob"
    paths = [BlobParts.path(row["id"], row["exp"], n) for n in range(4)]
    assert [p[0] for p in signer.puts] == paths
    assert [d["path"] for d in begun["direct"]] == paths
    # Blob holds only ciphertext; finish checked each piece's size.
    stored = b"".join(blob.blobs[p] for p in paths)
    assert len(stored) == len(data) + 4 * SEAL_OVERHEAD
    assert all(data[i : i + 4] not in stored for i in range(0, len(data) - 4))
    assert blob.heads == 4
    # The row keeps the file's key encrypted, never as the browser got it.
    assert begun["key"] not in json.dumps(row)
    assert base64.b64decode(begun["key"]) == app.state.drops.blob.key_of(row)
    # The recipient reads it through the app too (an assistant's download_drop).
    read = mcp_call(owner, "download_drop", role="viewer", drop_id=row["id"])
    assert read["isError"] is False, read
    assert base64.b64decode(read["structuredContent"]["content_base64"]) == data[:8]


def test_a_direct_file_saves_to_drive_byte_for_byte(setup, blob, world) -> None:
    _app_, owner, eve = setup
    data = b"direct bytes, 25 of them!"
    _direct_upload(eve, blob, data)
    [row] = _held(_app_)
    saved = mcp_call(owner, "save_drop", role="editor", drop_id=row["id"])
    assert saved["isError"] is False, saved
    [folder] = _drop_folders(world)
    [copy] = [f for f in world.files.values() if f.parents == [folder]]
    assert copy.content == data
    assert blob.blobs == {}


def test_finish_refuses_when_a_piece_is_missing(setup, blob) -> None:
    app, _owner, eve = setup
    _begun, done = _direct_upload(eve, blob, b"x" * 20, skip=1)
    assert done.status_code == 400 and done.json()["error"] == "invalid_input"
    assert _held(app) == []


def test_finish_refuses_a_piece_of_the_wrong_size(setup, blob) -> None:
    app, _owner, eve = setup
    token, r = _start(eve, 20)
    begun = r.json()
    for n in range(3):
        _browser_put(blob, begun, n, b"y" * (8 if n < 2 else 3))  # the last should be 4
    done = eve.post(f"/shared/send/{begun['upload_id']}/finish", data={"csrf": token})
    assert done.json()["error"] == "invalid_input"
    assert _held(app) == []


def test_a_direct_upload_takes_no_pieces_through_the_app(setup, blob) -> None:
    _app_, _owner, eve = setup
    token, r = _start(eve, 8)
    upload = r.json()["upload_id"]
    r = eve.post(
        f"/shared/send/{upload}/piece/0", data={"csrf": token}, files={"piece": ("p", b"8bytes!!")}
    )
    assert r.status_code == 400 and r.json()["error"] == "invalid_input"
    assert blob.blobs == {}


def test_the_browser_can_ask_for_the_proxied_route_instead(setup, blob, signer) -> None:
    """ui.js starts again with direct=0 when it cannot reach Blob."""
    app, _owner, eve = setup
    token = csrf(eve, "/sharing?tab=with-me")
    r = eve.post(
        "/shared/send/start",
        data={"csrf": token, "to": OWNER_EMAIL, "name": "a.pdf", "type": "application/pdf"}
        | {"size": 8, "direct": "0"},
        headers={"Accept": "application/json"},
    )
    begun = r.json()
    assert "direct" not in begun and signer.puts == []
    base = f"/shared/send/{begun['upload_id']}"
    r = eve.post(f"{base}/piece/0", data={"csrf": token}, files={"piece": ("p", b"8bytes!!")})
    assert r.status_code == 200, r.text
    assert eve.post(f"{base}/finish", data={"csrf": token}).json()["ok"] is True
    [row] = _held(app)
    assert "enc" not in row
    # Encrypted by the app, as before.
    assert next(iter(blob.blobs.values()))[:1] == b"\x01"


def test_a_signer_error_falls_back_to_the_proxied_route(setup, blob, signer) -> None:
    app, owner, eve = setup
    signer.fail = True
    token, r = _start(eve, 16)
    begun = r.json()
    assert r.status_code == 200 and "direct" not in begun
    base = f"/shared/send/{begun['upload_id']}"
    for n in range(2):
        r = eve.post(f"{base}/piece/{n}", data={"csrf": token}, files={"piece": ("p", b"z" * 8)})
        assert r.status_code == 200, r.text
    assert eve.post(f"{base}/finish", data={"csrf": token}).json()["ok"] is True
    [row] = _held(app)
    assert "enc" not in row
    # Its pieces are encrypted, so the browser fetches them from the app.
    r = owner.get(f"/drops/{row['id']}/piece/0/url")
    assert r.json() == {"ok": True, "url": f"/drops/{row['id']}/piece/0"}


def test_after_a_signer_error_it_rests_a_few_minutes(setup, signer, monkeypatch) -> None:
    app, _owner, eve = setup
    box = app.state.drops
    now = [datetime(2026, 11, 24, 12, tzinfo=UTC)]
    monkeypatch.setattr(box, "clock", lambda: now[0])
    signer.fail = True
    assert "direct" not in _start(eve, 8)[1].json()
    signer.fail = False
    assert "direct" not in _start(eve, 8)[1].json()
    assert signer.puts == []
    now[0] += timedelta(minutes=6)
    assert "direct" in _start(eve, 8)[1].json()


def test_the_download_url_is_presigned_and_only_for_the_recipient(setup, blob, signer) -> None:
    app, owner, eve = setup
    _direct_upload(eve, blob, b"q" * 12)
    [row] = _held(app)
    r = owner.get(f"/drops/{row['id']}/piece/1/url")
    assert r.status_code == 200
    body = r.json()
    path = BlobParts.path(row["id"], row["exp"], 1)
    assert body["direct"] is True and body["url"].startswith("https://store.private.blob")
    assert body["path"] == path
    assert signer.gets == [(path, 5 * 60)]
    # With the key, the recipient's page opens what it fetches from Blob.
    assert _unseal(body["key"], path, blob.blobs[path]) == b"q" * 4
    assert r.headers["cache-control"] == "no-store"
    # Not the sender, and no piece past the end.
    assert eve.get(f"/drops/{row['id']}/piece/0/url").status_code == 400
    assert owner.get(f"/drops/{row['id']}/piece/2/url").status_code == 400
    assert owner.get("/drops/nope/piece/0/url").status_code == 400
    assert len(signer.gets) == 1
    # Signed out: no URL at all.
    assert client(app).get(f"/drops/{row['id']}/piece/0/url").status_code in {302, 303, 401, 403}


def test_a_download_url_falls_back_to_the_app_when_the_signer_fails(setup, blob, signer) -> None:
    app, owner, eve = setup
    data = b"r" * 12
    _direct_upload(eve, blob, data)
    [row] = _held(app)
    signer.fail = True
    r = owner.get(f"/drops/{row['id']}/piece/0/url")
    assert r.json() == {"ok": True, "url": f"/drops/{row['id']}/piece/0"}
    # The app's own route opens the piece the browser sealed.
    assert owner.get(f"/drops/{row['id']}/piece/0").content == data[:8]


def test_the_page_allows_blob_hosts_only_when_direct(setup, world, memstore, oauth) -> None:
    _app_, _owner, eve = setup
    r = eve.get("/sharing?tab=with-me")
    csp = r.headers["content-security-policy"]
    blob_hosts = "https://vercel.com/api/blob/ https://*.private.blob.vercel-storage.com"
    assert f"connect-src 'self' {blob_hosts};" in csp
    # With the store known, only that one store's host.
    _app_.state.drops.signer.store_host = "store.private.blob.vercel-storage.com"
    csp = eve.get("/sharing?tab=with-me").headers["content-security-policy"]
    assert "https://vercel.com/api/blob/ https://store.private.blob.vercel-storage.com;" in csp
    assert "*.private" not in csp
    # Every other page keeps the strict policy.
    assert "vercel.com" not in eve.get("/").headers.get("content-security-policy", "")


def test_without_a_signer_the_page_stays_strict(world, memstore, oauth, blob, monkeypatch) -> None:
    for name in ("BLOB_SIGNER_URL", "VERCEL_URL"):
        monkeypatch.delenv(name, raising=False)
    app = _app(world, memstore, oauth, blob_api=blob)
    c = client(app)
    login(c, "eve-code")
    assert "vercel.com" not in c.get("/sharing?tab=with-me").headers["content-security-policy"]
    assert app.state.drops.direct is False


def test_without_an_encryption_key_nothing_goes_direct(
    world, memstore, oauth, blob, signer
) -> None:
    """A file's key is kept encrypted with ENCRYPTION_KEY: without one, a signer that is
    there is never called and every piece goes through the app."""
    parts = BlobParts(blob, None)
    assert parts.can_wrap is False
    app, _owner, eve = _paired(_app(world, memstore, oauth, blob_api=blob, blob_signer=signer))
    box = app.state.drops
    assert box.direct is True
    box.blob = parts
    assert box.direct is False
    assert "vercel.com" not in eve.get("/sharing?tab=with-me").headers["content-security-policy"]
    assert "direct" not in _start(eve, 8)[1].json()
    assert signer.puts == []


def test_the_old_setting_is_gone_and_ignored(world, memstore, oauth, blob, signer, monkeypatch):
    monkeypatch.setenv("DROP_DIRECT_UPLOADS", "false")
    app = _app(world, memstore, oauth, blob_api=blob, blob_signer=signer)
    assert app.state.drops.direct is True


def test_a_piece_that_was_changed_or_moved_does_not_open(setup, blob) -> None:
    """Someone who can write to the Blob store cannot change a held file, or put one
    piece (or one file's piece) in another's place."""
    app, owner, eve = setup
    _direct_upload(eve, blob, b"A" * 8 + b"B" * 8)
    [row] = _held(app)
    first, second = (BlobParts.path(row["id"], row["exp"], n) for n in range(2))
    assert owner.get(f"/drops/{row['id']}/piece/1").content == b"B" * 8
    original = dict(blob.blobs)
    blob.blobs[second] = original[first]
    assert owner.get(f"/drops/{row['id']}/piece/1").status_code == 400
    flipped = bytearray(original[second])
    flipped[-1] ^= 1
    blob.blobs[second] = bytes(flipped)
    assert owner.get(f"/drops/{row['id']}/piece/1").status_code == 400
    # Not sealed at all, or sealed with this app's own key instead of the file's.
    blob.blobs[second] = b"B" * (8 + SEAL_OVERHEAD)
    assert owner.get(f"/drops/{row['id']}/piece/1").status_code == 400
    blob.blobs[second] = app.state.drops.blob._seal(second, b"B" * 8)
    assert owner.get(f"/drops/{row['id']}/piece/1").status_code == 400
    saved = mcp_call(owner, "save_drop", role="editor", drop_id=row["id"])
    assert saved["isError"] is True


def test_a_files_key_reaches_only_its_sender_and_its_recipient(setup, blob) -> None:
    app, owner, eve = setup
    begun, _done = _direct_upload(eve, blob, b"k" * 12)
    [row] = _held(app)
    wrapped = row["key"]
    # Not in the page, not in what an assistant sees, not in the saved record.
    page = owner.get("/sharing?tab=with-me").text
    assert wrapped not in page and begun["key"] not in page
    listed = json.dumps(mcp_call(owner, "list_drops", role="viewer"))
    assert wrapped not in listed and begun["key"] not in listed
    # The sender has no route to the piece or its key afterwards.
    assert eve.get(f"/drops/{row['id']}/piece/0/url").status_code == 400
    assert eve.get(f"/drops/{row['id']}/piece/0").status_code == 400
    # Another file's key does not open this one.
    other = _direct_upload(eve, blob, b"o" * 4)[0]
    path = BlobParts.path(row["id"], row["exp"], 0)
    with pytest.raises(InvalidTag):
        _unseal(other["key"], path, blob.blobs[path])
    assert mcp_call(owner, "save_drop", role="editor", drop_id=row["id"])["isError"] is False
    [saved] = [r for r in _held(app) if r["id"] == row["id"]]
    assert "key" not in saved


def test_a_row_whose_key_does_not_open_is_refused(setup, blob) -> None:
    """A record changed in the store cannot point a file at another key."""
    app, owner, eve = setup
    _direct_upload(eve, blob, b"z" * 8)
    [row] = _held(app)
    parts = app.state.drops.blob
    for bad in ("", "not a token", BlobParts(blob, "another-key" * 4).new_key()[1]):
        assert parts.get_piece({**row, "key": bad}, 0) is None
    assert parts.get_piece({k: v for k, v in row.items() if k != "key"}, 0) is None
    assert parts.get_piece(row, 0) == b"z" * 8


def test_only_marked_rows_are_read_raw(blob) -> None:
    """An unmarked row must still open as sealed: raw bytes there are refused. Rows an
    earlier version marked blob-at-rest are still readable until they expire."""
    parts = BlobParts(blob, "k" * 44)
    blob.blobs[BlobParts.path("a", 5, 0)] = b"\x00plain"
    blob.blobs[BlobParts.path("b", 5, 0)] = b"raw bytes"
    assert (
        parts.get_piece({"id": "b", "exp": 5, "parts": 1, "enc": BLOB_AT_REST}, 0) == b"raw bytes"
    )
    assert parts.get_piece({"id": "b", "exp": 5, "parts": 1}, 0) is None
    assert parts.get_piece({"id": "b", "exp": 5, "parts": 1, "enc": ENC_CLIENT}, 0) is None
    assert parts.get_piece({"id": "a", "exp": 5, "parts": 1}, 0) is None
    sealed = {"id": "c", "exp": 5, "parts": 1}
    parts.put_piece("c", 5, 0, b"secret")
    assert parts.get_piece(sealed, 0) == b"secret"


# ---- the HTTP client and its configuration ---------------------------------------


def test_signer_url_prefers_the_deployments_own_url(monkeypatch) -> None:
    for name in ("BLOB_SIGNER_URL", "VERCEL_URL", "VERCEL_ENV"):
        monkeypatch.delenv(name, raising=False)
    assert signer_url_from_env("https://app.example") is None  # not on Vercel
    monkeypatch.setenv("VERCEL_URL", "botrbac-git-x.vercel.app")
    monkeypatch.setenv("VERCEL_ENV", "preview")
    assert signer_url_from_env("https://app.example") == (
        "https://botrbac-git-x.vercel.app/api/blob-sign"
    )
    monkeypatch.setenv("VERCEL_ENV", "production")
    assert signer_url_from_env("https://app.example/") == "https://app.example/api/blob-sign"
    monkeypatch.setenv("BLOB_SIGNER_URL", "off")
    assert signer_url_from_env("https://app.example") is None


def test_the_http_signer_sends_an_hmac_and_the_bypass_header(monkeypatch) -> None:
    seen: dict = {}

    class Answer:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self, _n):
            return json.dumps(
                {
                    "url": "https://vercel.com/api/blob/?pathname=drops/1/a/0",
                    "headers": {"x-vercel-blob-access": "private", "set-cookie": "no"},
                }
            ).encode()

    def urlopen(request, timeout):
        seen["request"] = request
        return Answer()

    s = HttpBlobSigner(
        "https://x.vercel.app/api/blob-sign", "k" * 44, bypass="bypass!", clock=lambda: 1000
    )
    monkeypatch.setattr(s._opener, "open", urlopen)
    got = s.sign_put("drops/1/a/0", 8, 900, 2)
    assert got["headers"] == {"x-vercel-blob-access": "private"}
    req = seen["request"]
    headers = {k.lower(): v for k, v in req.header_items()}
    assert headers["x-vercel-protection-bypass"] == "bypass!"
    assert headers == {**headers, **signer_headers(signer_key("k" * 44), req.data, 1000)}
    assert json.loads(req.data) == {
        "op": "put",
        "pathname": "drops/1/a/0",
        "maxBytes": 8,
        "validForSeconds": 900,
        "ttlDays": 2,
    }


def _answering(monkeypatch, url: str) -> HttpBlobSigner:
    class Answer:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self, _n):
            return json.dumps({"url": url}).encode()

    s = HttpBlobSigner("https://x.vercel.app/api/blob-sign", "k" * 44)
    monkeypatch.setattr(s._opener, "open", lambda *_a, **_k: Answer())
    return s


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/drops/1/a/0",
        "http://s.private.blob.vercel-storage.com/drops/1/a/0",
        "https://s.private.blob.vercel-storage.com.evil.example/drops/1/a/0",
        "https://s.private.blob.vercel-storage.com@evil.example/drops/1/a/0",
        "https://s.private.blob.vercel-storage.com:8443/drops/1/a/0",
        "https://s.public.blob.vercel-storage.com/drops/1/a/0",
        # The right host, another file's piece.
        "https://s.private.blob.vercel-storage.com/drops/1/b/0",
        "https://s.private.blob.vercel-storage.com/drops/1/a/0/../../b/0",
        # An upload URL where a read was asked for.
        "https://vercel.com/api/blob/?pathname=drops/1/a/0",
        "https://[bad/drops/1/a/0",
    ],
)
def test_the_http_signer_refuses_a_read_url_that_is_not_what_it_asked_for(monkeypatch, url):
    with pytest.raises(SignerError):
        _answering(monkeypatch, url).sign_get("drops/1/a/0", 300)


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/api/blob/?pathname=drops/1/a/0",
        "https://vercel.com/api/other/?pathname=drops/1/a/0",
        "https://vercel.com/api/blob/?pathname=drops/1/b/0",
        "https://vercel.com/api/blob/?pathname=drops/1/a/0&pathname=drops/1/b/0",
        "https://vercel.com/api/blob/",
        "https://s.private.blob.vercel-storage.com/drops/1/a/0",
    ],
)
def test_the_http_signer_refuses_an_upload_url_that_is_not_what_it_asked_for(monkeypatch, url):
    with pytest.raises(SignerError):
        _answering(monkeypatch, url).sign_put("drops/1/a/0", 8, 900, 2)


def test_the_store_host_comes_from_the_connected_store(monkeypatch) -> None:
    for name in ("BLOB_STORE_ID", "BLOB_READ_WRITE_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    assert blob_store_host() is None
    monkeypatch.setenv("BLOB_READ_WRITE_TOKEN", "vercel_blob_rw_AbC123xyz_s3cretPart")
    assert blob_store_host() == "abc123xyz.private.blob.vercel-storage.com"
    # The secret part is never in it.
    assert "s3cret" not in blob_store_host().lower()
    monkeypatch.setenv("BLOB_STORE_ID", "store_OtherStore9")
    assert blob_store_host() == "otherstore9.private.blob.vercel-storage.com"
    monkeypatch.delenv("BLOB_STORE_ID")
    for odd in ("vercel_blob_rw_onlythree", "nonsense", "a_b_c_bad.host/x_secret", "a_b_c__d"):
        monkeypatch.setenv("BLOB_READ_WRITE_TOKEN", odd)
        assert blob_store_host() is None, odd


def test_without_a_store_host_there_is_no_signer(monkeypatch) -> None:
    """Browsers are let through to one store only: if it cannot be named, to none."""
    monkeypatch.setenv("BLOB_SIGNER_URL", "https://app.example/api/blob-sign")
    monkeypatch.delenv("BLOB_STORE_ID", raising=False)
    monkeypatch.setenv("BLOB_READ_WRITE_TOKEN", "an-odd-token")
    assert blob_signer_from_env("k" * 44, None) is None
    monkeypatch.setenv("BLOB_READ_WRITE_TOKEN", "vercel_blob_rw_Mine_secret")
    signer = blob_signer_from_env("k" * 44, None)
    assert signer is not None
    assert signer.store_host == "mine.private.blob.vercel-storage.com"


def test_a_read_url_for_another_store_is_refused(monkeypatch) -> None:
    mine = "https://mine.private.blob.vercel-storage.com/drops/1/a/0?sig=x"
    theirs = "https://theirs.private.blob.vercel-storage.com/drops/1/a/0?sig=x"
    s = _answering(monkeypatch, mine)
    s.store_host = "mine.private.blob.vercel-storage.com"
    assert s.sign_get("drops/1/a/0", 300) == mine
    s = _answering(monkeypatch, theirs)
    s.store_host = "mine.private.blob.vercel-storage.com"
    with pytest.raises(SignerError):
        s.sign_get("drops/1/a/0", 300)


def test_the_http_signer_takes_the_urls_it_asked_for(monkeypatch) -> None:
    read = "https://s.private.blob.vercel-storage.com/drops/1/a/0?vercel-blob-signature=x"
    assert _answering(monkeypatch, read).sign_get("drops/1/a/0", 300) == read
    put = "https://vercel.com/api/blob/?pathname=drops%2F1%2Fa%2F0&vercel-blob-signature=x"
    assert _answering(monkeypatch, put).sign_put("drops/1/a/0", 8, 900, 2)["url"] == put


def test_the_http_signer_does_not_follow_a_redirect() -> None:
    """Deployment Protection answers with a redirect to a sign-in page. Following it would
    send the request's signature and the bypass secret to another host."""
    seen: list[tuple[str, dict]] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def _answer(self) -> None:
            seen.append((self.path, {k.lower(): v for k, v in self.headers.items()}))
            if self.path == "/api/blob-sign":
                self.send_response(302)
                self.send_header("location", "/elsewhere")
            else:
                self.send_response(200)
            self.send_header("content-length", "0")
            self.end_headers()

        do_GET = do_POST = _answer  # noqa: N815 - http.server's names

        def log_message(self, *_args) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/blob-sign"
        s = HttpBlobSigner(url, "k" * 44, bypass="bypass!")
        with pytest.raises(SignerError, match="302"):
            s.sign_get("drops/1/a/0", 300)
    finally:
        server.shutdown()
        server.server_close()
    assert [path for path, _headers in seen] == ["/api/blob-sign"]


def test_a_python_signature_verifies_in_the_node_function() -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    body = json.dumps({"op": "get", "pathname": "drops/1/a/0", "validForSeconds": 300}).encode()
    headers = signer_headers(signer_key(" key-from-env \n"), body, 1_800_000_000)
    script = (
        "import { authError } from './api/blob-sign.mjs';"
        "const [h, b] = JSON.parse(process.argv[1]);"
        "const r1 = authError(new Headers(h), b, ' key-from-env \\n', 1800000030);"
        "const r2 = authError(new Headers(h), b, 'other', 1800000030);"
        "console.log(JSON.stringify([r1, r2]));"
    )
    out = subprocess.run(  # noqa: S603 - fixed args: node, this script, test data
        [node, "--input-type=module", "-e", script, json.dumps([headers, body.decode()])],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    assert json.loads(out.stdout) == [None, "unauthorized"]


def test_presigned_puts_count_against_the_budget_when_issued(setup, signer) -> None:
    app, _owner, eve = setup
    budget = app.state.drops.budget
    before = budget.usage()["month_uploads"]
    begun = _start(eve, 20)[1].json()  # 3 pieces
    assert len(begun["direct"]) == 3
    # The three URLs (and the first sweep) are counted now, once.
    assert budget.usage()["month_uploads"] - before == 4
    budget.monthly_uploads = budget.usage()["month_uploads"] + 2
    signer.puts.clear()
    r = _start(eve, 20)[1]
    assert r.json()["error"] == "storage_full"
    # Refused before any URL is signed.
    assert "direct" not in r.json() and signer.puts == []
    assert app.state.drops.ttl_days == 2


def test_a_refused_charge_releases_the_claims(setup, memstore, monkeypatch) -> None:
    """allows() passed at admit, but another send took the room before the charge."""
    app, _owner, eve = setup
    monkeypatch.setattr(app.state.drops.budget, "reserve", lambda _pieces: False)
    r = _start(eve, 20)[1]
    assert r.json()["error"] == "storage_full"
    assert [k for k in memstore._values if k.endswith(":claim")] == []


def test_claims_live_in_the_shared_store(setup, memstore) -> None:
    """So the check above looks where claims are."""
    _app_, _owner, eve = setup
    assert "direct" in _start(eve, 20)[1].json()
    assert len([k for k in memstore._values if k.endswith(":claim")]) == 3


def test_each_signed_put_is_claimed_and_finish_runs_once(setup, blob) -> None:
    app, _owner, eve = setup
    data = b"w" * 12
    token, r = _start(eve, len(data))
    begun = r.json()
    upload = begun["upload_id"]
    with acting_as(OWNER_EMAIL):
        store = app.state.drops.store
        claims = [store.get(f"drops:upload:{upload}:{n}:claim") for n in range(2)]
    assert claims == ["1", "1"]
    for n in range(2):
        _browser_put(blob, begun, n, data[n * PIECE : (n + 1) * PIECE])
    assert eve.post(f"/shared/send/{upload}/finish", data={"csrf": token}).json()["ok"] is True
    again = eve.post(f"/shared/send/{upload}/finish", data={"csrf": token})
    assert again.status_code == 400
    assert len(_held(app)) == 1
