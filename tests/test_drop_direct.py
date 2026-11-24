"""Held files the browser sends to and fetches from Vercel Blob itself, with URLs that
api/blob-sign.mjs signs (drop_storage.BlobSigner). Python still decides who may do what."""

import json
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from scoped_drive_mcp import drop_storage
from scoped_drive_mcp.drop_storage import (
    BLOB_AT_REST,
    BlobParts,
    HttpBlobSigner,
    SignerError,
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


def _browser_put(blob: HeadBlob, signed: dict, data: bytes) -> None:
    """What the browser's PUT to a presigned URL does: Blob stores the bytes as sent,
    refusing more than the URL allows."""
    query = parse_qs(urlsplit(signed["url"]).query)
    assert len(data) <= int(query["max"][0])
    blob.blobs[query["pathname"][0]] = data


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
    """Direct transfers turned on (DROP_DIRECT_UPLOADS); they are off by default."""
    monkeypatch.setenv("DROP_DIRECT_UPLOADS", "true")
    return _paired(_app(world, memstore, oauth, blob_api=blob, blob_signer=signer))


def _direct_upload(c, blob: HeadBlob, data: bytes, *, skip: int | None = None) -> tuple:
    token, r = _start(c, len(data))
    assert r.status_code == 200, r.text
    begun = r.json()
    assert len(begun["direct"]) == begun["pieces"]
    for n, signed in enumerate(begun["direct"]):
        if n != skip:
            _browser_put(blob, signed, data[n * PIECE : (n + 1) * PIECE])
    done = c.post(f"/shared/send/{begun['upload_id']}/finish", data={"csrf": token})
    return begun, done


def test_begin_hands_out_one_presigned_put_per_piece(setup, blob, signer) -> None:
    app, owner, eve = setup
    data = b"0123456789abcdefghijklmnopqrstu"  # 31 bytes: 4 pieces, the last 7
    begun, done = _direct_upload(eve, blob, data)
    assert done.status_code == 200 and done.json()["ok"] is True, done.text
    # Each URL allows exactly its piece's size, a short while, and Blob's own expiry.
    assert [p[1] for p in signer.puts] == [8, 8, 8, 7]
    assert {p[2] for p in signer.puts} == {15 * 60}
    assert {p[3] for p in signer.puts} == {2}
    [row] = _held(app)
    assert row["enc"] == BLOB_AT_REST and row["store"] == "blob"
    paths = [BlobParts.path(row["id"], row["exp"], n) for n in range(4)]
    assert [p[0] for p in signer.puts] == paths
    # The pieces are the browser's bytes as sent; finish checked each one's size.
    assert b"".join(blob.blobs[p] for p in paths) == data
    assert blob.heads == 4
    # The recipient reads it through the app too (an assistant's download_drop).
    read = mcp_call(owner, "download_drop", role="viewer", drop_id=row["id"])
    assert read["isError"] is False, read


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
    for n, signed in enumerate(begun["direct"]):
        _browser_put(blob, signed, b"y" * (8 if n < 2 else 3))  # the last should be 4
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
    assert body["direct"] is True and body["url"].startswith("https://store.private.blob")
    assert signer.gets == [(BlobParts.path(row["id"], row["exp"], 1), 5 * 60)]
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
    # The app's own route serves the raw bytes of a directly uploaded piece.
    assert owner.get(f"/drops/{row['id']}/piece/0").content == data[:8]


def test_the_page_allows_blob_hosts_only_when_direct(setup, world, memstore, oauth) -> None:
    _app_, _owner, eve = setup
    r = eve.get("/sharing?tab=with-me")
    csp = r.headers["content-security-policy"]
    assert "connect-src 'self' https://vercel.com https://*.private.blob.vercel-storage.com;" in csp
    # Every other page keeps the strict policy.
    assert "vercel.com" not in eve.get("/").headers.get("content-security-policy", "")


def test_without_a_signer_the_page_stays_strict(world, memstore, oauth, blob, monkeypatch) -> None:
    monkeypatch.setenv("DROP_DIRECT_UPLOADS", "true")
    for name in ("BLOB_SIGNER_URL", "VERCEL_URL"):
        monkeypatch.delenv(name, raising=False)
    app = _app(world, memstore, oauth, blob_api=blob)
    c = client(app)
    login(c, "eve-code")
    assert "vercel.com" not in c.get("/sharing?tab=with-me").headers["content-security-policy"]
    assert app.state.drops.direct is False


def test_direct_transfers_are_off_by_default(world, memstore, oauth, blob, signer) -> None:
    """Without DROP_DIRECT_UPLOADS a signer is never called, even one that is there: every
    piece goes through the app and is encrypted with ENCRYPTION_KEY, as before."""
    app, owner, eve = _paired(_app(world, memstore, oauth, blob_api=blob, blob_signer=signer))
    assert app.state.drops.direct is False
    page = eve.get("/sharing?tab=with-me")
    assert "vercel.com" not in page.headers["content-security-policy"]
    assert "data-drop-direct-note" not in page.text
    token, r = _start(eve, 16)
    begun = r.json()
    assert "direct" not in begun
    base = f"/shared/send/{begun['upload_id']}"
    for n in range(2):
        r = eve.post(f"{base}/piece/{n}", data={"csrf": token}, files={"piece": ("p", b"e" * 8)})
        assert r.status_code == 200, r.text
    assert eve.post(f"{base}/finish", data={"csrf": token}).json()["ok"] is True
    [row] = _held(app)
    assert "enc" not in row
    assert all(raw[:1] == b"\x01" and b"eeee" not in raw for raw in blob.blobs.values())
    r = owner.get(f"/drops/{row['id']}/piece/0/url")
    assert r.json() == {"ok": True, "url": f"/drops/{row['id']}/piece/0"}
    assert signer.puts == [] and signer.gets == []


def test_a_signer_url_alone_does_not_turn_it_on(world, memstore, oauth, blob, monkeypatch) -> None:
    monkeypatch.setenv("VERCEL_URL", "botrbac-git-x.vercel.app")
    monkeypatch.setenv("BLOB_READ_WRITE_TOKEN", "vercel_blob_rw_store_secret")
    app = _app(world, memstore, oauth, blob_api=blob)
    assert app.state.drops.signer is None


def test_the_send_form_says_how_direct_files_are_protected(setup) -> None:
    _app_, _owner, eve = setup
    page = " ".join(eve.get("/sharing?tab=with-me").text.split())
    assert "protected only by Vercel Blob's own encryption" in page


def test_only_marked_rows_are_read_raw(blob) -> None:
    """An unmarked row must still open as sealed: raw bytes there are refused."""
    parts = BlobParts(blob, "k" * 44)
    blob.blobs[BlobParts.path("a", 5, 0)] = b"\x00plain"
    blob.blobs[BlobParts.path("b", 5, 0)] = b"raw bytes"
    assert (
        parts.get_piece({"id": "b", "exp": 5, "parts": 1, "enc": BLOB_AT_REST}, 0) == b"raw bytes"
    )
    assert parts.get_piece({"id": "b", "exp": 5, "parts": 1}, 0) is None
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

    monkeypatch.setattr(drop_storage.urllib.request, "urlopen", urlopen)
    s = HttpBlobSigner(
        "https://x.vercel.app/api/blob-sign", "k" * 44, bypass="bypass!", clock=lambda: 1000
    )
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


def test_the_http_signer_refuses_urls_to_other_hosts(monkeypatch) -> None:
    class Answer:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self, _n):
            return b'{"url": "https://evil.example/drops/1/a/0"}'

    monkeypatch.setattr(drop_storage.urllib.request, "urlopen", lambda *_a, **_k: Answer())
    s = HttpBlobSigner("https://x.vercel.app/api/blob-sign", "k" * 44)
    with pytest.raises(SignerError):
        s.sign_get("drops/1/a/0", 300)


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
    for n, signed in enumerate(begun["direct"]):
        _browser_put(blob, signed, data[n * PIECE : (n + 1) * PIECE])
    assert eve.post(f"/shared/send/{upload}/finish", data={"csrf": token}).json()["ok"] is True
    again = eve.post(f"/shared/send/{upload}/finish", data={"csrf": token})
    assert again.status_code == 400
    assert len(_held(app)) == 1
