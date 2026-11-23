"""Regression tests for audit findings in the Drive scope checks, the store, the audit
log and the token script. Each test fails on the code before the fix."""

import datetime
import hashlib
import importlib.util
import io
import json
import re
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from tests.conftest import OWNER_EMAIL, make_settings
from tests.dash import client, connect_drive, sign_in

DRIVE_FILE = "https://www.googleapis.com/auth/drive.file"
# Scopes that reach past the files a person picked. Only full Drive was refused before.
WIDE_SCOPES = [
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/drive.metadata.readonly",
    "https://www.googleapis.com/auth/drive.metadata",
    "https://www.googleapis.com/auth/drive.photos.readonly",
    "https://www.googleapis.com/auth/drive.appdata",
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/gmail.readonly",
]
# NEW wide scopes only: full Drive was already refused by the old check.
NEWLY_REFUSED = [s for s in WIDE_SCOPES if s != "https://www.googleapis.com/auth/drive"]
IDENTITY = [
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]


# ---- 1. scopes are an allowlist: drive.file plus sign-in scopes, nothing else ----


@pytest.mark.parametrize("extra", NEWLY_REFUSED)
def test_any_scope_outside_the_allowlist_is_not_acceptable(extra) -> None:
    from scoped_drive_mcp.drive_client import scopes_acceptable

    assert not scopes_acceptable(f"{DRIVE_FILE} {extra}")
    assert not scopes_acceptable(f"openid email {DRIVE_FILE} {extra}")


def test_drive_file_with_sign_in_scopes_is_acceptable() -> None:
    from scoped_drive_mcp.drive_client import scopes_acceptable

    assert scopes_acceptable(" ".join([DRIVE_FILE, *IDENTITY]))
    assert scopes_acceptable([DRIVE_FILE, "openid"])
    assert not scopes_acceptable(" ".join(IDENTITY))
    assert not scopes_acceptable(None)


def _fake_grant(monkeypatch, granted: str, token: str = "at-new"):  # noqa: S107
    def fake_refresh_grant(request, token_uri, refresh_token, client_id, client_secret, **kw):
        expiry = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
        response = {"access_token": token, "scope": granted}
        return token, refresh_token, expiry + datetime.timedelta(hours=1), response, None

    monkeypatch.setattr("google.oauth2.reauth.refresh_grant", fake_refresh_grant)


@pytest.mark.parametrize("extra", NEWLY_REFUSED)
def test_refresh_refuses_a_token_with_an_extra_scope(monkeypatch, extra) -> None:
    """Every refresh, including the GOOGLE_OAUTH_REFRESH_TOKEN path (build_credentials)."""
    from google.auth import exceptions

    from scoped_drive_mcp.drive_client import build_credentials

    _fake_grant(monkeypatch, f"{DRIVE_FILE} {extra}")
    creds = build_credentials(make_settings())
    with pytest.raises(exceptions.RefreshError):
        creds.refresh(None)
    assert creds.token is None


class _GoogleAnswer:
    def __init__(self, status: int, body: dict) -> None:
        self.status_code = status
        self._body = body

    def json(self) -> dict:
        return self._body


@pytest.mark.parametrize("extra", NEWLY_REFUSED)
def test_picker_token_with_an_extra_scope_is_not_issued(monkeypatch, extra) -> None:
    from scoped_drive_mcp import oauth

    answer = {"access_token": "ya29-token", "scope": f"{DRIVE_FILE} {extra}"}
    monkeypatch.setattr(oauth.httpx, "post", lambda *a, **k: _GoogleAnswer(200, answer))
    with pytest.raises(oauth.OAuthError):
        oauth.refresh_access_token("id", "secret", "rt")
    # The sign-in scopes alongside drive.file are still fine.
    answer["scope"] = " ".join([DRIVE_FILE, *IDENTITY])
    assert oauth.refresh_access_token("id", "secret", "rt") == "ya29-token"


@pytest.mark.parametrize("extra", NEWLY_REFUSED)
def test_connect_refuses_and_revokes_a_token_with_an_extra_scope(
    p2_app, oauth, monkeypatch, extra
) -> None:
    c = client(p2_app)
    sign_in(c)
    real = oauth.exchange_code

    def wider(code):
        tokens = real(code)
        if not tokens.refresh_token:
            return tokens
        return replace(tokens, scopes=tokens.scopes | {extra})

    monkeypatch.setattr(oauth, "exchange_code", wider)
    r = connect_drive(c)
    assert r.status_code == 400 and "more access than Bot RBAC asks for" in r.text
    assert oauth.revoked
    assert p2_app.state.dashboard.vault.owner() is None


def test_connection_allowlist() -> None:
    from scoped_drive_mcp.connections import GOOGLE_DRIVE

    assert not GOOGLE_DRIVE.scopes_too_wide({"openid", "email", DRIVE_FILE})
    assert GOOGLE_DRIVE.scopes_too_wide({"openid", DRIVE_FILE, NEWLY_REFUSED[0]})


# ---- 2. a refreshed token is not visible on the shared credentials before its check ----


def _spy_on_token(creds) -> list:
    seen: list = []
    base = type(creds)

    class Spy(base):  # type: ignore[misc, valid-type]
        def __setattr__(self, name, value):
            if name == "token":
                seen.append(value)
            super().__setattr__(name, value)

    creds.__class__ = Spy
    return seen


def test_a_refused_token_is_never_set_on_the_shared_credentials(monkeypatch) -> None:
    from google.auth import exceptions

    from scoped_drive_mcp.drive_client import build_credentials

    _fake_grant(monkeypatch, f"{DRIVE_FILE} {NEWLY_REFUSED[0]}", token="at-wide")
    creds = build_credentials(make_settings())
    seen = _spy_on_token(creds)
    with pytest.raises(exceptions.RefreshError):
        creds.refresh(None)
    assert "at-wide" not in seen
    assert creds.token is None

    # A later refresh that passes publishes its token once, after the check.
    seen.clear()
    _fake_grant(monkeypatch, f"openid {DRIVE_FILE}", token="at-good")
    creds.refresh(None)
    assert seen == ["at-good"]
    assert creds.valid
    assert set(creds.granted_scopes) == {"openid", DRIVE_FILE}


def test_concurrent_refreshes_never_assign_a_refused_token(monkeypatch) -> None:
    """Several threads refresh the one shared credentials object at once. The spy records
    every assignment to its `token`, which is the only way another thread could ever see a
    refused token, so none may carry it."""
    from google.auth import exceptions

    from scoped_drive_mcp.drive_client import build_credentials

    def fake_refresh_grant(request, token_uri, refresh_token, client_id, client_secret, **kw):
        expiry = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
        response = {"access_token": "at-wide", "scope": f"{DRIVE_FILE} {NEWLY_REFUSED[0]}"}
        return "at-wide", refresh_token, expiry + datetime.timedelta(hours=1), response, None

    monkeypatch.setattr("google.oauth2.reauth.refresh_grant", fake_refresh_grant)
    creds = build_credentials(make_settings())
    seen = _spy_on_token(creds)
    errors: list = []

    def run() -> None:
        try:
            creds.refresh(None)
        except exceptions.RefreshError as exc:
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(errors) == 4
    assert "at-wide" not in seen
    assert creds.token is None


# ---- 3. Postgres incr keeps a fixed window ----


class _Row:
    def fetchone(self):
        return ("2",)


class _RecordingConn:
    def __init__(self) -> None:
        self.sql: list[str] = []

    def execute(self, sql, params=()):
        self.sql.append(sql)
        return _Row()


def _incr_sql() -> str:
    from scoped_drive_mcp.store import PostgresStore

    store = PostgresStore("postgresql://unused")
    conn = _RecordingConn()
    store._run = lambda fn: fn(conn)  # type: ignore[method-assign]
    assert store.incr("rl:k", 60) == 2
    (sql,) = conn.sql
    return " ".join(sql.split())


def test_postgres_incr_does_not_slide_the_window() -> None:
    """No Postgres in the test run, so this checks the statement incr sends: a hit on a
    live counter keeps its expiry (like Redis and MemoryStore), and only a new, expired
    or non-numeric row gets a fresh one."""
    sql = _incr_sql()
    assert "expires_at = EXCLUDED.expires_at" not in sql
    match = re.search(r"expires_at = \( CASE (.*?) END \)", sql)
    assert match, sql
    branches = match.group(1)
    assert "WHEN sdm_kv.value ~ '^[0-9]+$' THEN sdm_kv.expires_at" in branches
    assert "sdm_kv.expires_at <= NOW() THEN EXCLUDED.expires_at" in branches
    assert branches.rstrip().endswith("ELSE EXCLUDED.expires_at")


# ---- 4. tenant addresses cannot break the `u:{email}:` prefix ----


BAD_EMAILS = ["a:b@x.com", "a@x.com:allowlist", "a\nb@x.com", "a b@x.com", "a*@x.com"]


@pytest.mark.parametrize("email", BAD_EMAILS)
def test_actor_store_refuses_an_address_that_breaks_the_prefix(email) -> None:
    from scoped_drive_mcp.auth import current_actor
    from scoped_drive_mcp.store import ActorStore, MemoryStore

    store = ActorStore(MemoryStore(), admin_email=OWNER_EMAIL)
    reset = current_actor.set(email)
    try:
        with pytest.raises(ValueError):
            store.set("allowlist", "x")
        with pytest.raises(ValueError):
            store.hget("allowlist", "f")
    finally:
        current_actor.reset(reset)


@pytest.mark.parametrize("email", BAD_EMAILS)
def test_tenant_directory_refuses_an_address_that_breaks_the_prefix(email) -> None:
    from scoped_drive_mcp.store import MemoryStore, TenantDirectory

    directory = TenantDirectory(MemoryStore(), admin_email=OWNER_EMAIL, encryption_key=None)
    with pytest.raises(ValueError):
        directory.store_for(email)


def test_good_tenant_addresses_still_route_and_sign() -> None:
    from scoped_drive_mcp.auth import current_actor
    from scoped_drive_mcp.store import ActorStore, MemoryStore, signs, tenant_prefix

    inner = MemoryStore()
    store = ActorStore(inner, admin_email=OWNER_EMAIL)
    reset = current_actor.set("first.last+tag@example.co.uk")
    try:
        store.set("k", "v")
    finally:
        current_actor.reset(reset)
    assert inner.get("u:first.last+tag@example.co.uk:k") == "v"
    assert signs(tenant_prefix("eve@example.com") + "allowlist")


@pytest.mark.parametrize("email", ["a:b@x.com", "a\x00b@x.com", "a\x7f@x.com", "a@x.com:"])
def test_settings_refuse_addresses_with_delimiters(email) -> None:
    with pytest.raises(ValueError):
        make_settings(owner_email=email)
    with pytest.raises(ValueError):
        make_settings(allowed_emails=f"ok@example.com,{email}")


# ---- 5. audit fields are capped ----


def _last_line(capsys) -> dict:
    lines = [line for line in capsys.readouterr().out.splitlines() if line.strip()]
    return json.loads(lines[-1])


def test_auth_failure_path_is_capped(capsys) -> None:
    from scoped_drive_mcp.audit import audit_auth_failure

    audit_auth_failure("bad_token", "/mcp/" + "x" * 10_000)
    record = _last_line(capsys)
    assert len(record["path"]) <= 200
    assert record["path"].startswith("/mcp/")


def test_owner_fields_are_capped(capsys) -> None:
    from scoped_drive_mcp.audit import audit_owner

    audit_owner("grant", file_id="f" * 10_000, label="n" * 10_000, count=3)
    record = _last_line(capsys)
    assert len(record["file_id"]) <= 200
    assert len(record["label"]) <= 200
    assert record["count"] == 3


# ---- 6. make_token.py --hash-only reads the token from stdin, not argv ----


def _make_token_module():
    path = Path(__file__).resolve().parent.parent / "scripts" / "make_token.py"
    spec = importlib.util.spec_from_file_location("make_token_under_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_hash_only_reads_the_token_from_stdin(monkeypatch, capsys) -> None:
    module = _make_token_module()
    monkeypatch.setattr("sys.argv", ["make_token.py", "--hash-only"])
    monkeypatch.setattr("sys.stdin", io.StringIO("my-secret-token\n"))
    module.main()
    out = capsys.readouterr().out.strip()
    assert out == hashlib.sha256(b"my-secret-token").hexdigest()


def test_hash_only_refuses_a_token_on_the_command_line(monkeypatch, capsys) -> None:
    module = _make_token_module()
    monkeypatch.setattr("sys.argv", ["make_token.py", "--hash-only", "my-secret-token"])
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    with pytest.raises(SystemExit) as exc:
        module.main()
    assert exc.value.code != 0
    assert hashlib.sha256(b"my-secret-token").hexdigest() not in capsys.readouterr().out


@pytest.mark.parametrize(
    "email", ["a:b@example.com", "a*@example.com", "a@ex[1].com", "a\x01@x.com"]
)
def test_shared_owner_address_refuses_tenant_delimiters(email) -> None:
    from scoped_drive_mcp.external import SharedAccessError, normalize_email

    with pytest.raises(SharedAccessError):
        normalize_email(email)
    assert normalize_email("Pat+x@Mail.Example.com") == "pat+x@mail.example.com"
