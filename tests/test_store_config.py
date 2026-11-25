"""Settings, the key-value stores above the primitives (prefixing, tenants, the token vault,
the allowlist, the activity log, the Redis-to-Postgres copy), the Google scope allowlist
and the small scripts that make secrets and tokens.

Store primitives themselves are checked against every backend in test_store_backends.py."""

import datetime
import hashlib
import importlib.util
import io
import json
import re
import secrets
import threading
from dataclasses import replace
from pathlib import Path

import pytest
from pydantic import ValidationError

from scoped_drive_mcp.config import Settings
from scoped_drive_mcp.drive_client import DRIVE_FILE_SCOPE as DRIVE_FILE
from scoped_drive_mcp.drive_client import BotNotConnectedError, LazyBotDriveClient
from scoped_drive_mcp.store import (
    REDIS_IMPORT_FLAG,
    REDIS_IMPORT_LOCK,
    ActivityLog,
    ActorStore,
    AllowEntry,
    Allowlist,
    MemoryStore,
    PrefixedStore,
    RedisStore,
    StoreImportError,
    TenantDirectory,
    TokenVault,
    build_store,
    import_admin_keys,
    signs,
    tenant_prefix,
)
from tests.conftest import API_TOKENS, ENCRYPTION_KEY, OWNER_EMAIL, FakeClock, make_settings
from tests.dash import client, connect_drive, sign_in
from tests.test_multi_user import as_actor

KV_TOKEN = secrets.token_urlsafe(16)
UP_TOKEN = secrets.token_urlsafe(16)
VAULT_TOKEN = secrets.token_urlsafe(16)
PG_URL = "postgresql://user:secret-token@localhost/db"

# ---- settings ----


def test_redis_env_names(monkeypatch) -> None:
    monkeypatch.setenv("API_TOKENS", API_TOKENS)
    monkeypatch.setenv("KV_REST_API_URL", "https://kv.example.upstash.io")
    monkeypatch.setenv("KV_REST_API_TOKEN", KV_TOKEN)
    s = Settings()
    assert s.redis_rest_url == "https://kv.example.upstash.io" and s.redis_configured
    monkeypatch.setenv("UPSTASH_REDIS_REST_URL", "https://up.example.upstash.io")
    monkeypatch.setenv("UPSTASH_REDIS_REST_TOKEN", UP_TOKEN)
    s = Settings()
    assert s.redis_rest_url == "https://up.example.upstash.io"  # Upstash names win
    assert s.redis_rest_token.get_secret_value() == UP_TOKEN
    assert UP_TOKEN not in repr(s)


def test_phase2_env(monkeypatch) -> None:
    monkeypatch.setenv("API_TOKENS", API_TOKENS)
    monkeypatch.setenv("OWNER_EMAIL", " Owner@Example.com ")
    monkeypatch.setenv("BOT_EMAIL", "bot@example.com")
    monkeypatch.setenv("APP_BASE_URL", "https://scoped-drive-mcp.vercel.app/")
    monkeypatch.setenv("ROOT_FOLDER_ID", "")
    s = Settings()
    assert s.owner_email == "owner@example.com"
    assert s.app_base_url == "https://scoped-drive-mcp.vercel.app"
    assert s.root_folder_id is None
    assert s.missing_settings() == [
        "GOOGLE_OAUTH_CLIENT_ID",
        "GOOGLE_OAUTH_CLIENT_SECRET",
        "SESSION_SECRET",
        "ENCRYPTION_KEY",
        "UPSTASH_REDIS_REST_URL",
        "UPSTASH_REDIS_REST_TOKEN",
        "GOOGLE_PICKER_API_KEY",
        "GOOGLE_CLOUD_PROJECT_NUMBER",
    ]
    # The picker is listed, but its absence does not take the dashboard down.
    assert "GOOGLE_PICKER_API_KEY" not in s.dashboard_missing()


# Addresses with a tenant-key delimiter (`u:{email}:`) or a control character.
DELIMITER_EMAILS = ["a:b@x.com", "a\x00b@x.com", "a\x7f@x.com", "a@x.com:"]


@pytest.mark.parametrize(
    "overrides",
    [
        {"encryption_key": "not-a-fernet-key"},
        {"session_secret": "short"},
        {"owner_email": "not-an-email"},
        {"allowed_emails": "not-an-email"},
        {"app_base_url": "http://scoped.example.com"},
        {"app_base_url": "ftp://x"},
        {"redis_rest_url": "http://insecure.example.com"},
        {"allowlist_cache_ttl": 60},
        *({"owner_email": e} for e in DELIMITER_EMAILS),
        *({"allowed_emails": f"ok@example.com,{e}"} for e in DELIMITER_EMAILS),
    ],
)
def test_invalid_phase2_settings(overrides) -> None:
    with pytest.raises(ValidationError):
        make_settings(**overrides)


def test_allowed_emails_blank_is_open(monkeypatch) -> None:
    monkeypatch.setenv("API_TOKENS", API_TOKENS)
    monkeypatch.setenv("OWNER_EMAIL", "owner@example.com")
    monkeypatch.setenv("ALLOWED_EMAILS", " Eve@Example.com , ")
    listed = Settings()
    assert listed.allowed_emails == frozenset({"eve@example.com"})
    assert listed.sign_in_allowed("eve@example.com")
    assert listed.sign_in_allowed("owner@example.com")
    assert not listed.sign_in_allowed("other@example.com")
    monkeypatch.setenv("ALLOWED_EMAILS", "  ")
    assert Settings().sign_in_allowed("other@example.com")


def test_localhost_base_url_allowed_and_cookies() -> None:
    s = make_settings(app_base_url="http://localhost:8000")
    assert s.app_base_url == "http://localhost:8000" and s.secure_cookies is False
    assert make_settings().secure_cookies is True


def test_make_secrets_script(capsys) -> None:
    import runpy

    runpy.run_path("scripts/make_secrets.py", run_name="__main__")
    out = capsys.readouterr().out
    lines = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    assert len(lines["SESSION_SECRET"]) >= 32
    make_settings(session_secret=lines["SESSION_SECRET"], encryption_key=lines["ENCRYPTION_KEY"])


# ---- make_token.py --hash-only reads the token from stdin, never argv (audit fix) ----


def _run_make_token(monkeypatch, argv: list[str], stdin: str) -> None:
    path = Path(__file__).resolve().parent.parent / "scripts" / "make_token.py"
    spec = importlib.util.spec_from_file_location("make_token_under_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr("sys.argv", ["make_token.py", *argv])
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    module.main()


def test_make_token_hash_only_reads_stdin_and_refuses_argv(monkeypatch, capsys) -> None:
    digest = hashlib.sha256(b"my-secret-token").hexdigest()
    _run_make_token(monkeypatch, ["--hash-only"], "my-secret-token\n")
    assert capsys.readouterr().out.strip() == digest
    # A token on the command line would land in shell history and `ps`.
    with pytest.raises(SystemExit) as exc:
        _run_make_token(monkeypatch, ["--hash-only", "my-secret-token"], "")
    assert exc.value.code != 0
    assert digest not in capsys.readouterr().out


# ---- picking a backend ----


def test_build_store_picks_backend() -> None:
    assert build_store(make_settings()).kind == "memory"
    s = make_settings(redis_rest_url="https://x.upstash.io", redis_rest_token="tok")
    store = build_store(s)
    assert store.kind == "redis" and isinstance(store.inner, RedisStore)

    settings = make_settings(database_url=PG_URL)
    assert settings.postgres_configured
    assert "secret-token" not in repr(settings)
    store = build_store(settings)
    assert store.kind == "postgres"
    assert "secret-token" not in repr(store)
    assert settings.missing_settings() == ["GOOGLE_PICKER_API_KEY", "GOOGLE_CLOUD_PROJECT_NUMBER"]


def test_redis_store_calls(monkeypatch) -> None:
    calls = []

    class FakeRedis:
        def __init__(self, **kwargs):
            calls.append(("init", kwargs))

        def __getattr__(self, name):
            def call(*args, **kwargs):
                calls.append((name, args, kwargs))
                return {"hgetall": {"a": "1"}, "lrange": ["x"], "get": "v"}.get(name)

            return call

    import upstash_redis

    monkeypatch.setattr(upstash_redis, "Redis", FakeRedis)
    r = RedisStore("https://x.upstash.io", "tok")
    assert calls[0][1]["allow_telemetry"] is False
    r.set("k", "v", ex=10)
    assert r.get("k") == "v"
    assert r.hgetall("h") == {"a": "1"} and r.lrange("l", 0, -1) == ["x"]
    assert ("set", ("k", "v"), {"ex": 10}) in calls


# ---- Postgres incr keeps a fixed window (audit fix) ----


def test_postgres_incr_does_not_slide_the_window() -> None:
    """Checks the statement incr sends (the backend contract test runs it for real): a hit
    on a live counter keeps its expiry, like Redis and MemoryStore, and only a new, expired
    or non-numeric row gets a fresh one."""
    from scoped_drive_mcp.store import PostgresStore

    sent: list[str] = []

    class Conn:
        def execute(self, sql, params=()):
            sent.append(sql)
            return type("Row", (), {"fetchone": lambda self: ("2",)})()

    store = PostgresStore("postgresql://unused")
    store._run = lambda fn: fn(Conn())  # type: ignore[method-assign]
    assert store.incr("rl:k", 60) == 2
    sql = " ".join(sent[0].split())
    assert "expires_at = EXCLUDED.expires_at" not in sql
    match = re.search(r"expires_at = \( CASE (.*?) END \)", sql)
    assert match, sql
    branches = match.group(1)
    assert "WHEN sdm_kv.value ~ '^[0-9]+$' THEN sdm_kv.expires_at" in branches
    assert "sdm_kv.expires_at <= NOW() THEN EXCLUDED.expires_at" in branches
    assert branches.rstrip().endswith("ELSE EXCLUDED.expires_at")


# ---- layers above the primitives ----


def test_prefixed_store_namespaces_keys() -> None:
    inner = MemoryStore()
    p = PrefixedStore(inner)
    p.set("a", "1")
    assert inner.get("sdm:a") == "1" and inner.get("a") is None


def test_actor_store_keeps_admin_keys_and_prefixes_others() -> None:
    inner = MemoryStore()
    actor = ActorStore(PrefixedStore(inner), OWNER_EMAIL)
    with as_actor(OWNER_EMAIL):
        actor.set("allowlist", "admin")
    with as_actor("eve@example.com"):
        actor.set("allowlist", "eve")
    with as_actor("first.last+tag@example.co.uk"):
        actor.set("k", "v")
    assert inner.get("sdm:allowlist") == "admin"
    assert inner.get("sdm:u:eve@example.com:allowlist") == "eve"
    assert inner.get("sdm:u:first.last+tag@example.co.uk:k") == "v"
    with as_actor(None):
        assert actor.get("allowlist") == "admin"
    assert signs(tenant_prefix("eve@example.com") + "allowlist")


@pytest.mark.parametrize(
    "email", ["a:b@x.com", "a@x.com:allowlist", "a\nb@x.com", "a b@x.com", "a*@x.com"]
)
def test_tenant_keys_refuse_an_address_that_breaks_the_prefix(email) -> None:
    """Audit fix: an address like `a@x.com:allowlist` must not reach another key."""
    store = ActorStore(MemoryStore(), admin_email=OWNER_EMAIL)
    with as_actor(email):
        with pytest.raises(ValueError):
            store.set("allowlist", "x")
        with pytest.raises(ValueError):
            store.hget("allowlist", "f")
    directory = TenantDirectory(MemoryStore(), admin_email=OWNER_EMAIL, encryption_key=None)
    with pytest.raises(ValueError):
        directory.store_for(email)


@pytest.mark.parametrize(
    "email", ["a:b@example.com", "a*@example.com", "a@ex[1].com", "a\x01@x.com"]
)
def test_shared_owner_address_refuses_tenant_delimiters(email) -> None:
    from scoped_drive_mcp.external import SharedAccessError, normalize_email

    with pytest.raises(SharedAccessError):
        normalize_email(email)
    assert normalize_email("Pat+x@Mail.Example.com") == "pat+x@mail.example.com"


def test_token_vault_encrypts() -> None:
    kv = PrefixedStore(MemoryStore())
    vault = TokenVault(kv, ENCRYPTION_KEY)
    vault.set_owner(VAULT_TOKEN, "owner@example.com", "openid email " + DRIVE_FILE)
    raw = kv.get("vault:owner_refresh_token")
    assert raw and VAULT_TOKEN not in raw and "owner@example.com" not in raw
    assert vault.owner()["t"] == VAULT_TOKEN
    from cryptography.fernet import Fernet

    other = TokenVault(kv, Fernet.generate_key().decode())
    assert other.owner() is None  # wrong key cannot read it
    assert TokenVault(kv, None).owner() is None
    vault.clear_owner()
    assert vault.owner() is None


def test_allowlist_roundtrip_and_corrupt_entries() -> None:
    kv = PrefixedStore(MemoryStore())
    allow = Allowlist(kv)
    allow.add(AllowEntry("f1", "File", "text/plain", "perm-1"))
    kv.hset("allowlist", "bad", "{not json")
    assert set(allow.entries()) == {"f1"}
    assert allow.mime_map() == {"f1": "text/plain"}


def test_activity_log_newest_first() -> None:
    log = ActivityLog(PrefixedStore(MemoryStore()), max_items=3)
    for i in range(5):
        log({"n": i})
    assert [r["n"] for r in log.recent()] == [4, 3, 2]


def test_lazy_bot_client_prefers_env_then_store() -> None:
    built = []

    def factory(token):
        built.append(token)
        return object()

    stored = {"t": None}
    clock = FakeClock()
    lazy = LazyBotDriveClient(None, lambda: stored["t"], factory, ttl=30, clock=clock)
    with pytest.raises(BotNotConnectedError):
        lazy._inner()
    stored["t"] = "from-store"
    with pytest.raises(BotNotConnectedError):
        lazy._inner()  # cached "not connected" for up to ttl
    lazy.invalidate()
    lazy._inner()
    lazy._inner()
    assert built == ["from-store"]
    stored["t"] = "rotated"
    clock.advance(31)
    lazy._inner()
    assert built == ["from-store", "rotated"]

    env = LazyBotDriveClient("from-env", lambda: "from-store", factory)
    env._inner()
    assert built[-1] == "from-env"


# ---- copying the admin keys from Redis to Postgres ----


def _admin_source(*index: str) -> MemoryStore:
    source = MemoryStore()
    source.lpush("sdm:activity", "older")
    source.lpush("sdm:activity", "newer")
    for rid in index:
        source.lpush("sdm:requests:index", rid)
    return source


def test_import_admin_keys_runs_once() -> None:
    source = _admin_source("rid")
    dest = MemoryStore()
    source.hset("sdm:allowlist", "file-1", "{}")
    source.set("sdm:vault:owner_refresh_token", "enc-owner")
    source.set("sdm:vault:bot_refresh_token", "enc-bot")
    source.set("sdm:req:rid", '{"file_id":"file-1"}')
    source.set("sdm:req:pending:file-1", "rid")
    import_admin_keys(source, dest)
    import_admin_keys(source, dest)
    assert dest.hget("sdm:allowlist", "file-1") == "{}"
    assert dest.get("sdm:vault:owner_refresh_token") == "enc-owner"
    assert dest.get("sdm:vault:bot_refresh_token") == "enc-bot"
    assert dest.lrange("sdm:activity", 0, -1) == ["newer", "older"]
    assert dest.lrange("sdm:requests:index", 0, -1) == ["rid"]
    assert dest.get("sdm:req:rid") == '{"file_id":"file-1"}'
    assert dest.get("sdm:req:pending:file-1") == "rid"
    assert dest.get(REDIS_IMPORT_FLAG)


def test_import_failure_does_not_mark_done(monkeypatch) -> None:
    import scoped_drive_mcp.store as store_mod

    source = _admin_source("rid")
    dest = MemoryStore()
    source.hset("sdm:allowlist", "file-1", "{}")
    calls = {"n": 0}
    real_copy = store_mod._copy_list

    def flaky(src: MemoryStore, dst: MemoryStore, key: str) -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError(PG_URL)
        real_copy(src, dst, key)

    monkeypatch.setattr(store_mod, "_copy_list", flaky)
    with pytest.raises(RuntimeError, match="secret-token"):
        import_admin_keys(source, dest)
    assert dest.get(REDIS_IMPORT_FLAG) is None
    assert dest.get(REDIS_IMPORT_LOCK) is None
    import_admin_keys(source, dest)
    assert dest.hget("sdm:allowlist", "file-1") == "{}"
    assert dest.lrange("sdm:activity", 0, -1) == ["newer", "older"]
    assert dest.lrange("sdm:requests:index", 0, -1) == ["rid"]
    assert dest.get(REDIS_IMPORT_FLAG)
    assert dest.get(REDIS_IMPORT_LOCK) is None


def test_concurrent_import_has_one_winner(monkeypatch) -> None:
    import scoped_drive_mcp.store as store_mod

    source = _admin_source("rid-a", "rid-b")
    dest = MemoryStore()
    entered = threading.Event()
    release = threading.Event()
    real_copy = store_mod._copy_list

    def slow(src: MemoryStore, dst: MemoryStore, key: str) -> None:
        if key.endswith("activity"):
            entered.set()
            assert release.wait(2)
        real_copy(src, dst, key)

    monkeypatch.setattr(store_mod, "_copy_list", slow)
    winner = threading.Thread(target=import_admin_keys, args=(source, dest))
    winner.start()
    assert entered.wait(2)
    with pytest.raises(StoreImportError, match="^admin store copy is already running$"):
        import_admin_keys(source, dest)
    release.set()
    winner.join(2)
    assert not winner.is_alive()
    assert dest.lrange("sdm:activity", 0, -1) == ["newer", "older"]
    assert dest.lrange("sdm:requests:index", 0, -1) == ["rid-b", "rid-a"]
    assert dest.get(REDIS_IMPORT_FLAG)
    assert dest.get(REDIS_IMPORT_LOCK) is None
    import_admin_keys(source, dest)
    assert dest.lrange("sdm:activity", 0, -1) == ["newer", "older"]


def test_build_store_does_not_serve_postgres_when_import_fails(monkeypatch) -> None:
    import scoped_drive_mcp.store as store_mod

    created: dict[str, MemoryStore] = {}

    class Boom(MemoryStore):
        kind = "postgres"

        def __init__(self, url: str):
            super().__init__()
            self.url = url
            created["store"] = self

        def get(self, key: str) -> str | None:
            raise RuntimeError(f"could not connect to {self.url}")

    monkeypatch.setattr(store_mod, "PostgresStore", Boom)
    monkeypatch.setattr(store_mod, "RedisStore", lambda url, token: MemoryStore())
    settings = make_settings(
        database_url=PG_URL, redis_rest_url="https://x.upstash.io", redis_rest_token="tok"
    )
    with pytest.raises(StoreImportError) as caught:
        build_store(settings)
    assert "secret-token" not in str(caught.value)
    assert "postgresql" not in str(caught.value)
    assert REDIS_IMPORT_FLAG not in created["store"]._values


# ---- Google scopes are an allowlist: drive.file plus sign-in scopes (audit fix) ----
# Only full Drive was refused before; every other wide scope below slipped through.

NEWLY_REFUSED = [
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/drive.metadata.readonly",
    "https://www.googleapis.com/auth/drive.metadata",
    "https://www.googleapis.com/auth/drive.photos.readonly",
    "https://www.googleapis.com/auth/drive.appdata",
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/gmail.readonly",
]
IDENTITY = [
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]


def test_scope_allowlist() -> None:
    from scoped_drive_mcp.connections import GOOGLE_DRIVE
    from scoped_drive_mcp.drive_client import scopes_acceptable

    assert scopes_acceptable(" ".join([DRIVE_FILE, *IDENTITY]))
    assert scopes_acceptable([DRIVE_FILE, "openid"])
    assert not scopes_acceptable(" ".join(IDENTITY))
    assert not scopes_acceptable(None)
    assert not GOOGLE_DRIVE.scopes_too_wide({"openid", "email", DRIVE_FILE})
    for extra in NEWLY_REFUSED:
        assert not scopes_acceptable(f"{DRIVE_FILE} {extra}"), extra
        assert not scopes_acceptable(f"openid email {DRIVE_FILE} {extra}"), extra
        assert GOOGLE_DRIVE.scopes_too_wide({"openid", DRIVE_FILE, extra}), extra


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


def test_picker_token_with_an_extra_scope_is_not_issued(monkeypatch) -> None:
    from scoped_drive_mcp import oauth

    answer: dict = {"access_token": "ya29-token"}
    response = type("Answer", (), {"status_code": 200, "json": lambda self: answer})()
    monkeypatch.setattr(oauth.httpx, "post", lambda *a, **k: response)
    for extra in NEWLY_REFUSED:
        answer["scope"] = f"{DRIVE_FILE} {extra}"
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


# ---- a refreshed token is not visible on the shared credentials before its check ----


def _spy_on_token(creds) -> list:
    """Record every assignment to creds.token: the only way another thread could see it."""
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
    errors: list = []

    def run() -> None:
        try:
            creds.refresh(None)
        except exceptions.RefreshError as exc:
            errors.append(exc)

    # Several threads refresh the one shared credentials object at once.
    threads = [threading.Thread(target=run) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(errors) == 4
    assert "at-wide" not in seen
    assert creds.token is None

    # A later refresh that passes publishes its token once, after the check.
    seen.clear()
    _fake_grant(monkeypatch, f"openid {DRIVE_FILE}", token="at-good")
    creds.refresh(None)
    assert seen == ["at-good"]
    assert creds.valid
    assert set(creds.granted_scopes) == {"openid", DRIVE_FILE}


# ---- audit log fields are capped ----


def test_audit_fields_are_capped(capsys) -> None:
    from scoped_drive_mcp.audit import audit_auth_failure, audit_owner

    audit_auth_failure("bad_token", "/mcp/" + "x" * 10_000)
    audit_owner("grant", file_id="f" * 10_000, label="n" * 10_000, count=3)
    auth, owner = (json.loads(line) for line in capsys.readouterr().out.splitlines()[-2:])
    assert len(auth["path"]) <= 200 and auth["path"].startswith("/mcp/")
    assert len(owner["file_id"]) <= 200
    assert len(owner["label"]) <= 200
    assert owner["count"] == 3
