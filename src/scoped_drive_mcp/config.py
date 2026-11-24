"""Settings loaded from environment variables only (no credential files on disk).

Only malformed values make the settings fail to load. Settings the
dashboard or the bot connection need are optional at load time; `missing_settings()` reports
which ones are absent so the signed-in admin overview can list them (names only, never values).
The public /health route stays a liveness check and does not repeat that list.
"""

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import AliasChoices, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_DRIVE_ID = re.compile(r"^[A-Za-z0-9_-]{10,200}$")
# Each address keys its own store (`u:{email}:`), so ':' and control, whitespace and
# Redis glob characters are refused (see store.tenant_prefix).
_EMAIL_CHAR = r"[^@:\s\x00-\x1f\x7f*?\[\]\\]"
_EMAIL = re.compile(rf"^{_EMAIL_CHAR}+@{_EMAIL_CHAR}+\.{_EMAIL_CHAR}+$")
_PROJECT_NUMBER = re.compile(r"^[0-9]{6,20}$")
_LOCAL_HOSTS = ("localhost", "127.0.0.1")


class Role(StrEnum):
    VIEWER = "viewer"
    EDITOR = "editor"
    ADMIN = "admin"


@dataclass(frozen=True)
class TokenEntry:
    name: str
    role: Role
    sha256: str


def parse_api_tokens(raw: str) -> list[TokenEntry]:
    """Parse `name:role:sha256hex,name:role:sha256hex,...`."""
    entries: list[TokenEntry] = []
    seen_names: set[str] = set()
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = chunk.split(":")
        if len(parts) != 3:
            raise ValueError("each API_TOKENS entry must look like name:role:sha256hex")
        name, role, digest = (p.strip() for p in parts)
        digest = digest.lower()
        if not _TOKEN_NAME.fullmatch(name):
            raise ValueError(f"invalid token name {name!r} (use letters, digits, _ . -)")
        if name in seen_names:
            raise ValueError(f"duplicate token name {name!r}")
        try:
            parsed_role = Role(role.lower())
        except ValueError:
            raise ValueError(
                f"invalid role {role!r} for token {name!r} (use viewer, editor or admin)"
            ) from None
        if not _SHA256_HEX.fullmatch(digest):
            raise ValueError(f"token {name!r} hash must be 64 lowercase hex characters (SHA-256)")
        seen_names.add(name)
        entries.append(TokenEntry(name=name, role=parsed_role, sha256=digest))
    if not entries:
        raise ValueError("API_TOKENS must contain at least one entry")
    return entries


def _secret_set(value: SecretStr | None) -> bool:
    return value is not None and bool(value.get_secret_value().strip())


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore", case_sensitive=False)

    # Optional since phase 2: when set it is one more allowlisted root folder.
    root_folder_id: str | None = None
    auth_mode: Literal["oauth_bot"] = "oauth_bot"

    google_oauth_client_id: SecretStr | None = None
    google_oauth_client_secret: SecretStr | None = None
    # Optional since phase 2: the bot can be connected from the dashboard instead.
    google_oauth_refresh_token: SecretStr | None = None

    # Optional legacy bearer tokens for the admin (xAI API, scripts). Assistants that
    # connect with OAuth do not need them.
    api_tokens: Annotated[list[TokenEntry], NoDecode] = Field(default_factory=list)

    owner_email: str | None = None
    bot_email: str | None = None
    # Optional. When set, only these addresses (plus OWNER_EMAIL) can sign in.
    allowed_emails: Annotated[frozenset[str], NoDecode] = frozenset()
    app_base_url: str | None = None
    session_secret: SecretStr | None = None
    encryption_key: SecretStr | None = None
    # Local testing only: also accept this server's own /oauth/done as an OAuth redirect.
    oauth_test_callback: bool = False
    # Also accept http://localhost:8787/callback and http://127.0.0.1:8787/callback as
    # OAuth redirects. No supported assistant uses them, and any program on the approver's
    # computer could be listening there, so they are off unless you run such a client.
    oauth_loopback_callback: bool = False
    # Wake-up pings to paired assistants are on whenever WEBHOOK_KEK is set.
    webhook_kek: SecretStr | None = None
    webhook_host_allowlist: str = "api2.cursor.sh,api.anthropic.com"
    # Optional: Notion as a second connection (a public OAuth "developer connection").
    # Notion is offered on Settings only when both are set.
    notion_oauth_client_id: SecretStr | None = None
    notion_oauth_client_secret: SecretStr | None = None
    # Vercel Edge Config connection string (set when an Edge Config is connected to the
    # project). Holds server-side switches such as `self_pairing`; see flags.py.
    edge_config: SecretStr | None = None

    redis_rest_url: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "redis_rest_url", "upstash_redis_rest_url", "kv_rest_api_url"
        ),
    )
    redis_rest_token: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "redis_rest_token", "upstash_redis_rest_token", "kv_rest_api_token"
        ),
    )
    # Vercel Marketplace Neon injects a pooled DATABASE_URL (or POSTGRES_URL).
    database_url: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("database_url", "postgres_url"),
    )

    max_bytes: int = Field(default=5 * 1024 * 1024, ge=1024, le=50 * 1024 * 1024)
    max_chars: int = Field(default=100_000, ge=1000, le=2_000_000)
    # How long a file a paired person sent is held for its recipient to save to their own
    # Drive. After this it is deleted here; a saved copy in their Drive stays.
    drop_hold_hours: int = Field(default=24, ge=24, le=168)
    # Largest file a person may send from the dashboard (in pieces, each under Vercel's
    # 4.5 MB request limit). An assistant's send_file keeps the MAX_BYTES limit.
    drop_max_mb: int = Field(default=20, ge=1, le=100)
    # With a Vercel Blob store connected, held files go there. These keep them inside the
    # free (Hobby) Blob tier: 2,000 uploads a month and 1 GB stored. Going over turns Blob
    # off for 30 days, so the defaults leave room. Raise them on a paid plan.
    drop_blob_monthly_uploads: int = Field(default=1500, ge=10, le=10_000_000)
    drop_blob_storage_mb: int = Field(default=800, ge=16, le=10_000_000)
    # Read PDF and Office files in a separate process with hard memory and CPU limits.
    # Turn off only where the host does not allow starting a process.
    extract_isolation: bool = True
    # Address-space limit for that process, in MB.
    extract_memory_mb: int = Field(default=768, ge=256, le=8192)
    scope_cache_ttl: float = Field(default=60.0, ge=0, le=3600)
    # How long the allowlist is cached per instance; bounds how fast a revoke takes effect.
    allowlist_cache_ttl: float = Field(default=2.0, ge=0, le=10)

    # Browser key and Cloud project number for the Google Picker. Both are public
    # in the signed-in page (restrict the key by HTTP referrer). Not required to boot.
    google_picker_api_key: str | None = None
    google_cloud_project_number: str | None = None

    # Fixed-window counters. Login is per address (IPv6 per /64). /mcp is per connection
    # (OAuth app or API_TOKENS entry); refused bearers are counted per address. High
    # defaults so normal use is unaffected.
    login_rate_limit: int = Field(default=30, ge=1, le=10_000)
    login_rate_window_seconds: int = Field(default=600, ge=1, le=86_400)
    mcp_rate_limit: int = Field(default=300, ge=1, le=100_000)
    # On (the default): an unsigned allowlist, app or pairing record is ignored. Set it
    # to 0 only on an older deployment, until /admin has signed the records from before.
    require_signed_records: bool = True
    # Access requests one connected app may have waiting for the person at once.
    max_pending_requests: int = Field(default=50, ge=1, le=300)
    mcp_rate_window_seconds: int = Field(default=60, ge=1, le=86_400)

    @field_validator(
        "root_folder_id",
        "owner_email",
        "bot_email",
        "app_base_url",
        "redis_rest_url",
        "google_picker_api_key",
        "google_cloud_project_number",
        "google_oauth_client_id",
        "google_oauth_client_secret",
        "google_oauth_refresh_token",
        "session_secret",
        "encryption_key",
        "redis_rest_token",
        "database_url",
        mode="before",
    )
    @classmethod
    def _blank_is_unset(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("root_folder_id")
    @classmethod
    def _check_root(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not _DRIVE_ID.fullmatch(value):
            raise ValueError("ROOT_FOLDER_ID does not look like a Google Drive folder ID")
        return value

    @field_validator("allowed_emails", mode="before")
    @classmethod
    def _parse_allowed_emails(cls, value: object) -> object:
        if value is None:
            return frozenset()
        if isinstance(value, str):
            if not value.strip():
                return frozenset()
            emails: set[str] = set()
            for chunk in value.split(","):
                email = chunk.strip().lower()
                if not email:
                    continue
                if not _EMAIL.fullmatch(email):
                    raise ValueError(
                        f"ALLOWED_EMAILS entry {chunk.strip()!r} is not an email address"
                    )
                emails.add(email)
            return frozenset(emails)
        return value

    @field_validator("owner_email", "bot_email")
    @classmethod
    def _check_email(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip().lower()
        if not _EMAIL.fullmatch(value):
            raise ValueError("must be an email address")
        return value

    @field_validator("google_cloud_project_number")
    @classmethod
    def _check_project_number(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not _PROJECT_NUMBER.fullmatch(value):
            raise ValueError("GOOGLE_CLOUD_PROJECT_NUMBER must be the numeric project number")
        return value

    @field_validator("google_picker_api_key")
    @classmethod
    def _check_picker_key(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if len(value) < 10 or any(ch.isspace() for ch in value):
            raise ValueError("GOOGLE_PICKER_API_KEY does not look like an API key")
        return value

    @field_validator("app_base_url")
    @classmethod
    def _check_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip().rstrip("/")
        scheme, _, rest = value.partition("://")
        host = rest.split("/", 1)[0].split(":", 1)[0]
        if scheme == "https" and host:
            return value
        if scheme == "http" and host in _LOCAL_HOSTS:
            return value
        raise ValueError("APP_BASE_URL must be https://... (http:// only for localhost)")

    @field_validator("database_url")
    @classmethod
    def _check_database_url(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        url = value.get_secret_value().strip()
        if not url.startswith(("postgres://", "postgresql://")):
            raise ValueError("DATABASE_URL must start with postgres:// or postgresql://")
        return SecretStr(url)

    @field_validator("redis_rest_url")
    @classmethod
    def _check_redis_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value.startswith("https://"):
            raise ValueError("the Redis REST URL must start with https://")
        return value

    @field_validator("session_secret")
    @classmethod
    def _check_session_secret(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and len(value.get_secret_value().strip()) < 32:
            raise ValueError("SESSION_SECRET must be at least 32 characters")
        return value

    @field_validator("encryption_key")
    @classmethod
    def _check_encryption_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        from cryptography.fernet import Fernet

        try:
            Fernet(value.get_secret_value().strip().encode())
        except (ValueError, TypeError):
            raise ValueError(
                "ENCRYPTION_KEY must be a Fernet key (run scripts/make_secrets.py)"
            ) from None
        return value

    @field_validator("api_tokens", mode="before")
    @classmethod
    def _parse_tokens(cls, value: object) -> object:
        if value is None:
            return []
        if isinstance(value, str):
            return parse_api_tokens(value) if value.strip() else []
        return value

    # ---- derived ---------------------------------------------------------

    def sign_in_allowed(self, email: str) -> bool:
        """Open sign-in, unless ALLOWED_EMAILS is set. The admin is always allowed."""
        if not self.allowed_emails:
            return True
        allowed = set(self.allowed_emails)
        if self.owner_email:
            allowed.add(self.owner_email)
        return email in allowed

    @property
    def same_account(self) -> bool:
        """The MCP tools act as the signed-in user. `BOT_EMAIL` is ignored."""
        return True

    @property
    def mode(self) -> Literal["same_account"]:
        return "same_account"

    @property
    def oauth_client_configured(self) -> bool:
        return _secret_set(self.google_oauth_client_id) and _secret_set(
            self.google_oauth_client_secret
        )

    @property
    def notion_configured(self) -> bool:
        """Both Notion OAuth values are set (a placeholder such as REPLACE_WITH_... does
        not count) and there is a public address for Notion to send people back to."""

        def real(value: SecretStr | None) -> bool:
            if not _secret_set(value):
                return False
            assert value is not None
            return not value.get_secret_value().strip().upper().startswith("REPLACE")

        return (
            real(self.notion_oauth_client_id)
            and real(self.notion_oauth_client_secret)
            and bool(self.app_base_url)
        )

    @property
    def redis_configured(self) -> bool:
        return bool(self.redis_rest_url) and _secret_set(self.redis_rest_token)

    @property
    def postgres_configured(self) -> bool:
        return _secret_set(self.database_url)

    @property
    def postgres_url(self) -> str | None:
        if not self.postgres_configured or self.database_url is None:
            return None
        return self.database_url.get_secret_value()

    @property
    def env_bot_refresh_token(self) -> str | None:
        if _secret_set(self.google_oauth_refresh_token):
            assert self.google_oauth_refresh_token is not None
            return self.google_oauth_refresh_token.get_secret_value().strip()
        return None

    def missing_settings(self) -> list[str]:
        """Names of required phase-2 settings that are not set (never their values)."""
        checks = [
            ("GOOGLE_OAUTH_CLIENT_ID", _secret_set(self.google_oauth_client_id)),
            ("GOOGLE_OAUTH_CLIENT_SECRET", _secret_set(self.google_oauth_client_secret)),
            ("OWNER_EMAIL", self.owner_email is not None),
            ("APP_BASE_URL", self.app_base_url is not None),
            ("SESSION_SECRET", _secret_set(self.session_secret)),
            ("ENCRYPTION_KEY", _secret_set(self.encryption_key)),
            ("UPSTASH_REDIS_REST_URL", self.redis_rest_url is not None),
            ("UPSTASH_REDIS_REST_TOKEN", _secret_set(self.redis_rest_token)),
            # Drive access is per file, and Google's file picker is how files are added.
            ("GOOGLE_PICKER_API_KEY", self.google_picker_api_key is not None),
            ("GOOGLE_CLOUD_PROJECT_NUMBER", self.google_cloud_project_number is not None),
        ]
        missing = [name for name, ok in checks if not ok]
        if self.postgres_configured:
            missing = [name for name in missing if not name.startswith("UPSTASH_")]
        return missing

    @model_validator(mode="after")
    def _signing_needs_a_key(self) -> "Settings":
        # Records are signed with a key made from ENCRYPTION_KEY. Without it nothing is
        # signed or checked, so asking for signed records explicitly must not quietly do
        # nothing. The default (on) applies only once a key is set.
        if (
            self.require_signed_records
            and "require_signed_records" in self.model_fields_set
            and self.encryption_key is None
        ):
            raise ValueError("REQUIRE_SIGNED_RECORDS needs ENCRYPTION_KEY to be set")
        return self

    def dashboard_missing(self) -> list[str]:
        """Settings the web dashboard cannot run without (Redis may fall back to memory).

        The picker settings are listed as missing but do not stop the dashboard: sign-in,
        Settings and Disconnect still have to work while they are being set up."""
        optional = ("UPSTASH_", "GOOGLE_PICKER_", "GOOGLE_CLOUD_PROJECT_NUMBER")
        return [m for m in self.missing_settings() if not m.startswith(optional)]

    @property
    def secure_cookies(self) -> bool:
        return not (self.app_base_url or "").startswith("http://")

    @property
    def picker_configured(self) -> bool:
        return bool(self.google_picker_api_key and self.google_cloud_project_number)
