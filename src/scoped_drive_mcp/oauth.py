"""Google OAuth 2.0 authorization-code flow for the dashboard.

Google is asked twice, on purpose:

1. **Sign in.** `SIGN_IN_SCOPES` only (`openid`, `email`). This proves who the person
   is. No refresh token is requested or stored, and nothing of theirs is reachable.
2. **Connect a service.** A separate, explicit step after sign-in asks for the wider
   scope one connection needs (see `connections.py`; Google Drive asks for `drive.file`
   only). That request uses offline access without incremental authorization, so the
   refresh token it returns carries only that scope, and it is what the server stores.

One "Web application" OAuth client serves both steps; the redirect URI is always
APP_BASE_URL/auth/callback and the step is carried in a signed `state`.
"""

import contextlib
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlencode

import httpx

from .drive_client import DRIVE_FILE_SCOPE, TOKEN_URI, scopes_acceptable

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"
DRIVE_ABOUT_URL = "https://www.googleapis.com/drive/v3/about"
# Step 1 only identifies the person. Wider scopes belong to a connection (step 2).
SIGN_IN_SCOPES: tuple[str, ...] = ("openid", "email")


class OAuthError(Exception):
    """The Google OAuth exchange failed; the message is safe to show."""


@dataclass(frozen=True)
class OAuthTokens:
    access_token: str
    refresh_token: str | None
    scopes: frozenset[str]


class OAuthClient(Protocol):
    def authorization_url(
        self,
        state: str,
        login_hint: str | None = None,
        scopes: tuple[str, ...] = SIGN_IN_SCOPES,
        offline: bool = False,
    ) -> str: ...
    def picker_url(self, state: str, login_hint: str | None = None) -> str: ...
    def exchange_code(self, code: str) -> OAuthTokens: ...
    def userinfo(self, access_token: str) -> dict[str, Any]: ...
    def drive_account(self, access_token: str) -> str | None: ...
    def revoke(self, token: str) -> bool: ...


class GoogleOAuthClient:
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str, timeout: float = 15):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.timeout = timeout

    def authorization_url(
        self,
        state: str,
        login_hint: str | None = None,
        scopes: tuple[str, ...] = SIGN_IN_SCOPES,
        offline: bool = False,
    ) -> str:
        """Build Google's consent URL.

        `offline=False` is the sign-in step: identity scopes, no refresh token, and
        Google's account chooser. `offline=True` is a connection step: it asks for a
        refresh token and always shows the consent screen (so Google returns one). It
        does not fold in scopes granted earlier (`include_granted_scopes=false`), so a
        person who once granted full Drive gets back only what is asked for now.
        """
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": " ".join(scopes),
            "state": state,
        }
        if offline:
            params["access_type"] = "offline"
            params["prompt"] = "consent"
            params["include_granted_scopes"] = "false"
        else:
            params["access_type"] = "online"
            params["prompt"] = "select_account"
            params["include_granted_scopes"] = "false"
        if login_hint:
            params["login_hint"] = login_hint
        return f"{AUTH_URL}?{urlencode(params)}"

    def picker_url(self, state: str, login_hint: str | None = None) -> str:
        """Google's file picker as a full page on Google's own site.

        This is Google's redirect picker (the one it documents for desktop and mobile
        apps): the consent URL with `trigger_onepick`, which shows the picker after the
        consent screen and comes back to the redirect URI with `picked_file_ids`. The
        in-page picker runs in a frame and needs Google's cookies there, which Safari and
        every iPhone and iPad browser block; a full page on google.com does not. Google
        allows only `drive.file` here, alone. `access_type=online`: the server already
        holds this person's refresh token, and each extra one counts against Google's
        per-account limit, which drops the oldest.
        """
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": DRIVE_FILE_SCOPE,
            "state": state,
            "access_type": "online",
            "prompt": "consent",
            "include_granted_scopes": "false",
            "trigger_onepick": "true",
            "allow_multiple": "true",
            "allow_folder_selection": "true",
        }
        if login_hint:
            params["login_hint"] = login_hint
        return f"{AUTH_URL}?{urlencode(params)}"

    def exchange_code(self, code: str) -> OAuthTokens:
        try:
            resp = httpx.post(
                TOKEN_URI,
                data={
                    "code": code,
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "redirect_uri": self.redirect_uri,
                    "grant_type": "authorization_code",
                },
                timeout=self.timeout,
            )
        except httpx.HTTPError:
            raise OAuthError("could not reach Google") from None
        if resp.status_code != 200:
            raise OAuthError("Google rejected the sign-in code")
        try:
            data = resp.json()
            return OAuthTokens(
                access_token=str(data["access_token"]),
                refresh_token=data.get("refresh_token"),
                scopes=frozenset(str(data.get("scope", "")).split()),
            )
        except (ValueError, KeyError, TypeError, AttributeError):
            raise OAuthError("Google returned an unexpected sign-in response") from None

    def userinfo(self, access_token: str) -> dict[str, Any]:
        try:
            resp = httpx.get(
                USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=self.timeout,
            )
        except httpx.HTTPError:
            raise OAuthError("could not reach Google") from None
        if resp.status_code != 200:
            raise OAuthError("Google did not return the account's email")
        try:
            info = resp.json()
        except ValueError:
            info = None
        if not isinstance(info, dict):
            raise OAuthError("Google did not return the account's email")
        return info

    def drive_account(self, access_token: str) -> str | None:
        """The address of the Google account a Drive token belongs to, or None when
        Google does not say. A `drive.file` token cannot call userinfo; Drive's own
        `about` names the account."""
        try:
            resp = httpx.get(
                DRIVE_ABOUT_URL,
                params={"fields": "user(emailAddress)"},
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=self.timeout,
            )
        except httpx.HTTPError:
            return None
        if resp.status_code != 200:
            return None
        try:
            user = resp.json().get("user")
        except (ValueError, AttributeError):
            return None
        email = user.get("emailAddress") if isinstance(user, dict) else None
        return email.strip().lower() if isinstance(email, str) and email.strip() else None

    def revoke(self, token: str) -> bool:
        """Ask Google to end this token's grant. True when Google confirms it is gone:
        revoked now (200), or already invalid (400 invalid_token). False when Google could
        not be reached or refused, so a caller can keep the token and try again."""
        try:
            resp = httpx.post(REVOKE_URL, data={"token": token}, timeout=self.timeout)
        except httpx.HTTPError:
            return False
        if resp.status_code == 200:
            return True
        if resp.status_code == 400:
            with contextlib.suppress(ValueError):
                return resp.json().get("error") == "invalid_token"
        return False


PICKER_SCOPE = DRIVE_FILE_SCOPE


def refresh_access_token(
    client_id: str, client_secret: str, refresh_token: str, timeout: float = 15
) -> str:
    """Mint a short-lived access token for the Google Picker, which runs in the browser.

    The token is asked for with only `drive.file`, the permission the Picker needs, and
    Google's answer has to say that is what it gave. A token that can open the whole
    Drive is never returned: page script could use it outside the allowlist. If Google
    will not narrow a sign-in, the Picker is unavailable for it and Browse does the job.
    """
    try:
        resp = httpx.post(
            TOKEN_URI,
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
                "scope": PICKER_SCOPE,
            },
            timeout=timeout,
        )
    except httpx.HTTPError:
        raise OAuthError("could not reach Google") from None
    if resp.status_code != 200:
        raise OAuthError("Google did not give a token limited to picked files")
    body = resp.json()
    token = body.get("access_token")
    if not isinstance(token, str) or not token:
        raise OAuthError("Google did not refresh the sign-in")
    # drive.file and the sign-in scopes only: anything wider (full Drive, drive.readonly,
    # cloud-platform, ...) would let page script reach files outside the allowlist.
    if not scopes_acceptable(str(body.get("scope") or "")):
        raise OAuthError("Google did not give a token limited to picked files")
    return token
