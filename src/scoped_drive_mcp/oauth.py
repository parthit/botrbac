"""Google OAuth 2.0 authorization-code flow for the dashboard.

Google is asked twice, on purpose:

1. **Sign in.** `SIGN_IN_SCOPES` only (`openid`, `email`). This proves who the person
   is. No refresh token is requested or stored, and nothing of theirs is reachable.
2. **Connect a service.** A separate, explicit step after sign-in asks for the wider
   scopes one connection needs (see `connections.py`; Google Drive is the first). That
   request uses incremental authorization and offline access, so the refresh token it
   returns is what the server stores.

One "Web application" OAuth client serves both steps; the redirect URI is always
APP_BASE_URL/auth/callback and the step is carried in a signed `state`.
"""

import contextlib
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlencode

import httpx

from .drive_client import TOKEN_URI

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"
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
    def exchange_code(self, code: str) -> OAuthTokens: ...
    def userinfo(self, access_token: str) -> dict[str, Any]: ...
    def revoke(self, token: str) -> None: ...


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
        refresh token, always shows the consent screen (so Google returns one), and
        adds the new scopes to what this app already holds (incremental auth).
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
            params["include_granted_scopes"] = "true"
        else:
            params["access_type"] = "online"
            params["prompt"] = "select_account"
            params["include_granted_scopes"] = "false"
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

    def revoke(self, token: str) -> None:
        with contextlib.suppress(httpx.HTTPError):
            httpx.post(REVOKE_URL, data={"token": token}, timeout=self.timeout)


def refresh_access_token(
    client_id: str, client_secret: str, refresh_token: str, timeout: float = 15
) -> str:
    """Mint a short-lived access token for the Google Picker.

    The scope parameter is omitted on purpose: Google returns the scopes that
    already belong to this refresh token. A full-Drive sign-in and a leftover
    drive.file sign-in both refresh. The new access token is not stored.
    """
    try:
        resp = httpx.post(
            TOKEN_URI,
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            },
            timeout=timeout,
        )
    except httpx.HTTPError:
        raise OAuthError("could not reach Google") from None
    if resp.status_code != 200:
        raise OAuthError("Google did not refresh the sign-in")
    token = resp.json().get("access_token")
    if not isinstance(token, str) or not token:
        raise OAuthError("Google did not refresh the sign-in")
    return token
