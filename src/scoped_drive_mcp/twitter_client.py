"""X (Twitter) API v2: the OAuth 2.0 exchange and the few calls Bot RBAC makes.

Connecting X is a separate OAuth flow from Google sign-in: X's authorization-code flow
with PKCE, for a confidential client (the client secret goes in a Basic header). X's
scopes cannot be limited to some accounts, so they are the outer limit only. Bot RBAC's
own X allowlist (accounts and lists chosen on Files) is the inner limit that assistants
are held to.

The reads are: the connected account, an account by id or handle, a list, an account's
or a list's recent posts, one post, the connected account's own lists, and recent
search. The one write is creating a post (`create_post`), only with the `tweet.write`
scope, which is asked for only when the deployment turns posting on. Nothing here likes,
reposts, follows, sends messages, or deletes anything.
"""

import base64
import contextlib
import hashlib
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlencode, urlsplit

import httpx

API_BASE = "https://api.x.com/2"
AUTHORIZE_URL = "https://x.com/i/oauth2/authorize"
TOKEN_URL = f"{API_BASE}/oauth2/token"
REVOKE_URL = f"{API_BASE}/oauth2/revoke"

# Reading: posts, accounts and lists. offline.access is what gives a refresh token (an
# access token lasts two hours).
READ_SCOPES: tuple[str, ...] = ("tweet.read", "users.read", "list.read", "offline.access")
# Posting, asked for only when the deployment sets TWITTER_ALLOW_POST.
WRITE_SCOPE = "tweet.write"
POST_SCOPES: tuple[str, ...] = (*READ_SCOPES, WRITE_SCOPE)
# A token without these is refused: nothing works without them.
REQUIRED_SCOPES: frozenset[str] = frozenset({"tweet.read", "users.read"})

# What each post read asks X to include.
TWEET_FIELDS = "created_at,author_id,conversation_id,public_metrics,referenced_tweets,note_tweet"
USER_FIELDS = "username,name,protected"
LIST_FIELDS = "name,owner_id,private,member_count,description"

USER = "user"
LIST = "list"
# What parse_source found: an account by id, an account by handle, or a list by id.
BY_ID = "user_id"
BY_HANDLE = "username"

_HANDLE = re.compile(r"[A-Za-z0-9_]{1,15}")
_NUMERIC = re.compile(r"[0-9]{1,20}")
_X_HOSTS = frozenset(
    {"x.com", "www.x.com", "mobile.x.com", "twitter.com", "www.twitter.com", "mobile.twitter.com"}
)
# Paths on x.com that are not accounts.
_NOT_HANDLES = frozenset(
    {"i", "home", "explore", "search", "settings", "messages", "notifications", "intent"}
)


class TwitterOAuthError(Exception):
    """The OAuth exchange with X failed; the message is safe to show."""


class TwitterApiError(Exception):
    """An X API call failed."""

    def __init__(self, status: int, code: str = "") -> None:
        super().__init__(f"X returned {status} {code}".strip())
        self.status = status
        self.code = code


class TwitterNotFoundError(TwitterApiError):
    """Not found, suspended, or not visible to this account."""


class TwitterForbiddenError(TwitterApiError):
    """403: this app or account may not make the call (a protected account, a private
    list, or an API plan without that endpoint)."""


class TwitterUnauthorizedError(TwitterApiError):
    """The access token is no longer valid (revoked at X, or expired)."""


class TwitterRateLimitedError(TwitterApiError):
    """429: too many calls, or the app's monthly allowance is spent."""


def normalize_scopes(raw: object) -> set[str]:
    if not isinstance(raw, str):
        return set()
    return {s for s in raw.split() if s}


def scopes_acceptable(granted: set[str], requested: tuple[str, ...]) -> bool:
    """X granted what is needed, and nothing outside what was asked for."""
    return REQUIRED_SCOPES <= granted and granted <= set(requested)


def can_post(record: dict[str, str] | None) -> bool:
    """Whether a stored connection was granted posting."""
    return bool(record) and WRITE_SCOPE in normalize_scopes((record or {}).get("scp"))


def parse_source(raw: object) -> tuple[str, str] | None:
    """(kind, value) from what a person or assistant typed for an account or list.

    Accounts: "@handle", "handle", "x.com/handle" (BY_HANDLE, the handle without @) or
    "user:<id>" (BY_ID). Lists: "list:<id>" or "x.com/i/lists/<id>" (LIST, the id).
    None when it is neither."""
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text or len(text) > 300:
        return None
    lowered = text.lower()
    if lowered.startswith("list:"):
        value = text[5:].strip()
        return (LIST, value) if _NUMERIC.fullmatch(value) else None
    if lowered.startswith("user:"):
        value = text[5:].strip()
        return (BY_ID, value) if _NUMERIC.fullmatch(value) else None
    if text.startswith("@"):
        handle = text[1:]
        return (BY_HANDLE, handle) if _HANDLE.fullmatch(handle) else None
    if "/" in text or "." in text:
        url = text if "://" in text else f"https://{text}"
        try:
            parts = urlsplit(url)
        except ValueError:
            return None
        if (parts.hostname or "").lower() not in _X_HOSTS:
            return None
        segments = [s for s in parts.path.split("/") if s]
        if len(segments) >= 3 and segments[0] == "i" and segments[1] == "lists":
            return (LIST, segments[2]) if _NUMERIC.fullmatch(segments[2]) else None
        if segments and segments[0].lower() not in _NOT_HANDLES:
            return (BY_HANDLE, segments[0]) if _HANDLE.fullmatch(segments[0]) else None
        return None
    return (BY_HANDLE, text) if _HANDLE.fullmatch(text) else None


def normalize_tweet_id(raw: object) -> str | None:
    """A post id from an id or an x.com / twitter.com post URL. None otherwise."""
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if _NUMERIC.fullmatch(text):
        return text
    if len(text) > 300:
        return None
    url = text if "://" in text else f"https://{text}"
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if (parts.hostname or "").lower() not in _X_HOSTS:
        return None
    segments = [s for s in parts.path.split("/") if s]
    # /<handle>/status/<id> and /i/web/status/<id>
    for i, segment in enumerate(segments[:-1]):
        if segment == "status" and _NUMERIC.fullmatch(segments[i + 1]):
            return segments[i + 1]
    return None


def pkce_pair() -> tuple[str, str]:
    """(verifier, S256 challenge) for one authorization."""
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


@dataclass(frozen=True)
class TwitterTokens:
    access_token: str
    refresh_token: str | None
    expires_at: float
    scopes: str


@dataclass(frozen=True)
class TwitterAccount:
    user_id: str
    username: str
    name: str


class TwitterOAuth:
    """X's OAuth 2.0 authorization-code flow with PKCE, for a confidential client."""

    def __init__(
        self, client_id: str, client_secret: str, redirect_uri: str, timeout: float = 15
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.timeout = timeout

    def _basic(self) -> str:
        pair = f"{self.client_id}:{self.client_secret}".encode()
        return "Basic " + base64.b64encode(pair).decode()

    def authorization_url(self, state: str, challenge: str, scopes: tuple[str, ...]) -> str:
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        return f"{AUTHORIZE_URL}?{urlencode(params)}"

    def _token_call(self, body: dict[str, str]) -> TwitterTokens:
        try:
            resp = httpx.post(
                TOKEN_URL,
                data=body,
                headers={"Authorization": self._basic()},
                timeout=self.timeout,
            )
        except httpx.HTTPError:
            raise TwitterOAuthError("could not reach X") from None
        if resp.status_code != 200:
            raise TwitterOAuthError("X rejected the connection code")
        try:
            data = resp.json()
            token = data["access_token"]
            if not isinstance(token, str) or not token:
                raise ValueError
            refresh = data.get("refresh_token")
            expires_in = int(data.get("expires_in") or 7200)
            scope = data.get("scope")
            return TwitterTokens(
                access_token=token,
                refresh_token=refresh if isinstance(refresh, str) and refresh else None,
                # A minute early, so a call does not start with a token about to lapse.
                expires_at=time.time() + max(expires_in - 60, 0),
                scopes=scope if isinstance(scope, str) else "",
            )
        except (ValueError, KeyError, TypeError, AttributeError):
            raise TwitterOAuthError("X returned an unexpected response") from None

    def exchange_code(self, code: str, verifier: str) -> TwitterTokens:
        return self._token_call(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect_uri,
                "code_verifier": verifier,
            }
        )

    def refresh(self, refresh_token: str) -> TwitterTokens:
        return self._token_call({"grant_type": "refresh_token", "refresh_token": refresh_token})

    def revoke(self, token: str, hint: str = "access_token") -> bool:
        """Ask X to end this token. True when X confirms. False when X could not be
        reached or refused, so the caller can tell the person to remove the app at X."""
        try:
            resp = httpx.post(
                REVOKE_URL,
                data={"token": token, "token_type_hint": hint},
                headers={"Authorization": self._basic()},
                timeout=self.timeout,
            )
        except httpx.HTTPError:
            return False
        if resp.status_code != 200:
            return False
        with contextlib.suppress(ValueError, AttributeError):
            return resp.json().get("revoked") is not False
        return True


class TwitterApi(Protocol):
    def me(self) -> dict[str, Any]: ...
    def user(self, user_id: str) -> dict[str, Any]: ...
    def user_by_username(self, username: str) -> dict[str, Any]: ...
    def get_list(self, list_id: str) -> dict[str, Any]: ...
    def owned_lists(self, user_id: str) -> dict[str, Any]: ...
    def user_posts(self, user_id: str, max_results: int) -> dict[str, Any]: ...
    def list_posts(self, list_id: str, max_results: int) -> dict[str, Any]: ...
    def get_post(self, post_id: str) -> dict[str, Any]: ...
    def search_recent(self, query: str, max_results: int) -> dict[str, Any]: ...
    def create_post(self, text: str, reply_to: str | None = None) -> dict[str, Any]: ...


class HttpTwitterApi:
    """X's v2 REST API with one OAuth 2.0 user access token."""

    def __init__(self, access_token: str, timeout: float = 20) -> None:
        self._client = httpx.Client(
            base_url=API_BASE,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=timeout,
        )

    def close(self) -> None:
        self._client.close()

    def _call(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        # Every failure is a TwitterApiError, which the tools and the dashboard report as
        # "X didn't answer"; a raw network error would surface as a 500.
        try:
            resp = self._client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise TwitterApiError(0, "unreachable") from exc
        data: Any = None
        with contextlib.suppress(ValueError):
            data = resp.json()
        if resp.status_code in (200, 201):
            if not isinstance(data, dict):
                raise TwitterApiError(resp.status_code, "bad_response")
            if "data" not in data and data.get("errors"):
                # X answers a lookup of something missing or suspended with 200 and an
                # errors list instead of data.
                raise TwitterNotFoundError(404, _error_code(data))
            return data
        code = _error_code(data) if isinstance(data, dict) else ""
        if resp.status_code == 404:
            raise TwitterNotFoundError(404, code)
        if resp.status_code == 401:
            raise TwitterUnauthorizedError(401, code)
        if resp.status_code == 403:
            raise TwitterForbiddenError(403, code)
        if resp.status_code == 429:
            raise TwitterRateLimitedError(429, code)
        raise TwitterApiError(resp.status_code, code)

    def me(self) -> dict[str, Any]:
        return self._call("GET", "/users/me", params={"user.fields": USER_FIELDS})

    def user(self, user_id: str) -> dict[str, Any]:
        return self._call("GET", f"/users/{user_id}", params={"user.fields": USER_FIELDS})

    def user_by_username(self, username: str) -> dict[str, Any]:
        return self._call(
            "GET", f"/users/by/username/{username}", params={"user.fields": USER_FIELDS}
        )

    def get_list(self, list_id: str) -> dict[str, Any]:
        return self._call("GET", f"/lists/{list_id}", params={"list.fields": LIST_FIELDS})

    def owned_lists(self, user_id: str) -> dict[str, Any]:
        return self._call(
            "GET",
            f"/users/{user_id}/owned_lists",
            params={"max_results": 100, "list.fields": LIST_FIELDS},
        )

    def _post_params(self, max_results: int, low: int) -> dict[str, Any]:
        return {
            "max_results": max(low, min(max_results, 100)),
            "tweet.fields": TWEET_FIELDS,
            "expansions": "author_id",
            "user.fields": USER_FIELDS,
        }

    def user_posts(self, user_id: str, max_results: int) -> dict[str, Any]:
        # X takes 5 to 100 here.
        return self._call(
            "GET", f"/users/{user_id}/tweets", params=self._post_params(max_results, 5)
        )

    def list_posts(self, list_id: str, max_results: int) -> dict[str, Any]:
        return self._call(
            "GET", f"/lists/{list_id}/tweets", params=self._post_params(max_results, 1)
        )

    def get_post(self, post_id: str) -> dict[str, Any]:
        params = self._post_params(1, 1)
        del params["max_results"]
        return self._call("GET", f"/tweets/{post_id}", params=params)

    def search_recent(self, query: str, max_results: int) -> dict[str, Any]:
        # X takes 10 to 100 here.
        params = {"query": query, **self._post_params(max_results, 10)}
        return self._call("GET", "/tweets/search/recent", params=params)

    def create_post(self, text: str, reply_to: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"text": text}
        if reply_to:
            body["reply"] = {"in_reply_to_tweet_id": reply_to}
        return self._call("POST", "/tweets", json=body)


def _error_code(data: dict[str, Any]) -> str:
    """A short code from X's error body: its `type` URL's last part, or `title`."""
    errors = data.get("errors")
    first = errors[0] if isinstance(errors, list) and errors else data
    if not isinstance(first, dict):
        return ""
    kind = first.get("type")
    if isinstance(kind, str) and kind:
        return kind.rstrip("/").rsplit("/", 1)[-1][:60]
    title = first.get("title")
    return str(title)[:60] if title else ""


# ---- reading X objects -------------------------------------------------------------


def post_text(post: dict[str, Any]) -> str:
    """A post's full text: a long post's note text when X includes it."""
    note = post.get("note_tweet")
    if isinstance(note, dict) and isinstance(note.get("text"), str) and note["text"]:
        return note["text"]
    return str(post.get("text") or "")


def users_by_id(page: dict[str, Any]) -> dict[str, dict[str, Any]]:
    includes = page.get("includes")
    users = includes.get("users") if isinstance(includes, dict) else None
    out: dict[str, dict[str, Any]] = {}
    if isinstance(users, list):
        for u in users:
            if isinstance(u, dict) and isinstance(u.get("id"), str):
                out[u["id"]] = u
    return out


def post_url(username: str | None, post_id: str) -> str:
    return f"https://x.com/{username or 'i/web'}/status/{post_id}"
