"""Wake-up webhooks: saving, moving, clearing and testing one, and the ping sent through
it when mail arrives. Keys are sealed with `wake.py`.

One part of `Mailbox` (see `mailbox.py`). The other two are pairing (`pairing.py`) and
mail (`mail.py`).
"""

import json
import logging
from collections.abc import Callable
from typing import Any

from ..store import KeyValueStore
from ..wake import (
    SCHEMES,
    WakeSettings,
    approve_url,
    check_scheme_target,
    deliver,
    hint,
    open_secret,
    record_slot,
    seal,
)
from .common import (
    _TOKEN_SHAPE,
    MESSAGE_TTL,
    MailboxError,
    _email,
    _id,
    _key_carries,
    _same_target,
    _self_addr,
    _wake_error,
    _wake_http,
    current_assistant,
)


class WebhookMixin:
    # Set by `Mailbox.__init__` (mailbox.py).
    store: KeyValueStore
    wake: WakeSettings
    # The clock, from `Mailbox`.
    _iso: Callable[..., str]
    # From `PairingMixin`, used only by `missing_wakeups` (which pairings are on).
    _link: Callable[[str], dict[str, Any] | None]
    _revoked: Callable[..., bool]
    _status: Callable[[dict[str, Any]], str]
    _user_link_ids: Callable[[str], list[str]]
    # Nothing from `MailMixin`.

    def get_webhook(self, email: str, app: str | None = None) -> dict[str, Any]:
        """The wake-up hook this caller uses. `app` (dashboard only) picks a slot: "" for
        the account, or an app's grant id. Without it an assistant sees its own slot."""
        you = _email(email)
        if not self.wake.ready:
            return {"available": False, "configured": False, "enabled": False}
        owner = self._hook_owner(you, app)
        record = self._hook(owner)
        if record is None:
            return {
                "available": True,
                "configured": False,
                "enabled": False,
                "url": None,
                "auth_scheme": None,
                "secret_hint": None,
                "last_error": None,
                "last_wake": None,
            }
        return {
            "available": True,
            "configured": True,
            "enabled": bool(record.get("enabled")),
            "url": record.get("url"),
            "auth_scheme": record.get("scheme"),
            "secret_hint": record.get("hint"),
            "last_error": self.store.get(f"bridge:hookerr:{owner}"),
            "last_wake": self._last_wake(owner),
        }

    def set_webhook(
        self,
        email: str,
        url: str,
        sender_key: str | None = None,
        auth_scheme: str = "bearer",
        enabled: bool | None = None,
        app: str | None = None,
    ) -> dict[str, Any]:
        you = _email(email)
        if not self.wake.ready:
            raise MailboxError(
                "webhook_disabled", "Webhook wake-ups are turned off on this server."
            )
        scheme = (auth_scheme or "bearer").strip()
        if scheme not in SCHEMES:
            raise MailboxError(
                "invalid_input",
                "auth_scheme must be bearer, bearer_and_x_automation_key, or claude_routine.",
            )
        try:
            host, path, _address = approve_url(url, self.wake.allowlist, self.wake.lookup)
            check_scheme_target(scheme, host, path)
        except ValueError as exc:
            code = str(exc)
            if code == "webhook_host_not_allowed":
                raise MailboxError(
                    "webhook_host_not_allowed",
                    "That webhook host is not on the allowlist.",
                ) from None
            raise MailboxError(
                "invalid_webhook_url",
                "Use an https URL on an allowlisted host, with no user, query, or fragment. "
                "A claude_routine wake needs the routine's fire URL, "
                "https://api.anthropic.com/v1/claude_code/routines/<id>/fire, "
                "and that host only takes claude_routine.",
            ) from None
        except OSError:
            raise MailboxError(
                "invalid_webhook_url",
                "That webhook host did not resolve to a public address.",
            ) from None
        owner = self._hook_owner(you, app)
        current = self._hook(owner) or {}
        key = (sender_key or "").strip()
        if not key and current and not _key_carries(current, host, path, scheme):
            # Never carry a saved key to a different host (a Grok key must not reach
            # Anthropic, or the other way around), nor to a different Claude routine:
            # a routine's token only starts that one routine.
            current = {}
        if key:
            ciphertext, nonce = seal(key, self.wake.kek or b"", owner)
            saved_hint = hint(key)
            bound = True
        else:
            ciphertext = current.get("ciphertext")
            nonce = current.get("nonce")
            saved_hint = current.get("hint")
            bound = bool(current.get("bound"))
        if not ciphertext or not nonce:
            raise MailboxError(
                "secret_required",
                "A sender key is required the first time you save a webhook.",
            )
        record = {
            "url": url.strip(),
            "scheme": scheme,
            "ciphertext": ciphertext,
            "nonce": nonce,
            "hint": saved_hint,
            "enabled": current.get("enabled", True) if enabled is None else bool(enabled),
            # The key only opens for this slot (see wake.seal).
            "bound": bound,
        }
        self.store.set(f"bridge:hook:{owner}", json.dumps(record))
        self.store.delete(f"bridge:hookerr:{owner}")
        if not _same_target(current, record):
            # A new URL or key has not been tried yet; the old result is not about it.
            self.store.delete(f"bridge:hooklast:{owner}")
        self._index_hook(you, owner, present=True)
        return self.get_webhook(you, app)

    def clear_webhook(self, email: str, app: str | None = None) -> dict[str, Any]:
        you = _email(email)
        if not self.wake.ready:
            raise MailboxError(
                "webhook_disabled", "Webhook wake-ups are turned off on this server."
            )
        owner = self._hook_owner(you, app)
        self.store.delete(f"bridge:hook:{owner}")
        self.store.delete(f"bridge:hookerr:{owner}")
        self.store.delete(f"bridge:hooklast:{owner}")
        self._index_hook(you, owner, present=False)
        return self.get_webhook(you, app)

    def move_webhook(self, email: str, app: str, from_app: str = "") -> dict[str, Any]:
        """Dashboard only: give a saved hook to another app's slot. `from_app` is "" for
        the account-wide hook, or the app it sits on now. The key moves with it; nothing
        is re-entered."""
        you = _email(email)
        if not self.wake.ready:
            raise MailboxError(
                "webhook_disabled", "Webhook wake-ups are turned off on this server."
            )
        if not app:
            raise MailboxError("invalid_input", "Choose an app.")
        source = self._hook_owner(you, from_app)
        record = self._hook(source)
        if record is None:
            raise MailboxError("not_found", "There is no wake-up there to move.")
        owner = self._hook_owner(you, app)
        if owner == source:
            raise MailboxError("invalid_input", "It already belongs to that app.")
        if self._hook(owner) is not None:
            raise MailboxError(
                "invalid_state",
                "That assistant already has its own wake-up. Remove that one first, then "
                "give it this one.",
            )
        # The key is sealed for the slot it sits in, so it is sealed again for the new one.
        try:
            key = open_secret(
                str(record["ciphertext"]),
                str(record["nonce"]),
                self.wake.kek or b"",
                record_slot(record, source),
            )
        except Exception:
            raise MailboxError(
                "invalid_state",
                "That wake-up's key could not be read. Remove it and add it again.",
            ) from None
        ciphertext, nonce = seal(key, self.wake.kek or b"", owner)
        record = {**record, "ciphertext": ciphertext, "nonce": nonce, "bound": True}
        self.store.set(f"bridge:hook:{owner}", json.dumps(record))
        self.store.delete(f"bridge:hookerr:{owner}")
        self._index_hook(you, owner, present=True)
        last = self.store.get(f"bridge:hooklast:{source}")
        if last:
            self.store.set(f"bridge:hooklast:{owner}", last, ex=MESSAGE_TTL)
        self.store.delete(f"bridge:hook:{source}")
        self.store.delete(f"bridge:hookerr:{source}")
        self.store.delete(f"bridge:hooklast:{source}")
        self._index_hook(you, source, present=False)
        return self.get_webhook(you, app)

    def webhook_apps(self, email: str) -> list[str]:
        """Grant ids that have their own wake-up hook saved."""
        you = _email(email)
        return sorted(self.store.hgetall(f"bridge:hookapps:{you}"))

    def _index_hook(self, you: str, owner: str, present: bool) -> None:
        if "#" not in owner:
            return
        grant = owner.split("#", 1)[1]
        if present:
            self.store.hset(f"bridge:hookapps:{you}", grant, "1")
        else:
            self.store.hdel(f"bridge:hookapps:{you}", grant)

    def _hook_owner(self, you: str, app: str | None = None) -> str:
        """Which webhook slot a call uses.

        Every connected app (OAuth grant) has its own slot, so one app's wake-up never
        replaces another's. The account-wide slot is left from when mail from other
        people existed; it is never woken now, and the dashboard only offers to move or
        remove a hook saved there. `app` is the dashboard's choice: "" for the account,
        else a grant.
        """
        if app is not None:
            if not app:
                return you
            if not _TOKEN_SHAPE.fullmatch(app):
                raise MailboxError("invalid_input", "Unknown app.")
            return _self_addr(you, app)
        assistant = current_assistant.get()
        return _self_addr(you, assistant.grant_id) if assistant is not None else you

    def _hook(self, email: str) -> dict[str, Any] | None:
        raw = self.store.get(f"bridge:hook:{email}")
        if not raw:
            return None
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(parsed, dict):
            return None
        return self._bind_hook(email, raw, parsed)

    def _bind_hook(self, slot: str, raw: str, record: dict[str, Any]) -> dict[str, Any]:
        """Seal a key saved before keys were bound to their slot for this slot, once.
        If that cannot be done now the record is returned as it is and still works."""
        if record.get("bound") or not self.wake.kek:
            return record
        try:
            key = open_secret(str(record["ciphertext"]), str(record["nonce"]), self.wake.kek)
        except Exception:
            return record
        ciphertext, nonce = seal(key, self.wake.kek, slot)
        bound = {**record, "ciphertext": ciphertext, "nonce": nonce, "bound": True}
        swap = getattr(self.store, "replace", None) or getattr(self.store, "swap", None)
        if swap is None or not swap(f"bridge:hook:{slot}", raw, json.dumps(bound)):
            logging.getLogger(__name__).warning("wake_key_not_bound_yet")
            return record
        return bound

    def _maybe_wake(self, message: dict[str, Any]) -> dict[str, Any]:
        """Ping the recipient's wake-up hook(s) and say what happened, so the sender
        learns whether the other assistant is starting or will only see the mail when it
        next checks. The result names no URL, key or address."""
        if not self.wake.ready:
            return {"status": "off"}
        log = logging.getLogger(__name__)
        targets = self._wake_targets(str(message["to"]))
        if not targets:
            kind = "app" if "#" in str(message["to"]) else "account"
            log.warning("mailbox_wake_none %s", kind)
            return {"status": "no_wakeup"}
        outcomes: list[str] = []
        reason = ""
        for slot, record in targets:
            if not record.get("enabled") or not record.get("url"):
                outcomes.append("paused")
                continue
            # One mark per message and hook, so a retry does not ping a hook twice.
            suffix = "" if slot == message["to"] else f":{slot}"
            mark = f"bridge:woke:{message['msg_id']}{suffix}"
            held = self._claim_wake(mark)
            if held is not None:
                # Another call holds this ping: "sent" only once it succeeded ("1"); while
                # it is in flight the outcome is not known yet.
                outcomes.append("sent" if held == "1" else "pending")
                continue
            # Which slot, never the address or URL: "app" for one app's own, else "account".
            kind = "app" if "#" in slot else "account"
            try:
                status = deliver(self.wake, record, message, slot)
            except Exception as exc:
                self.store.delete(mark)
                logged = _wake_error(exc)
                log.warning("mailbox_wake_failed %s %s", kind, logged)
                self._note_wake(slot, record, logged, http=_wake_http(exc))
                outcomes.append("failed")
                reason = reason or logged
            else:
                self.store.set(mark, "1", ex=MESSAGE_TTL)
                log.warning("mailbox_wake_sent %s", kind)
                self._note_wake(slot, record, None, http=status)
                outcomes.append("sent")
        if "sent" in outcomes:
            return {"status": "sent"}
        if "failed" in outcomes:
            return {"status": "failed", "reason": reason}
        if "pending" in outcomes:
            return {"status": "pending"}
        return {"status": "paused"}

    def _claim_wake(self, mark: str) -> str | None:
        """Take the right to send this ping. None means this call holds it now; otherwise
        the other holder's mark ("pending" or "1"). A failed holder deletes its mark, so a
        missing mark is claimed again rather than read as success."""
        for _ in range(2):
            if self.store.set_if_absent(mark, "pending", ex=MESSAGE_TTL):
                return None
            held = self.store.get(mark)
            if held is not None:
                return held
        return "pending"

    def test_webhook(self, email: str, app: str | None = None) -> dict[str, Any]:
        """Dashboard only: send one ping to a saved hook now, so a person can see it work.
        The ping carries made-up ids; the assistant that wakes finds no new mail."""
        you = _email(email)
        if not self.wake.ready:
            raise MailboxError(
                "webhook_disabled", "Webhook wake-ups are turned off on this server."
            )
        owner = self._hook_owner(you, app)
        record = self._hook(owner)
        if record is None:
            raise MailboxError("not_found", "There is no wake-up there to test.")
        message = {
            "link_id": "test",
            "thread_id": "test",
            "msg_id": _id("test"),
            "created_at": self._iso(),
        }
        try:
            status = deliver(self.wake, record, message, owner)
        except Exception as exc:
            logged = _wake_error(exc)
            self._note_wake(owner, record, logged, http=_wake_http(exc))
            return {"ok": False, "error": logged, "http": _wake_http(exc)}
        self._note_wake(owner, record, None, http=status)
        return {"ok": True, "http": status}

    def missing_wakeups(self, email: str) -> list[dict[str, Any]]:
        """Own-assistant pairings where one side has no working wake-up: mail sent to that
        assistant is stored but does not start it. One row per (link, assistant)."""
        you = _email(email)
        rows: list[dict[str, Any]] = []
        if not self.wake.ready:
            return rows
        for link_id in self._user_link_ids(you):
            link = self._link(link_id)
            if link is None or not link.get("same_account") or self._revoked(link_id):
                continue
            if self._status(link) != "active":
                continue
            for side, other in (("a", "b"), ("b", "a")):
                grant = link.get(f"grant_{side}")
                if not grant:
                    continue
                record = self._hook(_self_addr(you, str(grant)))
                if record is not None and record.get("enabled") and record.get("url"):
                    continue
                rows.append(
                    {
                        "link_id": link_id,
                        "grant_id": str(grant),
                        "assistant": link.get(f"label_{side}") or "Assistant",
                        "sender": link.get(f"label_{other}") or "Assistant",
                        "paused": record is not None,
                    }
                )
        return rows

    def _wake_targets(self, recipient: str) -> list[tuple[str, dict[str, Any]]]:
        """Which saved hook to ping for mail addressed to `recipient`.

        Mail only goes between one person's own assistants, addressed to `email#grant`,
        so the only hook is that app's own. Another app's hook would wake the wrong
        assistant (often the sender). The account-wide slot is never woken: it served mail
        from other people, which no longer exists.
        """
        if "#" not in recipient:
            return []
        own = self._hook(recipient)
        return [(recipient, own)] if own is not None else []

    def _note_wake(
        self, email: str, used: dict[str, Any], error: str | None, http: int | None = None
    ) -> None:
        """Record the outcome only while the saved webhook is still the one we called."""
        current = self._hook(email)
        if current is None:
            return
        same = (
            current.get("url") == used.get("url")
            and current.get("ciphertext") == used.get("ciphertext")
            and current.get("nonce") == used.get("nonce")
        )
        if not same:
            return
        key = f"bridge:hookerr:{email}"
        if error is None:
            self.store.delete(key)
        else:
            self.store.set(key, error, ex=MESSAGE_TTL)
        last = {"at": self._iso(), "ok": error is None, "error": error, "http": http}
        self.store.set(f"bridge:hooklast:{email}", json.dumps(last), ex=MESSAGE_TTL)

    def _last_wake(self, owner: str) -> dict[str, Any] | None:
        raw = self.store.get(f"bridge:hooklast:{owner}")
        if not raw:
            return None
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None
