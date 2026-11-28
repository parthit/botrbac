"""Mail between one person's own assistants: sending and replying (with idempotency
keys), inboxes, threads, read marks, purging, and the hourly limits.

One part of `Mailbox` (see `mailbox.py`). The other two are pairing (`pairing.py`) and
wake-up webhooks (`webhooks.py`).
"""

import json
import logging
from collections.abc import Callable
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from ..store import KeyValueStore, parse_inbox_token
from .common import (
    _TOKEN_SHAPE,
    HANDLING,
    HOUR,
    LINK_REQUESTS_PER_HOUR,
    MESSAGE_TTL,
    PEER_MAIL_OFF,
    PER_LINK_PER_HOUR,
    PER_USER_PER_HOUR,
    MailboxError,
    _check_body,
    _digest,
    _email,
    _from_assistant,
    _id,
    _iso,
    _labels,
    _limit,
    _parse_since,
    _parties,
    _pending_token,
    _retry,
    _self_addr,
    _sent,
    _split_pending,
    _wake_view,
    present_untrusted,
    preview_untrusted,
)


class MailMixin:
    # Set by `Mailbox.__init__` (mailbox.py).
    store: KeyValueStore
    _fernet: Fernet | None
    _legacy_fernet: Fernet | None
    # The clock, from `Mailbox`.
    _now: Callable[[], float]
    _iso: Callable[..., str]
    _stamp: Callable[[str], float]
    # From `PairingMixin`: which link a message belongs to, whether it is on, and which
    # side of it the caller is.
    _link: Callable[[str], dict[str, Any] | None]
    _peer: Callable[[str], str | None]
    _status: Callable[[dict[str, Any]], str]
    _user_link_ids: Callable[[str], list[str]]
    _require_party: Callable[[str, str], dict[str, Any]]
    _require_active: Callable[[str, str], dict[str, Any]]
    _mine: Callable[[str], set[str]]
    _addr: Callable[[dict[str, Any], str], str | None]
    _other: Callable[[dict[str, Any], str], str | None]
    # From `WebhookMixin`: the ping after a message is queued (`_publish`).
    _maybe_wake: Callable[[dict[str, Any]], dict[str, Any]]

    def send_message(
        self,
        email: str,
        link_id: str,
        body: str,
        thread_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        you = _email(email)
        return self._deliver(
            you, link_id, body, thread_id=thread_id, idempotency_key=idempotency_key
        )

    def reply(
        self,
        email: str,
        body: str,
        msg_id: str | None = None,
        thread_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        you = _email(email)
        if not msg_id and not thread_id:
            raise MailboxError("invalid_input", "Provide msg_id or thread_id to reply.")
        if msg_id:
            message = self._message(msg_id)
            if message is None or not self._mine(you) & {message["from"], message["to"]}:
                raise MailboxError("not_found", "No matching message for this person.")
            if thread_id and thread_id != message["thread_id"]:
                raise MailboxError("thread_mismatch", "That message is in a different thread.")
            return self._deliver(
                you,
                message["link_id"],
                body,
                thread_id=message["thread_id"],
                idempotency_key=idempotency_key,
            )
        assert thread_id is not None
        link = self._link_for_thread(you, thread_id)
        return self._deliver(
            you,
            link["link_id"],
            body,
            thread_id=thread_id,
            idempotency_key=idempotency_key,
        )

    def list_inbox(
        self,
        email: str,
        link_id: str | None = None,
        unread_only: bool = False,
        limit: int = 20,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        you = _email(email)
        size = _limit(limit)
        if link_id:
            # Mail already delivered stays readable after the pairing is turned off, until
            # it expires (or someone deletes stored messages). Only party membership counts.
            self._require_party(you, link_id)
        mine = self._mine(you)
        entries = self._inbox_index(you, link_id, unread_only)
        start = 0
        if cursor:
            ids = [entry["msg_id"] for entry in entries]
            if cursor not in ids:
                raise MailboxError(
                    "invalid_cursor",
                    "The inbox cursor is not valid. Call list_inbox again without it.",
                )
            start = ids.index(cursor) + 1
        messages: list[dict[str, Any]] = []
        index = start
        while index < len(entries) and len(messages) < size:
            entry = entries[index]
            message = self._message(entry["msg_id"])
            index += 1
            if message is None or message["to"] not in mine:
                continue
            messages.append({**message, "link_status": entry["link_status"]})
        next_cursor = messages[-1]["msg_id"] if messages and index < len(entries) else None
        return {
            "content_trust": "untrusted_peer",
            "handling": HANDLING,
            "messages": [self._public_message(row) for row in messages],
            "next_cursor": next_cursor,
        }

    def check_messages(self, email: str, since: str | None = None) -> dict[str, Any]:
        you = _email(email)
        after = _parse_since(since) if since else None
        entries = self._inbox_index(you, None, unread_only=True)
        visible = entries
        if after is not None:
            visible = [entry for entry in entries if entry["created"] > after]
        previews = []
        mine = self._mine(you)
        for entry in visible:
            if len(previews) == 5:
                break
            message = self._message(entry["msg_id"])
            if message is None or message["to"] not in mine:
                continue
            previews.append(
                {
                    "msg_id": message["msg_id"],
                    "link_id": message["link_id"],
                    "from": message["from"],
                    **_from_assistant(message),
                    "preview": preview_untrusted(message["body"]),
                    "created_at": message["created_at"],
                    "thread_id": message["thread_id"],
                    "link_status": entry["link_status"],
                }
            )
        return {
            "content_trust": "untrusted_peer",
            "handling": HANDLING,
            "unread_count": len(entries),
            "latest_preview": previews,
        }

    def mark_read(self, email: str, msg_ids: list[str]) -> dict[str, Any]:
        you = _email(email)
        if not msg_ids or len(msg_ids) > 50:
            raise MailboxError("invalid_input", "msg_ids must contain 1 to 50 ids.")
        marked = 0
        now = self._iso()
        mine = self._mine(you)
        for msg_id in msg_ids:
            message = self._message(msg_id)
            if message is None or message["to"] not in mine or message.get("read_at"):
                continue
            link = self._link(message["link_id"])
            if link is None or not link.get("same_account"):
                continue
            message["read_at"] = now
            self._save_message(message)
            self._mark_inbox_read(message["to"], message)
            marked += 1
        return {"ok": True, "marked": marked}

    def delete_messages(self, email: str, link_id: str) -> dict[str, Any]:
        """Delete every stored message on a pairing that is already off, for both people."""
        you = _email(email)
        link = self._require_party(you, link_id)
        if self._status(link) != "revoked":
            raise MailboxError(
                "invalid_state",
                "Turn the pairing off first. Messages on a pairing that is on are not deleted.",
                link_id=link["link_id"],
            )
        return {"link_id": link["link_id"], "purged_messages": self._purge(link["link_id"])}

    def _deliver(
        self,
        you: str,
        link_id: str,
        body: str,
        thread_id: str | None,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        key = (idempotency_key or "").strip() or None
        if key and not _TOKEN_SHAPE.fullmatch(key):
            raise MailboxError(
                "invalid_input",
                "idempotency_key must be 1–80 letters, numbers, underscores, or hyphens.",
            )
        if thread_id and not _TOKEN_SHAPE.fullmatch(thread_id):
            raise MailboxError(
                "invalid_input",
                "thread_id must be 1–80 letters, numbers, underscores, or hyphens.",
            )
        party = self._require_party(you, link_id)
        # An invite nobody joined yet is not known to be either kind; it is just pending.
        if not party.get("same_account") and self._peer(party["link_id"]):
            # Another person's assistant never reaches yours, not even with text.
            raise MailboxError("peer_mail_off", PEER_MAIL_OFF, link_id=party["link_id"])
        link = self._require_active(you, link_id)
        _check_body(body)
        peer = self._other(link, you)
        sender = self._addr(link, you)
        if link.get("same_account"):
            if sender is None:
                raise MailboxError(
                    "not_found",
                    "That pairing is between two of your other assistants.",
                    link_id=link["link_id"],
                )
            # From here on the sender is this assistant, not the whole account. The hourly
            # cap still counts the account (see _charge_send).
            you = sender
        if peer is None:
            raise MailboxError(
                "link_pending",
                "This link is not active yet.",
                link_id=link["link_id"],
                status=self._status(link),
            )
        idem_key = f"bridge:idem:{you}:{key}" if key else None
        if idem_key:
            existing = self.store.get(idem_key)
            if existing:
                return self._finish_idem(existing, idem_key, you, link, peer, body, thread_id)
        thread = thread_id or _id("thr")
        now = self._now()
        message = {
            "msg_id": _id("msg"),
            "link_id": link["link_id"],
            "from": you,
            "to": peer,
            **_labels(link, you),
            "body": body,
            "thread_id": thread,
            "created_at": _iso(now),
            "read_at": None,
            "expires_at": _iso(now + MESSAGE_TTL),
        }
        pending = _pending_token(message, thread_id or "", now, body)
        if idem_key and not self.store.set_if_absent(idem_key, pending, ex=MESSAGE_TTL):
            winner = self.store.get(idem_key) or ""
            if not winner:
                raise MailboxError(
                    "idempotency_conflict",
                    "That idempotency key was already used with a different message.",
                )
            return self._finish_idem(winner, idem_key, you, link, peer, body, thread_id)
        try:
            self._charge_once(you, link["link_id"], message["msg_id"])
        except MailboxError:
            self._release_pending(idem_key, pending, peer, message["msg_id"])
            raise
        wake = self._keep_wake(message["msg_id"], _wake_view(self._publish(message), link, peer))
        if idem_key:
            self.store.set(idem_key, message["msg_id"], ex=MESSAGE_TTL)
        return _sent(message, replay=False, wake=wake)

    def _finish_idem(
        self,
        token: str,
        idem_key: str,
        you: str,
        link: dict[str, Any],
        peer: str,
        body: str,
        thread_id: str | None,
    ) -> dict[str, Any]:
        """Finish or replay a reserved send. A pending key is not success until it is queued."""
        pending = _split_pending(token)
        if pending is None:
            return self._replay(token, you, link["link_id"], body, thread_id)
        msg_id, thread, client_thread, created, digest = pending
        if _digest(link["link_id"], client_thread, body) != digest:
            raise MailboxError(
                "idempotency_conflict",
                "That idempotency key was already used with a different message.",
            )
        if thread_id and thread_id != thread:
            raise MailboxError(
                "idempotency_conflict",
                "That idempotency key was already used with a different message.",
            )
        message = self._message(msg_id)
        if message is None:
            message = {
                "msg_id": msg_id,
                "link_id": link["link_id"],
                "from": you,
                "to": peer,
                **_labels(link, you),
                "body": body,
                "thread_id": thread,
                "created_at": _iso(created),
                "read_at": None,
                "expires_at": _iso(created + MESSAGE_TTL),
            }
        elif (
            message["from"] != you
            or message["body"] != body
            or message["link_id"] != link["link_id"]
            or message["thread_id"] != thread
        ):
            raise MailboxError(
                "idempotency_conflict",
                "That idempotency key was already used with a different message.",
            )
        already_queued = self._queued(peer, msg_id)
        try:
            self._charge_once(you, link["link_id"], msg_id)
        except MailboxError as exc:
            if exc.code == "rate_limited" and not already_queued:
                self._release_pending(idem_key, token, peer, msg_id)
            raise
        wake = self._keep_wake(msg_id, _wake_view(self._publish(message), link, peer))
        self.store.set(idem_key, msg_id, ex=MESSAGE_TTL)
        return _sent(message, replay=already_queued, wake=wake)

    def _release_pending(self, idem_key: str | None, pending: str, peer: str, msg_id: str) -> None:
        if idem_key and self.store.get(idem_key) == pending and not self._queued(peer, msg_id):
            self.store.delete(idem_key)

    def _charge_once(self, you: str, link_id: str, msg_id: str) -> None:
        """Count this msg_id once. A second caller waits out the charge instead of sending early."""
        flag = f"bridge:sent:{msg_id}"
        if self.store.get(flag) == "1":
            return
        if not self.store.set_if_absent(flag, "charging", ex=60):
            if self.store.get(flag) == "1":
                return
            raise MailboxError(
                "retry",
                "That send is still finishing. Retry the same idempotency key.",
            )
        try:
            self._charge_send(you, link_id)
        except MailboxError:
            self.store.delete(flag)
            raise
        self.store.set(flag, "1", ex=MESSAGE_TTL)

    def _publish(self, message: dict[str, Any]) -> dict[str, Any]:
        """Save the body, then queue the id. A second call does not insert another copy."""
        self._save_message(message)
        link_id = message["link_id"]
        thread = message["thread_id"]
        self.store.set(f"bridge:thread:{link_id}:{thread}", link_id, ex=MESSAGE_TTL)
        token = self._inbox_token(message, read=False)
        remaining = max(int(self._stamp(message["expires_at"]) - self._now()), 1)
        self.store.set(f"bridge:row:{message['msg_id']}", token, ex=remaining)
        inbox_key = f"bridge:inbox:{message['to']}"
        # Reading the inbox prunes it too, but a recipient who never reads would
        # otherwise keep a row for every message ever sent to them.
        self.store.ldrop_expired(inbox_key, int(self._now()))
        self._push_once(inbox_key, message["msg_id"], token)
        self._push_once(f"bridge:linkmsgs:{link_id}", message["msg_id"], message["msg_id"])
        thread_key = f"bridge:threadmsgs:{link_id}:{thread}"
        self._push_once(thread_key, message["msg_id"], message["msg_id"])
        return self._maybe_wake(message)

    def _push_once(self, key: str, msg_id: str, value: str) -> None:
        """Queue `value` unless this list already has `msg_id`. The mark follows the push."""
        mark = f"bridge:queued:{key}:{msg_id}"
        if self.store.get(mark) and self._list_has(key, msg_id):
            return
        if not self._list_has(key, msg_id):
            self.store.lpush(key, value)
        self.store.set(mark, "1", ex=MESSAGE_TTL)

    def _list_has(self, key: str, msg_id: str) -> bool:
        prefix = f"{msg_id}|"
        return any(
            item == msg_id or item.startswith(prefix) for item in self.store.lrange(key, 0, -1)
        )

    def _queued(self, peer: str, msg_id: str) -> bool:
        return self._list_has(f"bridge:inbox:{peer}", msg_id)

    def _inbox_token(self, message: dict[str, Any], read: bool) -> str:
        created = int(self._stamp(message["created_at"]))
        expires = int(self._stamp(message["expires_at"]))
        flag = "0" if read else "1"
        return f"{message['msg_id']}|{message['link_id']}|{created}|{expires}|{flag}"

    def _mark_inbox_read(self, you: str, message: dict[str, Any]) -> None:
        inbox = f"bridge:inbox:{you}"
        read_token = self._inbox_token(message, read=True)
        unread_token = self._inbox_token(message, read=False)
        stored = self.store.get(f"bridge:row:{message['msg_id']}")
        if stored and stored not in (read_token, unread_token):
            self.store.lreplace(inbox, stored, read_token)
        self.store.lreplace(inbox, unread_token, read_token)
        remaining = max(int(self._stamp(message["expires_at"]) - self._now()), 1)
        self.store.set(f"bridge:row:{message['msg_id']}", read_token, ex=remaining)

    def _replay(
        self, msg_id: str, you: str, link_id: str, body: str, thread_id: str | None
    ) -> dict[str, Any]:
        message = self._message(msg_id)
        same = (
            message is not None
            and message["from"] == you
            and message["body"] == body
            and message["link_id"] == link_id
            and (not thread_id or message["thread_id"] == thread_id)
        )
        if not same:
            raise MailboxError(
                "idempotency_conflict",
                "That idempotency key was already used with a different message.",
            )
        return _sent(message, replay=True, wake=self._kept_wake(msg_id))

    def _keep_wake(self, msg_id: str, view: dict[str, Any]) -> dict[str, Any]:
        """Remember what the sender was told, so a retry with the same idempotency key
        (the usual move after a timeout) gets the same wake result."""
        self.store.set(f"bridge:wakeview:{msg_id}", json.dumps(view), ex=MESSAGE_TTL)
        return view

    def _kept_wake(self, msg_id: str) -> dict[str, Any] | None:
        raw = self.store.get(f"bridge:wakeview:{msg_id}")
        try:
            view = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            return None
        return view if isinstance(view, dict) else None

    def _attempts_left(self, you: str) -> None:
        """Refuse when this hour's wrong invite codes are already over the limit."""
        bucket = int(self._now()) // HOUR
        raw = self.store.get(f"bridge:attempts:{you}:{bucket}")
        try:
            count = int(raw) if raw else 0
        except ValueError:
            count = 0
        if count >= LINK_REQUESTS_PER_HOUR:
            raise MailboxError(
                "rate_limited",
                "Too many pairing attempts this hour.",
                retry_after_seconds=_retry(self._now(), bucket),
            )

    def _charge_attempt(self, you: str) -> None:
        bucket = int(self._now()) // HOUR
        count = self.store.incr(f"bridge:attempts:{you}:{bucket}", ex=HOUR)
        if count > LINK_REQUESTS_PER_HOUR:
            raise MailboxError(
                "rate_limited",
                "Too many pairing attempts this hour.",
                retry_after_seconds=_retry(self._now(), bucket),
            )

    def _charge_send(self, you: str, link_id: str) -> None:
        you = you.split("#", 1)[0]
        bucket = int(self._now()) // HOUR
        retry = _retry(self._now(), bucket)
        on_link = self.store.incr(f"bridge:rate:{you}:{link_id}:{bucket}", ex=HOUR)
        if on_link > PER_LINK_PER_HOUR:
            raise MailboxError(
                "rate_limited",
                "This link hit its hourly message cap.",
                retry_after_seconds=retry,
            )
        on_user = self.store.incr(f"bridge:rate:{you}:{bucket}", ex=HOUR)
        if on_user > PER_USER_PER_HOUR:
            raise MailboxError(
                "rate_limited",
                "This account hit its hourly message cap.",
                retry_after_seconds=retry,
            )

    def owner_messages(self, email: str, limit: int = 100) -> list[dict[str, Any]]:
        """Mail between this person's own assistants that has not expired, newest first,
        for the dashboard's Mailbox page. Reading it here marks nothing as read, so an
        assistant still sees its unread mail. Bodies are untrusted text: the page shows
        them escaped, never as markup."""
        you = _email(email)
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        statuses: dict[str, str | None] = {}
        peer_links: set[str] = set()
        names: dict[str, str] = {}
        for link_id in self._user_link_ids(you):
            link = self._link(link_id)
            if link is None or not link.get("same_account"):
                continue
            for side in ("a", "b"):
                grant = link.get(f"grant_{side}")
                if not grant:
                    continue
                address = _self_addr(you, str(grant))
                names[address] = str(link.get(f"label_{side}") or "Assistant")
                self._read_inbox(
                    f"bridge:inbox:{address}", link_id, False, rows, seen, statuses, peer_links
                )
        rows.sort(key=lambda row: row["created"], reverse=True)
        out: list[dict[str, Any]] = []
        for row in rows:
            if len(out) >= limit:
                break
            message = self._message(row["msg_id"])
            if message is None:
                continue
            out.append(
                {
                    "msg_id": message["msg_id"],
                    "link_id": message["link_id"],
                    "thread_id": message.get("thread_id"),
                    "from": message.get("from_assistant")
                    or names.get(message["from"], "Assistant"),
                    "to": names.get(message["to"], "Assistant"),
                    "body": str(message["body"]),
                    "created_at": message["created_at"],
                    "read_at": message.get("read_at"),
                    "link_status": row["link_status"],
                }
            )
        return out

    def _public_message(self, message: dict[str, Any]) -> dict[str, Any]:
        return {
            "msg_id": message["msg_id"],
            "link_id": message["link_id"],
            "from": message["from"],
            **_from_assistant(message),
            "body": present_untrusted(message["body"]),
            "body_trust": "untrusted_peer",
            "handling": HANDLING,
            "thread_id": message["thread_id"],
            "created_at": message["created_at"],
            "read_at": message.get("read_at"),
            "expires_at": message["expires_at"],
            "link_status": message.get("link_status", "active"),
        }

    def _inbox_index(
        self, you: str, link_id: str | None, unread_only: bool
    ) -> list[dict[str, Any]]:
        """Newest-first ids from the inbox list. Message bodies are loaded later, per page.

        An assistant in a same-account pairing also has its own inbox; both are read."""
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        statuses: dict[str, str | None] = {}
        peer_links: set[str] = set()
        for address in sorted(self._mine(you)):
            self._read_inbox(
                f"bridge:inbox:{address}", link_id, unread_only, rows, seen, statuses, peer_links
            )
        # Mail between two people from before it was turned off: never shown, and deleted
        # for both people the first time either inbox is read.
        for stale in sorted(peer_links):
            try:
                self._purge(stale)
            except Exception:
                # Clean-up only: the mail is already hidden, so a failed delete must never
                # turn a read into an error. The next read tries again.
                logging.getLogger(__name__).warning("peer_mail_purge_failed", exc_info=True)
        rows.sort(key=lambda row: row["created"], reverse=True)
        return rows

    def _read_inbox(
        self,
        inbox_key: str,
        link_id: str | None,
        unread_only: bool,
        rows: list[dict[str, Any]],
        seen: set[str],
        statuses: dict[str, str | None],
        peer_links: set[str],
    ) -> None:
        self.store.ldrop_expired(inbox_key, int(self._now()))
        for raw in self.store.lrange(inbox_key, 0, -1):
            parsed = parse_inbox_token(raw)
            if parsed is None:
                self.store.lrem(inbox_key, raw)
                continue
            msg_id, token_link, created, expires, unread = parsed
            if msg_id in seen or expires <= self._now():
                continue
            seen.add(msg_id)
            if token_link not in statuses:
                link = self._link(token_link)
                if link is not None and not link.get("same_account"):
                    peer_links.add(token_link)
                    statuses[token_link] = None
                else:
                    statuses[token_link] = self._status(link) if link is not None else None
            if token_link in peer_links:
                continue
            if link_id and token_link != link_id:
                continue
            if unread_only and not unread:
                continue
            # Delivered mail stays readable after the pairing is turned off. Only mail on a
            # link that no longer exists at all is skipped.
            if statuses[token_link] is None:
                continue
            rows.append(
                {
                    "msg_id": msg_id,
                    "link_id": token_link,
                    "created": float(created),
                    "link_status": statuses[token_link],
                }
            )

    def _link_for_thread(self, you: str, thread_id: str) -> dict[str, Any]:
        active: list[dict[str, Any]] = []
        revoked: list[dict[str, Any]] = []
        for link_id in self._user_link_ids(you):
            if not self.store.get(f"bridge:thread:{link_id}:{thread_id}"):
                continue
            link = self._link(link_id)
            if link is None or you not in _parties(link, self._peer(link_id)):
                continue
            if not self._thread_has_person(link_id, thread_id, you):
                continue
            status = self._status(link)
            if status == "revoked":
                revoked.append(link)
            elif status == "active":
                active.append(link)
        if len(active) == 1:
            return active[0]
        if len(active) > 1:
            raise MailboxError(
                "thread_mismatch",
                "That thread id is in use on more than one of your links. Reply with msg_id.",
            )
        if len(revoked) == 1:
            return revoked[0]
        if not revoked:
            raise MailboxError("not_found", "No matching thread for this person.")
        raise MailboxError(
            "thread_mismatch",
            "That thread id is in use on more than one of your links. Reply with msg_id.",
        )

    def _thread_has_person(self, link_id: str, thread_id: str, you: str) -> bool:
        key = f"bridge:threadmsgs:{link_id}:{thread_id}"
        mine = self._mine(you)
        for msg_id in self.store.lrange(key, 0, -1):
            message = self._message(msg_id)
            if message and mine & {message["from"], message["to"]}:
                return True
        return False

    def _message(self, msg_id: str) -> dict[str, Any] | None:
        raw = self.store.get(f"bridge:msg:{msg_id}")
        if not raw:
            return None
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict) or self._stamp(str(data.get("expires_at"))) <= self._now():
            return None
        if data.get("body_enc"):
            body = self._open_body(str(data["body"]))
            if body is None:
                return None
            data["body"] = body
            data.pop("body_enc", None)
        return data

    def _open_body(self, sealed: str) -> str | None:
        if self._fernet is None or self._legacy_fernet is None:
            return None
        try:
            return str(self._fernet.decrypt(sealed.encode()).decode())
        except (InvalidToken, ValueError):
            pass
        # Mail from before the mailbox had its own key. ENCRYPTION_KEY also encrypts the
        # Drive sign-in vault, whose records are JSON objects, so a body that opens to one
        # is refused: it is a vault record put here to be read out, not mail. This branch
        # can go once mail from before the change has expired (MESSAGE_TTL, 14 days).
        try:
            body = str(self._legacy_fernet.decrypt(sealed.encode()).decode())
        except (InvalidToken, ValueError):
            return None
        try:
            if isinstance(json.loads(body), dict):
                logging.getLogger(__name__).warning("mailbox_body_not_mail_refused")
                return None
        except ValueError:
            pass
        return body

    def _save_message(self, message: dict[str, Any]) -> None:
        remaining = int(self._stamp(message["expires_at"]) - self._now())
        stored = dict(message)
        if self._fernet is not None:
            stored["body"] = self._fernet.encrypt(message["body"].encode()).decode()
            stored["body_enc"] = True
        self.store.set(f"bridge:msg:{message['msg_id']}", json.dumps(stored), ex=max(remaining, 1))

    def _purge(self, link_id: str) -> int:
        deleted = 0
        link = self._link(link_id)
        people = [link["email_a"]] if link else []
        peer = self._peer(link_id)
        if peer and peer not in people:
            people.append(peer)
        if link and link.get("same_account"):
            for side in ("a", "b"):
                if link.get(f"grant_{side}"):
                    people.append(_self_addr(link["email_a"], str(link[f"grant_{side}"])))
        for msg_id in self.store.lrange(f"bridge:linkmsgs:{link_id}", 0, -1):
            message = self._message(msg_id)
            row_key = f"bridge:row:{msg_id}"
            stored = self.store.get(row_key)
            if self.store.get(f"bridge:msg:{msg_id}") is not None:
                self.store.delete(f"bridge:msg:{msg_id}")
                deleted += 1
            self.store.delete(row_key)
            tokens = [msg_id]
            if stored:
                tokens.append(stored)
            if message is not None:
                tokens.append(self._inbox_token(message, read=False))
                tokens.append(self._inbox_token(message, read=True))
                thread_key = f"bridge:threadmsgs:{link_id}:{message['thread_id']}"
                self.store.lrem(thread_key, msg_id)
            for person in people:
                inbox_key = f"bridge:inbox:{person}"
                for token in tokens:
                    self.store.lrem(inbox_key, token)
        self.store.delete(f"bridge:linkmsgs:{link_id}")
        return deleted
