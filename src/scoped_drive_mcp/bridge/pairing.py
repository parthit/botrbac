"""Pairing: invites, joining, approvals, a link's status, ending it, and who is on it.

One part of `Mailbox` (see `mailbox.py`). The other two are mail (`mail.py`) and wake-up
webhooks (`webhooks.py`).
"""

import json
import logging
import secrets
import threading
from collections.abc import Callable
from typing import Any

from ..store import KeyValueStore
from .common import (
    _INVITE_ALPHABET,
    INVITE_TTL,
    PEER_TTL,
    MailboxError,
    _email,
    _id,
    _iso,
    _next_step,
    _parties,
    _self_addr,
    current_assistant,
)


class PairingMixin:
    # Set by `Mailbox.__init__` (mailbox.py).
    store: KeyValueStore
    strict: bool
    base_url: str
    on_unpaired: Callable[[str, str], None] | None
    _lock: threading.Lock
    # The clock, from `Mailbox`.
    _now: Callable[[], float]
    _iso: Callable[..., str]
    _stamp: Callable[[str], float]
    # From `MailMixin`: the unread count in `summary`, deleting mail on `revoke`, and the
    # hourly limit on starting or joining a pairing.
    _attempts_left: Callable[[str], None]
    _charge_attempt: Callable[[str], None]
    _inbox_index: Callable[[str, str | None, bool], list[dict[str, Any]]]
    _purge: Callable[[str], int]
    # From `WebhookMixin`: an assistant that is removed loses its wake-up webhook.
    _index_hook: Callable[[str, str, bool], None]

    def request_link(
        self, email: str, invite_code: str | None = None, new_invite: bool = False
    ) -> dict[str, Any]:
        """Join with `invite_code`, or start a pairing.

        Without a code, an invite of yours that nobody joined yet and that has not expired
        is returned again (`reused: true`) instead of minting another one, so repeated
        calls do not leave a trail of dead invites. `new_invite=True` always starts a
        fresh one, for pairing with a second person in parallel.
        """
        you = _email(email)
        code = (invite_code or "").strip().upper()
        if not code:
            if not new_invite:
                open_invite = self._open_invite(you)
                if open_invite is not None:
                    return {**self._public_link(open_invite, you), "reused": True}
            return {**self._create(you), "reused": False}
        return {**self._redeem(you, code), "reused": False}

    def summary(self, email: str) -> dict[str, int]:
        """Counts for the dashboard: pairings that need this person's approval, active
        pairings (split into other people and your own assistants), and unread mail
        (inbox rows only, no bodies)."""
        you = _email(email)
        needs = active = own = 0
        for link_id in self._user_link_ids(you):
            link = self._link(link_id)
            if link is None or you not in _parties(link, self._peer(link_id)):
                continue
            status = self._status(link)
            if status == "active":
                active += 1
                own += 1 if link.get("same_account") else 0
            elif status == "pending_approval":
                side = "a" if you == link["email_a"] else "b"
                if not self._approved(link_id, side, link=link):
                    needs += 1
        unread = len(self._inbox_index(you, None, unread_only=True))
        return {
            "needs_approval": needs,
            "active": active,
            "people": active - own,
            "own": own,
            "unread": unread,
        }

    def needs_approval_count(self, email: str) -> int:
        """Pairings waiting on this person's approval. Cheap enough for every page's nav."""
        you = _email(email)
        count = 0
        for link_id in self._user_link_ids(you):
            peer = self._peer(link_id)
            if not peer or self._revoked(link_id):
                continue
            link = self._link(link_id)
            if link is None or you not in _parties(link, peer):
                continue
            side = "a" if you == link["email_a"] else "b"
            if not self._approved(link_id, side, peer, link):
                count += 1
        return count

    def list_links(self, email: str) -> dict[str, Any]:
        you = _email(email)
        links = []
        for link_id in self._user_link_ids(you):
            link = self._link(link_id)
            if link is None or you not in _parties(link, self._peer(link_id)):
                continue
            links.append(self._public_link(link, you))
        links.sort(key=lambda item: item["created_at"], reverse=True)
        return {"you": you, "links": links}

    def active_peers(self, email: str) -> list[str]:
        """Emails of people with an active (both approved, not revoked) link to `email`.

        This is what external sharing trusts: a peer's assistant may read the items that
        person put on their shared list. It is read fresh on every call, so turning a
        pairing off on the Sharing page ends that access at once.
        """
        you = _email(email)
        peers: set[str] = set()
        for link_id in self._user_link_ids(you):
            link = self._link(link_id)
            if link is None or link.get("same_account") or self._status(link) != "active":
                continue
            other = self._other(link, you)
            if other and other != you:
                peers.add(other)
        return sorted(peers)

    def is_linked(self, a: str, b: str) -> bool:
        """Whether `a` and `b` share an active link."""
        try:
            other = _email(b)
        except MailboxError:
            return False
        return other in self.active_peers(a)

    def revoke(self, email: str, link_id: str, purge: bool = False) -> dict[str, Any]:
        """Turn a pairing off. Sending, replying and Sharing between the two stop at once.

        Mail already delivered stays readable by the person it was sent to until it expires,
        unless `purge` deletes every stored message on the link for both people.
        """
        you = _email(email)
        link = self._require_party(you, link_id)
        status = self._status(link)
        already = status == "revoked"
        if not already:
            self._end(link, you, "turned_off" if status == "active" else "cancelled")
        else:
            self._seal_ended(link)
        deleted = self._purge(link["link_id"]) if purge else 0
        return {
            "link_id": link["link_id"],
            "status": "revoked",
            "purged_messages": deleted,
            "already_revoked": already,
        }

    def cancel_invite(self, email: str, link_id: str) -> dict[str, Any]:
        """The creator withdraws an invite nobody joined. The code stops working and the
        card goes away."""
        you = _email(email)
        link = self._require_party(you, link_id)
        if link["email_a"] != you or self._peer(link["link_id"]):
            raise MailboxError(
                "invalid_state",
                "Someone already joined with this invite. Approve, deny or turn it off instead.",
                link_id=link["link_id"],
            )
        if not self._revoked(link["link_id"]):
            self._end(link, you, "cancelled")
        self.store.delete(f"bridge:invite:{link['invite_code']}")
        self.store.hdel(f"bridge:user:{you}", link["link_id"])
        return {"link_id": link["link_id"], "status": "revoked", "removed": True}

    def dismiss(self, email: str, link_id: str) -> dict[str, Any]:
        """Remove a dead card (off, declined or expired) from this person's list only."""
        you = _email(email)
        link = self._require_party(you, link_id)
        status = self._status(link)
        expired = status == "awaiting_peer" and not self._invite_live(link)
        if status != "revoked" and not expired:
            raise MailboxError(
                "invalid_state",
                "Only a pairing that is off, declined or expired can be removed.",
                link_id=link["link_id"],
                status=status,
            )
        if expired:
            self._end(link, you, "cancelled")
        self.store.hdel(f"bridge:user:{you}", link["link_id"])
        return {"link_id": link["link_id"], "removed": True}

    def decide(
        self, email: str, link_id: str, decision: str, expect_peer: str | None = None
    ) -> dict[str, Any]:
        """`expect_peer` is the account the person was looking at when they chose. An
        approval is refused if someone else is joined by the time it arrives."""
        you = _email(email)
        if decision not in ("approve", "deny"):
            raise MailboxError("invalid_input", "Choose approve or deny.")
        link = self._require_party(you, link_id)
        status = self._status(link)
        if status == "revoked":
            raise MailboxError(
                "link_revoked",
                "This link has been revoked.",
                link_id=link_id,
                status="revoked",
            )
        side = "a" if you == link["email_a"] else "b"
        if decision == "deny":
            # A Decline from a stale page on a pairing that is already on is a turn-off:
            # it was on and mail may have moved, so it must not read as "never turned on".
            self._end(link, you, "turned_off" if status == "active" else "declined")
            return {"link_id": link["link_id"], "status": "revoked"}
        # Who joined is read once here and used for every check below and for what the
        # approval stores, so it cannot be one account for the check and another after.
        peer = self._peer(link["link_id"])
        if not peer:
            raise MailboxError(
                "waiting_for_peer",
                "The other person has not joined yet, so there is no account to confirm.",
                link_id=link["link_id"],
                status=status,
                invite_code=link["invite_code"],
            )
        owner_of_link = str(link["email_a"])
        if link.get("same_account"):
            # A pairing of one person's own assistants is that person's alone to approve,
            # and only while the account recorded as joined is theirs too.
            if you != owner_of_link or peer != owner_of_link:
                raise MailboxError(
                    "peer_changed",
                    "This pairing is not between two of your own assistants any more. "
                    "Turn it off and start a new one.",
                    link_id=link["link_id"],
                    status=status,
                )
            other = owner_of_link
        else:
            if peer == owner_of_link:
                raise MailboxError(
                    "peer_changed",
                    "The account on this pairing is not the one this page showed. Reload "
                    "the page and check who is asking before you approve.",
                    link_id=link["link_id"],
                    status=status,
                )
            other = peer if you == owner_of_link else owner_of_link
        if expect_peer and other != expect_peer.strip().lower():
            raise MailboxError(
                "peer_changed",
                "The account on this pairing is not the one this page showed. Reload the "
                "page and check who is asking before you approve.",
                link_id=link["link_id"],
                status=status,
            )
        if link.get("same_account"):
            # One person, one click: approving covers both of their assistants.
            for both in ("a", "b"):
                self.store.hset(f"bridge:appr:{link['link_id']}", both, self._approval(link, peer))
        else:
            self.store.hset(f"bridge:appr:{link['link_id']}", side, self._approval(link, peer))
        updated = self._status(link)
        return {"link_id": link["link_id"], "status": updated}

    def _create(self, you: str) -> dict[str, Any]:
        self._charge_attempt(you)
        now = self._now()
        expires = now + INVITE_TTL
        with self._lock:
            for _ in range(5):
                code = "".join(secrets.choice(_INVITE_ALPHABET) for _ in range(10))
                link_id = _id("lnk")
                if not self.store.set_if_absent(f"bridge:invite:{code}", link_id, ex=INVITE_TTL):
                    continue
                link = {
                    "link_id": link_id,
                    "email_a": you,
                    "invite_code": code,
                    "created_at": _iso(now),
                    "invite_expires_at": _iso(expires),
                }
                assistant = current_assistant.get()
                if assistant is not None:
                    link["grant_a"] = assistant.grant_id
                    link["label_a"] = assistant.label
                self.store.set(f"bridge:link:{link_id}", json.dumps(link))
                self.store.hset(f"bridge:user:{you}", link_id, link["created_at"])
                return self._public_link(link, you)
        raise MailboxError("internal_error", "Could not create an invite. Try again.")

    def _redeem(self, you: str, code: str) -> dict[str, Any]:
        # Checked before the code is looked up: past the limit even a right code is
        # refused, or the limit would not slow guessing at all.
        self._attempts_left(you)
        link_id = self.store.get(f"bridge:invite:{code}")
        if not link_id:
            self._charge_attempt(you)
            raise MailboxError("invite_not_found", "That invite code does not exist.")
        link = self._link(link_id)
        if link is None or link["invite_code"] != code:
            self._charge_attempt(you)
            raise MailboxError("invite_not_found", "That invite code does not exist.")
        if you == link["email_a"] and self._self_join(link):
            return self._redeem_self(you, link)
        if link.get("same_account"):
            assistant = current_assistant.get()
            grants = (link.get("grant_a"), link.get("grant_b"))
            if assistant is not None and assistant.grant_id not in grants:
                self._charge_attempt(you)
                raise MailboxError("invite_taken", "That invite was already used.")
        if you == link["email_a"] or you == self._peer(link_id):
            self.store.hset(f"bridge:user:{you}", link["link_id"], link["created_at"])
            return self._public_link(link, you)
        if self._revoked(link["link_id"]):
            self._charge_attempt(you)
            raise MailboxError(
                "link_revoked", "That invite was revoked.", link_id=link_id, status="revoked"
            )
        if self._stamp(link["invite_expires_at"]) <= self._now():
            self._charge_attempt(you)
            raise MailboxError("invite_not_found", "That invite code does not exist.")
        existing = self._live_link_between(you, str(link["email_a"]))
        if existing is not None:
            raise MailboxError(
                "already_paired",
                f"You already have a pairing with {link['email_a']}. Use that one, or turn it "
                "off on the Sharing page (People) before joining a new one.",
                link_id=existing["link_id"],
                status=self._status(existing),
                manage_url=self._page(),
            )
        claim = f"bridge:peer:{link_id}"
        if not self.store.set_if_absent(claim, you, ex=PEER_TTL):
            current = self.store.get(claim)
            if current != you:
                self._charge_attempt(you)
                raise MailboxError(
                    "invite_taken", "That invite was already used by another person."
                )
        self.store.hset(f"bridge:user:{you}", link_id, link["created_at"])
        return self._public_link(link, you)

    def _self_join(self, link: dict[str, Any]) -> bool:
        """Whether this call is a different assistant of the invite's creator joining it.

        Only a known grant joining an invite another known grant made counts. Anything
        else (an API token, an invite from before grants were recorded, the creator asking
        again) keeps the old behaviour: the invite is handed back."""
        if link.get("same_account"):
            return False
        assistant = current_assistant.get()
        grant_a = link.get("grant_a")
        if assistant is None or not grant_a or assistant.grant_id == grant_a:
            return False
        peer = self._peer(link["link_id"])
        if peer is None:
            return True
        # A join that claimed the invite but did not finish writing the link: resume it.
        claim = self.store.get(f"bridge:selfclaim:{link['link_id']}")
        return peer == link["email_a"] and claim == assistant.grant_id

    def _redeem_self(self, you: str, link: dict[str, Any]) -> dict[str, Any]:
        """Join your own invite from another assistant: a same-account link."""
        assistant = current_assistant.get()
        assert assistant is not None
        link_id = link["link_id"]
        if self._revoked(link_id):
            self._charge_attempt(you)
            raise MailboxError(
                "link_revoked", "That invite was revoked.", link_id=link_id, status="revoked"
            )
        if not self._invite_live(link):
            self._charge_attempt(you)
            raise MailboxError("invite_not_found", "That invite code does not exist.")
        existing = self._live_self_link(you, {str(link["grant_a"]), assistant.grant_id})
        if existing is not None:
            raise MailboxError(
                "already_paired",
                "These two assistants are already paired. Use that pairing, or turn it off "
                "on the Sharing page (People) before joining a new one.",
                link_id=existing["link_id"],
                status=self._status(existing),
                manage_url=self._page(),
            )
        claim = f"bridge:selfclaim:{link_id}"
        peer_key = f"bridge:peer:{link_id}"
        taken = MailboxError("invite_taken", "That invite was already used.")
        # The first assistant to claim the invite wins; a second one of yours is refused.
        claimed = self.store.set_if_absent(claim, assistant.grant_id, ex=PEER_TTL)
        if not claimed and self.store.get(claim) != assistant.grant_id:
            self._charge_attempt(you)
            raise taken
        joined = self.store.set_if_absent(peer_key, you, ex=PEER_TTL)
        if not joined and self.store.get(peer_key) != you:
            self._charge_attempt(you)
            raise taken
        link = {
            **link,
            "same_account": True,
            "grant_b": assistant.grant_id,
            "label_b": assistant.label,
        }
        self.store.set(f"bridge:link:{link_id}", json.dumps(link))
        return self._public_link(link, you)

    def end_assistant_links(self, email: str, grant_id: str) -> int:
        """End this assistant's same-account links and open invites, and drop its wake-up
        hook (its access is gone)."""
        you = _email(email)
        slot = _self_addr(you, grant_id)
        self.store.delete(f"bridge:hook:{slot}")
        self.store.delete(f"bridge:hookerr:{slot}")
        self.store.delete(f"bridge:hooklast:{slot}")
        self._index_hook(you, slot, present=False)
        ended = 0
        for link_id in self._user_link_ids(you):
            link = self._link(link_id)
            if link is None or self._revoked(link_id):
                continue
            if link.get("same_account"):
                if grant_id not in (link.get("grant_a"), link.get("grant_b")):
                    continue
            elif link.get("grant_a") != grant_id or self._peer(link_id):
                continue
            status = self._status(link)
            self._end(link, you, "turned_off" if status == "active" else "cancelled")
            ended += 1
        return ended

    def relabel_assistant(self, email: str, grant_id: str, label: str) -> int:
        """The owner renamed one of their assistants. Its pairings named it when they were
        made, so give them the new name too. Mail already sent keeps the old one. Returns
        how many pairings changed."""
        you = _email(email)
        if not grant_id or not label:
            return 0
        changed = 0
        for link_id in self._user_link_ids(you):
            key = f"bridge:link:{link_id}"
            replace = getattr(self.store, "replace", None)
            for _attempt in range(4):
                raw = self.store.get(key)
                try:
                    link = json.loads(raw) if raw else None
                except json.JSONDecodeError:
                    link = None
                if not isinstance(link, dict) or not link.get("link_id"):
                    break
                # Only the side that is this person's: grant_a is always theirs when they
                # made the link; grant_b is theirs only on a pairing of their own assistants.
                sides = [
                    side
                    for side in ("a", "b")
                    if link.get(f"grant_{side}") == grant_id
                    and ((side == "a" and link.get("email_a") == you) or link.get("same_account"))
                    and link.get(f"label_{side}") != label
                ]
                if not sides:
                    break
                updated = json.dumps({**link, **{f"label_{side}": label for side in sides}})
                if replace is None:
                    self.store.set(key, updated)
                elif not replace(key, raw, updated):
                    continue
                changed += 1
                break
            else:
                # Lost every race on this record. It keeps the old name until the next rename.
                logging.getLogger(__name__).warning("relabel_link_gave_up")
        return changed

    def _public_link(self, link: dict[str, Any], you: str) -> dict[str, Any]:
        """One pairing as this person sees it.

        `status` is awaiting_peer, pending_approval, active or revoked, plus two values
        that only describe a dead link: `declined` (someone chose Deny; it behaves exactly
        like revoked) and `expired` (an invite nobody joined in time). `ended_reason`,
        `ended_by` and `ended_at` say who ended a link and how, when that was recorded.
        """
        if link.get("same_account"):
            return self._public_self_link(link, you)
        peer = self._other(link, you)
        status = self._status(link)
        you_approved = self._approved(
            link["link_id"], "a" if you == link["email_a"] else "b", link=link
        )
        peer_approved = False
        if peer:
            peer_side = "b" if you == link["email_a"] else "a"
            peer_approved = self._approved(link["link_id"], peer_side, link=link)
        page = self._page()
        code_live = self._invite_live(link)
        show_code = status in ("awaiting_peer", "pending_approval") and code_live
        needs_you = status == "pending_approval" and not you_approved
        ended = self._ended(link["link_id"]) if status == "revoked" else None
        shown = status
        if ended is not None and ended.get("how") == "declined":
            shown = "declined"
        elif status == "awaiting_peer" and not code_live:
            shown = "expired"
        return {
            "link_id": link["link_id"],
            "status": shown,
            "you": you,
            "you_approved": you_approved,
            "peer_approved": peer_approved,
            "peer_email": peer,
            # A pairing with another person shares documents only. It never carries mail.
            "mailbox": False,
            "created_by_you": link["email_a"] == you,
            **({"invite_code": link["invite_code"]} if show_code else {}),
            **(
                {"invite_expires_at": link["invite_expires_at"]}
                if status == "awaiting_peer"
                else {}
            ),
            **({"approval_url": page} if needs_you else {}),
            **(
                {
                    "ended_reason": ended.get("how"),
                    "ended_by": ended.get("by"),
                    "ended_at": ended.get("at"),
                }
                if ended
                else {}
            ),
            "manage_url": page,
            "created_at": link["created_at"],
            "next_step": _next_step(shown, you_approved, peer, ended, you),
        }

    def _public_self_link(self, link: dict[str, Any], you: str) -> dict[str, Any]:
        """A pairing between two assistants of one person, as that person (or one of the
        two assistants) sees it."""
        side = self._side(link, you)
        other = {"a": "b", "b": "a"}.get(side or "", "b")
        status = self._status(link)
        ended = self._ended(link["link_id"]) if status == "revoked" else None
        approved = self._approved(link["link_id"], "a", link=link)
        page = self._page()
        needs_you = status == "pending_approval" and not approved
        you_label = str(link.get(f"label_{side}") or link.get("label_a") or "") if side else None
        peer_label = str(link.get(f"label_{other}") or "your other assistant")
        if status == "pending_approval":
            step = "Approve on the Sharing page (People) to connect your two assistants."
        elif status == "active":
            step = (
                f"Your assistants are connected. Send to {peer_label} on this link_id."
                if side
                else "Your assistants are connected."
            )
        else:
            step = (
                "This pairing is off. Neither assistant can send on it. Mail already "
                "delivered stays readable until it expires. To pair them again, ask one of "
                "them for a new invite code."
            )
        return {
            "link_id": link["link_id"],
            "status": status,
            "same_account": True,
            "mailbox": True,
            "you": you,
            "you_label": you_label,
            "you_approved": approved,
            "peer_approved": approved,
            "peer_email": you,
            "peer_label": peer_label,
            "assistants": [link.get("label_a") or "Assistant", link.get("label_b") or "Assistant"],
            "grant_ids": [link.get("grant_a"), link.get("grant_b")],
            "created_by_you": side in (None, "a"),
            **({"approval_url": page} if needs_you else {}),
            **(
                {
                    "ended_reason": ended.get("how"),
                    "ended_by": ended.get("by"),
                    "ended_at": ended.get("at"),
                }
                if ended
                else {}
            ),
            "manage_url": page,
            "created_at": link["created_at"],
            "next_step": step,
        }

    def _page(self) -> str:
        return f"{self.base_url}/sharing?tab=people" if self.base_url else "/sharing?tab=people"

    def _invite_live(self, link: dict[str, Any]) -> bool:
        return self._stamp(link["invite_expires_at"]) > self._now()

    def _open_invite(self, you: str) -> dict[str, Any] | None:
        """Newest invite this person created that nobody joined, still live."""
        found: dict[str, Any] | None = None
        for link_id in self._user_link_ids(you):
            if self._revoked(link_id) or self._peer(link_id):
                continue
            link = self._link(link_id)
            if link is None or link["email_a"] != you or not self._invite_live(link):
                continue
            assistant = current_assistant.get()
            if assistant is not None and link.get("grant_a") not in (None, assistant.grant_id):
                continue
            if self.store.get(f"bridge:invite:{link['invite_code']}") != link_id:
                continue
            if found is None or link["created_at"] > found["created_at"]:
                found = link
        return found

    def _live_link_between(self, you: str, other: str) -> dict[str, Any] | None:
        """An active or pending pairing between these two people, if there is one."""
        for link_id in self._user_link_ids(you):
            link = self._link(link_id)
            if link is None or self._status(link) not in ("active", "pending_approval"):
                continue
            if not link.get("same_account") and self._other(link, you) == other:
                return link
        return None

    def _live_self_link(self, you: str, grants: set[str]) -> dict[str, Any] | None:
        """An active or pending same-account pairing between exactly these two grants."""
        for link_id in self._user_link_ids(you):
            link = self._link(link_id)
            if link is None or not link.get("same_account"):
                continue
            if self._status(link) not in ("active", "pending_approval"):
                continue
            pair = {str(link.get("grant_a")), str(link.get("grant_b"))}
            if grants == pair:
                return link
        return None

    def _end(self, link: dict[str, Any], you: str, how: str) -> None:
        """Mark a link dead. `bridge:revoked:` is what every check reads; `bridge:ended:`
        only records who ended it and how, for the people looking at it."""
        at = self._iso()
        record = json.dumps({"by": you, "at": at, "how": how})
        self.store.set_if_absent(f"bridge:ended:{link['link_id']}", record, ex=PEER_TTL)
        self.store.set(f"bridge:revoked:{link['link_id']}", at)
        # Also written into the signed link record, and both approvals are removed: a
        # pairing that was turned off stays off if the marker above goes missing.
        self._mark_ended(link, at)
        for side in ("a", "b"):
            self.store.hdel(f"bridge:appr:{link['link_id']}", side)
        peer = self._peer(link["link_id"])
        if self.on_unpaired is None or link.get("same_account") or not peer:
            return
        a = str(link["email_a"])
        if self.is_linked(a, peer):
            return  # another pairing between the same two people is still on
        try:
            self.on_unpaired(a, peer)
        except Exception:
            # The pairing is already off, which ends access on its own. A person named on
            # an item stays named; they still read nothing until a pairing is approved.
            logging.getLogger(__name__).warning("unpair_prune_failed", exc_info=True)

    def _mark_ended(self, link: dict[str, Any], at: str) -> None:
        """Write `ended_at` into the link record without losing a change someone else
        makes to that record at the same moment: compare-and-swap, a few tries."""
        key = f"bridge:link:{link['link_id']}"
        replace = getattr(self.store, "replace", None)
        for _ in range(4):
            raw = self.store.get(key)
            try:
                current = json.loads(raw) if raw else None
            except json.JSONDecodeError:
                current = None
            if not isinstance(current, dict):
                current, raw = link, None
            ended = json.dumps({**current, "ended_at": at})
            if raw is None or replace is None:
                self.store.set(key, ended)
                return
            if replace(key, raw, ended):
                return
        # Lost every race, which a person clicking cannot cause. Off is the safe side.
        self.store.set(key, json.dumps({**link, "ended_at": at}))

    def _ended(self, link_id: str) -> dict[str, Any] | None:
        raw = self.store.get(f"bridge:ended:{link_id}")
        if not raw:
            return None
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None

    def _require_party(self, you: str, link_id: str) -> dict[str, Any]:
        link = self._link(link_id)
        if link is None or you not in _parties(link, self._peer(link_id)):
            raise MailboxError("not_found", "No matching link for this person.")
        return link

    def _require_active(self, you: str, link_id: str) -> dict[str, Any]:
        link = self._require_party(you, link_id)
        status = self._status(link)
        if status == "revoked":
            raise MailboxError(
                "link_revoked", "This link has been revoked.", link_id=link_id, status=status
            )
        if status != "active":
            raise MailboxError(
                "link_pending",
                "This link is not active yet. Both people have to approve it.",
                link_id=link_id,
                status=status,
            )
        return link

    def _status(self, link: dict[str, Any]) -> str:
        link_id = link["link_id"]
        if self._revoked(link_id, link):
            return "revoked"
        peer = self._peer(link_id)
        if not peer:
            return "awaiting_peer"
        if self._approved(link_id, "a", peer, link) and self._approved(link_id, "b", peer, link):
            return "active"
        return "pending_approval"

    def _approval(self, link: dict[str, Any], peer: str) -> str:
        """What an approval stores: when, who had joined, and which kind of pairing it
        was for ("self": one person's own assistants; "pair": two people). It counts
        only while all of that is still what the pairing says."""
        kind = "self" if link.get("same_account") else "pair"
        return f"{self._iso()}|{peer}|{kind}"

    def _approved(
        self,
        link_id: str,
        side: str,
        peer: str | None = None,
        link: dict[str, Any] | None = None,
    ) -> bool:
        raw = self.store.hget(f"bridge:appr:{link_id}", side)
        if raw is None:
            return False
        parts = raw.split("|")
        if len(parts) == 1:
            # From before approvals named the person. Accepted until records must be
            # signed; `bind_legacy_approvals` rewrites these first.
            return not self.strict
        if link is None:
            link = self._link(link_id)
        if link is None:
            return False
        if peer is None:
            peer = self._peer(link_id)
        who = parts[1]
        # An approval written before the kind was stored was for two people, unless it
        # names the link's own creator, which only a pairing of their own assistants does.
        owner_of_link = str(link["email_a"])
        kind = parts[2] if len(parts) > 2 else ("self" if who == owner_of_link else "pair")
        if not who or who != peer:
            return False
        if link.get("same_account"):
            return kind == "self" and peer == owner_of_link
        return kind == "pair" and peer != owner_of_link

    def _seal_ended(self, link: dict[str, Any]) -> bool:
        """Make "off" permanent for a pairing that only has the old marker: write it into
        the signed link record and remove both approvals. True when something changed."""
        link_id = link["link_id"]
        approvals = self.store.hgetall(f"bridge:appr:{link_id}")
        if link.get("ended_at") and not approvals:
            return False
        if not link.get("ended_at"):
            ended = self._ended(link_id) or {}
            marker = self.store.get(f"bridge:revoked:{link_id}")
            self._mark_ended(link, str(ended.get("at") or marker or self._iso()))
        for side in approvals:
            self.store.hdel(f"bridge:appr:{link_id}", side)
        return True

    def seal_ended_pairings(self, people: list[str]) -> int:
        """Pairings that were turned off before "off" was written into the link record
        have only a marker saying so. Give each the permanent form. Returns how many
        changed. Run from the admin page before REQUIRE_SIGNED_RECORDS is turned on."""
        changed = 0
        for link_id in dict.fromkeys(i for email in people for i in self._user_link_ids(email)):
            link = self._link(link_id)
            if link is not None and self._revoked(link_id, link) and self._seal_ended(link):
                changed += 1
        return changed

    def bind_legacy_approvals(self, people: list[str]) -> int:
        """Rewrite approvals from before they named the person who joined, using who is
        joined now. A pairing that is off is left alone. Returns how many changed. Run
        from the admin page before REQUIRE_SIGNED_RECORDS is turned on."""
        changed = 0
        for email in people:
            for link_id in self._user_link_ids(email):
                peer = self._peer(link_id)
                if not peer or self._revoked(link_id):
                    continue
                key = f"bridge:appr:{link_id}"
                for side, raw in self.store.hgetall(key).items():
                    if "|" not in raw:
                        link = self._link(link_id)
                        if link is None:
                            break  # no readable link record: nothing to say it is for
                        kind = "self" if link.get("same_account") else "pair"
                        self.store.hset(key, side, f"{raw}|{peer}|{kind}")
                        changed += 1
        return changed

    def _revoked(self, link_id: str, link: dict[str, Any] | None = None) -> bool:
        """Off for good. The marker is what was always read; the link record says so too,
        and that record is signed, so deleting the marker does not turn a pairing back on."""
        if self.store.get(f"bridge:revoked:{link_id}") is not None:
            return True
        if link is None:
            link = self._link(link_id)
        return bool(link and link.get("ended_at"))

    def _peer(self, link_id: str) -> str | None:
        value = self.store.get(f"bridge:peer:{link_id}")
        return value or None

    def _side(self, link: dict[str, Any], you: str) -> str | None:
        """Which side of the link this call is: "a", "b", or None (not a side). On a
        same-account link the side is the calling assistant; the human is neither."""
        if link.get("same_account"):
            assistant = current_assistant.get()
            if you != link["email_a"] or assistant is None:
                return None
            for side in ("a", "b"):
                if assistant.grant_id == link.get(f"grant_{side}"):
                    return side
            return None
        if you == link["email_a"]:
            return "a"
        if you == self._peer(link["link_id"]):
            return "b"
        return None

    def _addr(self, link: dict[str, Any], you: str) -> str | None:
        """Where this caller's mail on this link is addressed."""
        side = self._side(link, you)
        if side is None:
            return None
        if link.get("same_account"):
            return _self_addr(you, str(link[f"grant_{side}"]))
        return you

    def _mine(self, you: str) -> set[str]:
        """Every address this call may read mail for."""
        found = {you}
        assistant = current_assistant.get()
        # Not gated on the switch: mail already delivered stays readable until it expires.
        if assistant is not None:
            found.add(_self_addr(you, assistant.grant_id))
        return found

    def _other(self, link: dict[str, Any], you: str) -> str | None:
        if link.get("same_account"):
            side = self._side(link, you)
            if side is None:
                return None
            other = "b" if side == "a" else "a"
            grant = link.get(f"grant_{other}")
            return _self_addr(you, str(grant)) if grant else None
        peer = self._peer(link["link_id"])
        if you == link["email_a"]:
            return peer
        if peer == you:
            return str(link["email_a"])
        return None

    def _link(self, link_id: str) -> dict[str, Any] | None:
        raw = self.store.get(f"bridge:link:{link_id}")
        if not raw:
            return None
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) and data.get("link_id") else None

    def _user_link_ids(self, email: str) -> list[str]:
        return list(self.store.hgetall(f"bridge:user:{email}"))
