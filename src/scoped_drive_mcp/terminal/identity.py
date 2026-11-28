"""Who sent an audit batch, and on whose behalf each row was done.

Signatures: a terminal that registered a key (botrbac_cli.identity) must sign every
audit batch with it; a bad, stale or replayed signature is refused with 401. A terminal
without a key (a CLI from before keys) is still accepted, and its rows say unsigned.

Delegation: the server sets these on every stored row, never from what the CLI sent:

- `signed`: whether this batch carried a good signature from the terminal's key.
- `subject`: the person (the terminal owner's email).
- `actor`: who acted for them, shaped like RFC 8693's `act` claim, outermost first:
  `{"sub": "terminal:<id>", "act": {"sub": "agent:<agent>[/<agent_id>]"}}`.
- `grant`: the role (and policy version) the CLI says it decided under.
"""

from collections.abc import Callable, Mapping
from typing import Any

from botrbac_cli import identity as cli_identity

from .device import Terminal

NONCE_KEY = "term:nonce:{terminal_id}:{nonce}"


class SignatureRejected(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def verify_batch(
    store: Any,
    public_key: str | None,
    terminal_id: str,
    headers: Mapping[str, str],
    body: bytes,
    now: float,
) -> bool:
    """True for a good signature, False for an unsigned batch from a terminal with no
    key. Raises SignatureRejected for anything else."""
    if not public_key:
        return False
    try:
        nonce = cli_identity.verify(public_key, "POST", cli_identity.AUDIT_PATH, body, headers, now)
    except cli_identity.SignatureError as exc:
        raise SignatureRejected(exc.code) from None
    key = NONCE_KEY.format(terminal_id=terminal_id, nonce=nonce)
    if not store.set_if_absent(key, "1", ex=2 * cli_identity.WINDOW + 60):
        raise SignatureRejected("replayed_signature")
    return True


def actor(terminal_id: str, agent: Any = "", agent_id: Any = "") -> dict[str, Any]:
    out: dict[str, Any] = {"sub": f"terminal:{terminal_id}"}
    if agent:
        sub = f"agent:{agent}"
        if agent_id:
            sub += f"/{agent_id}"
        out["act"] = {"sub": sub}
    return out


def stamper(
    terminal: Terminal,
    signed: bool,
    stored: list[dict[str, Any]] | None = None,
    assigned: Mapping[str, str] | None = None,
) -> Callable[[dict[str, Any]], None]:
    """Sets the server's own fields on each row just before it is stored (overwriting
    anything the CLI sent under those names), and collects the rows in `stored`.

    `assigned` is the site's own record at upload time: `{"role": <name>,
    "policy_version": <version>}` for this terminal. `grant` carries that, and keeps
    what the computer reported (`reported_role`, `reported_policy_version`) beside it,
    never in its place: a computer can write any role name into its rows."""

    def stamp(row: dict[str, Any]) -> None:
        row["signed"] = signed
        row["subject"] = terminal.email
        row["actor"] = actor(terminal.id, row.get("agent"), row.get("agent_id"))
        grant = {k: v for k, v in (assigned or {}).items() if v}
        for key in ("role", "policy_version"):
            if row.get(key):
                grant[f"reported_{key}"] = row[key]
        if grant:
            row["grant"] = grant
        else:
            row.pop("grant", None)
        if stored is not None:
            stored.append(row)

    return stamp


def chain_text(row: Mapping[str, Any]) -> str:
    """The delegation chain for the Activity page: you → laptop → claude-code (subagent …)."""
    parts = ["you", f"terminal {row.get('terminal') or row.get('terminal_id') or '?'}"]
    agent = str(row.get("agent") or "")
    if agent:
        agent_id = str(row.get("agent_id") or "")
        kind = str(row.get("agent_type") or "subagent")
        parts.append(f"{agent} ({kind} …{agent_id[-8:]})" if agent_id else agent)
    return " → ".join(parts)
