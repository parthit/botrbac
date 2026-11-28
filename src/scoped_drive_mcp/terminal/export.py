"""Terminal activity as OpenTelemetry logs (OTLP/JSON), for a collector or a SIEM.

`GET /terminal/activity/export?format=otlp` returns one `resourceLogs` entry with one
`scopeLogs` entry holding one log record per audit row. Attribute names follow the
OpenTelemetry semantic conventions where one fits, pinned to SEMCONV_VERSION. The GenAI
attributes used here (`gen_ai.*`) have Development status in that version, so their
names can still change upstream; Bot RBAC's own fields are under `botrbac.*`.

Sealed fields (the recorded command, the session task) are
included only as the owner's export already includes them: opened, for the owner.
"""

import json
from collections.abc import Iterable, Mapping
from typing import Any

SEMCONV_VERSION = "1.37.0"
SCHEMA_URL = f"https://opentelemetry.io/schemas/{SEMCONV_VERSION}"
SCOPE = "botrbac.terminal"
SCOPE_VERSION = "1"
EVENT_NAME = "botrbac.terminal.audit"

# Severity numbers from the OTLP logs data model.
_SEVERITY = {
    "deny": (13, "WARN"),
    "error": (17, "ERROR"),
}
_INFO = (9, "INFO")

# Row field -> attribute name, where the semantic conventions have one.
SEMCONV = {
    "tool": "gen_ai.tool.name",
    "tool_use_id": "gen_ai.tool.call.id",
    "agent_session_id": "gen_ai.conversation.id",
    "agent_id": "gen_ai.agent.id",
    "agent": "gen_ai.agent.name",
    "subject": "user.email",
}
# Never sent as a field of its own: shown through other attributes, or internal.
_SKIP = {"ts", "received", "command_unreadable", "actor", "grant", "terminal"}


def _value(value: Any) -> dict[str, Any] | None:
    """An OTLP AnyValue. int64 travels as a string in OTLP/JSON."""
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, str):
        return {"stringValue": value} if value else None
    if isinstance(value, (dict, list)):
        return {"stringValue": json.dumps(value, separators=(",", ":"), sort_keys=True)}
    return None


def _attr(key: str, value: Any) -> dict[str, Any] | None:
    encoded = _value(value)
    return {"key": key, "value": encoded} if encoded is not None else None


def _nanos(value: Any) -> str:
    try:
        return str(int(float(value) * 1_000_000_000))
    except (TypeError, ValueError):
        return "0"


def log_record(row: Mapping[str, Any]) -> dict[str, Any]:
    decision = str(row.get("decision") or "")
    number, text = _SEVERITY.get(decision, _INFO)
    attrs: list[dict[str, Any] | None] = []
    if row.get("tool"):
        attrs.append(_attr("gen_ai.operation.name", "execute_tool"))
    for field, name in SEMCONV.items():
        attrs.append(_attr(name, row.get(field)))
    attrs.append(_attr("botrbac.terminal.name", row.get("terminal")))
    if row.get("actor"):
        attrs.append(_attr("botrbac.actor", row["actor"]))
    grant = row.get("grant") if isinstance(row.get("grant"), Mapping) else {}
    for key, value in sorted((grant or {}).items()):
        attrs.append(_attr(f"botrbac.grant.{key}", value))
    for field, value in sorted(row.items()):
        if field in SEMCONV or field in _SKIP:
            continue
        attrs.append(_attr(f"botrbac.{field}", value))
    what = row.get("tool") or row.get("program") or ""
    return {
        "timeUnixNano": _nanos(row.get("ts")),
        "observedTimeUnixNano": _nanos(row.get("received") or row.get("ts")),
        "severityNumber": number,
        "severityText": text,
        "eventName": EVENT_NAME,
        "body": {"stringValue": f"{decision} {what}".strip()},
        "attributes": [a for a in attrs if a is not None],
    }


def otlp_logs(rows: Iterable[Mapping[str, Any]], site: str = "") -> dict[str, Any]:
    resource = [a for a in (_attr("service.name", "botrbac"), _attr("botrbac.site", site)) if a]
    return {
        "resourceLogs": [
            {
                "resource": {"attributes": resource},
                "schemaUrl": SCHEMA_URL,
                "scopeLogs": [
                    {
                        "scope": {"name": SCOPE, "version": SCOPE_VERSION},
                        "schemaUrl": SCHEMA_URL,
                        "logRecords": [log_record(r) for r in rows],
                    }
                ],
            }
        ]
    }
