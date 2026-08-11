"""Shared tool-schema helpers for the Gemini agent and the MCP server.

One tool per catalog Operation. Arg types: constrainable args are numbers (they are
what warrants bound numerically); everything else is a string unless the description
clearly says otherwise. Catalog ops are dotted ("helpdesk.vpn.grant"); tool names
replace '.' with '_' to satisfy Gemini/MCP name rules.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from core.catalog import CATALOG, Operation

# Legacy commerce leftover — still treated as numeric even if not listed constrainable.
_LEGACY_NUMERIC = frozenset({"amount"})

# Hint patterns in arg descriptions that imply a number.
_NUMERIC_HINT = re.compile(
    r"\b(hours?|minutes?|seconds?|amount|budget|count|qty|quantity|limit|ceiling|"
    r"inr|usd|rupees?|price|total)\b",
    re.IGNORECASE,
)


def tool_name_for(op_name: str) -> str:
    return op_name.replace(".", "_")


def op_name_for(tool_name: str) -> str:
    """Best-effort reverse of tool_name_for (first underscore → first dot)."""
    return tool_name.replace("_", ".", 1)


def is_numeric_arg(op: Operation | Mapping[str, Any], arg: str) -> bool:
    """Whether this argument should be typed as a JSON number in tool schemas."""
    if arg in _LEGACY_NUMERIC:
        return True
    constrainable = (
        op.constrainable if isinstance(op, Operation) else list(op.get("constrainable") or [])
    )
    if arg in constrainable:
        return True
    args = op.args if isinstance(op, Operation) else dict(op.get("args") or {})
    desc = str(args.get(arg, ""))
    return bool(_NUMERIC_HINT.search(desc))


def _is_optional(description: str) -> bool:
    return description.strip().lower().startswith("optional")


def input_schema_for(op: Operation | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(op, Operation):
        args = op.args
        constrainable = op.constrainable
        resource_param = op.resource_param
    else:
        args = dict(op.get("args") or {})
        constrainable = list(op.get("constrainable") or [])
        resource_param = op.get("resource_param")

    properties: dict[str, Any] = {}
    required: list[str] = []

    for arg, description in args.items():
        prop: dict[str, Any] = {
            "type": "number" if is_numeric_arg(op, arg) else "string",
            "description": description,
        }
        if arg in constrainable:
            prop["description"] = f"{description} (the warrant may bound this value)"
        properties[arg] = prop
        if not _is_optional(description):
            required.append(arg)

    if resource_param and resource_param in properties and resource_param not in required:
        required.append(resource_param)

    return {"type": "object", "properties": properties, "required": required}


def description_for(op: Operation | Mapping[str, Any]) -> str:
    if isinstance(op, Operation):
        desc = op.description.strip()
        mutating = op.mutating
        resource_type = op.resource_type
        resource_param = op.resource_param
    else:
        desc = str(op.get("description") or "").strip()
        mutating = bool(op.get("mutating"))
        resource_type = op.get("resource_type")
        resource_param = op.get("resource_param")

    lines = [desc] if desc else []
    lines.append("MUTATING -- this changes real state." if mutating else "Read-only.")
    if resource_type and resource_param:
        lines.append(
            f"Resource identity checked by the broker: "
            f"{resource_type}:<{resource_param}>."
        )
    else:
        lines.append("This operation is not resource-scoped; it reaches everything.")
    lines.append(
        "This call is sent to the broker, which checks it against the warrant and "
        "may refuse it with a reason."
    )
    return "\n".join(lines)


def tool_dict_for(op: Operation | Mapping[str, Any]) -> dict[str, Any]:
    """Claude / MCP-shaped tool definition for one operation."""
    if isinstance(op, Operation):
        op_id = op.op
    else:
        op_id = str(op["op"])
    return {
        "name": tool_name_for(op_id),
        "description": description_for(op),
        "input_schema": input_schema_for(op),
    }


def build_tools_from_catalog() -> list[dict[str, Any]]:
    """One tool per local CATALOG entry (agent path)."""
    return [tool_dict_for(op) for op in CATALOG.values()]


def build_tools_from_operations(operations: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """One tool per operation dict (MCP path — broker /catalog payload)."""
    return [tool_dict_for(op) for op in operations]


def resolve_op(tool_name: str, known_ops: Mapping[str, Any] | None = None) -> str:
    """Map a tool name back to a catalog op id, or raise KeyError."""
    catalog = known_ops if known_ops is not None else CATALOG
    candidate = op_name_for(tool_name)
    if candidate in catalog:
        return candidate
    for op_name in catalog:
        if tool_name_for(op_name) == tool_name:
            return op_name
    raise KeyError(f"unknown tool {tool_name!r}")
