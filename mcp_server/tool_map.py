"""Map upstream MCP tools → Warrant catalog operations.

Each tool becomes one op under a namespace (e.g. wrap.echo_write). Mutating tools
are pinned to resource mcp_tool:<tool_name> via an injected arg so wildcards
cannot authorize them. Read-ish tools stay unscoped.
"""

from __future__ import annotations

import re
from typing import Any

_READ_TOKEN = re.compile(
    r"(?:^|_)(get|list|read|search|find|fetch|describe|show|lookup|inspect)(?:_|$)",
    re.IGNORECASE,
)


def looks_readonly(name: str, description: str = "") -> bool:
    if _READ_TOKEN.search(name or ""):
        return True
    desc = (description or "").lower()
    if "read-only" in desc or "readonly" in desc or "does not modify" in desc:
        return True
    return False


def tool_to_operation(tool: Any, *, service: str = "mcp") -> dict[str, Any]:
    """Convert an MCP Tool (mcp_types.Tool or duck-typed) into a catalog declaration.

    Op id is the bare tool name; the caller prefixes a namespace on register.
    """
    name = getattr(tool, "name", None) or tool["name"]
    description = (getattr(tool, "description", None) or "").strip()
    if not description and isinstance(tool, dict):
        description = str(tool.get("description") or "").strip()
    schema = getattr(tool, "inputSchema", None)
    if schema is None and isinstance(tool, dict):
        schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    if hasattr(schema, "model_dump"):
        schema = schema.model_dump(mode="json")
    schema = dict(schema or {})

    properties = dict(schema.get("properties") or {})
    args: dict[str, str] = {}
    for prop, prop_schema in properties.items():
        if not isinstance(prop_schema, dict):
            args[prop] = str(prop)
            continue
        args[prop] = str(prop_schema.get("description") or prop)

    readonly = looks_readonly(name, description)
    mutating = not readonly

    if mutating:
        # Injected on every wrap call. Grants pin to mcp_tool:<name>.
        args["mcp_tool"] = (
            f"Stable tool identity — always '{name}'. Injected by the Warrant wrap "
            "layer; do not invent other values."
        )

    return {
        "op": name,
        "method": "POST",
        "path": f"/mcp/{name}",
        "service": service,
        "mutating": mutating,
        "resource_type": "mcp_tool" if mutating else None,
        "resource_param": "mcp_tool" if mutating else None,
        "args": args,
        "constrainable": [],
        "broadcast_values": [],
        "description": description
        or (f"Upstream MCP tool {name!r} ({'mutating' if mutating else 'read-only'})."),
    }


def upstream_tool_name(op_id: str, namespace: str | None) -> str:
    """Strip the registration namespace to recover the upstream MCP tool name."""
    if namespace and op_id.startswith(namespace + "."):
        return op_id[len(namespace) + 1 :]
    # also handle tool_name_for style if someone passed underscores — leave as-is
    return op_id
