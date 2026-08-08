"""Claude tool definitions, generated from core.catalog.CATALOG.

One Claude tool per Operation. The input schema comes from Operation.args --
adding an operation to the catalog adds a tool here with no edit.

Claude tool names must match ^[a-zA-Z0-9_-]{1,128}$, and catalog ops are dotted
("orders.get"), so the dot becomes an underscore on the way out and back.
"""

from __future__ import annotations

from typing import Any

from core.catalog import CATALOG, Operation

# Args the broker will want to bound numerically. Everything else is a string.
NUMERIC_ARGS = {"amount"}


def tool_name_for(op_name: str) -> str:
    return op_name.replace(".", "_")


def op_name_for(tool_name: str) -> str:
    return tool_name.replace("_", ".", 1)


def _is_optional(description: str) -> bool:
    return description.strip().lower().startswith("optional")


def input_schema_for(op: Operation) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    required: list[str] = []

    for arg, description in op.args.items():
        prop: dict[str, Any] = {
            "type": "number" if arg in NUMERIC_ARGS else "string",
            "description": description,
        }
        if arg in op.constrainable:
            prop["description"] = f"{description} (the warrant may bound this value)"
        properties[arg] = prop

        if not _is_optional(description):
            required.append(arg)

    # The resource id is what the broker scopes on; never let it be omitted.
    if op.resource_param and op.resource_param in properties:
        if op.resource_param not in required:
            required.append(op.resource_param)

    return {"type": "object", "properties": properties, "required": required}


def description_for(op: Operation) -> str:
    lines = [op.description.strip()]
    lines.append("MUTATING -- this changes real state." if op.mutating else "Read-only.")
    if op.resource_type and op.resource_param:
        lines.append(
            f"Resource identity checked by the broker: "
            f"{op.resource_type}:<{op.resource_param}>."
        )
    else:
        lines.append("This operation is not resource-scoped; it reaches everything.")
    lines.append(
        "This call is sent to the broker, which checks it against the warrant and "
        "may refuse it with a reason."
    )
    return "\n".join(lines)


def build_tools() -> list[dict[str, Any]]:
    """One Claude tool per catalog operation."""
    return [
        {
            "name": tool_name_for(op.op),
            "description": description_for(op),
            "input_schema": input_schema_for(op),
        }
        for op in CATALOG.values()
    ]


def resolve_op(tool_name: str) -> str:
    """Map a Claude tool name back to a catalog op, or raise."""
    candidate = op_name_for(tool_name)
    if candidate in CATALOG:
        return candidate
    for op_name in CATALOG:
        if tool_name_for(op_name) == tool_name:
            return op_name
    raise KeyError(f"unknown tool {tool_name!r}")
