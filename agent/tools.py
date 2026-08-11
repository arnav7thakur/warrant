"""Agent tool definitions — thin wrapper over core.tool_schema.

Kept so existing `from agent.tools import …` imports keep working.
"""

from __future__ import annotations

from core.tool_schema import (  # noqa: F401 — re-export
    build_tools_from_catalog as build_tools,
    description_for,
    input_schema_for,
    op_name_for,
    resolve_op,
    tool_name_for,
)

# Back-compat for anything that still reads this set.
NUMERIC_ARGS = {"amount"}
