"""Upstream MCP client helpers for wrap mode."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


def load_wrap_config(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"wrap config {path} must be a JSON object")
    for key in ("command", "namespace"):
        if not data.get(key):
            raise ValueError(f"wrap config {path} missing required field {key!r}")
    data.setdefault("name", data["namespace"])
    data.setdefault("args", [])
    data.setdefault("env", {})
    data.setdefault("cwd", None)
    return data


def stdio_params_from_config(config: dict[str, Any]) -> StdioServerParameters:
    return StdioServerParameters(
        command=config["command"],
        args=list(config.get("args") or []),
        env={str(k): str(v) for k, v in dict(config.get("env") or {}).items()} or None,
        cwd=config.get("cwd"),
    )


async def list_upstream_tools(config: dict[str, Any]) -> list[Any]:
    params = stdio_params_from_config(config)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
            return list(result.tools or [])


async def call_upstream_tool(
    session: ClientSession, name: str, arguments: dict[str, Any]
) -> Any:
    return await session.call_tool(name, arguments)
