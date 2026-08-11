"""Warrant as an MCP server (MCP Python SDK 2.x).

Two modes:

1. **Catalog mode** (default) — tools come from GET /catalog; each call is
   POST /call to the broker, which forwards to your HTTP APIs.

2. **Wrap mode** — set WARRANT_WRAP_CONFIG to a JSON file describing someone
   else's MCP server. Tools are that server's tools (synced into the broker
   catalog). Each call is authorize-only at the broker, then forwarded to the
   upstream MCP. Sync first: `python -m mcp_server.sync`.

Env:
  WARRANT_BROKER_URL   default http://127.0.0.1:8100
  WARRANT_TOKEN        signed warrant token (required for tool calls)
  WARRANT_WRAP_CONFIG  optional path to wrap config JSON

    python -m mcp_server
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import anyio
import httpx
import mcp_types as types
from mcp.client.session import ClientSession
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from core.tool_schema import build_tools_from_operations, resolve_op
from mcp_server.tool_map import upstream_tool_name
from mcp_server.upstream import load_wrap_config, stdio_params_from_config

BROKER_URL = os.environ.get("WARRANT_BROKER_URL", "http://127.0.0.1:8100").rstrip("/")
WARRANT_TOKEN = os.environ.get("WARRANT_TOKEN", "").strip()
WRAP_CONFIG_PATH = os.environ.get("WARRANT_WRAP_CONFIG", "").strip()

# Filled in wrap mode once the upstream session is live.
_WRAP: dict[str, Any] = {
    "config": None,
    "session": None,
    "namespace": None,
}


def _fetch_catalog() -> dict[str, Any]:
    with httpx.Client(timeout=15.0) as client:
        response = client.get(f"{BROKER_URL}/catalog")
        response.raise_for_status()
        return response.json()


def _call_broker(
    op: str, args: dict[str, Any], *, authorize_only: bool = False
) -> dict[str, Any]:
    if not WARRANT_TOKEN:
        return {
            "ok": False,
            "reason": (
                "WARRANT_TOKEN is not set. Mint with `python -m demo.operator "
                "--task \"...\" --quiet` and export the token before starting MCP."
            ),
        }
    body: dict[str, Any] = {"op": op, "args": args}
    if authorize_only:
        body["authorize_only"] = True
    with httpx.Client(timeout=30.0) as client:
        response = client.post(
            f"{BROKER_URL}/call",
            json=body,
            headers={"X-Warrant": WARRANT_TOKEN},
        )
        try:
            payload = response.json()
        except ValueError:
            payload = {"ok": False, "reason": response.text, "status": response.status_code}
        if not isinstance(payload, dict):
            payload = {"ok": False, "reason": str(payload)}
        payload.setdefault("http_status", response.status_code)
        return payload


def _tool_result(payload: dict[str, Any], *, is_error: bool) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(payload, indent=2))],
        isError=is_error,
    )


async def on_list_tools(ctx: Any, params: Any) -> types.ListToolsResult:
    catalog = _fetch_catalog()
    operations = catalog.get("operations") or []
    namespace = (_WRAP.get("config") or {}).get("namespace")
    if namespace:
        operations = [
            op for op in operations if str(op.get("op", "")).startswith(namespace + ".")
        ]
    tools = build_tools_from_operations(operations)
    return types.ListToolsResult(
        tools=[
            types.Tool(
                name=t["name"],
                description=t["description"],
                inputSchema=t["input_schema"],
            )
            for t in tools
        ]
    )


async def on_call_tool(ctx: Any, params: Any) -> types.CallToolResult:
    name = getattr(params, "name", None) or (
        params.get("name") if isinstance(params, dict) else None
    )
    arguments = getattr(params, "arguments", None)
    if arguments is None and isinstance(params, dict):
        arguments = params.get("arguments")
    arguments = dict(arguments or {})

    catalog = _fetch_catalog()
    ops = {op["op"]: op for op in (catalog.get("operations") or [])}
    try:
        op_id = resolve_op(str(name), ops)
    except KeyError:
        if name in ops:
            op_id = str(name)
        else:
            return _tool_result({"ok": False, "reason": f"unknown tool {name!r}"}, is_error=True)

    wrap_config = _WRAP.get("config")
    if wrap_config:
        return await _call_wrap(op_id, arguments, ops[op_id])

    result = _call_broker(op_id, arguments, authorize_only=False)
    return _tool_result(result, is_error=not result.get("ok", False))


async def _call_wrap(
    op_id: str, arguments: dict[str, Any], op_meta: dict[str, Any]
) -> types.CallToolResult:
    session: ClientSession | None = _WRAP.get("session")
    if session is None:
        return _tool_result(
            {"ok": False, "reason": "wrap mode: upstream MCP session is not connected"},
            is_error=True,
        )

    namespace = wrap_ns = (_WRAP.get("config") or {}).get("namespace")
    tool_name = upstream_tool_name(op_id, namespace)

    # Mutating MCP ops expect mcp_tool=<bare tool name> for resource pinning.
    call_args = dict(arguments)
    if op_meta.get("mutating") and op_meta.get("resource_param") == "mcp_tool":
        call_args["mcp_tool"] = tool_name

    decision = _call_broker(op_id, call_args, authorize_only=True)
    if not decision.get("ok"):
        return _tool_result(decision, is_error=True)

    # Strip the injected pin before forwarding to the real upstream.
    upstream_args = {k: v for k, v in call_args.items() if k != "mcp_tool"}
    try:
        upstream = await session.call_tool(tool_name, upstream_args)
    except Exception as exc:  # noqa: BLE001 — surface to the MCP client
        return _tool_result(
            {
                "ok": False,
                "authorized": True,
                "reason": f"upstream MCP call failed: {exc}",
                "op": op_id,
            },
            is_error=True,
        )

    # Normalize CallToolResult into JSON the client can read.
    content_out = []
    for block in getattr(upstream, "content", None) or []:
        if getattr(block, "type", None) == "text":
            content_out.append({"type": "text", "text": getattr(block, "text", "")})
        else:
            content_out.append({"type": getattr(block, "type", "unknown"), "raw": str(block)})
    payload = {
        "ok": not bool(getattr(upstream, "isError", False)),
        "authorized": True,
        "op": op_id,
        "upstream_tool": tool_name,
        "namespace": wrap_ns,
        "content": content_out,
    }
    return _tool_result(payload, is_error=not payload["ok"])


def _build_server() -> Server:
    mode = "wrap" if WRAP_CONFIG_PATH else "catalog"
    instructions = (
        "Warrant MCP wrap: tools belong to an upstream MCP server. "
        "Every call is authorized against a warrant, then forwarded."
        if mode == "wrap"
        else "Warrant MCP: every tool is a catalog operation forwarded through the broker. "
        "Calls are checked against the active warrant (WARRANT_TOKEN). "
        "This server cannot mint authority."
    )
    return Server(
        "warrant",
        version="0.1.0",
        instructions=instructions,
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


server = _build_server()


async def _run_catalog() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


async def _run_wrap() -> None:
    config = load_wrap_config(WRAP_CONFIG_PATH)
    if not config.get("cwd"):
        config["cwd"] = str(_ROOT)
    if config["command"] == "python":
        config["command"] = sys.executable
    _WRAP["config"] = config
    _WRAP["namespace"] = config["namespace"]

    params = stdio_params_from_config(config)
    async with stdio_client(params) as (uread, uwrite):
        async with ClientSession(uread, uwrite) as session:
            await session.initialize()
            _WRAP["session"] = session
            print(
                f"warrant-mcp: wrap upstream ready namespace={config['namespace']!r}",
                file=sys.stderr,
            )
            async with stdio_server() as (read_stream, write_stream):
                await server.run(
                    read_stream,
                    write_stream,
                    server.create_initialization_options(),
                )


def main() -> None:
    if not WARRANT_TOKEN:
        print(
            "warrant-mcp: WARRANT_TOKEN unset; tool calls will be refused until it is set.",
            file=sys.stderr,
        )
    if WRAP_CONFIG_PATH:
        print(
            f"warrant-mcp: WRAP mode config={WRAP_CONFIG_PATH} broker={BROKER_URL}",
            file=sys.stderr,
        )
        anyio.run(_run_wrap)
    else:
        print(
            f"warrant-mcp: catalog mode broker={BROKER_URL} (tools = live /catalog)",
            file=sys.stderr,
        )
        anyio.run(_run_catalog)


if __name__ == "__main__":
    main()
