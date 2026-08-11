"""Tiny upstream MCP server for wrap-mode demos.

Exposes two tools: notes_get (read) and notes_write (mutating). Run as:

    python -m examples.mock_upstream_mcp

Wrap config: examples/wrap_mock.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import anyio
import mcp_types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

NOTES: dict[str, str] = {
    "n-1": "Standup notes: ship the wrap path.",
    "n-2": "Private: rotation keys live in vault.",
}


async def on_list_tools(ctx: Any, params: Any) -> types.ListToolsResult:
    return types.ListToolsResult(
        tools=[
            types.Tool(
                name="notes_get",
                description="Read a note by id. Read-only.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "note_id": {
                            "type": "string",
                            "description": "Note id, e.g. n-1",
                        }
                    },
                    "required": ["note_id"],
                },
            ),
            types.Tool(
                name="notes_write",
                description="Overwrite a note. Mutates stored text.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "note_id": {
                            "type": "string",
                            "description": "Note id to write",
                        },
                        "text": {
                            "type": "string",
                            "description": "New note body",
                        },
                    },
                    "required": ["note_id", "text"],
                },
            ),
        ]
    )


async def on_call_tool(ctx: Any, params: Any) -> types.CallToolResult:
    name = getattr(params, "name", None)
    arguments = dict(getattr(params, "arguments", None) or {})
    if name == "notes_get":
        note_id = str(arguments.get("note_id") or "")
        text = NOTES.get(note_id)
        if text is None:
            payload = {"ok": False, "error": f"unknown note {note_id!r}"}
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=json.dumps(payload))],
                isError=True,
            )
        payload = {"ok": True, "note_id": note_id, "text": text}
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(payload))]
        )
    if name == "notes_write":
        note_id = str(arguments.get("note_id") or "")
        text = str(arguments.get("text") or "")
        NOTES[note_id] = text
        payload = {"ok": True, "note_id": note_id, "written": True, "length": len(text)}
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(payload))]
        )
    return types.CallToolResult(
        content=[
            types.TextContent(
                type="text",
                text=json.dumps({"ok": False, "error": f"unknown tool {name}"}),
            )
        ],
        isError=True,
    )


server = Server(
    "mock-upstream",
    version="0.1.0",
    instructions="Demo upstream MCP for Warrant wrap mode.",
    on_list_tools=on_list_tools,
    on_call_tool=on_call_tool,
)


async def _run() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def main() -> None:
    print("mock-upstream-mcp: notes_get / notes_write on stdio", file=sys.stderr)
    anyio.run(_run)


if __name__ == "__main__":
    main()
