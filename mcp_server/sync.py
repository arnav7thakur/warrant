"""Sync an upstream MCP server's tools into the Warrant broker catalog.

    set WARRANT_WRAP_CONFIG=examples/wrap_mock.json
    python -m mcp_server.sync

Requires the broker up and X-Operator-Key (OPERATOR_KEY). After sync, mint a
warrant whose task names those tools, then run:

    set WARRANT_WRAP_CONFIG=examples/wrap_mock.json
    set WARRANT_TOKEN=...
    python -m mcp_server
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import anyio
import httpx

from mcp_server.tool_map import tool_to_operation
from mcp_server.upstream import list_upstream_tools, load_wrap_config

OPERATOR_KEY = os.environ.get("OPERATOR_KEY", "operator-key-change-me")
BROKER_URL = os.environ.get("WARRANT_BROKER_URL", "http://127.0.0.1:8100").rstrip("/")


async def sync(config_path: str) -> int:
    config = load_wrap_config(config_path)
    # Resolve relative cwd / command against repo root when cwd is null
    if not config.get("cwd"):
        config["cwd"] = str(_ROOT)
    if config["command"] == "python":
        config["command"] = sys.executable

    print(f"listing tools from {config['command']} {config.get('args')} …", flush=True)
    tools = await list_upstream_tools(config)
    if not tools:
        print("upstream exposed zero tools — nothing to register", flush=True)
        return 1

    operations = [tool_to_operation(t, service="mcp") for t in tools]
    body = {
        "namespace": config["namespace"],
        "name": config.get("name"),
        "owner": config.get("owner"),
        "description": config.get("description"),
        "services": {
            # Placeholder: authorize_only never HTTP-forwards MCP ops.
            "mcp": "http://127.0.0.1:9",
        },
        "operations": operations,
    }

    with httpx.Client(timeout=30.0) as client:
        response = client.post(
            f"{BROKER_URL}/catalog/register",
            json=body,
            headers={"X-Operator-Key": OPERATOR_KEY},
        )
        try:
            payload = response.json()
        except ValueError:
            payload = {"raw": response.text}

    if response.status_code >= 400:
        print(f"register failed ({response.status_code}): {payload}", flush=True)
        return 1

    registered = payload.get("registered") or []
    print(f"registered {len(registered)} ops under namespace {config['namespace']!r}:", flush=True)
    for op_id in registered:
        print(f"  - {op_id}", flush=True)
    print(f"catalog_size={payload.get('catalog_size')}", flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m mcp_server.sync")
    parser.add_argument(
        "--config",
        default=os.environ.get("WARRANT_WRAP_CONFIG", ""),
        help="Path to wrap config JSON (or set WARRANT_WRAP_CONFIG)",
    )
    parser.add_argument(
        "--broker",
        default=os.environ.get("WARRANT_BROKER_URL", "http://127.0.0.1:8100"),
        help="Broker base URL",
    )
    args = parser.parse_args(argv)
    if not args.config:
        print("pass --config or set WARRANT_WRAP_CONFIG", file=sys.stderr)
        return 2

    async def _run() -> int:
        # local override for this process
        global BROKER_URL
        BROKER_URL = args.broker.rstrip("/")
        return await sync(args.config)

    return anyio.run(_run)


if __name__ == "__main__":
    raise SystemExit(main())
