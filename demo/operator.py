"""The operator: the only process in this project that can create authority.

    python -m demo.operator --task "<task statement>"
    python -m demo.operator --task "<task statement>" --quiet
    python -m demo.operator --task "<task statement>" --write-cursor
    python -m demo.operator --task "…" --grants examples/grants_read_note.json --remint --write-cursor

This exists as a separate file for one reason. Minting requires `OPERATOR_KEY`, and
the argument this project makes is that the agent must not be able to mint -- not
"does not", *cannot*. That is only true if the credential lives somewhere the agent
process does not. So it lives here, and the agent is handed a token.

`--write-cursor` updates `WARRANT_TOKEN` in Cursor's mcp.json so reminting is one
command instead of copy-paste. `--grants` skips Gemini and signs the listed grants.
`--remint` releases the sealed task first so a fresh mint is allowed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
import time
from pathlib import Path
from typing import Any

# Allow `python -m demo.operator` to find `core` even if cwd drifted.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import httpx  # noqa: E402

from core.models import Grant  # noqa: E402

# Self-labelling default, matching the broker's. In a real deployment this is a secret
# held by whatever human-facing console mints tasks, and the agent's environment has
# never seen it.
OPERATOR_KEY = os.environ.get("OPERATOR_KEY", "operator-key-change-me")

RULE = "=" * 96


class MintRefused(RuntimeError):
    """The broker would not mint. The reason is the interesting part."""


def default_port() -> int:
    return int(os.environ.get("WARRANT_PORT_BASE") or 8100)


def default_cursor_mcp() -> Path:
    override = (os.environ.get("WARRANT_CURSOR_MCP") or "").strip()
    if override:
        return Path(override).expanduser()
    return Path.home() / ".cursor" / "mcp.json"


def load_grants(path: Path) -> list[dict[str, Any]]:
    """Load grants from a JSON file: either a list, or `{ "grants": [ ... ] }`."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "grants" in data:
        raw = data["grants"]
    else:
        raw = data
    if not isinstance(raw, list) or not raw:
        raise MintRefused(f"grants file {path} must be a non-empty JSON array (or {{grants: [...]}})")
    # Validate shape early so a typo fails here, not as a cryptic 422 from the broker.
    return [Grant.model_validate(item).model_dump(mode="json") for item in raw]


def release(port: int | None = None, operator_key: str = OPERATOR_KEY) -> None:
    """POST /release so a sealed task can be reminted. Operator credential required."""
    base = f"http://127.0.0.1:{port or default_port()}"
    try:
        response = httpx.post(
            f"{base}/release",
            headers={"X-Operator-Key": operator_key},
            timeout=30.0,
        )
    except httpx.RequestError as exc:
        raise MintRefused(
            f"cannot reach the broker at {base} ({exc.__class__.__name__}). "
            "Bring the stack up first: python -m demo.stack up"
        ) from exc
    if response.status_code != 200:
        try:
            reason = response.json().get("reason") or response.text
        except ValueError:
            reason = response.text[:500]
        raise MintRefused(f"POST /release -> {response.status_code}: {reason}")


def mint(
    task: str,
    ttl: int = 300,
    port: int | None = None,
    operator_key: str = OPERATOR_KEY,
    timeout: float = 120.0,
    grants: list[dict[str, Any]] | None = None,
) -> dict:
    """POST /mint with the operator credential. Returns the broker's response body."""
    base = f"http://127.0.0.1:{port or default_port()}"
    body: dict[str, Any] = {"task_statement": task, "ttl_seconds": ttl}
    if grants is not None:
        body["grants"] = grants
    try:
        response = httpx.post(
            f"{base}/mint",
            json=body,
            headers={"X-Operator-Key": operator_key},
            timeout=timeout,
        )
    except httpx.RequestError as exc:
        raise MintRefused(
            f"cannot reach the broker at {base} ({exc.__class__.__name__}). "
            "Bring the stack up first: python -m demo.stack up"
        ) from exc

    if response.status_code == 200:
        return response.json()

    try:
        reason = response.json().get("reason") or response.json().get("detail")
    except ValueError:
        reason = response.text[:500]
    raise MintRefused(f"POST /mint -> {response.status_code}: {reason}")


def write_cursor_token(
    token: str,
    *,
    mcp_path: Path | None = None,
    server_name: str = "warrant",
) -> Path:
    """Set mcpServers.<server>.env.WARRANT_TOKEN in Cursor's mcp.json.

    Creates the warrant server block's env map if missing, but will not invent a
    whole new server config (command/args) -- those paths are machine-specific and
    must already exist. Returns the path written.
    """
    path = mcp_path or default_cursor_mcp()
    if not path.is_file():
        raise MintRefused(
            f"Cursor mcp.json not found at {path}. Create a warrant server entry first "
            "(see README), or pass --cursor-mcp PATH."
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise MintRefused(f"cannot parse {path}: {exc}") from exc

    servers = data.get("mcpServers")
    if not isinstance(servers, dict) or server_name not in servers:
        raise MintRefused(
            f"no mcpServers.{server_name!r} in {path}. Add the warrant block from the "
            "README first, then re-run with --write-cursor."
        )
    entry = servers[server_name]
    if not isinstance(entry, dict):
        raise MintRefused(f"mcpServers.{server_name} in {path} must be an object")
    env = entry.get("env")
    if env is None:
        env = {}
        entry["env"] = env
    if not isinstance(env, dict):
        raise MintRefused(f"mcpServers.{server_name}.env in {path} must be an object")
    env["WARRANT_TOKEN"] = token

    # Atomic-ish replace: write beside, then replace. Avoids a half-written mcp.json
    # if the process is killed mid-write.
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)
    return path


def print_warrant(body: dict) -> None:
    warrant = body["warrant"]
    remaining = int(warrant["expires_at"] - time.time())

    print(RULE)
    print("MINTED BY THE OPERATOR  (this process holds OPERATOR_KEY; the agent will not)")
    print(RULE)
    print(f"  task      : {warrant['task_statement']}")
    print(f"  warrant   : {warrant['warrant_id']}")
    print(f"  task id   : {warrant['task_id']}")
    print(f"  principal : {warrant['principal']}")
    print(f"  agent     : {warrant['agent']}")
    print(f"  expires   : in {remaining}s")
    print(f"  derived in: {body.get('derivation_ms', 0)}ms")
    reasoning = body.get("reasoning") or ""
    if reasoning:
        print(f"  reasoning : {reasoning}")
    print()
    print(f"  grants ({len(warrant['grants'])}):")
    if not warrant["grants"]:
        print("    (none -- this warrant authorizes nothing at all)")
    for index, grant in enumerate(warrant["grants"], start=1):
        wildcard = (
            "  [WILDCARD]"
            if grant["resource"] == "*" or grant["resource"].endswith(":*")
            else ""
        )
        bounds = (
            ", ".join(
                f"{arg} <= {c['lte']}"
                for arg, c in grant["constraints"].items()
                if c.get("lte") is not None
            )
            or "none"
        )
        print(f"    [{index}] {grant['op']:<16} {grant['resource']}{wildcard}")
        print(f"        bounds: {bounds}   uses: {grant['uses']}")
        wrapped = textwrap.wrap(grant.get("justification") or "", width=78) or [""]
        print(f"        why   : {wrapped[0]}")
        for line in wrapped[1:]:
            print(f"                {line}")
    print()
    print("  Everything not listed above is refused by the broker, whatever the agent")
    print("  decides to attempt. This is the whole of the agent's authority.")
    print()
    print(RULE)
    print("TOKEN  (hand this to the agent; it is all the agent gets)")
    print(RULE)
    print(body["token"])
    print()
    print("  The task is now sealed as soon as the agent makes its first call. No")
    print("  second /mint will succeed for it -- widening needs POST /release and a")
    print("  human who has looked at why. Prefer: --remint --write-cursor.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m demo.operator",
        description=(
            "Mint a warrant. Holds OPERATOR_KEY, which the agent process must not."
        ),
    )
    parser.add_argument("--task", required=True, help="The human's task statement.")
    parser.add_argument("--ttl", type=int, default=300, help="Warrant lifetime in seconds.")
    parser.add_argument("--port", type=int, default=None, help="Broker port. Default 8100.")
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Print only the raw token, so it can be piped or captured.",
    )
    parser.add_argument(
        "--grants",
        type=Path,
        default=None,
        metavar="FILE",
        help=(
            "JSON file of grants to sign as-is (skips Gemini derivation). "
            "Either a list of Grant objects, or {\"grants\": [...]}."
        ),
    )
    parser.add_argument(
        "--remint",
        action="store_true",
        help="POST /release first so a sealed task can be minted again.",
    )
    parser.add_argument(
        "--write-cursor",
        action="store_true",
        help="Write WARRANT_TOKEN into Cursor's mcp.json (see --cursor-mcp).",
    )
    parser.add_argument(
        "--cursor-mcp",
        type=Path,
        default=None,
        help=f"Path to mcp.json. Default: {default_cursor_mcp()}",
    )
    parser.add_argument(
        "--server-name",
        default="warrant",
        help="mcpServers key to update when using --write-cursor. Default: warrant.",
    )
    args = parser.parse_args(argv)

    grants = None
    if args.grants is not None:
        try:
            grants = load_grants(args.grants)
        except (OSError, MintRefused, ValueError) as exc:
            print(f"GRANTS: {exc}", file=sys.stderr)
            return 1

    try:
        if args.remint:
            release(port=args.port)
        body = mint(args.task, ttl=args.ttl, port=args.port, grants=grants)
    except MintRefused as exc:
        hint = ""
        if "409" in str(exc) or "sealed" in str(exc).lower():
            hint = "\n  Tip: re-run with --remint to release the sealed task first."
        print(f"MINT REFUSED: {exc}{hint}", file=sys.stderr)
        return 1

    if args.write_cursor:
        try:
            written = write_cursor_token(
                body["token"],
                mcp_path=args.cursor_mcp,
                server_name=args.server_name,
            )
        except MintRefused as exc:
            print(f"CURSOR: {exc}", file=sys.stderr)
            return 1
        if not args.quiet:
            print(f"Wrote WARRANT_TOKEN → {written}  (reload the warrant MCP in Cursor)")
            print()

    if args.quiet:
        print(body["token"])
        return 0

    print_warrant(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
