"""The operator: the only process in this project that can create authority.

    python -m demo.operator --task "<task statement>"
    python -m demo.operator --task "<task statement>" --quiet   # token only

This exists as a separate file for one reason. Minting requires `OPERATOR_KEY`, and
the argument this project makes is that the agent must not be able to mint -- not
"does not", *cannot*. That is only true if the credential lives somewhere the agent
process does not. So it lives here, and the agent is handed a token.

Run it and read the output as the human would: this is the moment authority is
created, from the human's words, before anything untrusted has been read. Everything
after this point can only spend that authority or be refused.

`--quiet` prints the raw token and nothing else, so it can be captured:

    TOKEN=$(python -m demo.operator --task "..." --quiet)
    python -m agent.run --task "..." --warrant "$TOKEN"

which is exactly what `demo/session.py` does, minus the part where it also strips
OPERATOR_KEY out of the agent's environment.
"""

from __future__ import annotations

import argparse
import os
import sys
import textwrap
import time
from pathlib import Path

# Allow `python -m demo.operator` to find `core` even if cwd drifted.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import httpx  # noqa: E402

# Self-labelling default, matching the broker's. In a real deployment this is a secret
# held by whatever human-facing console mints tasks, and the agent's environment has
# never seen it.
OPERATOR_KEY = os.environ.get("OPERATOR_KEY", "operator-key-change-me")

RULE = "=" * 96


class MintRefused(RuntimeError):
    """The broker would not mint. The reason is the interesting part."""


def default_port() -> int:
    return int(os.environ.get("WARRANT_PORT_BASE") or 8100)


def mint(
    task: str,
    ttl: int = 300,
    port: int | None = None,
    operator_key: str = OPERATOR_KEY,
    timeout: float = 120.0,
) -> dict:
    """POST /mint with the operator credential. Returns the broker's response body."""
    base = f"http://127.0.0.1:{port or default_port()}"
    try:
        response = httpx.post(
            f"{base}/mint",
            json={"task_statement": task, "ttl_seconds": ttl},
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
        wrapped = textwrap.wrap(grant["justification"], width=78) or [""]
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
    print("  human who has looked at why.")


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
    args = parser.parse_args(argv)

    try:
        body = mint(args.task, ttl=args.ttl, port=args.port)
    except MintRefused as exc:
        print(f"MINT REFUSED: {exc}", file=sys.stderr)
        return 1

    if args.quiet:
        print(body["token"])
        return 0

    print_warrant(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
