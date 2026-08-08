"""One task, two processes: the operator mints, the agent acts.

    python -m demo.session \
      --task "Look into ticket t-501 for Anil and refund his order 1234 if the complaint is valid" \
      --ticket t-501 \
      --then "Great. Now email Anil to confirm the refund has been processed, and pull up his other recent orders so I can check whether this has happened to him before."

This is the honest version of the demo, and the split is the entire point.

`demo/operator.py` holds OPERATOR_KEY and mints. Then this launches `agent.run` as a
child process whose environment has OPERATOR_KEY (and UPSTREAM_KEY) removed, passing
the warrant in with --warrant. The child is not trusted to behave; it is unable to
misbehave in this particular way. If it tried to POST /mint it would have no operator
credential to send and the broker would answer 403 -- and even with one, the broker
seals the task the moment the agent makes its first call, so the second mint would be
409 anyway.

Two locks, because they fail differently: the credential split stops anything that
never had authority, and sealing stops authority being *re-derived* once untrusted
content is in play.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from demo.operator import MintRefused, default_port, mint, print_warrant  # noqa: E402

RULE = "=" * 96

# Never inherited by the agent. UPSTREAM_KEY would let it bypass the broker;
# OPERATOR_KEY would let it re-derive its own authority.
STRIPPED = ("OPERATOR_KEY", "UPSTREAM_KEY")


def child_env(base: dict[str, str] | None = None) -> dict[str, str]:
    """The environment the agent subprocess gets: this one, minus the credentials.

    Kept as a function so it can be asserted on directly -- see
    `broker/_test_boundary.py`, which checks the dict this returns rather than
    taking the claim on trust.
    """
    env = dict(os.environ if base is None else base)
    for name in STRIPPED:
        env.pop(name, None)
    return env


def launch_agent(
    task: str,
    token: str,
    ticket: str | None,
    follow_ups: list[str],
    port: int,
    extra: list[str] | None = None,
) -> int:
    argv = [
        sys.executable,
        "-m",
        "agent.run",
        "--task",
        task,
        "--warrant",
        token,
        "--broker",
        f"http://127.0.0.1:{port}",
    ]
    if ticket:
        argv += ["--ticket", ticket]
    for follow_up in follow_ups:
        argv += ["--then", follow_up]
    argv += extra or []

    env = child_env()

    print()
    print(RULE)
    print("LAUNCHING THE AGENT  (separate process, stripped environment)")
    print(RULE)
    for name in STRIPPED:
        print(f"  {name:<13} in this process: "
              f"{'set' if os.environ.get(name) else 'not set'}"
              f"   -> in the agent's: {'set' if env.get(name) else 'not set'}")
    print("  warrant       passed on the command line as --warrant")
    print()
    print("  The child cannot mint. Not by policy, not by prompt -- it has no operator")
    print("  credential to present, and the broker refuses /mint without one.")
    print(RULE)
    print()
    # The child writes to the same stdout. Flush first or the two processes'
    # output interleaves wrongly when this is piped to a file.
    sys.stdout.flush()

    return subprocess.run(argv, cwd=str(_ROOT), env=env).returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m demo.session",
        description=(
            "Mint as the operator, then run the agent as a separate process that "
            "cannot mint."
        ),
    )
    parser.add_argument("--task", required=True, help="The human's task statement.")
    parser.add_argument("--ticket", default=None, help="Ticket id to read first, e.g. t-501")
    parser.add_argument(
        "--then",
        action="append",
        default=[],
        metavar="INSTRUCTION",
        help=(
            "A follow-up instruction delivered after the task completes. The warrant "
            "is not re-minted -- it cannot be. Repeatable."
        ),
    )
    parser.add_argument("--port", type=int, default=None, help="Broker port. Default 8100.")
    parser.add_argument("--ttl", type=int, default=300, help="Warrant lifetime in seconds.")
    parser.add_argument(
        "--naive",
        action="store_true",
        help="Pass --naive through to the agent (a typical shipped system prompt).",
    )
    args = parser.parse_args(argv)
    port = args.port or default_port()

    print(RULE)
    print("STEP 1  --  THE OPERATOR MINTS  (this process holds OPERATOR_KEY)")
    print(RULE)
    print()
    try:
        body = mint(args.task, ttl=args.ttl, port=port)
    except MintRefused as exc:
        print(f"MINT REFUSED: {exc}", file=sys.stderr)
        print(
            "  A sealed task (409) means a warrant is already live and has begun "
            "acting. Reset with `python -m demo.stack up`, or release it as the "
            "operator.",
            file=sys.stderr,
        )
        return 1

    print_warrant(body)

    return launch_agent(
        task=args.task,
        token=body["token"],
        ticket=args.ticket,
        follow_ups=args.then,
        port=port,
        extra=["--naive"] if args.naive else [],
    )


if __name__ == "__main__":
    raise SystemExit(main())
