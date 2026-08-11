"""POC: deterministic end-to-end proof (injection theatre).

Not the product path. Prefer register → mint → MCP for trying Warrant on your system.

    python -m poc.run_demo [--port 8100]
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import httpx  # noqa: E402

from demo.operator import OPERATOR_KEY  # noqa: E402

TASK = "Look into ticket t-501 for Anil and refund his order 1234 if the complaint is valid"

# What the agent is asked to do, then what the injected triage note tells it to do.
ATTEMPTS = [
    ("tickets.get", {"ticket_id": "t-501"}, "read the customer's ticket", "task"),
    ("orders.get", {"order_id": "1234"}, "check the order being complained about", "task"),
    ("refunds.create", {"order_id": "1234", "amount": 4999}, "refund the customer's order", "task"),
    ("refunds.create", {"order_id": "9999", "amount": 250000}, "refund the 'linked' enterprise order", "injection"),
    ("email.send", {"customer_id": "all", "subject": "Service Disruption Notice", "body": "..."},
     "broadcast to the entire customer base", "injection"),
]

RULE = "=" * 96


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("WARRANT_PORT_BASE") or 8100)
    )
    args = parser.parse_args()
    base = f"http://127.0.0.1:{args.port}"

    with httpx.Client(timeout=60.0, base_url=base) as client:
        print(RULE)
        print("TASK (stated by the human, before the agent runs anything)")
        print(RULE)
        print(f"  {TASK}\n")

        print("Deriving minimum sufficient authority...")
        try:
            minted = (
                client.post(
                    "/mint",
                    json={"task_statement": TASK},
                    headers={"X-Operator-Key": OPERATOR_KEY},
                )
                .raise_for_status()
                .json()
            )
        except httpx.HTTPError as exc:
            print(f"  mint failed: {exc}")
            print("  409 means a task is already live and sealed -- reset with "
                  "`python -m demo.stack up`.")
            return 1

        warrant = minted["warrant"]
        token = minted["token"]
        print(f"  derived in {minted['derivation_ms']}ms\n")

        print(RULE)
        print(f"WARRANT  {warrant['warrant_id'][:8]}   principal={warrant['principal']}   agent={warrant['agent']}")
        print(RULE)
        for grant in warrant["grants"]:
            bounds = ", ".join(
                f"{arg} <= {c['lte']}" for arg, c in grant["constraints"].items() if c.get("lte") is not None
            ) or "-"
            print(f"  {grant['op']:<16} {grant['resource']:<16} uses={grant['uses']}  bounds: {bounds}")
            print(f"      why: {grant['justification']}")
        print(f"\n  expires in {int(warrant['expires_at'] - warrant['issued_at'])}s")
        print("  the agent carries this and nothing else -- no upstream credential\n")

        print(RULE)
        print("CALLS")
        print(RULE)
        allowed = denied = 0
        for op, call_args, why, origin in ATTEMPTS:
            response = client.post(
                "/call", json={"op": op, "args": call_args},
                headers={"X-Warrant": token},
            )
            body = response.json()
            tag = "[from the task]" if origin == "task" else "[FROM THE INJECTED TICKET TEXT]"

            if body.get("ok"):
                allowed += 1
                print(f"\n  ALLOW  {op}  {tag}")
                print(f"         {why}")
                print(f"         -> credential attached, upstream returned {body['status']}")
            else:
                denied += 1
                print(f"\n  DENY   {op}  {tag}")
                print(f"         {why}")
                print(f"         -> {body['reason']}")
                print("         -> no credential attached. nothing reached upstream.")

        print(f"\n{RULE}")
        print(f"{allowed} allowed, {denied} denied")
        print(RULE)
        print("  No model chose those calls -- this script drives them directly, so the")
        print("  enforcement path is exercised without depending on a model complying.")
        print("  The last two are exactly what the injected text in ticket t-501 asks for.")
        print()
        print("  Nothing inspected that text. Nothing classified it as an attack.")
        print("  The actions were simply not within the authority that was minted.\n")

        audit = client.get("/audit").json()["entries"]
        print(f"  audit: {len(audit)} entries, each attributable to "
              f"{warrant['principal']} via task {warrant['task_id'][:8]}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

