"""What happens when the derivation step produces a bad scope.

The warrant here is not minted. No model runs. It is hand-written to be as broad as a
derivation could possibly get it -- wildcards on every operation -- and then signed with
the real key, so it is cryptographically indistinguishable from one the broker issued.
Enforcement does not know or care where a grant came from.

    python -m demo.overbroad [--port 8100]
"""

from __future__ import annotations

import argparse
import os
import sys
import textwrap
import time

import httpx

from core.models import Grant, Warrant
from core.sign import encode, sign

RULE = "=" * 96
THIN = "-" * 96

# The task the human actually stated. The grants below are what a maximally sloppy or
# manipulated derivation might have emitted from it.
TASK = "Look into ticket t-501 for Anil and refund his order 1234 if the complaint is valid"

OVERBROAD_GRANTS = [
    Grant(
        op="refunds.create",
        resource="order:*",
        uses=99,
        justification="refund any order, any amount, no bound",
    ),
    Grant(
        op="email.send",
        resource="customer:*",
        uses=99,
        justification="email any customer, any content",
    ),
    Grant(
        op="orders.list",
        resource="*",
        uses=99,
        justification="read the whole order book",
    ),
    Grant(
        op="customers.get",
        resource="customer:*",
        uses=99,
        justification="read any customer record",
    ),
]

# (op, args, what the caller is trying to do, expected outcome)
MUTATIONS = [
    ("refunds.create", {"order_id": "9999", "amount": 250000},
     "refund the enterprise order in full", "DENY"),
    ("refunds.create", {"order_id": "1234", "amount": 1},
     "refund one rupee on the order the task was actually about", "DENY"),
    ("email.send", {"customer_id": "all", "subject": "Notice", "body": "..."},
     "broadcast to every customer", "DENY"),
    ("email.send", {"customer_id": "c-anil", "subject": "Notice", "body": "..."},
     "email one single named customer", "DENY"),
]

READS = [
    ("orders.list", {}, "list every order in the system", "ALLOW"),
    ("customers.get", {"customer_id": "c-enterprise"},
     "read a customer record -- same customer:* grant that email.send was refused on", "ALLOW"),
]


def wrap(text: str, indent: str = "         -> ") -> str:
    hang = " " * len(indent)
    return textwrap.fill(text, width=94, initial_indent=indent, subsequent_indent=hang)


def build_overbroad() -> Warrant:
    return sign(
        Warrant(
            principal="human:arnav",
            agent="agent:support-01",
            task_statement=TASK,
            grants=OVERBROAD_GRANTS,
            expires_at=time.time() + 300,
        )
    )


def build_narrow() -> Warrant:
    return sign(
        Warrant(
            principal="human:arnav",
            agent="agent:support-01",
            task_statement=TASK,
            grants=[
                Grant(
                    op="orders.get",
                    resource="order:1234",
                    uses=99,
                    justification="read the one order named in the task",
                )
            ],
            expires_at=time.time() + 300,
        )
    )


def attempt(client: httpx.Client, token: str, op: str, args: dict,
            why: str, expect: str) -> bool:
    """Fire one call and print it. Returns True if the outcome matched `expect`."""
    body = client.post(
        "/call", json={"op": op, "args": args}, headers={"X-Warrant": token}
    ).json()
    got = "ALLOW" if body.get("ok") else "DENY"
    target = args.get("order_id") or args.get("customer_id") or "-"

    print(f"\n  {got:<6} {op:<16} {target}")
    print(f"         {why}")
    if body.get("ok"):
        print(wrap(f"upstream returned {body['status']}; credential attached by the broker"))
    else:
        print(wrap(body["reason"]))
        print("         -> no credential attached. nothing reached upstream.")

    if got != expect:
        print(f"         !! EXPECTED {expect}, GOT {got}")
        return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("WARRANT_PORT_BASE") or 8100)
    )
    args = parser.parse_args()
    base = f"http://127.0.0.1:{args.port}"
    ok = True

    print(RULE)
    print("WHAT IF THE MODEL DERIVES A BAD SCOPE?")
    print(RULE)
    print("  Nothing below is minted. No model runs. The warrant is hand-written to be as")
    print("  broad as a derivation could possibly get it, then signed with the real key --")
    print("  so the broker cannot tell it apart from one it issued itself.\n")

    warrant = build_overbroad()
    token = encode(warrant)

    with httpx.Client(timeout=60.0, base_url=base) as client:
        try:
            client.get("/healthz").raise_for_status()
        except httpx.HTTPError as exc:
            print(f"  broker not reachable at {base}: {exc}")
            print("  bring the stack up first: python -m demo.stack up")
            return 1

        print(RULE)
        print(f"THE FORGED-BROAD WARRANT  {warrant.warrant_id[:8]}   "
              f"signature: VALID (signed with the live key)")
        print(RULE)
        print(f"  stated task: {TASK}\n")
        for grant in warrant.grants:
            wide = "WILDCARD" if grant.resource == "*" or grant.resource.endswith(":*") else "exact"
            print(f"  {grant.op:<16} {grant.resource:<14} {wide:<9} uses={grant.uses}")
            print(f"      claims: {grant.justification}")
        print("\n  Every grant is unbounded. This is the worst case, not a near miss.\n")

        print(RULE)
        print("MUTATING CALLS -- the wildcard grants appear to authorize all of these")
        print(RULE)
        for op, call_args, why, expect in MUTATIONS:
            ok &= attempt(client, token, op, call_args, why, expect)

        print(f"\n{THIN}")
        print("  Refused before any argument was examined, before the resource was matched,")
        print("  before the use budget was touched. The grant's shape alone disqualifies it.")
        print(THIN)

        print(f"\n{RULE}")
        print("READ CALLS -- the same wildcard grants, including the identical customer:*")
        print(RULE)
        for op, call_args, why, expect in READS:
            ok &= attempt(client, token, op, call_args, why, expect)

        print(f"\n{THIN}")
        print("  The rule is aimed at mutations, not at wildcards in general. customer:* reads")
        print("  a customer fine and cannot send that customer mail. If everything were refused")
        print("  the rule would prove nothing.")
        print(THIN)

        print(f"\n{RULE}")
        print("AND IF THE HOLDER EDITS THE WARRANT INSTEAD")
        print(RULE)
        narrow = build_narrow()
        print(f"  A narrow warrant {narrow.warrant_id[:8]}: orders.get on order:1234, signed.")
        ok &= attempt(client, encode(narrow), "orders.get", {"order_id": "1234"},
                      "read the order it was actually issued for", "ALLOW")
        ok &= attempt(client, encode(narrow), "orders.get", {"order_id": "9999"},
                      "read the enterprise order it was not issued for", "DENY")

        print("\n  Now widen that grant by hand, after signing: order:1234 -> order:*")
        narrow.grants[0].resource = "order:*"
        ok &= attempt(client, encode(narrow), "orders.get", {"order_id": "9999"},
                      "same call again, now with the widened grant", "DENY")
        print("\n         orders.get is a read, so the wildcard rule would have let this")
        print("         through. The signature is what stopped it.")

        ids = {warrant.warrant_id, narrow.warrant_id}
        entries = [e for e in client.get("/audit").json()["entries"]
                   if e["warrant_id"] in ids]
        allowed = sum(e["decision"] == "ALLOW" for e in entries)

        print(f"\n{RULE}")
        print(f"{allowed} allowed, {len(entries) - allowed} denied   "
              f"({len(entries)} audit entries, every one attributable to {warrant.principal})")
        print(RULE)
        if not ok:
            print("  SOME OUTCOME DID NOT MATCH ITS EXPECTATION -- see the !! lines above.\n")
            return 1
        print("  Derivation decides what to ask for; enforcement decides what is possible,")
        print("  so a bad scope costs you reads you did not need -- never writes you cannot bound.\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
