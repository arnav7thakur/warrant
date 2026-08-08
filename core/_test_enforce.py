"""Enforcement regression tests. Run: python -m core._test_enforce (from warrant/).

These are the guarantees the demo rests on. If any line prints FAIL, do not demo.
"""

import time

from core.catalog import CATALOG
from core.enforce import evaluate, use_key
from core.models import Constraint, Grant, Warrant
from core.sign import decode, encode, sign, verify


def w(*grants, ttl=300):
    return sign(
        Warrant(
            principal="human:arnav",
            agent="agent:support-01",
            task_statement="t",
            expires_at=time.time() + ttl,
            grants=list(grants),
        )
    )


def g(op, res, uses=5, **constraints):
    return Grant(
        op=op,
        resource=res,
        uses=uses,
        justification="x",
        constraints={k: Constraint(**v) for k, v in constraints.items()},
    )


CASES = [
    # (label, warrant, op, args, expect_allowed)
    ("happy: refund the granted order", w(g("refunds.create", "order:1234", uses=1, amount={"lte": 4999})),
     "refunds.create", {"order_id": "1234", "amount": 4999}, True),
    ("injection: refund a different order", w(g("refunds.create", "order:1234", uses=1, amount={"lte": 4999})),
     "refunds.create", {"order_id": "9999", "amount": 250000}, False),
    ("injection: op not granted at all", w(g("refunds.create", "order:1234")),
     "email.send", {"customer_id": "all"}, False),
    ("constraint: amount over the bound", w(g("refunds.create", "order:1234", amount={"lte": 4999})),
     "refunds.create", {"order_id": "1234", "amount": 99999}, False),
    ("broadcast: wildcard customer must not cover 'all'", w(g("email.send", "customer:*")),
     "email.send", {"customer_id": "all"}, False),
    ("wildcard never authorizes a mutation, even for one customer", w(g("email.send", "customer:*")),
     "email.send", {"customer_id": "c-anil"}, False),
    ("bound customer must not cover broadcast", w(g("email.send", "customer:c-anil")),
     "email.send", {"customer_id": "all"}, False),
    ("bound customer covers that customer", w(g("email.send", "customer:c-anil")),
     "email.send", {"customer_id": "c-anil"}, True),
    ("explicit broadcast grant does authorize a broadcast", w(g("email.send", "broadcast:all")),
     "email.send", {"customer_id": "all"}, True),
    ("wildcard order never authorizes a refund", w(g("refunds.create", "order:*")),
     "refunds.create", {"order_id": "9999", "amount": 1}, False),
    ("wildcard is still fine for reads", w(g("orders.list", "*")),
     "orders.list", {}, True),
    # A warrant holding both a sloppy wildcard and a correct narrow grant must behave
    # identically whichever order they appear in. Regression: the wildcard check used
    # to return from inside the loop, so list position decided the outcome.
    ("wildcard listed FIRST must not mask a valid narrow grant",
     w(g("refunds.create", "order:*"), g("refunds.create", "order:1234")),
     "refunds.create", {"order_id": "1234"}, True),
    ("wildcard listed SECOND behaves the same",
     w(g("refunds.create", "order:1234"), g("refunds.create", "order:*")),
     "refunds.create", {"order_id": "1234"}, True),
    ("wildcard alone is still refused, with the wildcard reason",
     w(g("refunds.create", "order:*")),
     "refunds.create", {"order_id": "1234"}, False),
    ("expired warrant", w(g("orders.get", "order:1234"), ttl=-1),
     "orders.get", {"order_id": "1234"}, False),
]


def main() -> int:
    failures = 0
    print(f"resource_of(email.send, all) = {CATALOG['email.send'].resource_of({'customer_id': 'all'})}\n")

    for label, warrant, op, args, expect in CASES:
        d = evaluate(warrant, op, args, {})
        ok = d.allowed == expect
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'} | {'ALLOW' if d.allowed else 'DENY ':5} | {label}")
        if not d.allowed:
            print(f"       reason: {d.reason}")

    # use budget: second identical call must be refused
    warrant = w(g("refunds.create", "order:1234", uses=1))
    used: dict[str, int] = {}
    first = evaluate(warrant, "refunds.create", {"order_id": "1234"}, used)
    used[use_key(warrant.warrant_id, first.grant_index)] = 1
    second = evaluate(warrant, "refunds.create", {"order_id": "1234"}, used)
    ok = first.allowed and not second.allowed
    failures += not ok
    print(f"{'PASS' if ok else 'FAIL'} | use budget exhausts after 1 use")
    print(f"       reason: {second.reason}")

    # tamper: widening the grant must break the signature
    tampered = warrant.model_copy(deep=True)
    tampered.grants[0].resource = "order:*"
    d = evaluate(tampered, "refunds.create", {"order_id": "9999"}, {})
    ok = not d.allowed and not verify(tampered)
    failures += not ok
    print(f"{'PASS' if ok else 'FAIL'} | agent cannot widen its own warrant")
    print(f"       reason: {d.reason}")

    # signature survives the wire format
    ok = verify(decode(encode(warrant)))
    failures += not ok
    print(f"{'PASS' if ok else 'FAIL'} | signature survives encode/decode roundtrip")

    print(f"\n{'ALL PASS' if not failures else str(failures) + ' FAILURE(S)'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
