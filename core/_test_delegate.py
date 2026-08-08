"""Delegation / attenuation regression tests. Run: python -m core._test_delegate

The claim under test is one sentence: **a child warrant can never reach anything its
parent could not reach.** Everything below is an attempt to break that, one dimension at
a time -- operation, resource, each kind of argument bound, use budget, expiry, the
wildcard-mutation rule, the chain itself -- followed by proof that legitimate narrowing
still works and that the narrowed child actually functions through core.enforce.evaluate.

If any line prints FAIL, delegation is a suggestion rather than a boundary.
"""

from __future__ import annotations

import time

from core.delegate import (
    AttenuationError,
    DelegationLedger,
    attenuate,
)
from core.enforce import evaluate, use_key
from core.models import Constraint, Grant, Warrant
from core.sign import decode, encode, sign

FAILURES = 0


# ----------------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------------


def g(op: str, res: str, uses: int = 5, **constraints) -> Grant:
    return Grant(
        op=op,
        resource=res,
        uses=uses,
        justification="x",
        constraints={k: Constraint(**v) for k, v in constraints.items()},
    )


def root(*grants: Grant, ttl: int = 300, agent: str = "agent:lead") -> Warrant:
    return sign(
        Warrant(
            principal="human:arnav",
            agent=agent,
            task_statement="look into ticket t-501 and refund order 1234 if valid",
            expires_at=time.time() + ttl,
            grants=list(grants),
        )
    )


def report(ok: bool, label: str, detail: str = "") -> None:
    global FAILURES
    FAILURES += not ok
    print(f"{'PASS' if ok else 'FAIL'} | {label}")
    if detail:
        print(f"       {detail}")


def denies(label: str, expected_dimension: str, fn) -> None:
    """The attack must raise AttenuationError, and name the right dimension."""
    try:
        fn()
    except AttenuationError as exc:
        ok = exc.dimension == expected_dimension
        report(
            ok,
            label,
            f"raised [{exc.dimension}] {exc.reason}"
            + ("" if ok else f"   <-- expected dimension {expected_dimension!r}"),
        )
    except Exception as exc:  # noqa: BLE001 - any other exception is a test failure
        report(False, label, f"raised {type(exc).__name__}: {exc} (expected AttenuationError)")
    else:
        report(False, label, "NO ERROR RAISED -- the child warrant was issued")


def allows(label: str, fn) -> Warrant | None:
    try:
        child = fn()
    except AttenuationError as exc:
        report(False, label, f"unexpectedly raised [{exc.dimension}] {exc.reason}")
        return None
    report(True, label)
    return child


def decision(label: str, expect_allowed: bool, warrant, op, args, used=None, chain=None) -> None:
    d = evaluate(warrant, op, args, used if used is not None else {}, chain=chain)
    report(
        d.allowed == expect_allowed,
        f"{label}  ->  {'ALLOW' if d.allowed else 'DENY'}",
        "" if d.allowed else f"reason: {d.reason}",
    )


# ----------------------------------------------------------------------------------
# the parent every attack starts from
# ----------------------------------------------------------------------------------


def parent_warrant(ttl: int = 300) -> Warrant:
    return root(
        g("tickets.get", "ticket:t-501", uses=2),
        g("orders.get", "order:*", uses=4),
        g("refunds.create", "order:1234", uses=3, amount={"lte": 5000}, reason={"one_of": ["defect", "late"]}),
        g("email.send", "customer:c-anil", uses=1),
        ttl=ttl,
    )


def main() -> int:  # noqa: PLR0915 - it is a test list; flat is the point
    print("=" * 78)
    print("ATTACKS -- each must be refused, naming the dimension it widened")
    print("=" * 78)

    # -- operation ------------------------------------------------------------------
    p = parent_warrant()
    denies(
        "widen the op set: request an op the parent does not hold",
        "operation",
        lambda: attenuate(
            p, [g("refunds.list", "*", uses=1)], agent="agent:sub", ttl_seconds=60
        ),
    )
    denies(
        "widen the op set: an op that is not even in the catalog",
        "operation",
        lambda: attenuate(
            p, [g("orders.delete", "order:1234", uses=1)], agent="agent:sub", ttl_seconds=60
        ),
    )

    # -- resource -------------------------------------------------------------------
    denies(
        "widen the resource: exact order:1234 -> wildcard order:* (read op)",
        "resource",
        lambda: attenuate(
            p,
            [g("tickets.get", "ticket:*", uses=1)],
            agent="agent:sub",
            ttl_seconds=60,
        ),
    )
    denies(
        "widen the resource: exact -> the universal wildcard '*'",
        "resource",
        lambda: attenuate(
            p, [g("tickets.get", "*", uses=1)], agent="agent:sub", ttl_seconds=60
        ),
    )
    denies(
        "sideways resource: order:1234 -> order:9999 (the injection's target)",
        "resource",
        lambda: attenuate(
            p,
            [g("refunds.create", "order:9999", uses=1, amount={"lte": 5000}, reason={"one_of": ["defect"]})],
            agent="agent:sub",
            ttl_seconds=60,
        ),
    )
    denies(
        "sideways resource: customer:c-anil -> broadcast:all",
        "resource",
        lambda: attenuate(
            p, [g("email.send", "broadcast:all", uses=1)], agent="agent:sub", ttl_seconds=60
        ),
    )
    denies(
        "a wildcard does not cross resource types: orders.get order:* -> ticket:t-501",
        "resource",
        lambda: attenuate(
            p, [g("orders.get", "ticket:t-501", uses=1)], agent="agent:sub", ttl_seconds=60
        ),
    )

    # -- argument constraints -------------------------------------------------------
    denies(
        "loosen a bound: amount lte 5000 -> lte 9000",
        "constraint",
        lambda: attenuate(
            p,
            [g("refunds.create", "order:1234", uses=1, amount={"lte": 9000}, reason={"one_of": ["defect"]})],
            agent="agent:sub",
            ttl_seconds=60,
        ),
    )
    denies(
        "drop a bound entirely: parent bounds amount, child does not",
        "constraint",
        lambda: attenuate(
            p,
            [g("refunds.create", "order:1234", uses=1, reason={"one_of": ["defect"]})],
            agent="agent:sub",
            ttl_seconds=60,
        ),
    )
    denies(
        "empty the bound: amount lte 5000 -> Constraint() with nothing set",
        "constraint",
        lambda: attenuate(
            p,
            [
                Grant(
                    op="refunds.create",
                    resource="order:1234",
                    uses=1,
                    constraints={"amount": Constraint(), "reason": Constraint(one_of=["defect"])},
                )
            ],
            agent="agent:sub",
            ttl_seconds=60,
        ),
    )
    denies(
        "widen a value set: one_of [defect, late] -> [defect, goodwill]",
        "constraint",
        lambda: attenuate(
            p,
            [
                g(
                    "refunds.create",
                    "order:1234",
                    uses=1,
                    amount={"lte": 1000},
                    reason={"one_of": ["defect", "goodwill"]},
                )
            ],
            agent="agent:sub",
            ttl_seconds=60,
        ),
    )
    denies(
        "escape a value set via eq: one_of [defect, late] -> eq 'goodwill'",
        "constraint",
        lambda: attenuate(
            p,
            [
                g(
                    "refunds.create",
                    "order:1234",
                    uses=1,
                    amount={"lte": 1000},
                    reason={"eq": "goodwill"},
                )
            ],
            agent="agent:sub",
            ttl_seconds=60,
        ),
    )
    floored = root(g("refunds.create", "order:1234", uses=2, amount={"gte": 100, "lte": 5000}))
    denies(
        "lower a floor: gte 100 -> gte 1",
        "constraint",
        lambda: attenuate(
            floored,
            [g("refunds.create", "order:1234", uses=1, amount={"gte": 1, "lte": 500})],
            agent="agent:sub",
            ttl_seconds=60,
        ),
    )

    # -- use budget -----------------------------------------------------------------
    denies(
        "widen the budget: parent grant has uses=3, child asks for 5",
        "uses",
        lambda: attenuate(
            p,
            [g("refunds.create", "order:1234", uses=5, amount={"lte": 100}, reason={"one_of": ["defect"]})],
            agent="agent:sub",
            ttl_seconds=60,
        ),
    )
    already_spent = {use_key(p.warrant_id, 2): 2}  # 2 of the refund grant's 3 uses gone
    denies(
        "budget is the REMAINING budget: 1 of 3 left, child asks for 2",
        "uses",
        lambda: attenuate(
            p,
            [g("refunds.create", "order:1234", uses=2, amount={"lte": 100}, reason={"one_of": ["defect"]})],
            agent="agent:sub",
            ttl_seconds=60,
            spent=already_spent,
        ),
    )
    denies(
        "siblings cannot each claim the whole budget: 2 + 2 out of 3",
        "uses",
        lambda: attenuate(
            p,
            [
                g("tickets.get", "ticket:t-501", uses=2),
                g("tickets.get", "ticket:t-501", uses=2),
            ],
            agent="agent:sub",
            ttl_seconds=60,
        ),
    )
    denies(
        "a zero-use grant is not a grant",
        "uses",
        lambda: attenuate(
            p, [g("tickets.get", "ticket:t-501", uses=0)], agent="agent:sub", ttl_seconds=60
        ),
    )

    # -- expiry ---------------------------------------------------------------------
    short = parent_warrant(ttl=30)
    denies(
        "outlive the parent: parent has 30s left, child asks for 600s",
        "expiry",
        lambda: attenuate(
            short, [g("tickets.get", "ticket:t-501", uses=1)], agent="agent:sub", ttl_seconds=600
        ),
    )
    dead = parent_warrant(ttl=-5)
    denies(
        "delegate from an already-expired parent",
        "expiry",
        lambda: attenuate(
            dead, [g("tickets.get", "ticket:t-501", uses=1)], agent="agent:sub", ttl_seconds=10
        ),
    )
    denies(
        "a non-positive ttl is not a lifetime",
        "expiry",
        lambda: attenuate(
            p, [g("tickets.get", "ticket:t-501", uses=1)], agent="agent:sub", ttl_seconds=0
        ),
    )

    # -- the wildcard-mutation rule -------------------------------------------------
    denies(
        "child ends up with a wildcard resource on a mutating op",
        "wildcard-mutation",
        lambda: attenuate(
            p,
            [g("refunds.create", "order:*", uses=1, amount={"lte": 100}, reason={"one_of": ["defect"]})],
            agent="agent:sub",
            ttl_seconds=60,
        ),
    )
    denies(
        "child ends up with '*' on a mutating op",
        "wildcard-mutation",
        lambda: attenuate(
            p, [g("email.send", "*", uses=1)], agent="agent:sub", ttl_seconds=60
        ),
    )
    # The escalation that looks like an attenuation: enforcement refuses a wildcard on a
    # mutating op, so `refunds.create order:*` is a DEAD grant -- it can authorize
    # nothing. Slicing `order:9999` out of it would produce a child that can move money
    # its parent structurally could not.
    dead_wildcard = root(g("refunds.create", "order:*", uses=5))
    decision(
        "sanity: the parent's own wildcard refund grant is refused by enforcement",
        False,
        dead_wildcard,
        "refunds.create",
        {"order_id": "9999", "amount": 250000},
    )
    denies(
        "resurrect a dead grant: refunds.create order:* -> order:9999",
        "unenforceable-parent",
        lambda: attenuate(
            dead_wildcard,
            [g("refunds.create", "order:9999", uses=1, amount={"lte": 250000})],
            agent="agent:sub",
            ttl_seconds=60,
        ),
    )
    dead_broadcast = root(g("email.send", "customer:*", uses=5))
    denies(
        "resurrect a dead grant: email.send customer:* -> customer:c-anil",
        "unenforceable-parent",
        lambda: attenuate(
            dead_broadcast,
            [g("email.send", "customer:c-anil", uses=1)],
            agent="agent:sub",
            ttl_seconds=60,
        ),
    )

    # -- structural -----------------------------------------------------------------
    tampered = p.model_copy(deep=True)
    tampered.grants[2].constraints["amount"].lte = 250000
    denies(
        "delegate from a hand-edited parent (signature broken)",
        "signature",
        lambda: attenuate(
            tampered,
            [g("refunds.create", "order:1234", uses=1, amount={"lte": 250000}, reason={"one_of": ["defect"]})],
            agent="agent:sub",
            ttl_seconds=60,
        ),
    )
    denies(
        "a child with no grants at all",
        "grants",
        lambda: attenuate(p, [], agent="agent:sub", ttl_seconds=60),
    )

    print()
    print("=" * 78)
    print("LEGITIMATE NARROWING -- and the child actually working through evaluate()")
    print("=" * 78)

    ledger = DelegationLedger()
    parent = parent_warrant()
    ledger.register(parent)
    used: dict[str, int] = {}

    child = allows(
        "narrow every dimension at once: fewer ops, exact resource, tighter amount, "
        "smaller value set, 1 use, shorter ttl",
        lambda: attenuate(
            parent,
            [
                g("orders.get", "order:1234", uses=1),
                g(
                    "refunds.create",
                    "order:1234",
                    uses=1,
                    amount={"lte": 1000},
                    reason={"eq": "defect"},
                ),
            ],
            agent="agent:refund-worker",
            ttl_seconds=60,
            spent=used,
            reserve=True,
            ledger=ledger,
        ),
    )
    assert child is not None

    report(child.parent_id == parent.warrant_id, "child records its parent_id")
    report(child.depth == parent.depth + 1 == 1, "child depth is parent depth + 1")
    report(child.principal == parent.principal, "child keeps the human principal (attribution)")
    report(child.task_id == parent.task_id, "child stays on the same task_id")
    report(child.agent == "agent:refund-worker", "child names the sub-agent")
    report(child.expires_at <= parent.expires_at, "child expires at or before the parent")
    report(
        {gr.op for gr in child.grants} < {gr.op for gr in parent.grants},
        "child op set is a strict subset of the parent's",
    )
    report(
        used.get(use_key(parent.warrant_id, 2)) == 1,
        "reserve=True debited the parent's refund budget",
        f"parent grant 2 spent: {used.get(use_key(parent.warrant_id, 2))} of 3",
    )
    report(
        decode(encode(child)).parent_id == parent.warrant_id,
        "parent_id survives the encode/decode wire format",
    )

    decision(
        "child refunds order 1234 for 900, reason defect",
        True,
        child,
        "refunds.create",
        {"order_id": "1234", "amount": 900, "reason": "defect"},
        used={},
        chain=ledger,
    )
    decision(
        "child refunds 1500 -- over its OWN tighter bound, under the parent's",
        False,
        child,
        "refunds.create",
        {"order_id": "1234", "amount": 1500, "reason": "defect"},
        used={},
        chain=ledger,
    )
    decision(
        "child uses a reason its parent allowed but it did not ('late')",
        False,
        child,
        "refunds.create",
        {"order_id": "1234", "amount": 900, "reason": "late"},
        used={},
        chain=ledger,
    )
    decision(
        "child reaches for order 9999",
        False,
        child,
        "refunds.create",
        {"order_id": "9999", "amount": 900, "reason": "defect"},
        used={},
        chain=ledger,
    )
    decision(
        "child reaches for an op the parent had but it was not given (email.send)",
        False,
        child,
        "email.send",
        {"customer_id": "c-anil", "subject": "s", "body": "b"},
        used={},
        chain=ledger,
    )
    decision(
        "child's own use budget exhausts after 1 refund",
        False,
        child,
        "refunds.create",
        {"order_id": "1234", "amount": 900, "reason": "defect"},
        used={use_key(child.warrant_id, 1): 1},
        chain=ledger,
    )
    decision(
        "the parent itself still works (delegation did not consume it entirely)",
        True,
        parent,
        "tickets.get",
        {"ticket_id": "t-501"},
        used={},
        chain=ledger,
    )

    print()
    print("=" * 78)
    print("CHAIN VERIFICATION -- what a signature alone does not prove")
    print("=" * 78)

    decision(
        "a delegated warrant presented where there is NO ledger (fails closed)",
        False,
        child,
        "refunds.create",
        {"order_id": "1234", "amount": 900, "reason": "defect"},
        used={},
        chain=None,
    )

    # A forged "child": correctly signed (the attacker has the key), naming a real parent,
    # but never produced by attenuate() -- and holding authority the parent never had.
    forged = sign(
        Warrant(
            principal=parent.principal,
            agent="agent:evil",
            task_id=parent.task_id,
            task_statement="forged",
            grants=[g("refunds.create", "order:9999", uses=99, amount={"lte": 250000})],
            expires_at=parent.expires_at,
            parent_id=parent.warrant_id,
            depth=1,
        )
    )
    from core.sign import verify as _verify

    report(_verify(forged), "the forged child's signature verifies (this is the problem)")
    decision(
        "forged child, never issued by this broker, refused by the ledger",
        False,
        forged,
        "refunds.create",
        {"order_id": "9999", "amount": 250000},
        used={},
        chain=ledger,
    )

    # Same id as a real issued warrant, re-signed with widened grants.
    substituted = child.model_copy(deep=True)
    substituted.grants[1].constraints["amount"].lte = 250000
    sign(substituted)
    report(_verify(substituted), "the substituted warrant's signature verifies too")
    decision(
        "widened warrant re-signed under an ISSUED id, refused by signature pinning",
        False,
        substituted,
        "refunds.create",
        {"order_id": "1234", "amount": 250000, "reason": "defect"},
        used={},
        chain=ledger,
    )
    denies(
        "and it cannot be used as a parent to delegate from either",
        "chain",
        lambda: attenuate(
            substituted,
            [g("refunds.create", "order:1234", uses=1, amount={"lte": 250000}, reason={"eq": "defect"})],
            agent="agent:sub",
            ttl_seconds=30,
            ledger=ledger,
        ),
    )

    print()
    print("=" * 78)
    print("THREE LINKS -- parent -> child -> grandchild")
    print("=" * 78)

    chain_ledger = DelegationLedger()
    chain_spent: dict[str, int] = {}
    p0 = root(
        g("refunds.create", "order:1234", uses=4, amount={"lte": 5000}),
        g("orders.get", "order:*", uses=6),
        ttl=300,
    )
    chain_ledger.register(p0)

    c1 = allows(
        "link 1: amount <= 5000, uses 4  ->  amount <= 2000, uses 2",
        lambda: attenuate(
            p0,
            [
                g("refunds.create", "order:1234", uses=2, amount={"lte": 2000}),
                g("orders.get", "order:1234", uses=2),
            ],
            agent="agent:mid",
            ttl_seconds=120,
            spent=chain_spent,
            reserve=True,
            ledger=chain_ledger,
        ),
    )
    assert c1 is not None

    c2 = allows(
        "link 2: amount <= 2000, uses 2  ->  amount <= 500, uses 1",
        lambda: attenuate(
            c1,
            [g("refunds.create", "order:1234", uses=1, amount={"lte": 500})],
            agent="agent:leaf",
            ttl_seconds=60,
            spent=chain_spent,
            reserve=True,
            ledger=chain_ledger,
        ),
    )
    assert c2 is not None

    report(c2.depth == 2, "grandchild depth is 2")
    report(c2.parent_id == c1.warrant_id, "grandchild's parent is the intermediate child")
    report(
        chain_ledger.chain_of(c2.warrant_id) == [c2.warrant_id, c1.warrant_id, p0.warrant_id],
        "ledger reconstructs the full chain from parent_id alone",
    )
    report(
        c2.expires_at <= c1.expires_at <= p0.expires_at,
        "expiry is monotonically non-increasing down the chain",
    )

    decision(
        "grandchild refunds 400 on order 1234",
        True,
        c2,
        "refunds.create",
        {"order_id": "1234", "amount": 400},
        used={},
        chain=chain_ledger,
    )
    decision(
        "grandchild tries 1500 -- fine for the intermediate, over its own bound",
        False,
        c2,
        "refunds.create",
        {"order_id": "1234", "amount": 1500},
        used={},
        chain=chain_ledger,
    )
    decision(
        "grandchild tries orders.get -- the intermediate had it, the grandchild does not",
        False,
        c2,
        "orders.get",
        {"order_id": "1234"},
        used={},
        chain=chain_ledger,
    )
    denies(
        "grandchild cannot climb back to the parent's looser bound (5000) via the child",
        "constraint",
        lambda: attenuate(
            c1,
            [g("refunds.create", "order:1234", uses=1, amount={"lte": 5000})],
            agent="agent:leaf-2",
            ttl_seconds=30,
            ledger=chain_ledger,
        ),
    )
    denies(
        "grandchild cannot outlive the parent by chaining short hops with a long ttl",
        "expiry",
        lambda: attenuate(
            c1,
            [g("refunds.create", "order:1234", uses=1, amount={"lte": 100})],
            agent="agent:leaf-2",
            ttl_seconds=290,
            ledger=chain_ledger,
        ),
    )

    # Budget across the whole tree: p0 had 4 refund uses, c1 reserved 2, c2 reserved 1
    # from c1. So p0 has 2 left and c1 has 1 left -- the tree can never exceed 4 in total.
    report(
        chain_spent.get(use_key(p0.warrant_id, 0)) == 2
        and chain_spent.get(use_key(c1.warrant_id, 0)) == 1,
        "budget divides down the tree instead of multiplying",
        f"p0 refund grant spent {chain_spent.get(use_key(p0.warrant_id, 0))}/4, "
        f"c1 refund grant spent {chain_spent.get(use_key(c1.warrant_id, 0))}/2",
    )
    denies(
        "a second sibling cannot re-spend budget already reserved by c1",
        "uses",
        lambda: attenuate(
            p0,
            [g("refunds.create", "order:1234", uses=3, amount={"lte": 100})],
            agent="agent:mid-2",
            ttl_seconds=60,
            spent=chain_spent,
            ledger=chain_ledger,
        ),
    )

    # Cascade revocation: killing the intermediate must kill the grandchild.
    killed = chain_ledger.revoke(c1.warrant_id)
    report(
        set(killed) == {c1.warrant_id, c2.warrant_id},
        "revoking the intermediate cascades to the grandchild",
        f"revoked {len(killed)} warrant(s)",
    )
    decision(
        "grandchild after its parent was revoked",
        False,
        c2,
        "refunds.create",
        {"order_id": "1234", "amount": 400},
        used={},
        chain=chain_ledger,
    )
    decision(
        "the root is untouched by revoking a subtree",
        True,
        p0,
        "orders.get",
        {"order_id": "1234"},
        used={},
        chain=chain_ledger,
    )

    # Depth cap.
    deep_ledger = DelegationLedger()
    current = root(g("orders.get", "order:1234", uses=9), ttl=3600)
    deep_ledger.register(current)
    depth_hit = None
    for step in range(12):
        try:
            current = attenuate(
                current,
                [g("orders.get", "order:1234", uses=1)],
                agent=f"agent:d{step}",
                # Shrink the ttl each hop so expiry is never the binding constraint --
                # we want to see the depth cap fire, not the clock.
                ttl_seconds=3000 - step * 100,
                ledger=deep_ledger,
            )
        except AttenuationError as exc:
            depth_hit = (step, exc.dimension)
            break
    report(
        depth_hit is not None and depth_hit[1] == "depth",
        "delegation depth is capped",
        f"refused at hop {depth_hit[0]} with [{depth_hit[1]}]" if depth_hit else "never refused",
    )

    print(f"\n{'ALL PASS' if not FAILURES else str(FAILURES) + ' FAILURE(S)'}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
