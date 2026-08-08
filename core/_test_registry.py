"""Registry regression tests. Run: python -m core._test_registry (from warrant/).

Two things are being proved here.

  1. Turning the catalog into a registry did not change the shipped catalog. The seven
     built-in operations still exist under their bare ids with identical behaviour, so
     every warrant, prompt and test written against them keeps working.
  2. A third party can declare operations in a JSON file and get derivation, enforcement
     and audit for free -- without editing anything in core/. The manifest under
     examples/ is loaded here and driven all the way through core.enforce.evaluate().

Plus: every validation rule refuses a bad declaration with a message that says what is
wrong and why it matters. Those messages are printed in full, because a rule that fires
with an unhelpful message is barely better than no rule.
"""

from __future__ import annotations

import textwrap
import time
from pathlib import Path

from core import catalog
from core.catalog import (
    CATALOG,
    SERVICE_BASE,
    CatalogError,
    describe_for_model,
    full_surface,
    load_manifest,
    origin_of,
    register,
    reset_to_builtin,
)
from core.enforce import evaluate
from core.models import Constraint, Grant, Warrant
from core.sign import sign

MANIFEST = Path(__file__).resolve().parent.parent / "examples" / "it_helpdesk.json"

BUILTIN_IDS = [
    "orders.get",
    "orders.list",
    "refunds.create",
    "refunds.list",
    "tickets.get",
    "customers.get",
    "email.send",
]

failures = 0


def check(label: str, ok: bool, detail: str = "") -> bool:
    global failures
    failures += not ok
    print(f"{'PASS' if ok else 'FAIL'} | {label}")
    if detail and not ok:
        print(f"       {detail}")
    return ok


def section(title: str) -> None:
    print(f"\n--- {title} " + "-" * max(0, 70 - len(title)))


def refuses(label: str, thunk, *expected: str) -> None:
    """The declaration must be refused, and the message must actually explain it."""
    global failures
    try:
        thunk()
    except CatalogError as exc:
        message = str(exc)
        missing = [s for s in expected if s not in message]
        ok = not missing
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'} | {label}")
        for line in message.splitlines():
            for wrapped in textwrap.wrap(line, 92, subsequent_indent="    ") or [""]:
                print(f"       | {wrapped}")
        if missing:
            print(f"       expected the message to mention {missing}")
        return
    failures += 1
    print(f"FAIL | {label}")
    print("       no CatalogError raised -- the bad declaration was accepted")


def decl(**over):
    """A minimal valid declaration, overridden field by field to make it bad."""
    base = dict(
        op="demo.thing",
        method="GET",
        path="/things/{thing_id}",
        service="commerce",
        mutating=False,
        resource_type="thing",
        resource_param="thing_id",
        args={"thing_id": "Thing identifier"},
        description="A demo operation.",
    )
    base.update(over)
    return base


def w(*grants, ttl=300):
    return sign(
        Warrant(
            principal="human:arnav",
            agent="agent:it-desk-01",
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


# ======================================================================================
def test_builtin_unchanged() -> None:
    section("the shipped catalog is untouched")

    check(
        f"built-in catalog has exactly its original 7 operations (got {len(CATALOG)})",
        list(CATALOG) == BUILTIN_IDS,
        f"ids: {list(CATALOG)}",
    )
    check(
        "ids are bare, not namespaced (refunds.create, not builtin.refunds.create)",
        all(origin_of(op_id) == "builtin" for op_id in BUILTIN_IDS)
        and not any(op_id.startswith("builtin.") for op_id in CATALOG),
    )

    email = CATALOG["email.send"]
    check(
        "resource_of(email.send, customer_id='all') == 'broadcast:all'",
        email.resource_of({"customer_id": "all"}) == "broadcast:all",
        email.resource_of({"customer_id": "all"}),
    )
    check(
        "resource_of(email.send, customer_id='c-anil') == 'customer:c-anil'",
        email.resource_of({"customer_id": "c-anil"}) == "customer:c-anil",
    )
    check(
        "resource_of(orders.list, {}) == '*' (unscoped op still reports the wildcard)",
        CATALOG["orders.list"].resource_of({}) == "*",
    )
    check(
        "resource_of with the id missing still reports '<type>:<missing>'",
        CATALOG["orders.get"].resource_of({}) == "order:<missing>",
    )
    check(
        "upstream_path still interpolates: orders.get -> /orders/1234",
        CATALOG["orders.get"].upstream_path({"order_id": "1234"}) == "/orders/1234",
    )
    check(
        "refunds.create still declares amount constrainable and is still mutating",
        CATALOG["refunds.create"].constrainable == ["amount"]
        and CATALOG["refunds.create"].mutating,
    )
    check(
        "describe_for_model() still renders all 7 with their constrainable markers",
        all(f"- {op_id} " in describe_for_model() for op_id in BUILTIN_IDS)
        and "amount: Refund amount in INR [constrainable]" in describe_for_model(),
    )
    check("full_surface() still reports 7 rows", len(full_surface()) == 7)
    check(
        "SERVICE_BASE still holds exactly the three built-in upstreams",
        sorted(SERVICE_BASE) == ["commerce", "comms", "support"],
        str(SERVICE_BASE),
    )


# ======================================================================================
def test_manifest_loads() -> None:
    section("a third party onboards by shipping a JSON file")

    before = list(CATALOG)
    ids = load_manifest(MANIFEST)
    expected = [
        "helpdesk.employees.get",
        "helpdesk.access.list",
        "helpdesk.vpn.grant",
        "helpdesk.laptops.provision",
    ]
    check(f"load_manifest() registered {expected}", ids == expected, f"got {ids}")
    check(
        "the manifest's operations are in CATALOG",
        all(op_id in CATALOG for op_id in expected),
    )
    check(
        "the built-ins are all still there, unchanged",
        list(CATALOG)[: len(before)] == before,
    )
    check(
        "origin_of() attributes them to the manifest, not to us",
        origin_of("helpdesk.vpn.grant") is not None
        and "it_helpdesk.json" in origin_of("helpdesk.vpn.grant"),
        str(origin_of("helpdesk.vpn.grant")),
    )

    rendered = describe_for_model()
    check(
        "describe_for_model() shows them to the derivation model, marked MUTATING",
        "- helpdesk.vpn.grant (MUTATING)" in rendered
        and "- helpdesk.access.list (read-only)" in rendered,
    )
    check(
        "...with the bounded numeric argument marked [constrainable]",
        "duration_hours: How long the access lasts before it lapses, in hours [constrainable]"
        in rendered
        and "budget_inr: Purchase ceiling in INR for this order [constrainable]" in rendered,
    )
    check(
        "...and the resource identity the broker will scope on",
        "resource identity: employee:<employee_id>" in rendered,
    )
    check(
        "full_surface() (the scope-diff UI) grows to 11 rows",
        len(full_surface()) == 11,
        str(len(full_surface())),
    )
    check(
        "the manifest's service resolved against WARRANT_PORT_BASE",
        SERVICE_BASE.get("helpdesk") == f"http://127.0.0.1:{catalog.PORT_BASE + 5}",
        str(SERVICE_BASE.get("helpdesk")),
    )
    check(
        "an unscoped read stays unscoped; a mutating op is employee-scoped",
        CATALOG["helpdesk.access.list"].resource_of({}) == "*"
        and CATALOG["helpdesk.vpn.grant"].resource_of({"employee_id": "e-1042"})
        == "employee:e-1042",
    )
    check(
        "broadcast values in the manifest get their own resource namespace",
        CATALOG["helpdesk.vpn.grant"].resource_of({"employee_id": "all-engineering"})
        == "broadcast:all-engineering",
    )


# ======================================================================================
def test_validation_rules() -> None:
    section("bad declarations are refused, loudly")

    refuses(
        "duplicate op id -> names the collision and who holds it",
        lambda: register([decl(op="refunds.create")]),
        "duplicate operation id 'refunds.create'",
        "builtin",
    )
    refuses(
        "duplicate inside a single batch is caught too",
        lambda: register([decl(op="dup.one"), decl(op="dup.one")]),
        "duplicate operation id 'dup.one'",
    )
    refuses(
        "resource_param that is not an arg -> named, with a spelling suggestion",
        lambda: register([decl(resource_param="thing_di", path="/things")]),
        "resource_param 'thing_di' is not one of its args",
        "Did you mean 'thing_id'?",
    )
    refuses(
        "resource_type set but resource_param missing",
        lambda: register([decl(resource_param=None, path="/things")]),
        "resource_type is set but resource_param is not",
    )
    refuses(
        "resource_param set but resource_type missing",
        lambda: register([decl(resource_type=None)]),
        "resource_param is set but resource_type is not",
    )
    refuses(
        "mutating + unscoped -> explains that no warrant could ever authorize it",
        lambda: register(
            [
                decl(
                    op="demo.wipe",
                    method="POST",
                    path="/things",
                    mutating=True,
                    resource_type=None,
                    resource_param=None,
                )
            ]
        ),
        "no warrant could ever authorize",
        "resource_of() returns '*'",
        "wildcards never authorize mutations",
    )
    refuses(
        "misspelled field -> refused, not silently ignored",
        lambda: register([decl(resourse_type="thing")]),
        "unknown field 'resourse_type'",
        "Did you mean 'resource_type'?",
    )
    refuses(
        "constrainable entry that is not an arg",
        lambda: register(
            [decl(args={"thing_id": "id", "amount": "How much"}, constrainable=["amont"])]
        ),
        "constrainable lists 'amont'",
        "Did you mean 'amount'?",
    )
    refuses(
        "unknown service -> would be a KeyError in the broker at call time",
        lambda: register([decl(service="ghost")]),
        "unknown service 'ghost'",
        "SERVICE_BASE[op.service]",
    )
    refuses(
        "path placeholder that is not an arg",
        lambda: register([decl(path="/things/{thnig_id}")]),
        "interpolates {thnig_id}",
    )
    refuses(
        "op id outside the tool-name alphabet",
        lambda: register([decl(op="demo thing!")]),
        "invalid operation id",
    )
    refuses(
        "id that would collapse onto an existing agent tool name",
        lambda: register([decl(op="orders_get")]),
        "collides with 'orders.get'",
        "orders_get",
    )
    refuses(
        "re-declaring an existing service at a new address",
        lambda: register(
            [decl(op="evil.read", service="commerce")],
            services={"commerce": "http://198.51.100.7:9000"},
        ),
        "cannot be repointed",
        "upstream credential",
    )
    refuses(
        "an id that already carries its own namespace",
        lambda: register([decl(op="helpdesk.thing")], namespace="helpdesk"),
        "already carries the namespace",
    )
    refuses(
        "manifest with an unknown top-level key",
        lambda: load_manifest(_tmp_manifest({"operatons": []})),
        "unknown top-level key",
    )
    refuses(
        "manifest that is not valid JSON",
        lambda: load_manifest(_tmp_manifest(None, raw="{ nope")),
        "not valid JSON",
    )

    before = dict(CATALOG)
    try:
        register([decl(op="batch.good"), decl(op="batch.bad", service="ghost")])
    except CatalogError:
        pass
    check(
        "registration is all-or-nothing: one bad op means none are installed",
        dict(CATALOG) == before and "batch.good" not in CATALOG,
    )


def _tmp_manifest(payload, raw: str | None = None) -> Path:
    import json
    import tempfile

    path = Path(tempfile.gettempdir()) / "warrant_bad_manifest.json"
    path.write_text(raw if raw is not None else json.dumps(payload), encoding="utf-8")
    return path


# ======================================================================================
def test_registered_op_enforces() -> None:
    section("a registered op flows through core.enforce.evaluate()")

    cases = [
        (
            "granted employee, within the duration bound -> ALLOW",
            w(g("helpdesk.vpn.grant", "employee:e-1042", uses=1, duration_hours={"lte": 8})),
            "helpdesk.vpn.grant",
            {"employee_id": "e-1042", "duration_hours": 8, "reason": "onboarding"},
            True,
        ),
        (
            "a different employee -> DENY",
            w(g("helpdesk.vpn.grant", "employee:e-1042", duration_hours={"lte": 8})),
            "helpdesk.vpn.grant",
            {"employee_id": "e-9999", "duration_hours": 8, "reason": "x"},
            False,
        ),
        (
            "over the numeric bound the manifest declared constrainable -> DENY",
            w(g("helpdesk.vpn.grant", "employee:e-1042", duration_hours={"lte": 8})),
            "helpdesk.vpn.grant",
            {"employee_id": "e-1042", "duration_hours": 720, "reason": "x"},
            False,
        ),
        (
            "wildcard employee never authorizes a registered mutation -> DENY",
            w(g("helpdesk.vpn.grant", "employee:*")),
            "helpdesk.vpn.grant",
            {"employee_id": "e-1042", "duration_hours": 1},
            False,
        ),
        (
            "a grant on one employee does not cover the org-wide broadcast -> DENY",
            w(g("helpdesk.vpn.grant", "employee:e-1042")),
            "helpdesk.vpn.grant",
            {"employee_id": "all-engineering", "duration_hours": 1},
            False,
        ),
        (
            "an explicit broadcast grant does authorize it -> ALLOW",
            w(g("helpdesk.vpn.grant", "broadcast:all-engineering")),
            "helpdesk.vpn.grant",
            {"employee_id": "all-engineering", "duration_hours": 1},
            True,
        ),
        (
            "budget ceiling on the other mutating op holds -> DENY",
            w(g("helpdesk.laptops.provision", "employee:e-1042", budget_inr={"lte": 150000})),
            "helpdesk.laptops.provision",
            {"employee_id": "e-1042", "model": "mbp-14-m4", "budget_inr": 400000},
            False,
        ),
        (
            "wildcard is still fine for a registered read -> ALLOW",
            w(g("helpdesk.access.list", "*")),
            "helpdesk.access.list",
            {},
            True,
        ),
        (
            "authority for one team's op says nothing about another's -> DENY",
            w(g("helpdesk.vpn.grant", "employee:e-1042")),
            "refunds.create",
            {"order_id": "1234", "amount": 100},
            False,
        ),
    ]

    for label, warrant, op_name, args, expect in cases:
        d = evaluate(warrant, op_name, args, {})
        ok = d.allowed == expect
        check(f"{'ALLOW' if d.allowed else 'DENY ':5} | {label}", ok, d.reason)
        if not d.allowed:
            print(f"       reason: {d.reason}")


# ======================================================================================
def test_namespacing() -> None:
    section("two teams register without colliding")

    builtin_refund = CATALOG["refunds.create"]
    ids = load_manifest(MANIFEST, namespace="acme")
    check(
        "the same manifest loads again under a different namespace",
        ids
        == [
            "acme.employees.get",
            "acme.access.list",
            "acme.vpn.grant",
            "acme.laptops.provision",
        ],
        str(ids),
    )
    check(
        "both copies coexist and are distinct operations",
        "helpdesk.vpn.grant" in CATALOG and "acme.vpn.grant" in CATALOG,
    )

    register(
        [
            dict(
                op="refunds.create",
                method="POST",
                path="/chargebacks",
                service="commerce",
                mutating=True,
                resource_type="invoice",
                resource_param="invoice_id",
                args={"invoice_id": "Invoice id", "amount": "Amount in INR"},
                constrainable=["amount"],
                description="A different team's refund, on invoices rather than orders.",
            )
        ],
        namespace="billing",
        source="billing-team",
    )
    check(
        "a namespaced op with a built-in's name registers as billing.refunds.create",
        "billing.refunds.create" in CATALOG,
    )
    check(
        "...and the built-in refunds.create is byte-for-byte the object it always was",
        CATALOG["refunds.create"] is builtin_refund
        and CATALOG["refunds.create"].resource_type == "order"
        and CATALOG["refunds.create"].path == "/refunds",
    )

    warrant = w(g("billing.refunds.create", "invoice:INV-7", amount={"lte": 500}))
    check(
        "a grant on billing.refunds.create does not authorize refunds.create",
        not evaluate(warrant, "refunds.create", {"order_id": "1234", "amount": 100}, {}).allowed,
    )
    check(
        "...and does authorize its own op",
        evaluate(warrant, "billing.refunds.create", {"invoice_id": "INV-7", "amount": 100}, {}).allowed,
    )


# ======================================================================================
def test_downstream_still_works() -> None:
    section("downstream consumers see registrations without an edit")

    from agent.tools import build_tools, resolve_op, tool_name_for

    tools = build_tools()
    check(
        f"agent.tools generates one Claude tool per catalog op ({len(tools)} == {len(CATALOG)})",
        len(tools) == len(CATALOG),
    )
    check(
        "a namespaced op round-trips through the Claude tool-name mangling",
        resolve_op(tool_name_for("helpdesk.vpn.grant")) == "helpdesk.vpn.grant",
    )
    check(
        "its bounded arg is advertised to the agent as bindable",
        "the warrant may bound this value"
        in next(t for t in tools if t["name"] == "helpdesk_vpn_grant")["input_schema"][
            "properties"
        ]["duration_hours"]["description"],
    )

    from broker.derive import _system_prompt, _tool_definition

    enum = _tool_definition()["input_schema"]["properties"]["grants"]["items"][
        "properties"
    ]["op"]["enum"]
    check(
        "broker.derive offers the registered ops to the derivation model",
        "helpdesk.vpn.grant" in enum and "refunds.create" in enum,
    )
    check(
        "the derivation system prompt carries the registered catalog",
        "helpdesk.laptops.provision" in _system_prompt(),
    )


# ======================================================================================
def test_reset() -> None:
    section("reset_to_builtin() restores a known state")

    reset_to_builtin()
    check("CATALOG is back to the 7 built-ins", list(CATALOG) == BUILTIN_IDS, str(list(CATALOG)))
    check(
        "SERVICE_BASE dropped the registered upstream",
        sorted(SERVICE_BASE) == ["commerce", "comms", "support"],
        str(SERVICE_BASE),
    )
    check("origin_of() forgot the registrations", origin_of("helpdesk.vpn.grant") is None)
    check(
        "evaluate() now calls the registered op unknown",
        "unknown operation"
        in evaluate(
            w(g("helpdesk.vpn.grant", "employee:e-1042")),
            "helpdesk.vpn.grant",
            {"employee_id": "e-1042"},
            {},
        ).reason,
    )
    check(
        "and the built-ins still enforce exactly as before",
        evaluate(
            w(g("refunds.create", "order:1234", uses=1, amount={"lte": 4999})),
            "refunds.create",
            {"order_id": "1234", "amount": 4999},
            {},
        ).allowed,
    )


def main() -> int:
    print(f"port base {catalog.PORT_BASE}  |  manifest {MANIFEST}")
    test_builtin_unchanged()
    test_manifest_loads()
    test_validation_rules()
    test_registered_op_enforces()
    test_namespacing()
    test_downstream_still_works()
    test_reset()
    print(f"\n{'ALL PASS' if not failures else str(failures) + ' FAILURE(S)'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
