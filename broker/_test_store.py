"""Durability + append-only regression tests for broker/store.py.

Run from the warrant/ directory:
    .venv\\Scripts\\python.exe -m broker._test_store

These are evidence, not scaffolding. The headline case is `restart_closes_the_bypass`:
before this store existed, a spent `uses=1` warrant became spendable again the moment the
broker process restarted, because the budget lived in RAM while the warrant carried its
own TTL. If that test prints FAIL, the warrant is once again bounded by the broker's
uptime rather than by its own terms, and you should not demo.

Every test builds its own database in a temp directory and tears it down, so this touches
no real state and can be run any number of times.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sqlite3
import tempfile
import time
import traceback
from pathlib import Path

from core.enforce import evaluate, use_key
from core.models import AuditEntry, Constraint, Grant, Warrant
from core.sign import sign

from broker.store import Store, StoreError

TMP = Path(tempfile.mkdtemp(prefix="warrant_store_test_"))
RESULTS: list[tuple[bool, str, str]] = []


def check(ok: bool, label: str, detail: str = "") -> bool:
    RESULTS.append((bool(ok), label, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if detail:
        print(f"         {detail}")
    return bool(ok)


def section(title: str) -> None:
    print(f"\n{title}\n{'-' * len(title)}")


def db(name: str) -> str:
    return str(TMP / f"{name}.db")


def a_warrant(uses: int = 1, ttl: float = 3600.0) -> Warrant:
    """A signed, long-lived, single-use refund warrant -- the demo's worst case."""
    return sign(
        Warrant(
            principal="human:arnav",
            agent="agent:support-01",
            task_statement="Refund Anil's order #1234",
            expires_at=time.time() + ttl,
            grants=[
                Grant(
                    op="refunds.create",
                    resource="order:1234",
                    uses=uses,
                    justification="the ticket asks for a refund of this order",
                    constraints={"amount": Constraint(lte=4999)},
                )
            ],
        )
    )


def an_entry(**overrides) -> AuditEntry:
    base = dict(
        principal="human:arnav",
        agent="agent:support-01",
        task_id="task-1",
        warrant_id="w-1",
        op="refunds.create",
        resource="order:1234",
        args={"order_id": "1234", "amount": 4999},
        decision="ALLOW",
        reason="within warrant",
        upstream_status=200,
    )
    base.update(overrides)
    return AuditEntry(**base)


# --------------------------------------------------------------------------- 1

def test_fresh_db_from_nothing() -> None:
    section("1. a fresh database works from nothing")
    path = db("fresh")
    check(not os.path.exists(path), "no file exists before we start")

    store = Store(path)
    check(os.path.exists(path), "constructing the store creates the file")
    check(store.all_audit() == [], "audit starts empty")
    check(store.audit_count() == 0, "audit_count starts at 0")
    check(store.get_active_warrant() is None, "no active warrant")
    check(store.sealed_warrant() is None, "nothing is sealed")
    check(store.spent("nobody", 0) == 0, "unknown counter reads 0, does not raise")
    check(store.used_map("nobody") == {}, "used_map of an unknown warrant is empty")
    store.close()

    # ... and reopening an existing, healthy database is equally uneventful.
    again = Store(path)
    check(again.audit_count() == 0, "reopening an existing empty database is fine")
    again.close()

    # Nested directory that does not exist yet.
    nested = str(TMP / "does" / "not" / "exist" / "w.db")
    deep = Store(nested)
    check(os.path.exists(nested), "creates missing parent directories")
    deep.close()

    # Env var override, no argument passed.
    os.environ["WARRANT_DB"] = db("from_env")
    try:
        env_store = Store()
        check(env_store.db_path == db("from_env"), "WARRANT_DB overrides the default path")
        env_store.close()
    finally:
        del os.environ["WARRANT_DB"]


# --------------------------------------------------------------------------- 2

def test_audit_roundtrip() -> None:
    section("2. audit entries round-trip with every field intact")
    store = Store(db("roundtrip"))

    # Deliberately awkward: unicode, nested containers, None, bool, float, big int,
    # an empty dict, and a DENY with no upstream status.
    originals = [
        an_entry(
            args={
                "order_id": "1234",
                "amount": 4999.5,
                "reason": "customer said: \"refund, ना\" — 'quoted' \\ backslash\nnewline",
                "nested": {"a": [1, 2, {"b": None}], "c": True},
                "big": 2**62,
                "empty": {},
            },
        ),
        an_entry(
            decision="DENY",
            reason="use budget exhausted for refunds.create (1/1)",
            upstream_status=None,
            args={},
            op="warrant.mint",
            resource="-",
        ),
        an_entry(principal="human:ünïcodé", agent="agent:🛡", task_id="t/2", warrant_id="w-2"),
    ]
    for entry in originals:
        store.append_audit(entry)

    read_back = store.all_audit()
    check(len(read_back) == len(originals), f"all {len(originals)} entries came back")

    fields = list(AuditEntry.model_fields)
    check(len(fields) == 12, f"AuditEntry has {len(fields)} fields; all are compared", str(fields))

    identical = True
    for want, got in zip(originals, read_back):
        for field in fields:
            w_val, g_val = getattr(want, field), getattr(got, field)
            if w_val != g_val or type(w_val) is not type(g_val):
                identical = False
                print(f"         MISMATCH {field}: {w_val!r} ({type(w_val).__name__}) "
                      f"!= {g_val!r} ({type(g_val).__name__})")
    check(identical, "every field of every entry matches by value and by type")

    check(
        read_back[0].ts == originals[0].ts,
        "float timestamp survives exactly (no precision loss)",
        f"{originals[0].ts!r}",
    )
    check(
        read_back[0].args["nested"] == {"a": [1, 2, {"b": None}], "c": True},
        "nested args structure survives",
    )
    check(read_back[1].upstream_status is None, "None upstream_status stays None, not 0")
    check([e.entry_id for e in read_back] == [e.entry_id for e in originals],
          "insertion order is preserved (oldest first)")

    # limit returns the most recent N, still oldest-first.
    tail = store.all_audit(limit=2)
    check([e.entry_id for e in tail] == [e.entry_id for e in originals[-2:]],
          "all_audit(limit=2) returns the 2 most recent, in chronological order")
    check(store.all_audit(limit=0) == [], "all_audit(limit=0) is empty")

    # Indexed column query -- attribution without a full scan.
    check([e.entry_id for e in store.audit_for_warrant("w-2")] == [originals[2].entry_id],
          "audit_for_warrant filters on the indexed column")
    store.close()


# --------------------------------------------------------------------------- 3

def test_restart_closes_the_bypass() -> None:
    section("3. THE BYPASS: a restart must not refill a spent use budget")
    path = db("bypass")
    warrant = a_warrant(uses=1)
    args = {"order_id": "1234", "amount": 4999}

    # --- broker process #1 -------------------------------------------------
    store = Store(path)
    first = evaluate(warrant, "refunds.create", args, store.used_map(warrant.warrant_id))
    check(first.allowed, "call #1 is allowed (budget 0/1)")
    total = store.spend(warrant.warrant_id, first.grant_index)
    check(total == 1, f"spend() returns the new total: {total}")

    second = evaluate(warrant, "refunds.create", args, store.used_map(warrant.warrant_id))
    check(not second.allowed, "call #2 is denied in the same process", second.reason)

    store.append_audit(an_entry(warrant_id=warrant.warrant_id, decision="ALLOW"))
    store.append_audit(
        an_entry(warrant_id=warrant.warrant_id, decision="DENY", reason=second.reason,
                 upstream_status=None)
    )
    store.mark_acted(warrant.warrant_id)
    store.set_active_warrant(warrant)
    before_count = store.audit_count()

    # --- the broker dies ---------------------------------------------------
    store.close()
    del store

    # --- broker process #2, same database, same token in the agent's hands --
    store = Store(path)

    check(
        time.time() < warrant.expires_at,
        "the warrant is still unexpired across the restart (this is what makes it a bypass)",
        f"{int(warrant.expires_at - time.time())}s of TTL left",
    )
    check(store.spent(warrant.warrant_id, 0) == 1, "the counter is still 1 after the restart")
    check(
        store.used_map(warrant.warrant_id) == {use_key(warrant.warrant_id, 0): 1},
        "used_map has the same shape core.enforce.evaluate() expects",
        str(store.used_map(warrant.warrant_id)),
    )

    third = evaluate(warrant, "refunds.create", args, store.used_map(warrant.warrant_id))
    check(not third.allowed, "core.enforce.evaluate() STILL DENIES after the restart", third.reason)
    check("use budget exhausted" in third.reason, "and denies for the budget reason specifically")

    # Audit survived the same restart.
    survived = store.all_audit()
    check(len(survived) == before_count == 2, f"all {before_count} audit entries survived the restart")
    check([e.decision for e in survived] == ["ALLOW", "DENY"],
          "and survived in order, with their decisions intact")
    check(survived[1].reason == second.reason, "the denial reason text survived verbatim")

    # Sealing survived too.
    check(store.has_acted(warrant.warrant_id), "the warrant is still marked as having acted")
    check(store.get_active_warrant() is not None, "the active warrant survived")
    check(store.get_active_warrant().warrant_id == warrant.warrant_id, "and it is the same warrant")
    check(store.sealed_warrant() is not None,
          "the task is STILL SEALED after the restart, so /mint cannot widen it")
    store.close()

    # --- control: prove the test can fail ----------------------------------
    # The same warrant against a store that never saw the spend is allowed. This is
    # exactly the old in-memory behaviour, and it is what the test above rules out.
    clean = Store(db("bypass_control"))
    control = evaluate(warrant, "refunds.create", args, clean.used_map(warrant.warrant_id))
    check(control.allowed,
          "control: against a store with no record of the spend, the same token IS allowed "
          "-- which is precisely the in-memory bug")
    clean.close()


# --------------------------------------------------------------------------- 4

def test_append_only() -> None:
    section("4. append-only: there is no path to mutate or delete an entry")
    store = Store(db("appendonly"))
    entry = an_entry()
    store.append_audit(entry)

    # (a) No such method exists on the class. Not "we don't call it" -- not written.
    banned = ("update", "delete", "remove", "edit", "purge", "truncate", "drop", "rewrite",
              "clear_audit", "reset")
    public = [n for n in dir(Store) if not n.startswith("_")]
    audit_mutators = [
        n for n in public
        if any(b in n.lower() for b in banned) and ("audit" in n.lower() or n.lower() in banned)
    ]
    check(not audit_mutators, "Store exposes no audit update/delete/reset method", str(public))
    check("append_audit" in public, "the only writer is append_audit")

    # No reset_uses either -- a method that zeroes a spend counter would be this
    # module's own bug, handed out as an API.
    check(
        not [n for n in public if "reset" in n.lower() or n.lower() in ("clear_used", "clear_uses")],
        "Store exposes no way to reset a use counter",
    )
    # clear_acted is the one deliberate eraser: it is the existing operator-only
    # /release path, and it touches sealing, never the audit log or a budget.
    check("clear_acted" in public, "clear_acted exists (operator-only /release), and only that")

    # (b) Going behind the API with raw SQL is refused by the schema itself.
    conn = store._conn  # deliberately reaching past the interface
    # `reason` lives inside the JSON blob, so rewriting history means rewriting `json`
    # (and `decision`, the indexed copy). Both are covered by the same trigger.
    for column, value in (("json", '{"tampered": true}'), ("decision", "'ALLOW'")):
        try:
            conn.execute(f"UPDATE audit SET {column} = ?", (value,))
            check(False, f"raw UPDATE of audit.{column} is refused by a trigger", "IT SUCCEEDED")
        except sqlite3.DatabaseError as exc:
            check("append-only" in str(exc),
                  f"raw UPDATE of audit.{column} is refused by a trigger", str(exc))

    try:
        conn.execute("DELETE FROM audit")
        check(False, "raw DELETE on audit is refused by a trigger", "IT SUCCEEDED")
    except sqlite3.DatabaseError as exc:
        check("append-only" in str(exc), "raw DELETE on audit is refused by a trigger", str(exc))

    after = store.all_audit()
    check(len(after) == 1 and after[0].reason == entry.reason,
          "the entry is byte-for-byte unchanged after both attempts")

    # (c) Re-appending the same entry_id is a loud error, not a silent overwrite.
    try:
        store.append_audit(entry)
        check(False, "re-appending the same entry_id raises", "IT SUCCEEDED")
    except StoreError as exc:
        check("already recorded" in str(exc), "re-appending the same entry_id raises StoreError",
              str(exc).split(";")[0])
    check(store.audit_count() == 1, "and did not add a second row")
    store.close()


# --------------------------------------------------------------------------- 5

def test_concurrent_appends() -> None:
    section("5. concurrent appends from several async tasks lose nothing")
    store = Store(db("concurrent"))
    TASKS, PER_TASK = 12, 40
    expected = TASKS * PER_TASK

    async def writer(n: int) -> None:
        for i in range(PER_TASK):
            entry = an_entry(
                task_id=f"task-{n}",
                warrant_id=f"w-{n}",
                reason=f"writer {n} entry {i}",
                args={"n": n, "i": i},
            )
            # to_thread puts these on real OS threads, which is what actually
            # exercises the store's lock -- pure coroutines would serialise anyway.
            await asyncio.to_thread(store.append_audit, entry)

    async def spender(n: int) -> None:
        for _ in range(PER_TASK):
            await asyncio.to_thread(store.spend, "shared-warrant", 0)

    async def run() -> None:
        await asyncio.gather(*(writer(n) for n in range(TASKS)))
        await asyncio.gather(*(spender(n) for n in range(TASKS)))

    asyncio.run(run())

    rows = store.all_audit()
    check(len(rows) == expected, f"all {expected} concurrent appends landed", f"got {len(rows)}")
    check(len({e.entry_id for e in rows}) == expected, "every entry_id is distinct (nothing duplicated)")

    per_writer = {n: 0 for n in range(TASKS)}
    intact = True
    for e in rows:
        n = e.args.get("n")
        per_writer[n] = per_writer.get(n, 0) + 1
        if e.task_id != f"task-{n}" or e.reason != f"writer {n} entry {e.args['i']}":
            intact = False
    check(all(v == PER_TASK for v in per_writer.values()),
          f"each of the {TASKS} writers contributed exactly {PER_TASK} rows", str(per_writer))
    check(intact, "no row is a mix of two writers' fields (nothing interleaved or torn)")

    total = store.spent("shared-warrant", 0)
    check(total == expected,
          f"{expected} concurrent spends produced exactly {expected}, no lost increments",
          f"got {total}")

    # Atomic check-and-spend under the same pressure.
    async def race() -> list[int | None]:
        return list(await asyncio.gather(
            *(asyncio.to_thread(store.spend_if_under, "capped", 0, 1) for _ in range(50))
        ))

    outcomes = asyncio.run(race())
    winners = [o for o in outcomes if o is not None]
    check(len(winners) == 1 and winners[0] == 1,
          "spend_if_under(limit=1) lets exactly one of 50 racers through",
          f"{len(winners)} winner(s), counter={store.spent('capped', 0)}")
    check(store.spent("capped", 0) == 1, "and the counter never exceeds the limit")
    store.close()


# --------------------------------------------------------------------------- 6

def test_corrupt_db_fails_loudly() -> None:
    section("6. a corrupt or unusable database fails loudly at startup")
    path = db("corrupt")
    with open(path, "wb") as fh:
        fh.write(b"this is definitely not a sqlite database, it is just some bytes\n" * 40)
    try:
        Store(path)
        check(False, "a corrupt file raises StoreError at construction", "IT OPENED FINE")
    except StoreError as exc:
        check("unreadable or not a SQLite database" in str(exc),
              "a corrupt file raises StoreError at construction", str(exc)[:110] + "...")
    except Exception as exc:  # noqa: BLE001 -- a bare sqlite error would be a silent-ish failure
        check(False, "a corrupt file raises StoreError (not a raw sqlite error)", repr(exc))

    # Truncated / half-written file: header present, rest garbage.
    good = db("half")
    Store(good).close()
    raw = bytearray(Path(good).read_bytes())
    for i in range(100, min(len(raw), 3000)):
        raw[i] = 0xFF
    torn = db("torn")
    Path(torn).write_bytes(bytes(raw))
    try:
        Store(torn)
        check(False, "a mangled page raises StoreError at construction", "IT OPENED FINE")
    except StoreError as exc:
        check(True, "a mangled page raises StoreError at construction", str(exc)[:110] + "...")

    # A database from a future schema version is refused rather than half-understood.
    future = db("future")
    Store(future).close()
    conn = sqlite3.connect(future)
    conn.execute("UPDATE meta SET value='99' WHERE key='schema_version'")
    conn.commit()
    conn.close()
    try:
        Store(future)
        check(False, "an unknown schema version is refused", "IT OPENED FINE")
    except StoreError as exc:
        check("schema version" in str(exc), "an unknown schema version is refused", str(exc)[:110] + "...")

    # A tampered active warrant is refused instead of being served to the UI.
    tampered = db("tampered")
    store = Store(tampered)
    warrant = a_warrant()
    store.set_active_warrant(warrant)
    store.close()
    widened = warrant.model_copy(deep=True)
    widened.grants[0].resource = "order:*"
    widened.grants[0].uses = 999
    conn = sqlite3.connect(tampered)
    conn.execute("UPDATE warrants SET json = ? WHERE warrant_id = ?",
                 (widened.model_dump_json(), warrant.warrant_id))
    conn.commit()
    conn.close()
    try:
        Store(tampered)
        check(False, "a hand-edited stored warrant is refused at startup", "IT OPENED FINE")
    except StoreError as exc:
        check("signature verification" in str(exc),
              "editing warrant.db to widen the stored warrant is caught at startup",
              str(exc)[:110] + "...")


# --------------------------------------------------------------------------- 7

def test_lifecycle_semantics() -> None:
    section("7. active warrant, sealing and release behave like the broker expects")
    path = db("lifecycle")
    store = Store(path)
    warrant = a_warrant(uses=2)

    store.set_active_warrant(warrant)
    check(store.get_active_warrant().warrant_id == warrant.warrant_id, "set/get active warrant")
    check(store.get_active_warrant().grants[0].constraints["amount"].lte == 4999,
          "grants and constraints survive the round-trip")
    check(store.get_active_warrant().signature == warrant.signature, "signature survives verbatim")
    check(store.sealed_warrant() is None, "a minted-but-unused warrant is not sealed")

    store.mark_acted(warrant.warrant_id)
    check(store.sealed_warrant() is not None, "attempting to act seals the task")
    store.mark_acted(warrant.warrant_id)
    check(store.sealed_warrant() is not None, "mark_acted is idempotent")

    store.spend(warrant.warrant_id, 0)
    check(store.used_list(warrant) == [1], "used_list is index-aligned with warrant.grants")

    # Release: unseal, drop the active warrant -- and do NOT refund the budget.
    store.clear_acted()
    store.set_active_warrant(None)
    check(store.get_active_warrant() is None, "release clears the active warrant")
    check(store.sealed_warrant() is None, "release unseals")
    check(store.spent(warrant.warrant_id, 0) == 1,
          "release does NOT refund the spent budget -- the token is still out there")
    check(store.get_warrant(warrant.warrant_id) is not None,
          "the released warrant is still on record for attribution")

    # An expired warrant is not sealed, even though it acted.
    old = a_warrant(ttl=-1)
    store.set_active_warrant(old)
    store.mark_acted(old.warrant_id)
    check(store.sealed_warrant() is None, "an expired warrant does not keep a task sealed")

    # ... and none of that survives differently across a restart.
    store.close()
    store = Store(path)
    check(store.spent(warrant.warrant_id, 0) == 1, "spend survives release + restart together")
    store.close()


# --------------------------------------------------------------------------- main

def main() -> int:
    print(f"warrant store tests -- databases under {TMP}")
    for test in (
        test_fresh_db_from_nothing,
        test_audit_roundtrip,
        test_restart_closes_the_bypass,
        test_append_only,
        test_concurrent_appends,
        test_corrupt_db_fails_loudly,
        test_lifecycle_semantics,
    ):
        try:
            test()
        except Exception:  # noqa: BLE001 -- a crashed test is a failed test, keep going
            RESULTS.append((False, f"{test.__name__} raised", ""))
            print(f"  [FAIL] {test.__name__} raised:")
            traceback.print_exc()

    failures = [label for ok, label, _ in RESULTS if not ok]
    print(f"\n{'=' * 72}")
    print(f"{len(RESULTS) - len(failures)}/{len(RESULTS)} checks passed")
    for label in failures:
        print(f"  FAILED: {label}")
    print("ALL PASS" if not failures else f"{len(failures)} FAILURE(S)")
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
