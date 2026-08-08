"""Durable broker state: the audit log, the use budgets, the active warrant, and the
closed-warrant list.

WHY THIS EXISTS
===============
The broker used to keep all three in a `State` object in memory. For the audit log that
is merely a broken promise -- a log that dies with the process is not a log. For the use
budgets it is a security hole, and a real one:

    a warrant carries its own TTL, so it outlives the state that bounds it.

An agent holding a signed `uses=1` warrant spends it, is correctly denied a second time,
and then only has to wait for (or cause) a broker restart. The signature still verifies,
`expires_at` is still in the future, and the in-memory counter is gone -- so the same
token is allowed again. The budget was enforced by a process's lifetime rather than by
the warrant. This module moves the counter to disk so the bound is a property of the
warrant, not of the broker's uptime.

WHAT THIS MODULE IS NOT
=======================
It is not an enforcement layer. `core.enforce.evaluate()` still makes every decision;
this only remembers. `used_map()` returns exactly the `dict[use_key -> spent]` shape
`evaluate()` already takes, so enforcement needs no change at all.

CLOSURE
=======
`close_warrant()` / `is_closed()` are the durable answer to "authority that ends when the
work ends". Before them, authority ended in exactly two ways -- the TTL ran out, or a use
budget exhausted -- and both are timeouts: nothing ever *took authority back*. A sub-agent
that finished in two seconds kept a live warrant for the remaining 298; `/release`
unsealed a task without invalidating the token already issued; and `/revoke` lived in the
in-memory delegation ledger, so a revoked *root* came back to life on the next restart,
because `DelegationLedger.check()` accepts an unseen root on its signature alone. That was
the only place in the system that did not fail closed.

One table fixes all three, because all three want the same thing: a list of warrant ids
this broker will never honour again, on disk, checked at `/call` before anything else.

Closure is *permanent*. There is no `reopen_warrant()`, and the schema carries the same
BEFORE UPDATE / BEFORE DELETE triggers the audit log does. A closure that could be lifted
would be a closure whose value depends on nobody lifting it -- and re-issuing authority is
already a supported operation, spelled `/mint` and gated on a human. Taking it back and
handing it out again are deliberately not the same act.

APPEND-ONLY
===========
There is no `update_audit` and no `delete_audit` -- not "we don't call them", they are
not written. That is a convention, so the schema backs it with BEFORE UPDATE and BEFORE
DELETE triggers that RAISE(ABORT). Raw SQL on this connection cannot rewrite history
either. The same two triggers guard `closed_warrants`. What this does not stop: DROP
TABLE, or deleting the file. A tamper-evident log wants hash chaining and off-box
replication; this buys the honest part of that, which is that no code path in this process
can quietly edit an entry.

CONCURRENCY
===========
One connection, opened `check_same_thread=False`, guarded by a `threading.RLock`, in WAL
mode. Chosen over connection-per-call because:

  * every operation here is a single-row insert or lookup on a table with hundreds of
    rows, so the critical section is microseconds -- short enough to hold a blocking
    lock inside an async handler without meaningfully stalling the event loop;
  * `spend()` is a read-modify-write, and one connection plus one UPSERT ... RETURNING
    makes it atomic rather than a lock-around-two-queries;
  * an `asyncio.Lock` would guard only the event loop. A `threading.RLock` also covers
    calls arriving from `run_in_threadpool`, background tasks, or the SSE generator,
    which is the failure mode you would actually hit.

Durability is `synchronous=FULL`: a spend is on disk before the broker forwards the call
upstream. WAL's default NORMAL can lose the last commits to a hard kill, and "survives a
hard kill" is the entire point of the module.

CONFIG
======
`WARRANT_DB` overrides the path. Default is `warrant.db` beside the repo root. Pass
`":memory:"` for an ephemeral store (tests that do not need restart semantics).
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from core.enforce import use_key
from core.models import AuditEntry, Warrant
from core.sign import verify

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = REPO_ROOT / "warrant.db"

# 2 adds `closed_warrants`. The bump is deliberate even though the change is purely
# additive: a v1 broker opening a v2 file would not know the table exists and would honour
# a warrant that has been closed. Refusing to start is the fail-closed answer, and
# `_migrate()` below carries a v1 file forward in place so nobody loses an audit log to it.
SCHEMA_VERSION = 2

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Append-only. `json` is the full core.models.AuditEntry; the columns beside it exist
-- only to be queried and are derived from that same JSON, never independent of it.
CREATE TABLE IF NOT EXISTS audit (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id   TEXT    NOT NULL UNIQUE,
    ts         REAL    NOT NULL,
    warrant_id TEXT    NOT NULL,
    task_id    TEXT    NOT NULL,
    op         TEXT    NOT NULL,
    decision   TEXT    NOT NULL,
    json       TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_by_warrant ON audit(warrant_id, seq);
CREATE INDEX IF NOT EXISTS audit_by_ts      ON audit(ts);

CREATE TRIGGER IF NOT EXISTS audit_no_update
BEFORE UPDATE ON audit
BEGIN
    SELECT RAISE(ABORT, 'audit is append-only: UPDATE is not permitted');
END;

CREATE TRIGGER IF NOT EXISTS audit_no_delete
BEFORE DELETE ON audit
BEGIN
    SELECT RAISE(ABORT, 'audit is append-only: DELETE is not permitted');
END;

-- The counter that used to be a dict in RAM. This table is the fix.
CREATE TABLE IF NOT EXISTS use_budget (
    warrant_id  TEXT    NOT NULL,
    grant_index INTEGER NOT NULL,
    spent       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (warrant_id, grant_index)
);

CREATE TABLE IF NOT EXISTS warrants (
    warrant_id TEXT PRIMARY KEY,
    issued_at  REAL NOT NULL,
    expires_at REAL NOT NULL,
    json       TEXT NOT NULL
);

-- Sealing: a warrant that has reached /call at least once, whatever the decision.
-- Mirrors the old `State.acted` set, minus the amnesia.
CREATE TABLE IF NOT EXISTS acted (
    warrant_id TEXT PRIMARY KEY,
    first_at   REAL NOT NULL
);

-- Closure: warrant ids this broker will never honour again. Checked at /call before the
-- enforcement decision, so a closed warrant is denied whatever its grants, budget or TTL
-- say. Durable because the alternative is a revocation the holder can undo by waiting for
-- a restart -- see the CLOSURE note at the top of this module.
--
-- A row is the whole story: who closed it and why, so the denial can say so.
CREATE TABLE IF NOT EXISTS closed_warrants (
    warrant_id TEXT PRIMARY KEY,
    closed_at  REAL NOT NULL,
    closed_by  TEXT NOT NULL,
    reason     TEXT NOT NULL,
    -- The warrant the closure cascaded from, when this row is collateral of closing an
    -- ancestor. Equal to warrant_id when it was closed in its own right.
    root_id    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS closed_by_ts   ON closed_warrants(closed_at);
CREATE INDEX IF NOT EXISTS closed_by_root ON closed_warrants(root_id);

CREATE TRIGGER IF NOT EXISTS closed_no_update
BEFORE UPDATE ON closed_warrants
BEGIN
    SELECT RAISE(ABORT, 'closure is permanent: UPDATE is not permitted');
END;

CREATE TRIGGER IF NOT EXISTS closed_no_delete
BEFORE DELETE ON closed_warrants
BEGIN
    SELECT RAISE(ABORT, 'closure is permanent: DELETE is not permitted');
END;
"""


class StoreError(RuntimeError):
    """The store cannot be trusted. Always fatal -- never swallow this.

    Raised for a corrupt or unreadable database, an unknown schema version, or a stored
    warrant whose signature no longer verifies. The broker should die at startup rather
    than run with a state file it cannot vouch for.
    """


class Store:
    """Durable replacement for the broker's in-memory `State`.

    Everything here is synchronous and fast enough to call directly from an async
    handler; see the CONCURRENCY note above.
    """

    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        raw = str(path) if path is not None else os.environ.get("WARRANT_DB") or str(DEFAULT_DB_PATH)
        self.db_path: str = raw
        self._lock = threading.RLock()
        self._conn = self._open(raw)
        # Eager, so a database we cannot make sense of fails here at construction --
        # at broker startup -- and not three calls into a demo.
        self._ensure_schema()
        self._verify_readable()

    # ---------------------------------------------------------------- lifecycle

    def _open(self, raw: str) -> sqlite3.Connection:
        if raw != ":memory:":
            parent = Path(raw).expanduser().resolve().parent
            try:
                parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise StoreError(f"cannot create directory for warrant store {raw!r}: {exc}") from exc

        try:
            conn = sqlite3.connect(
                raw,
                check_same_thread=False,  # guarded by self._lock instead
                isolation_level=None,  # autocommit; multi-statement work uses _tx()
                timeout=5.0,
            )
            conn.row_factory = sqlite3.Row
            if raw != ":memory:":
                conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA busy_timeout=5000")
            # Forces a real read of the file header: sqlite3.connect() is lazy and a
            # corrupt file otherwise stays undetected until the first query.
            conn.execute("PRAGMA quick_check").fetchone()
        except sqlite3.DatabaseError as exc:
            raise StoreError(
                f"warrant store at {raw!r} is unreadable or not a SQLite database ({exc}). "
                "Refusing to start: the broker cannot enforce use budgets it cannot read. "
                "Move the file aside to start from a clean audit trail."
            ) from exc
        return conn

    def _ensure_schema(self) -> None:
        with self._lock:
            try:
                self._conn.executescript(_SCHEMA)
                row = self._conn.execute(
                    "SELECT value FROM meta WHERE key='schema_version'"
                ).fetchone()
                if row is None:
                    self._conn.execute(
                        "INSERT INTO meta(key, value) VALUES('schema_version', ?)",
                        (str(SCHEMA_VERSION),),
                    )
                elif int(row["value"]) == 1 and SCHEMA_VERSION == 2:
                    # v1 -> v2 is purely additive: `executescript(_SCHEMA)` above has
                    # already created `closed_warrants` on this file, so upgrading is
                    # nothing but writing down that we did. Done in place rather than
                    # refused, because the alternative is telling an operator to throw
                    # away an audit log to gain a feature. Downgrades still fail closed:
                    # a v1 broker refuses a v2 file rather than ignoring its closures.
                    self._conn.execute(
                        "UPDATE meta SET value = ? WHERE key='schema_version'",
                        (str(SCHEMA_VERSION),),
                    )
                elif int(row["value"]) != SCHEMA_VERSION:
                    raise StoreError(
                        f"warrant store at {self.db_path!r} has schema version "
                        f"{row['value']}, this broker speaks {SCHEMA_VERSION}. "
                        "Refusing to start. Move the file aside."
                    )
            except sqlite3.DatabaseError as exc:
                raise StoreError(
                    f"cannot initialise warrant store at {self.db_path!r}: {exc}"
                ) from exc

    def _verify_readable(self) -> None:
        """Touch every table once, and check the stored active warrant still verifies."""
        with self._lock:
            try:
                self._conn.execute("SELECT COUNT(*) FROM audit").fetchone()
                self._conn.execute("SELECT COUNT(*) FROM use_budget").fetchone()
                self._conn.execute("SELECT COUNT(*) FROM acted").fetchone()
                self._conn.execute("SELECT COUNT(*) FROM closed_warrants").fetchone()
            except sqlite3.DatabaseError as exc:
                raise StoreError(
                    f"warrant store at {self.db_path!r} is corrupt: {exc}"
                ) from exc
            self.get_active_warrant()  # raises StoreError on a tampered/unverifiable row

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        """All-or-nothing for the handful of operations that touch two tables."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    # -------------------------------------------------------------- audit trail

    def append_audit(self, entry: AuditEntry) -> None:
        """Append one decision. The only way to write the audit log.

        There is deliberately no counterpart that edits or removes one.
        """
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO audit(entry_id, ts, warrant_id, task_id, op, decision, json) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (
                        entry.entry_id,
                        entry.ts,
                        entry.warrant_id,
                        entry.task_id,
                        entry.op,
                        entry.decision,
                        entry.model_dump_json(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise StoreError(
                    f"audit entry {entry.entry_id} already recorded; an entry is written "
                    f"exactly once and is never rewritten ({exc})"
                ) from exc

    def all_audit(self, limit: int | None = None) -> list[AuditEntry]:
        """Entries oldest-first. `limit` returns the most recent N, still oldest-first."""
        with self._lock:
            if limit is None:
                rows = self._conn.execute("SELECT json FROM audit ORDER BY seq").fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT json FROM (SELECT seq, json FROM audit ORDER BY seq DESC LIMIT ?) "
                    "ORDER BY seq",
                    (max(0, limit),),
                ).fetchall()
        return [AuditEntry.model_validate_json(row["json"]) for row in rows]

    def audit_for_warrant(self, warrant_id: str) -> list[AuditEntry]:
        """Everything this warrant did. The attribution query the design promises."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT json FROM audit WHERE warrant_id = ? ORDER BY seq", (warrant_id,)
            ).fetchall()
        return [AuditEntry.model_validate_json(row["json"]) for row in rows]

    def audit_count(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT COUNT(*) AS n FROM audit").fetchone()["n"])

    # -------------------------------------------------------------- use budgets

    def spend(self, warrant_id: str, grant_index: int) -> int:
        """Consume one use of a grant. Returns the new total spent.

        Atomic: one UPSERT, so two callers cannot both read 0 and both write 1.
        """
        with self._lock:
            row = self._conn.execute(
                "INSERT INTO use_budget(warrant_id, grant_index, spent) VALUES(?,?,1) "
                "ON CONFLICT(warrant_id, grant_index) DO UPDATE SET spent = spent + 1 "
                "RETURNING spent",
                (warrant_id, grant_index),
            ).fetchone()
        return int(row["spent"])

    def spend_if_under(self, warrant_id: str, grant_index: int, limit: int) -> int | None:
        """Spend only if that keeps us within `limit`. Returns the new total, or None.

        Optional hardening, and not needed to fix the restart bypass. `evaluate()` reads
        the counter and the broker then increments it; today those are separated by no
        `await`, so on one event loop the pair is already indivisible. That is a property
        of the current control flow rather than a guarantee -- insert one `await` between
        the check and the increment and two concurrent calls can both spend the last use
        of a `uses=1` grant. This makes the check and the increment the same statement,
        so the guarantee stops depending on how the handler is written.
        """
        if limit < 1:
            return None
        with self._lock:
            row = self._conn.execute(
                "INSERT INTO use_budget(warrant_id, grant_index, spent) VALUES(?,?,1) "
                "ON CONFLICT(warrant_id, grant_index) DO UPDATE SET spent = spent + 1 "
                "WHERE spent < ? "
                "RETURNING spent",
                (warrant_id, grant_index, limit),
            ).fetchone()
        return None if row is None else int(row["spent"])

    def spent(self, warrant_id: str, grant_index: int) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT spent FROM use_budget WHERE warrant_id = ? AND grant_index = ?",
                (warrant_id, grant_index),
            ).fetchone()
        return 0 if row is None else int(row["spent"])

    def used_map(self, warrant_id: str) -> dict[str, int]:
        """Exactly what `core.enforce.evaluate()` wants for its `used` argument.

        Scoped to one warrant on purpose: `evaluate()` only ever looks up keys for the
        warrant in front of it, so no other warrant's counters need to be in the room.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT grant_index, spent FROM use_budget WHERE warrant_id = ?", (warrant_id,)
            ).fetchall()
        return {use_key(warrant_id, int(r["grant_index"])): int(r["spent"]) for r in rows}

    def used_list(self, warrant: Warrant) -> list[int]:
        """Spend per grant, index-aligned with `warrant.grants`, for /warrant/active."""
        counters = self.used_map(warrant.warrant_id)
        return [
            counters.get(use_key(warrant.warrant_id, i), 0) for i in range(len(warrant.grants))
        ]

    # ----------------------------------------------------------- active warrant

    def set_active_warrant(self, warrant: Warrant | None) -> None:
        """Record the live warrant, or clear it (a release).

        Clearing does not delete the warrant row and never touches `use_budget`. A spent
        budget is a fact about a warrant, not about whether the broker currently regards
        it as active -- and the token is still out there in the agent's hands.
        """
        with self._tx() as conn:
            if warrant is None:
                conn.execute("DELETE FROM meta WHERE key='active_warrant_id'")
                return
            conn.execute(
                "INSERT INTO warrants(warrant_id, issued_at, expires_at, json) VALUES(?,?,?,?) "
                "ON CONFLICT(warrant_id) DO UPDATE SET json = excluded.json",
                (
                    warrant.warrant_id,
                    warrant.issued_at,
                    warrant.expires_at,
                    warrant.model_dump_json(),
                ),
            )
            conn.execute(
                "INSERT INTO meta(key, value) VALUES('active_warrant_id', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (warrant.warrant_id,),
            )

    def get_active_warrant(self) -> Warrant | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT w.json AS json FROM meta m JOIN warrants w "
                "ON w.warrant_id = m.value WHERE m.key='active_warrant_id'"
            ).fetchone()
        if row is None:
            return None
        warrant = Warrant.model_validate_json(row["json"])
        if not verify(warrant):
            # The DB sits inside the trust boundary, so this means someone edited the
            # file or the signing key changed under us. Either way, do not serve it.
            raise StoreError(
                f"active warrant {warrant.warrant_id} in {self.db_path!r} fails signature "
                "verification -- the store has been tampered with, or WARRANT_SIGNING_KEY "
                "changed since it was written. Refusing to use it."
            )
        return warrant

    def get_warrant(self, warrant_id: str) -> Warrant | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT json FROM warrants WHERE warrant_id = ?", (warrant_id,)
            ).fetchone()
        return None if row is None else Warrant.model_validate_json(row["json"])

    # ------------------------------------------------------------------ sealing

    def mark_acted(self, warrant_id: str) -> None:
        """This warrant has attempted to act. Idempotent; keeps the first timestamp."""
        with self._lock:
            self._conn.execute(
                "INSERT INTO acted(warrant_id, first_at) VALUES(?,?) "
                "ON CONFLICT(warrant_id) DO NOTHING",
                (warrant_id, time.time()),
            )

    def has_acted(self, warrant_id: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM acted WHERE warrant_id = ?", (warrant_id,)
            ).fetchone()
        return row is not None

    def clear_acted(self) -> None:
        """Unseal. Reachable only from POST /release, which needs the operator key."""
        with self._lock:
            self._conn.execute("DELETE FROM acted")

    def sealed_warrant(self) -> Warrant | None:
        """The live warrant that has already begun acting, if there is one.

        Same three-part test the broker did in memory -- active, unexpired, has acted --
        except the third part now survives a restart, which is what makes sealing a
        property of the task rather than of the broker's uptime.
        """
        with self._lock:
            warrant = self.get_active_warrant()
            if warrant is None:
                return None
            if time.time() > warrant.expires_at:
                return None
            if not self.has_acted(warrant.warrant_id):
                return None
            return warrant

    # ------------------------------------------------------------------ closure

    def close_warrant(
        self, warrant_id: str, reason: str, closed_by: str, *, root_id: str | None = None
    ) -> bool:
        """Close a warrant permanently. Returns True if this call closed it.

        Idempotent by construction: the first closure wins and a second one changes
        nothing, so a caller retrying a `/close` (or a cascade re-covering a warrant an
        earlier cascade already reached) is harmless rather than a history rewrite.

        `root_id` is the warrant the closure cascaded from -- the id the operator or the
        holder actually named. It defaults to `warrant_id`, which is the case where a
        warrant was closed in its own right.

        This does NOT touch `use_budget`, `acted` or `warrants`. A closed warrant keeps
        everything it spent and everything it did: closure ends authority, it does not
        erase the record of having held it.
        """
        with self._lock:
            cursor = self._conn.execute(
                "INSERT INTO closed_warrants(warrant_id, closed_at, closed_by, reason, root_id) "
                "VALUES(?,?,?,?,?) ON CONFLICT(warrant_id) DO NOTHING",
                (warrant_id, time.time(), closed_by, reason, root_id or warrant_id),
            )
            return cursor.rowcount > 0

    def is_closed(self, warrant_id: str) -> str | None:
        """The reason this warrant was closed, or None if it is still live.

        The whole check `/call` needs, in one indexed primary-key lookup. Returning the
        reason rather than a bool is deliberate: a denial that cannot say *why* authority
        ended reads like a bug, and the holder cannot tell a closure from an outage.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT reason FROM closed_warrants WHERE warrant_id = ?", (warrant_id,)
            ).fetchone()
        return None if row is None else str(row["reason"])

    def closure_of(self, warrant_id: str) -> dict[str, object] | None:
        """The full closure record -- who closed it, when, why, and what it cascaded from."""
        with self._lock:
            row = self._conn.execute(
                "SELECT warrant_id, closed_at, closed_by, reason, root_id "
                "FROM closed_warrants WHERE warrant_id = ?",
                (warrant_id,),
            ).fetchone()
        return None if row is None else dict(row)

    def closures(self, root_id: str | None = None) -> list[dict[str, object]]:
        """Every closure, oldest first. `root_id` filters to one cascade."""
        with self._lock:
            if root_id is None:
                rows = self._conn.execute(
                    "SELECT warrant_id, closed_at, closed_by, reason, root_id "
                    "FROM closed_warrants ORDER BY closed_at, warrant_id"
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT warrant_id, closed_at, closed_by, reason, root_id "
                    "FROM closed_warrants WHERE root_id = ? ORDER BY closed_at, warrant_id",
                    (root_id,),
                ).fetchall()
        return [dict(row) for row in rows]

    def closure_count(self) -> int:
        with self._lock:
            return int(
                self._conn.execute(
                    "SELECT COUNT(*) AS n FROM closed_warrants"
                ).fetchone()["n"]
            )


# Deliberately absent, and it is worth saying why rather than leaving a gap:
#
#   update_audit / delete_audit  -- append-only is the point (triggers enforce it too).
#   reopen_warrant(warrant_id)   -- closure is permanent. A closure that can be lifted is
#                                   only worth what the discipline not to lift it is worth,
#                                   and the audit log would show authority ending and
#                                   restarting under one id, which is precisely the thing a
#                                   revocation is supposed to make impossible. Handing out
#                                   authority again is /mint, and it needs a human.
#   reset_uses(warrant_id)       -- a method that zeroes a spend counter is precisely the
#                                   bypass this module closes, exposed as an API. The old
#                                   /mint pruned `state.used` for the warrant it was about
#                                   to issue; that id is a freshly generated uuid4, so the
#                                   prune was always a no-op. If it ever were not a no-op,
#                                   clearing would be the bug and not the remedy.
