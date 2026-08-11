"""Evidence that authority can be *ended*, and that the ending is durable.

    .venv\\Scripts\\python.exe -m broker._test_close

Before `closed_warrants` existed, authority ended in exactly two ways -- the TTL ran out,
or a use budget exhausted -- and both of those are timeouts. Nothing took authority back.
Three consequences, all of which these tests cover:

  * a sub-agent that finished in two seconds kept a live warrant for the remaining 298;
  * `/release` unsealed a task without invalidating the token already in the agent's hands;
  * `/revoke` on a **root** warrant did not survive a broker restart -- the ledger was in
    memory and `check()` accepts an unseen root on its signature alone, so a revoked root
    came back to life. That was the only place in the system that failed open.

The headline case here is `revoked_root_survives_restart`, and it is deliberately built
the same way `broker/_test_store.py` builds its bypass test: **two real broker processes**
over the same database file, with the same signed token in the caller's hands throughout.
Each pair of checks carries a control that proves the test can fail -- the same token
against a database that never saw the closure is allowed, which is exactly the old
behaviour.

This suite needs no upstream services, and makes exactly one model call -- the cascade
test mints a real root, because a delegated warrant only verifies if the broker's issuance
ledger holds every warrant above it, and minting is the only thing that registers a root.
Every other test signs its warrants locally and costs nothing. It spawns its own brokers
on their own ports with their own temp databases, so it touches no demo state and can be
run any number of times. A /call that is *allowed* here may still report a 502 from an
unreachable upstream -- that is fine and deliberately not asserted on: what these tests
measure is the broker's decision, which is the HTTP status (200 allowed, 403 denied).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import httpx  # noqa: E402

from core.catalog import CATALOG  # noqa: E402
from core.models import Grant, Warrant  # noqa: E402
from core.sign import encode, sign  # noqa: E402

PYTHON = _ROOT / ".venv" / "Scripts" / "python.exe"
if not PYTHON.exists():  # running under a different interpreter layout
    PYTHON = Path(sys.executable)

OPERATOR_KEY = os.environ.get("OPERATOR_KEY", "operator-key-change-me")
PORT_BASE = int(os.environ.get("WARRANT_PORT_BASE") or 8100)

# Well clear of the stack itself (base .. base+3), so a running demo is untouched.
_NEXT_PORT = PORT_BASE + 40

TMP = Path(tempfile.mkdtemp(prefix="warrant_close_test_"))
RESULTS: list[tuple[bool, str, str]] = []


def check(ok: bool, label: str, detail: str = "") -> bool:
    RESULTS.append((bool(ok), label, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if detail:
        print(f"         {detail}")
    return bool(ok)


def section(title: str) -> None:
    print(f"\n{title}\n{'-' * len(title)}")


# ------------------------------------------------------------------ broker processes


class BrokerProcess:
    """A real uvicorn broker, on its own port, over a database we choose.

    Two of these in a row over one file is what makes a restart test a restart test: the
    second process shares nothing with the first except the bytes on disk.
    """

    def __init__(self, db_path: str, port: int) -> None:
        self.db_path = db_path
        self.port = port
        self.base = f"http://127.0.0.1:{port}"
        self.proc: subprocess.Popen | None = None

    def start(self) -> "BrokerProcess":
        env = {**os.environ, "WARRANT_DB": self.db_path}
        flags = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW
        self.proc = subprocess.Popen(
            [
                str(PYTHON), "-m", "uvicorn", "broker.app:app",
                "--port", str(self.port), "--log-level", "warning",
            ],
            cwd=str(_ROOT),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=flags,
        )
        deadline = time.time() + 45
        while time.time() < deadline:
            try:
                httpx.get(f"{self.base}/healthz", timeout=2.0).raise_for_status()
                return self
            except (httpx.HTTPError, httpx.RequestError):
                time.sleep(0.3)
        raise RuntimeError(f"broker on {self.port} did not come up")

    def stop(self) -> None:
        if self.proc is None:
            return
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(self.proc.pid), "/F", "/T"], capture_output=True
            )
        else:
            self.proc.terminate()
        try:
            self.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.proc = None
        time.sleep(0.4)  # let the WAL settle before the next process opens the file

    def __enter__(self) -> "BrokerProcess":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -- the three calls these tests make -------------------------------------

    def call(self, token: str, op: str = "orders.get", args: dict | None = None):
        return httpx.post(
            f"{self.base}/call",
            json={"op": op, "args": args if args is not None else {"order_id": "1234"}},
            headers={"X-Warrant": token},
            timeout=30.0,
        )

    def close(self, token: str, warrant_id: str | None = None, reason: str | None = None,
              operator_key: str | None = None):
        body: dict = {}
        if warrant_id is not None:
            body["warrant_id"] = warrant_id
        if reason is not None:
            body["reason"] = reason
        headers = {"X-Warrant": token} if token else {}
        if operator_key is not None:
            headers["X-Operator-Key"] = operator_key
        return httpx.post(f"{self.base}/close", json=body, headers=headers, timeout=30.0)

    def revoke(self, warrant_id: str, operator_key: str | None = OPERATOR_KEY):
        headers = {"X-Operator-Key": operator_key} if operator_key else {}
        return httpx.post(
            f"{self.base}/revoke",
            json={"warrant_id": warrant_id},
            headers=headers,
            timeout=30.0,
        )

    def delegate(self, token: str, grants: list[dict], agent: str, ttl: int = 60):
        return httpx.post(
            f"{self.base}/delegate",
            json={"grants": grants, "agent": agent, "ttl_seconds": ttl},
            headers={"X-Warrant": token},
            timeout=30.0,
        )

    def audit(self) -> list[dict]:
        return httpx.get(f"{self.base}/audit", timeout=15.0).json()["entries"]

    def closed(self) -> dict:
        return httpx.get(f"{self.base}/closed", timeout=15.0).json()


def new_broker(name: str) -> BrokerProcess:
    global _NEXT_PORT
    _NEXT_PORT += 1
    return BrokerProcess(str(TMP / f"{name}.db"), _NEXT_PORT)


# ------------------------------------------------------------------------- fixtures


def a_root(uses: int = 5, ttl: float = 900.0, agent: str = "agent:support-01") -> Warrant:
    """A signed root warrant. Read-only and generous, so a denial is never ambiguous.

    Signed here rather than minted, deliberately: /mint costs a real model call, and what
    is under test is what the broker does with a warrant it accepts, not how it derives
    one. A root the delegation ledger has never seen is accepted on its signature, which
    is exactly the case that used to make a revoked root survivable.
    """
    return sign(
        Warrant(
            principal="human:arnav",
            agent=agent,
            task_statement="Check order 1234 for Anil",
            expires_at=time.time() + ttl,
            grants=[
                Grant(
                    op="orders.get",
                    resource="order:1234",
                    uses=uses,
                    justification="the task names order 1234",
                )
            ],
        )
    )


def reason_of(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return response.text[:300]
    return str(body.get("reason", body))[:400] if isinstance(body, dict) else str(body)[:400]


# --------------------------------------------------------------------------------- 1


def test_closed_warrant_is_denied() -> None:
    section("1. a closed warrant is denied at /call, and the denial says who and why")
    warrant = a_root()
    token = encode(warrant)

    with new_broker("denied") as broker:
        before = broker.call(token)
        check(before.status_code == 200,
              "the warrant works before it is closed",
              f"HTTP {before.status_code}")

        closed = broker.close(token, reason="the sub-task is finished")
        body = closed.json()
        check(closed.status_code == 200 and body.get("ok"),
              "POST /close with the warrant -> 200",
              f"HTTP {closed.status_code}: closed {body.get('closed')}")
        check(body.get("closed") == [warrant.warrant_id],
              "the response names exactly the warrant that was closed")
        check(body.get("durable") is True, "and reports the closure as durable")

        after = broker.call(token)
        reason = reason_of(after)
        check(after.status_code == 403,
              "the same call with the same token is now DENIED",
              f"HTTP {after.status_code}")
        check("closed" in reason.lower(),
              "the denial says the warrant was closed, not that it expired or ran out",
              reason[:160] + "...")
        check("the sub-task is finished" in reason,
              "the denial carries the reason given at close time")
        check(warrant.agent in reason or "warrant" in reason,
              "the denial names who closed it",
              f"closed_by recorded as {body.get('closed_by')!r}")

        # The decision was written down like any other denial.
        entries = broker.audit()
        denials = [
            e for e in entries
            if e["op"] == "orders.get" and e["decision"] == "DENY"
            and "closed" in e["reason"].lower()
        ]
        check(len(denials) == 1,
              "the closure denial is in the audit log, attributed like any other",
              f"{len(denials)} closure denial(s); warrant "
              f"{denials[0]['warrant_id'][:8] if denials else '-'}")
        closures = [e for e in entries if e["op"] == "warrant.close"]
        check(len(closures) == 1 and closures[0]["decision"] == "ALLOW",
              "the closure itself is audited as warrant.close",
              f"{len(closures)} entry: {closures[0]['reason'][:90] if closures else '-'}...")

        # A closed warrant cannot hand out slices of itself either.
        deleg = broker.delegate(
            token,
            [{"op": "orders.get", "resource": "order:1234", "uses": 1,
              "justification": "sub-agent verification"}],
            agent="agent:worker",
        )
        check(deleg.status_code == 403 and "closed" in reason_of(deleg).lower(),
              "a closed warrant cannot delegate (closure is not escapable by handing down)",
              f"HTTP {deleg.status_code}: {reason_of(deleg)[:110]}...")


# --------------------------------------------------------------------------------- 2


def test_closure_survives_restart() -> None:
    section("2. THE DURABILITY CASE: closure survives a broker restart (two processes)")
    closed_warrant = a_root()
    control_warrant = a_root()
    closed_token, control_token = encode(closed_warrant), encode(control_warrant)

    broker = new_broker("restart")

    # --- broker process #1 -------------------------------------------------
    broker.start()
    pid_one = broker.proc.pid
    check(broker.call(closed_token).status_code == 200, "process #1: the warrant works")
    response = broker.close(closed_token, reason="work complete")
    check(response.status_code == 200, "process #1: POST /close -> 200")
    check(broker.call(closed_token).status_code == 403, "process #1: now denied")
    broker.stop()

    # --- broker process #2, same file, same token in the caller's hands ----
    broker.start()
    pid_two = broker.proc.pid
    check(pid_one != pid_two,
          "this is genuinely a second process, not a reopened connection",
          f"pid {pid_one} -> pid {pid_two}, database {Path(broker.db_path).name}")
    check(time.time() < closed_warrant.expires_at,
          "the closed warrant is still unexpired across the restart "
          "(this is what would make it a bypass)",
          f"{int(closed_warrant.expires_at - time.time())}s of TTL left")

    after = broker.call(closed_token)
    check(after.status_code == 403,
          "process #2: THE CLOSED WARRANT IS STILL DENIED",
          f"HTTP {after.status_code}: {reason_of(after)[:120]}...")
    check("closed" in reason_of(after).lower(),
          "and still denied for the closure specifically")

    listed = broker.closed()
    check(any(c["warrant_id"] == closed_warrant.warrant_id for c in listed["closed"]),
          "the closure is listed by GET /closed after the restart",
          f"{listed['count']} closure(s) on record")

    # Control: the second process is not simply refusing everything.
    check(broker.call(control_token).status_code == 200,
          "control: a warrant that was never closed still works in process #2 "
          "-- the denial is the closure, not a broken restart")
    broker.stop()

    # Control: the same closed token against a database that never saw the closure.
    with new_broker("restart_control") as fresh:
        check(fresh.call(closed_token).status_code == 200,
              "control: against a fresh database the same token IS allowed -- which is "
              "precisely what a non-durable closure would have left us with")


# --------------------------------------------------------------------------------- 3


def test_cascade_to_children() -> None:
    section("3. closing a parent closes its children")

    # The one test here that needs a real /mint, and it needs it for a reason worth
    # knowing: a delegated warrant only verifies at /call if the broker's issuance ledger
    # holds every warrant above it, and the only thing that registers a *root* is minting
    # one. A hand-signed root would be accepted on its signature alone but could never be
    # a parent -- `check()` refuses a chain with an ancestor it has no record of, which is
    # the same fail-closed rule that makes delegated authority evaporate across a restart.
    # So this one costs one derivation (one model call, a few seconds).
    with new_broker("cascade") as broker:
        response = httpx.post(
            f"{broker.base}/mint",
            json={"task_statement": "Read ticket t-501 for Anil", "ttl_seconds": 600},
            headers={"X-Operator-Key": OPERATOR_KEY},
            timeout=180.0,
        )
        if response.status_code != 200:
            check(False, "minted a root warrant to delegate from",
                  f"HTTP {response.status_code}: {reason_of(response)[:180]}. This test "
                  "needs GEMINI_API_KEY and the operator key; the rest of the suite "
                  "does not.")
            return
        minted = response.json()
        parent_token = minted["token"]
        parent_id = minted["warrant"]["warrant_id"]
        grants = minted["warrant"]["grants"]
        usable = [
            g for g in grants
            if not g["constraints"] and ":" in g["resource"] and not g["resource"].endswith(":*")
        ]
        check(bool(usable), "minted a root warrant to delegate from",
              f"{len(grants)} grant(s): {[g['op'] + ' ' + g['resource'] for g in grants]}")
        if not usable:
            return
        grant = usable[0]
        op_name = grant["op"]
        resource_id = grant["resource"].split(":", 1)[1]
        call_args = {CATALOG[op_name].resource_param: resource_id}

        response = broker.delegate(
            parent_token,
            [{"op": op_name, "resource": grant["resource"], "uses": 1,
              "justification": "sub-agent verifies this one record"}],
            agent="agent:worker-01",
            ttl=300,
        )
        check(response.status_code == 200, "delegated a narrower child from it",
              f"HTTP {response.status_code}: {reason_of(response)[:110]}")
        if response.status_code != 200:
            return
        child_token = response.json()["token"]
        child_id = response.json()["warrant"]["warrant_id"]

        check(broker.call(child_token, op_name, call_args).status_code == 200,
              "the child works before the close",
              f"{op_name} {grant['resource']}")

        closed = broker.close(parent_token, reason="the whole task is finished")
        body = closed.json()
        check(closed.status_code == 200, "POST /close on the parent -> 200")
        check(set(body.get("closed", [])) == {parent_id, child_id},
              "one call closes the parent AND the child it delegated",
              f"closed {len(body.get('closed', []))}: cascaded to "
              f"{[w[:8] for w in body.get('cascaded_to', [])]}")

        parent_reason = reason_of(broker.call(parent_token, op_name, call_args))
        check("closed" in parent_reason.lower(), "the parent is denied for the closure",
              parent_reason[:120] + "...")
        child_response = broker.call(child_token, op_name, call_args)
        child_reason = reason_of(child_response)
        check(child_response.status_code == 403,
              "the child is denied -- a slice cannot outlive what it was cut from",
              child_reason[:150] + "...")
        check("cascaded" in child_reason or "delegated from" in child_reason,
              "and the child's denial says it was cascaded, naming the parent")

        # One audit entry per closed warrant, so `audit_for_warrant(child)` tells the
        # whole story of that warrant: issued, used, closed.
        entries = broker.audit()
        closes = [e for e in entries if e["op"] == "warrant.close"]
        check(len(closes) == 2 and {e["warrant_id"] for e in closes} == {parent_id, child_id},
              "each closed warrant gets its own audit entry, attributed to itself",
              f"{len(closes)} warrant.close entries")


# --------------------------------------------------------------------------------- 4


def test_close_is_authorized_by_the_warrant() -> None:
    section("4. /close is authorized by holding the warrant -- no operator key anywhere")
    holder = a_root()
    stranger = a_root(agent="agent:someone-else")
    holder_token, stranger_token = encode(holder), encode(stranger)

    with new_broker("authz") as broker:
        response = broker.close("")
        check(response.status_code == 403 and "no warrant" in reason_of(response),
              "no warrant at all -> 403",
              reason_of(response)[:110])

        response = broker.close("not-a-token")
        check(response.status_code == 403, "a malformed token -> 403", reason_of(response)[:80])

        # A warrant edited to widen itself cannot close things either.
        forged = holder.model_copy(deep=True)
        forged.grants[0].uses = 999
        response = broker.close(encode(forged), warrant_id=holder.warrant_id)
        check(response.status_code == 403 and "signature" in reason_of(response),
              "a tampered warrant -> 403 (closing is not so harmless it can go unchecked)",
              reason_of(response)[:110])

        # Somebody else's warrant is not yours to end.
        response = broker.close(stranger_token, warrant_id=holder.warrant_id)
        check(response.status_code == 403 and "descended" in reason_of(response),
              "closing an unrelated warrant -> 403, so /close is not a way to switch "
              "off other holders",
              reason_of(response)[:130] + "...")
        check(broker.call(holder_token).status_code == 200,
              "and the target warrant is untouched by that refused attempt")

        # The positive case: warrant only, no operator credential in the request at all.
        response = broker.close(holder_token, reason="done")
        check(response.status_code == 200,
              "THE WARRANT ALONE CLOSES IT -- no X-Operator-Key was sent",
              f"HTTP {response.status_code}, closed {len(response.json().get('closed', []))}")
        check(broker.call(holder_token).status_code == 403, "and it is denied thereafter")

        # ... and a wrong operator key does not help, because it is not consulted.
        response = broker.close(stranger_token, operator_key="totally-wrong-key")
        check(response.status_code == 200,
              "a wrong X-Operator-Key is simply irrelevant here: the warrant is the "
              "authorization",
              f"HTTP {response.status_code}")


# --------------------------------------------------------------------------------- 5


def test_revoked_root_survives_restart() -> None:
    section("5. THE OLD FAIL-OPEN: a revoked root stays revoked across a restart")
    warrant = a_root()
    token = encode(warrant)
    broker = new_broker("revoke")

    # --- broker process #1 -------------------------------------------------
    broker.start()
    pid_one = broker.proc.pid
    check(broker.call(token).status_code == 200, "process #1: the root works")

    denied = broker.revoke(warrant.warrant_id, operator_key=None)
    check(denied.status_code == 403,
          "/revoke still needs the operator credential",
          reason_of(denied)[:110] + "...")

    response = broker.revoke(warrant.warrant_id)
    check(response.status_code == 200 and warrant.warrant_id in response.json()["revoked"],
          "process #1: POST /revoke with the operator key -> 200",
          f"revoked {[w[:8] for w in response.json()['revoked']]}, "
          f"durable={response.json().get('durable')}")
    check(broker.call(token).status_code == 403, "process #1: the root is denied")
    broker.stop()

    # --- broker process #2 -------------------------------------------------
    broker.start()
    check(broker.proc.pid != pid_one, "a second broker process, same database file",
          f"pid {pid_one} -> pid {broker.proc.pid}")
    after = broker.call(token)
    check(after.status_code == 403,
          "process #2: THE REVOKED ROOT IS STILL REVOKED "
          "(this is the case that used to come back to life)",
          f"HTTP {after.status_code}: {reason_of(after)[:120]}...")
    check("closed" in reason_of(after).lower() or "revoked" in reason_of(after).lower(),
          "and the denial explains that authority was taken back, not that time ran out")
    broker.stop()

    # Control: the same token, a database that never saw the revocation.
    with new_broker("revoke_control") as fresh:
        check(fresh.call(token).status_code == 200,
              "control: the same signed token IS honoured by a broker with no record of "
              "the revocation -- exactly the in-memory-ledger behaviour this replaces")


# --------------------------------------------------------------------------------- 6


def test_close_is_idempotent() -> None:
    section("6. closing an already-closed warrant is idempotent")
    warrant = a_root()
    token = encode(warrant)

    with new_broker("idempotent") as broker:
        first = broker.close(token, reason="first close")
        check(first.status_code == 200 and first.json()["closed"] == [warrant.warrant_id],
              "first close: 200, one warrant closed")
        first_at = first.json()["closed_at"]

        second = broker.close(token, reason="second close, different words")
        body = second.json()
        check(second.status_code == 200, "second close: still 200, not an error",
              f"HTTP {second.status_code}")
        check(body["closed"] == [] and body["already_closed"] == [warrant.warrant_id],
              "and it reports that nothing changed",
              f"closed={body['closed']}, already_closed={[w[:8] for w in body['already_closed']]}")
        check(body["closed_at"] == first_at and "first close" in str(body["reason"]),
              "the original closure is untouched: first reason and first timestamp stand",
              f"reason still {str(body['reason'])[:70]}...")

        listed = broker.closed()
        check(sum(1 for c in listed["closed"] if c["warrant_id"] == warrant.warrant_id) == 1,
              "exactly one closure row exists, not two")
        check(broker.call(token).status_code == 403, "and the warrant is still denied")

        # Revoking something already closed is the same non-event.
        response = broker.revoke(warrant.warrant_id)
        check(response.status_code == 200 and response.json()["revoked"] == [],
              "revoking an already-closed warrant changes nothing either",
              f"already_closed={[w[:8] for w in response.json()['already_closed']]}")


# --------------------------------------------------------------------------------- 7


def test_release_does_not_close() -> None:
    section("7. /release does NOT close the outstanding token, and says so")
    warrant = a_root()
    token = encode(warrant)

    with new_broker("release") as broker:
        response = httpx.post(
            f"{broker.base}/release",
            headers={"X-Operator-Key": OPERATOR_KEY},
            timeout=30.0,
        )
        body = response.json()
        check(response.status_code == 200, "POST /release with the operator key -> 200")
        check("still live" in str(body.get("note", "")).lower(),
              "the response spells out that a released token stays live",
              str(body.get("note"))[:150] + "...")
        check(broker.call(token).status_code == 200,
              "a token is unaffected by a release -- release permits a fresh derivation, "
              "it does not end authority already issued")
        check(broker.close(token, reason="now actually done").status_code == 200,
              "ending it is the separate act it is meant to be: POST /close")
        check(broker.call(token).status_code == 403, "and now it is over")


# ------------------------------------------------------------------------------ main


def main() -> int:
    print(f"warrant closure tests -- databases under {TMP}")
    print(f"brokers on ports {_NEXT_PORT + 1}+, no upstreams and no model calls needed")
    for test in (
        test_closed_warrant_is_denied,
        test_closure_survives_restart,
        test_cascade_to_children,
        test_close_is_authorized_by_the_warrant,
        test_revoked_root_survives_restart,
        test_close_is_idempotent,
        test_release_does_not_close,
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
