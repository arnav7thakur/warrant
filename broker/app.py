"""The broker.

This process is the only one holding upstream credentials, and it extends no trust to
its caller. An agent presents a warrant; the broker decides; on ALLOW it attaches the
real credential and forwards; on DENY nothing leaves. There is no path around it,
because the caller has no credential of its own.

Two credentials meet here, and they are deliberately not the same credential:

  UPSTREAM_KEY   the real service key. Never leaves this process.
  OPERATOR_KEY   the authority to CREATE authority. Required by /mint, /release,
                 /revoke and /catalog/register, and by nothing else. The agent does not
                 have it and must not: an agent that can mint can widen its own warrant,
                 which would make the whole mechanism a convention rather than a boundary.
                 /call and /delegate deliberately do not require it -- the first spends
                 authority, the second hands a narrower slice of it down.

Sealing. A task is sealed the moment its warrant is used for a /call -- allow or deny,
because attempting to act is what begins the task. From then on /mint refuses (409) for
as long as that warrant lives. This is what makes "authority is derived before the agent
reads anything untrusted" structural rather than a habit of our own agent: once the
agent has consumed ticket text or tool output, there is no longer any way to turn that
content into new authority for the same task. Widening requires a human, out of band,
via POST /release -- and the release is audited.

Delegation is the deliberate exception, and POST /delegate is *not* sealed. See the
comment on that endpoint: minting turns words into new authority, delegation only ever
hands down a slice of authority that already exists.

Closure. Authority used to end in exactly two ways -- the TTL ran out, or a use budget
exhausted -- and both of those are timeouts. Nothing took authority *back*, so a sub-agent
that finished its work in two seconds still held a live warrant for the remaining 298.
POST /close is the third way, and it is the only one that ends at the moment the work
does: the *holder* gives up what it holds, it cascades to everything delegated from it,
and it is written to `closed_warrants` in the store, so /call refuses that warrant from
then on -- through a restart, through a re-presentation of the same token, permanently.
POST /revoke is the same mechanism with the operator credential in front of it, for the
case where the holder is the party you no longer trust to give it up.

State lives in `broker/store.py`, on disk. Only the open SSE connections are kept in
this process, because a socket genuinely is process state. Everything a decision depends
on -- the audit log, the use budgets, the active warrant, the seal -- outlives the
process, because a warrant carries its own TTL and therefore outlives the broker that
issued it. The one exception is the delegation ledger; see the note on it below.
"""

from __future__ import annotations

import asyncio
import hmac
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from core.catalog import (
    CATALOG,
    SERVICE_BASE,
    CatalogError,
    catalog_meta,
    credential_for,
    describe_for_model,
    full_surface,
)
from core.catalog import register as catalog_register
from core.delegate import AttenuationError, DelegationLedger, attenuate
from core.enforce import evaluate, use_key
from core.models import AuditEntry, CallRequest, Grant, MintRequest, Warrant
from core.sign import decode, encode, sign, verify

from .store import Store

UPSTREAM_KEY = os.environ.get("UPSTREAM_KEY", "real-service-key-abc123")
# Kept for docs/compat. Forwarding uses core.catalog.credential_for(service), which
# checks WARRANT_CREDENTIAL_<SERVICE> then falls back to this value.

# The operator credential. Self-labelling default, same pattern as UPSTREAM_KEY: the
# demo works out of the box, and the value on screen says what it is. Whoever holds
# this can create authority; that is why the agent process is not allowed to have it.
OPERATOR_KEY = os.environ.get("OPERATOR_KEY", "operator-key-change-me")

UI_FILE = Path(__file__).resolve().parent.parent / "ui" / "index.html"
UI_CONSOLE_FILE = Path(__file__).resolve().parent.parent / "ui" / "console.html"

MINT_OP = "warrant.mint"
RELEASE_OP = "warrant.release"
DELEGATE_OP = "warrant.delegate"
REVOKE_OP = "warrant.revoke"
CLOSE_OP = "warrant.close"
REGISTER_OP = "catalog.register"


class State:
    """What is genuinely this process's own: the open audit-stream connections.

    Nothing else. The audit log, the use budgets, the active warrant and the seal all
    live in `broker.store.Store`, on disk, because a warrant outlives the broker that
    issued it -- a `uses=1` grant enforced by a dict in RAM is enforced by the broker's
    uptime, and the holder only has to wait for a restart.

    `active_warrant` stays a plain attribute to read and assign; the property forwards
    both to the store, so every existing caller keeps working unchanged.
    """

    def __init__(self, store: Store) -> None:
        self.store = store
        self.subscribers: list[asyncio.Queue[AuditEntry]] = []

    @property
    def active_warrant(self) -> Warrant | None:
        return self.store.get_active_warrant()

    @active_warrant.setter
    def active_warrant(self, warrant: Warrant | None) -> None:
        self.store.set_active_warrant(warrant)

    def record(self, entry: AuditEntry) -> None:
        # Durable first, then fan out to the live UI. If the append raises we would
        # rather fail the request than show a decision that was never written down.
        self.store.append_audit(entry)
        for queue in list(self.subscribers):
            queue.put_nowait(entry)

    def sealed_warrant(self) -> Warrant | None:
        """The live warrant that has already begun acting, if there is one."""
        return self.store.sealed_warrant()


# Constructed at import time, deliberately. A store that cannot be opened, or whose
# schema this broker does not speak, raises StoreError here and the process never binds
# a port. Coming up with no memory of what was already spent is worse than not coming up
# at all: every live warrant would silently get its budget back.
STORE = Store()
state = State(STORE)

# One ledger for the whole broker: the issuance record `/delegate` writes to and `/call`
# checks every delegated warrant against.
#
# KNOWN LIMIT, not fixed here: this is in-memory. Restart the broker and every delegated
# warrant stops verifying, because `DelegationLedger.check()` refuses any warrant naming
# a parent it has no record of issuing. That fails *closed* -- delegated authority
# evaporates rather than surviving unaccountably -- which is why it is acceptable and why
# it is not papered over with an "accept unknown children" fallback. Root warrants are
# unaffected: they survive in the store and a root the ledger has never seen is accepted
# on its signature, exactly as before delegation existed. Making delegation durable means
# putting the ledger in the same SQLite file as everything else; that is the fix, and it
# is a schema change we did not take on in this integration.
#
# The one place that limit used to fail *open* is now closed, and it is worth being precise
# about which one. Losing the ledger loses the record of what was issued -- and a root the
# ledger never saw is accepted on its signature, so a revoked root came back to life on the
# next restart. Revocation and closure therefore do not live here: they go to
# `STORE.close_warrant()`, on disk, and `/call` checks that list before it checks anything
# else. What is lost across a restart is the *cascade* -- the children links used to find
# descendants -- and losing that fails closed too, because a delegated warrant whose issuance
# record is gone stops verifying anyway. Ending authority never depends on this object.
LEDGER = DelegationLedger()


class CatalogRegisterRequest(BaseModel):
    """A manifest posted over the wire. Same shape as `core.catalog.load_manifest`."""

    operations: list[dict[str, Any]] = Field(default_factory=list)
    namespace: str | None = None
    services: dict[str, Any] | None = None
    credentials: dict[str, str] | None = None
    name: str | None = None
    owner: str | None = None
    version: str | None = None
    description: str | None = None


class DelegateRequest(BaseModel):
    grants: list[Grant]
    agent: str
    ttl_seconds: int = 60
    task_statement: str | None = None


class RevokeRequest(BaseModel):
    warrant_id: str


class CloseRequest(BaseModel):
    """Body of POST /close. Everything in it is optional.

    `warrant_id` names what to close. Omitted, it means the warrant presented in the
    X-Warrant header -- "I am done, take this back". Given, it must be that warrant or
    something descended from it: you may end authority you hold, and you may end authority
    you handed out, and nothing else.
    """

    warrant_id: str | None = None
    reason: str | None = None


def _control_audit(
    op: str,
    decision: str,
    reason: str,
    principal: str = "unknown",
    agent: str = "unknown",
    warrant: Warrant | None = None,
    args: dict[str, Any] | None = None,
) -> None:
    """Audit a lifecycle event -- a mint, release, delegation, revocation or catalog
    registration -- refused or allowed.

    A refused mint is the interesting one. Something tried to create authority and
    could not; that attempt belongs in the same log as the calls, attributable, not
    swallowed into a bare HTTP status nobody reads. The same argument is why
    /catalog/register is audited: the catalog is mutable state now, and a mutation with
    no trace would be the one gap left in the log.
    """
    task_id = warrant.task_id if warrant is not None else "-"
    state.record(
        AuditEntry(
            principal=warrant.principal if warrant is not None else principal,
            agent=warrant.agent if warrant is not None else agent,
            task_id=task_id,
            warrant_id=warrant.warrant_id if warrant is not None else "-",
            op=op,
            resource=task_id,
            args=args or {},
            decision="ALLOW" if decision == "ALLOW" else "DENY",
            reason=reason,
        )
    )


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _closure_denial(warrant: Warrant) -> str | None:
    """The reason this warrant may no longer be used, or None if it is still live.

    Checks the whole ancestry, not just the token presented. Closing a parent cascades to
    the children the ledger knows about at that moment, but a warrant delegated *before* a
    restart has no ledger record afterwards, and one delegated from a since-closed parent
    should never have existed at all. Walking the chain here means a closed ancestor denies
    its descendants even when the cascade could not reach them -- the durable list is the
    authority, and the in-memory links are only a convenience for finding rows to write.

    `chain_of` degrades to `[warrant_id]` for anything the ledger has no record of, so a
    root is one lookup and this costs nothing in the common case.
    """
    for warrant_id in LEDGER.chain_of(warrant.warrant_id):
        record = STORE.closure_of(warrant_id)
        if record is None:
            continue
        whose = "this warrant" if warrant_id == warrant.warrant_id else f"ancestor {warrant_id}"
        return (
            f"{whose} was closed at {_iso(float(record['closed_at']))} "
            f"by {record['closed_by']}: {record['reason']}. "
            "A closure is permanent and durable -- it is recorded on disk, it survives a "
            "broker restart, and there is no endpoint that lifts one. Authority that has "
            "been given up or taken back does not come back; a new task needs a new warrant."
        )
    return None


def _cascade_close(warrant_id: str, reason: str, closed_by: str) -> tuple[list[str], list[str]]:
    """Close `warrant_id` and everything descended from it. Returns (newly closed, already).

    Two records are written, and they are not redundant. `LEDGER.revoke()` marks the
    subtree revoked in memory, which is what makes the *rest of this process* stop
    verifying those warrants immediately; `STORE.close_warrant()` writes the same fact to
    disk, which is what makes it survive the process. If the ledger has never heard of the
    id -- a root issued before a restart, say -- the store still records the closure, and
    that alone is enough for /call to refuse it. Ending authority is never contingent on
    memory the broker can lose.
    """
    targets = [warrant_id] + LEDGER.descendants(warrant_id)
    LEDGER.revoke(warrant_id)

    closed: list[str] = []
    already: list[str] = []
    for target in targets:
        detail = reason if target == warrant_id else (
            f"{reason} (cascaded: delegated from {warrant_id}, and authority carved out of "
            "a warrant does not outlive it)"
        )
        if STORE.close_warrant(target, detail, closed_by, root_id=warrant_id):
            closed.append(target)
        else:
            already.append(target)
    return closed, already


@asynccontextmanager
async def lifespan(app: FastAPI):
    from core.llm import load_dotenv

    load_dotenv()
    app.state.http = httpx.AsyncClient(timeout=10.0)
    yield
    await app.state.http.aclose()


app = FastAPI(title="Warrant Broker", lifespan=lifespan)


@app.get("/catalog")
async def get_catalog() -> dict[str, Any]:
    meta = catalog_meta()
    return {
        "operations": [
            {
                "op": op.op,
                "mutating": op.mutating,
                "description": op.description,
                "args": op.args,
                "constrainable": op.constrainable,
                "resource_type": op.resource_type,
                "resource_param": op.resource_param,
                "service": op.service,
            }
            for op in CATALOG.values()
        ],
        "full_surface": full_surface(),
        "builtins": meta["builtins"],
        "namespaces": meta["namespaces"],
        "projects": meta["projects"],
        "project": meta["projects"][-1] if meta["projects"] else None,
        "operation_count": meta["operation_count"],
    }


@app.post("/catalog/register")
async def register_operations(
    req: CatalogRegisterRequest, x_operator_key: str = Header(default="")
):
    """Declare operations at runtime. Operator credential required, same gate as /mint.

    WHY THIS IS OPERATOR-GATED, and why that is not over-caution:

    registration creates the vocabulary authority is expressed in. A grant names an op;
    an op names a service, a method and a path. Anyone who can register can declare an
    operation under an *existing* service pointing at a path of their choosing, and the
    broker will then forward to it **with the real upstream credential attached** -- that
    is what `_forward()` does for every operation in the catalog, without distinction.

    So this is strictly more powerful than minting. A mint can only hand out authority
    over operations that already exist; a registration decides what "exists" means, and
    every warrant minted afterwards -- including ones derived by the model, which reads
    `describe_for_model()` -- can be written over it. Gating minting while leaving the
    catalog open would be locking the door and leaving the wall out.

    (`core.catalog` closes the sharpest edge itself: a registration cannot re-point an
    existing service at another host, because that would redirect the credential rather
    than merely extend its reach. This gate covers the rest.)
    """
    if not x_operator_key or not hmac.compare_digest(x_operator_key, OPERATOR_KEY):
        why = "missing X-Operator-Key" if not x_operator_key else "invalid X-Operator-Key"
        reason = (
            f"{why}. POST /catalog/register declares the operations warrants are written "
            "over, and the broker forwards to a registered path with the real upstream "
            "credential attached. That is strictly more powerful than minting, so it "
            "requires the operator credential too."
        )
        _control_audit(
            REGISTER_OP,
            "DENY",
            f"catalog registration refused: {reason}",
            args={
                "namespace": req.namespace,
                "operations": [str(o.get("op")) for o in req.operations],
            },
        )
        return JSONResponse(
            status_code=403,
            content={"ok": False, "reason": reason, "op": REGISTER_OP, "resource": "-"},
        )

    try:
        registered = catalog_register(
            req.operations,
            namespace=req.namespace,
            services=req.services,
            source="POST /catalog/register",
            project={
                "name": req.name,
                "owner": req.owner,
                "version": req.version,
                "description": req.description,
            },
            credentials=req.credentials,
        )
    except CatalogError as exc:
        # Verbatim, multi-line and all. These messages name the rule and how to satisfy
        # it; truncating one to fit an HTTP status line would throw away the only part
        # that lets the caller fix their manifest.
        reason = str(exc)
        _control_audit(
            REGISTER_OP,
            "DENY",
            f"catalog registration refused: {reason}",
            principal="operator",
            args={
                "namespace": req.namespace,
                "operations": [str(o.get("op")) for o in req.operations],
            },
        )
        return JSONResponse(status_code=400, content={"ok": False, "error": reason})

    _control_audit(
        REGISTER_OP,
        "ALLOW",
        f"registered {len(registered)} operation(s) by the operator credential: "
        f"{registered}; catalog is now {len(CATALOG)} operation(s)",
        principal="operator",
        args={"namespace": req.namespace, "operations": registered},
    )
    return {"ok": True, "registered": registered, "catalog_size": len(CATALOG)}


@app.post("/mint")
async def mint(req: MintRequest, x_operator_key: str = Header(default="")):
    """Derive minimal authority from the task statement, then sign it.

    This is the only moment authority is created. It happens before the agent runs,
    from the human's words alone -- see the trust boundary note in broker/derive.py.

    Two gates stand in front of it, and neither has a bypass:

      403  no operator credential. Reaching the broker is not authority to create
           authority. The agent can reach this endpoint and still cannot use it.
      409  the task is sealed: its warrant has already been used to attempt a call,
           so the agent has begun consuming content nobody vetted. Authority cannot
           widen after that point. Wait for expiry, or POST /release as a human.
    """
    from .derive import DerivationError, derive_grants  # imported late: keeps the broker bootable alone

    if not x_operator_key or not hmac.compare_digest(x_operator_key, OPERATOR_KEY):
        why = "missing X-Operator-Key" if not x_operator_key else "invalid X-Operator-Key"
        reason = (
            f"{why}. POST /mint creates authority and requires the operator "
            "credential. A warrant does not authorize minting -- if it did, an agent "
            "could widen its own scope."
        )
        _control_audit(
            MINT_OP,
            "DENY",
            f"mint refused: {reason}",
            principal=req.principal,
            agent=req.agent,
            args={"task_statement": req.task_statement},
        )
        return JSONResponse(
            status_code=403,
            content={"ok": False, "reason": reason, "op": MINT_OP, "resource": "-"},
        )

    sealed = state.sealed_warrant()
    if sealed is not None:
        reason = (
            f"task {sealed.task_id} is sealed: it has already begun acting, and "
            "authority cannot be widened after that. Wait for expiry or release it "
            "explicitly."
        )
        _control_audit(
            MINT_OP,
            "DENY",
            f"mint refused: {reason}",
            warrant=sealed,
            args={"task_statement": req.task_statement},
        )
        return JSONResponse(
            status_code=409,
            content={
                "ok": False,
                "reason": reason,
                "op": MINT_OP,
                "resource": sealed.task_id,
            },
        )

    started = time.perf_counter()
    if req.grants is not None:
        # Operator-supplied grants: no LLM. Same gates (operator key + seal) still
        # apply -- this only skips derivation, it does not bypass minting authority.
        grants = list(req.grants)
        reasoning = (
            f"operator-supplied {len(grants)} grant(s); derivation skipped"
        )
    else:
        try:
            grants, reasoning = await derive_grants(req.task_statement)
        except DerivationError as exc:
            raise HTTPException(status_code=422, detail=f"derivation failed: {exc}") from exc

    warrant = sign(
        Warrant(
            principal=req.principal,
            agent=req.agent,
            task_statement=req.task_statement,
            grants=grants,
            expires_at=time.time() + req.ttl_seconds,
        )
    )
    state.active_warrant = warrant

    # Register the root in the delegation ledger. Two reasons, both about /revoke:
    # `revoke()` cascades by walking a record's children, and a child is only linked to
    # its parent if the parent was in the ledger when the child was registered -- so
    # without this, revoking a root would kill nothing and orphan its whole subtree.
    # It also pins the signature, so a re-signed warrant reusing this id is refused.
    LEDGER.register(warrant)

    _control_audit(
        MINT_OP,
        "ALLOW",
        f"warrant minted with {len(warrant.grants)} grant(s), "
        f"ttl {req.ttl_seconds}s, by the operator credential",
        warrant=warrant,
        args={"task_statement": warrant.task_statement},
    )

    return {
        "warrant": warrant.model_dump(mode="json"),
        "token": encode(warrant),
        "reasoning": reasoning,
        "derivation_ms": int((time.perf_counter() - started) * 1000),
    }


@app.post("/release")
async def release(x_operator_key: str = Header(default="")):
    """Unseal: drop the active warrant so a new one can be minted for a new task.

    This is the escalation path, and it is deliberately the only one. It cannot be
    reached with a warrant, only with the operator credential -- a human, out of band,
    who has looked at why the agent wanted more. It is audited either way.

    WHAT THIS DOES NOT DO, STATED PLAINLY: **the token already in the agent's hands stays
    live.** Releasing does not close it. That token keeps its own grants, its own remaining
    budget and its own TTL, and the agent can go on spending it until one of those runs
    out. The response says so in `released_token_still_live`.

    That is a decision, not an oversight, and the argument is that these are two different
    acts with two different meanings:

      release = "let me derive fresh authority for this task"   (widening; needs a human)
      close   = "the authority already issued is finished"      (narrowing; permanent)

    Releasing in order to *re-mint* -- the ordinary case, where the operator has looked at
    a denial and decided the task genuinely needs more -- must not kill the warrant the
    agent is midway through using; that would turn every widening into an interruption and
    would silently discard whatever budget was left. And a release that quietly closed the
    outstanding token would make the two acts indistinguishable in the audit log, which is
    exactly the place they need to be told apart.

    The sharp edge is the other case: if you are releasing *because you no longer trust the
    agent*, releasing alone has stopped nothing. Do both -- POST /close on that warrant, or
    POST /revoke as the operator -- and the response points at it rather than leaving you to
    find out. Making one endpoint mean both would be convenient exactly once and wrong every
    other time.
    """
    if not x_operator_key or not hmac.compare_digest(x_operator_key, OPERATOR_KEY):
        why = "missing X-Operator-Key" if not x_operator_key else "invalid X-Operator-Key"
        reason = (
            f"{why}. POST /release unseals a task so wider authority can be minted, "
            "so it requires the operator credential."
        )
        active = state.active_warrant
        _control_audit(
            RELEASE_OP, "DENY", f"release refused: {reason}", warrant=active
        )
        return JSONResponse(
            status_code=403,
            content={
                "ok": False,
                "reason": reason,
                "op": RELEASE_OP,
                "resource": active.task_id if active is not None else "-",
            },
        )

    # Deliberately NOT closed here -- see the docstring. The token stays live; the release
    # only unseals the task so a fresh derivation is permitted.
    released = state.active_warrant
    state.active_warrant = None
    STORE.clear_acted()

    still_live = released is not None and STORE.is_closed(released.warrant_id) is None

    _control_audit(
        RELEASE_OP,
        "ALLOW",
        (
            f"task {released.task_id} released by the operator; it is no longer sealed "
            "and a new warrant may be minted. The token already issued "
            + (
                f"({released.warrant_id[:8]}) IS STILL LIVE -- release does not close it; "
                "POST /close or /revoke that warrant if it should stop working"
                if still_live
                else f"({released.warrant_id[:8]}) was already closed"
            )
            if released is not None
            else "release requested, but there was no active warrant to release"
        ),
        warrant=released,
    )

    return {
        "released": released.model_dump(mode="json") if released is not None else None,
        "sealed": False,
        # Named so it cannot be missed by anyone reading the response instead of the docs.
        "released_token_still_live": still_live,
        "note": (
            "A released token is STILL LIVE: release does not close it. It keeps its "
            "grants, its remaining use budget and its TTL, and this endpoint touched none "
            "of them. Release means 'a new warrant may now be minted for this task'. If "
            "the point was to stop the agent, that is a separate act -- POST /close "
            "holding the warrant, or POST /revoke with the operator credential; either one "
            "is permanent and survives a restart."
            + (
                f" The outstanding token here is {released.warrant_id} and it is still live."
                if still_live
                else " (No live token was outstanding for this task.)"
            )
        ),
    }


@app.post("/delegate")
async def delegate(req: DelegateRequest, x_warrant: str = Header(default="")):
    """Hand a sub-agent a strictly narrower slice of the authority you already hold.

    Authenticated by the *parent warrant*, not the operator key, and that is the point:
    delegating is spending authority you were given, not creating any. The holder is the
    only party who can decide to give some of it away, and it cannot give away more than
    it has -- `core.delegate.attenuate()` refuses on the first dimension that widens.

    WHY THIS IS NOT SEALED, while /mint is. The seal exists because after the agent has
    read untrusted content, that content must not be convertible into *new* authority:
    /mint takes a task statement -- words -- and produces grants, so a sealed task that
    could still mint would let injected text write its own warrant. Delegation cannot do
    that. Every dimension of a child is checked against the parent, so injected text can
    influence *which slice* is handed down and never *produce a slice the parent lacked*.
    The worst an injection achieves here is a sub-agent holding some subset of what the
    compromised agent already had and could have used directly. That is the load-bearing
    distinction between the two endpoints: minting is widening, delegation is structurally
    non-widening, and only widening needs a human.

    `reserve=True` is mandatory. A child warrant has its own id and therefore its own use
    counters, so delegation without debiting the parent *multiplies* the budget: a uses=1
    refund grant becomes unlimited refunds by delegating to a fresh sub-agent each time.
    The debit is written through to the store below, for the same reason the /call spend
    is -- a budget that a restart refunds is not a budget.
    """
    if not x_warrant:
        return JSONResponse(
            status_code=403,
            content={
                "ok": False,
                "dimension": "signature",
                "reason": "no parent warrant presented; POST /delegate is authenticated by "
                "the warrant being delegated from, not by the operator credential",
            },
        )

    try:
        parent = decode(x_warrant)
    except Exception:
        return JSONResponse(
            status_code=403,
            content={"ok": False, "dimension": "signature", "reason": "malformed warrant"},
        )

    # A closed warrant cannot delegate. Otherwise closure would be trivially escapable:
    # hand yourself a child a moment before giving the parent up and the slice outlives the
    # thing it was cut from. Checked on the whole ancestry, same as /call.
    closure = _closure_denial(parent)
    if closure is not None:
        _control_audit(
            DELEGATE_OP,
            "DENY",
            f"delegation refused [closed]: {closure}",
            warrant=parent,
            args={"agent": req.agent},
        )
        return JSONResponse(
            status_code=403,
            content={"ok": False, "dimension": "closed", "reason": closure},
        )

    # attenuate(reserve=True) debits this dict in place; we diff it afterwards and write
    # the difference through, so the parent's budget is spent on disk, not just in RAM.
    before = STORE.used_map(parent.warrant_id)
    spent = dict(before)

    try:
        child = attenuate(
            parent,
            req.grants,
            agent=req.agent,
            ttl_seconds=req.ttl_seconds,
            spent=spent,
            task_statement=req.task_statement,
            ledger=LEDGER,
            reserve=True,
        )
    except AttenuationError as exc:
        _control_audit(
            DELEGATE_OP,
            "DENY",
            f"delegation refused [{exc.dimension}]: {exc.reason}",
            warrant=parent,
            args={"agent": req.agent, "grants": [g.model_dump(mode="json") for g in req.grants]},
        )
        return JSONResponse(
            status_code=403,
            content={"ok": False, "dimension": exc.dimension, "reason": exc.reason},
        )

    for index in range(len(parent.grants)):
        key = use_key(parent.warrant_id, index)
        for _ in range(spent.get(key, 0) - before.get(key, 0)):
            STORE.spend(parent.warrant_id, index)

    # Durable from the moment it exists, same as a root minted by /mint -- otherwise
    # this child is real authority that only the roster at GET /warrants (and every
    # other reader of the `warrants` table) cannot see. See record_warrant()'s
    # docstring for why this is not set_active_warrant().
    STORE.record_warrant(child)

    _control_audit(
        DELEGATE_OP,
        "ALLOW",
        f"delegated {len(child.grants)} grant(s) to {child.agent} at depth {child.depth}, "
        f"ttl {req.ttl_seconds}s, debited from parent {parent.warrant_id[:8]}",
        warrant=child,
        args={"parent_id": parent.warrant_id, "agent": req.agent},
    )

    return {
        "warrant": child.model_dump(mode="json"),
        "token": encode(child),
        "parent_id": parent.warrant_id,
        "depth": child.depth,
    }


@app.post("/close")
async def close(req: CloseRequest, x_warrant: str = Header(default="")):
    """Give up authority you hold. Authenticated by the warrant, not the operator key.

    This is the endpoint that lets authority end when the *work* ends rather than when the
    clock does. A sub-agent that finishes in two seconds should not keep a live warrant for
    the remaining 298, and until this existed there was no way for it to hand one back:
    every ending was a timeout.

    WHY THE WARRANT AND NOT THE OPERATOR CREDENTIAL. Every other lifecycle endpoint that
    changes authority is operator-gated, because every other one can *widen* it -- /mint
    creates authority, /release permits creating more, /catalog/register decides what
    authority can even be written over. This one only ever subtracts. You may always give
    up what you hold; needing a human's permission to stop being able to act would be a
    permission barrier in front of the safe direction, and it would mean the only agents
    that gave authority back were the ones that could reach a human. Requiring the operator
    key here would guarantee that in practice nobody ever closed anything.

    WHAT MAY BE CLOSED. The warrant presented, or anything descended from it. Both follow
    from the same rule: authority you hold is yours to end, and authority you handed down
    was yours to withhold in the first place, so taking it back cannot exceed what you had.
    A warrant that is not you and not yours is refused -- otherwise any holder of any
    warrant could shut down any other, which is a denial-of-service dressed as a safety
    feature.

    THE CASCADE. Closing a parent closes every descendant, via the issuance ledger. A child
    is a slice of its parent; a slice that outlived the thing it was cut from would be
    authority with no source. `_cascade_close` writes each of them to the durable list.

    PERMANENT AND DURABLE. The closure goes to `broker/store.py`, in the same SQLite file
    as the audit log and the use budgets, and /call checks it before it evaluates anything.
    Waiting for a restart does not undo it. There is no endpoint that lifts one.

    Idempotent: closing an already-closed warrant is a 200 that changes nothing, because
    the useful guarantee is "this warrant is closed", not "you were the one who closed it".
    """
    if not x_warrant:
        return JSONResponse(
            status_code=403,
            content={
                "ok": False,
                "reason": "no warrant presented; POST /close is authenticated by the "
                "warrant being given up, not by the operator credential",
                "op": CLOSE_OP,
                "resource": "-",
            },
        )

    try:
        holder = decode(x_warrant)
    except Exception:
        return JSONResponse(
            status_code=403,
            content={"ok": False, "reason": "malformed warrant", "op": CLOSE_OP, "resource": "-"},
        )

    # A warrant that does not verify is not a warrant, and closing is not so harmless that
    # it can be done on an unauthenticated say-so: a forged token that could close things
    # would be a way to take other people's authority away.
    if not verify(holder):
        _control_audit(
            CLOSE_OP,
            "DENY",
            "close refused: the presented warrant's signature is invalid or tampered",
            warrant=holder,
            args={"warrant_id": req.warrant_id},
        )
        return JSONResponse(
            status_code=403,
            content={
                "ok": False,
                "reason": "warrant signature invalid or tampered",
                "op": CLOSE_OP,
                "resource": "-",
            },
        )

    ok, why = LEDGER.check(holder)
    if not ok:
        # Fails closed for the same reason /call does: a delegated warrant this broker has
        # no record of issuing proves nothing by its signature alone, so it cannot be used
        # to reach up and close an ancestor.
        _control_audit(
            CLOSE_OP,
            "DENY",
            f"close refused: delegation chain rejected: {why}",
            warrant=holder,
            args={"warrant_id": req.warrant_id},
        )
        return JSONResponse(
            status_code=403,
            content={
                "ok": False,
                "reason": f"delegation chain rejected: {why}",
                "op": CLOSE_OP,
                "resource": "-",
            },
        )

    target = req.warrant_id or holder.warrant_id
    if target != holder.warrant_id and target not in LEDGER.descendants(holder.warrant_id):
        reason = (
            f"warrant {target} is neither the warrant presented nor descended from it. "
            "A holder may end its own authority and any authority it delegated, and "
            "nothing else -- otherwise holding any warrant would be a way to switch off "
            "somebody else's."
        )
        _control_audit(
            CLOSE_OP, "DENY", f"close refused: {reason}", warrant=holder,
            args={"warrant_id": target},
        )
        return JSONResponse(
            status_code=403,
            content={"ok": False, "reason": reason, "op": CLOSE_OP, "resource": target},
        )

    stated = (req.reason or "").strip() or "the holder gave up this authority"
    reason = f"closed by the holder of warrant {holder.warrant_id[:8]}: {stated}"
    closed_by = f"{holder.agent} (warrant {holder.warrant_id[:8]})"

    closed, already = _cascade_close(target, reason, closed_by)

    # One audit entry per warrant closed, attributed to that warrant rather than to the
    # request, so `audit_for_warrant(child_id)` shows the whole life of a delegated
    # warrant -- issued, used, closed -- in one query.
    for warrant_id in closed:
        record = STORE.closure_of(warrant_id) or {}
        state.record(
            AuditEntry(
                principal=holder.principal,
                agent=holder.agent,
                task_id=holder.task_id,
                warrant_id=warrant_id,
                op=CLOSE_OP,
                resource=warrant_id,
                args={
                    "closed_by": closed_by,
                    "root_id": target,
                    "cascaded": warrant_id != target,
                    "reason": stated,
                },
                decision="ALLOW",
                reason=str(record.get("reason", reason)),
            )
        )

    if not closed:
        _control_audit(
            CLOSE_OP,
            "ALLOW",
            f"warrant {target} was already closed; closure is idempotent and permanent, "
            "so nothing changed",
            warrant=holder,
            args={"warrant_id": target},
        )

    record = STORE.closure_of(target) or {}
    return {
        "ok": True,
        "closed": closed,
        "already_closed": already,
        "warrant_id": target,
        "cascaded_to": [w for w in (closed + already) if w != target],
        "closed_at": record.get("closed_at"),
        "closed_by": record.get("closed_by"),
        "reason": record.get("reason"),
        "durable": True,
        "note": (
            "This warrant is finished. /call will refuse it from now on, including after a "
            "broker restart, and there is no endpoint that reopens it."
        ),
    }


@app.get("/closed")
async def closed_warrants() -> dict[str, Any]:
    """Every closure this broker has recorded, oldest first. Read-only."""
    return {"closed": STORE.closures(), "count": STORE.closure_count()}


@app.post("/revoke")
async def revoke(req: RevokeRequest, x_operator_key: str = Header(default="")):
    """Kill a warrant and everything descended from it. Operator credential required.

    Revocation is a human taking authority back from a holder who is not going to give it
    up, so it sits behind the same credential as minting and releasing. /close is the same
    ending reached voluntarily; this is the involuntary one, and it is the only difference
    between them.

    Durable. This routes through `broker.store.close_warrant()`, the same list /close
    writes and /call checks, so a revoked warrant stays revoked across a broker restart --
    including a revoked *root*, which used to be the one place in this system that failed
    open. The reason it did is worth remembering: the cascade lives in the in-memory
    issuance ledger, a root the ledger has never seen is accepted on its signature alone,
    and a restart empties the ledger -- so the revocation evaporated while the signed token
    in the holder's hands did not. Waiting for a restart is no longer a bypass.

    What a restart still costs is the *cascade*: without the ledger's children links the
    broker cannot enumerate descendants, so revoking a root afterwards closes the root
    alone. That fails closed anyway -- a delegated warrant whose issuance record is gone
    stops verifying at /call regardless -- but it is the honest boundary of what this
    endpoint can do after a restart.
    """
    if not x_operator_key or not hmac.compare_digest(x_operator_key, OPERATOR_KEY):
        why = "missing X-Operator-Key" if not x_operator_key else "invalid X-Operator-Key"
        reason = (
            f"{why}. POST /revoke withdraws authority already issued, and cascades to "
            "everything delegated from it, so it requires the operator credential. "
            "(A holder giving up its own authority does not need it: that is POST /close.)"
        )
        _control_audit(
            REVOKE_OP,
            "DENY",
            f"revocation refused: {reason}",
            args={"warrant_id": req.warrant_id},
        )
        return JSONResponse(
            status_code=403,
            content={"ok": False, "reason": reason, "op": REVOKE_OP, "resource": "-"},
        )

    known = req.warrant_id in {r["warrant_id"] for r in LEDGER.snapshot()}
    closed, already = _cascade_close(
        req.warrant_id,
        f"revoked by the operator (POST /revoke on {req.warrant_id[:8]})",
        "operator",
    )

    for warrant_id in closed:
        warrant = STORE.get_warrant(warrant_id)
        state.record(
            AuditEntry(
                principal=warrant.principal if warrant is not None else "operator",
                agent=warrant.agent if warrant is not None else "operator",
                task_id=warrant.task_id if warrant is not None else "-",
                warrant_id=warrant_id,
                op=REVOKE_OP,
                resource=warrant_id,
                args={"root_id": req.warrant_id, "cascaded": warrant_id != req.warrant_id},
                decision="ALLOW",
                reason=(
                    f"revoked by the operator credential and closed durably; /call will "
                    f"refuse it from now on, including after a restart"
                    + ("" if known else ". This broker has no issuance record of it "
                       "(never issued here, or issued before a restart), so the closure "
                       "covers this id alone and cannot enumerate descendants")
                ),
            )
        )

    if not closed:
        _control_audit(
            REVOKE_OP,
            "ALLOW",
            f"nothing to revoke: {req.warrant_id} was already closed. Closure is "
            "permanent, so the earlier one still stands",
            principal="operator",
            args={"warrant_id": req.warrant_id},
        )

    # `revoked` is kept as the response key it always was; it now means "closed durably".
    return {
        "ok": True,
        "revoked": closed,
        "already_closed": already,
        "durable": True,
        "in_issuance_ledger": known,
    }


@app.get("/warrant/active")
async def active_warrant() -> dict[str, Any]:
    """The single warrant `/mint` last pointed at, plus how much it has spent.

    This answers one specific question -- "what would `/mint` refuse (409) right
    now because it's sealed" -- and it is *not* "everyone currently holding
    authority": a delegated sub-agent's warrant never touches this slot. For the
    whole fleet, see `GET /warrants` below. `used` is index-aligned with
    `warrant.grants` so a caller can show "0 of 1 left" rather than just the budget.
    """
    warrant = state.active_warrant
    if warrant is None:
        return {"warrant": None, "used": [], "sealed": False, "closed": None}
    return {
        "warrant": warrant.model_dump(mode="json"),
        "used": STORE.used_list(warrant),
        "sealed": state.sealed_warrant() is not None,
        # None while live. A string once the warrant has been given up or taken back --
        # the third way authority ends, and the only one that is not a timeout.
        "closed": STORE.is_closed(warrant.warrant_id),
    }


def _warrant_summary(warrant: Warrant, *, active_id: str | None) -> dict[str, Any]:
    now = time.time()
    closed = STORE.is_closed(warrant.warrant_id)
    return {
        "warrant_id": warrant.warrant_id,
        "principal": warrant.principal,
        "agent": warrant.agent,
        "task_id": warrant.task_id,
        "task_statement": warrant.task_statement,
        "issued_at": warrant.issued_at,
        "expires_at": warrant.expires_at,
        "grant_count": len(warrant.grants),
        "parent_id": warrant.parent_id,
        "depth": warrant.depth,
        "closed": closed,
        "expired": warrant.expires_at <= now,
        # Neither closed nor expired -- the two ways authority ends on its own,
        # before a human /closes or /revokes it early. See broker/app.py's module
        # docstring on "Closure".
        "live": closed is None and warrant.expires_at > now,
        "is_active_slot": warrant.warrant_id == active_id,
    }


@app.get("/warrants")
async def list_warrants(limit: int = 200) -> dict[str, Any]:
    """Every warrant on this broker -- every root `/mint` issued and every child
    `/delegate` carved out of one -- most recent first.

    This is the roster a fleet needs and `/warrant/active` structurally cannot be:
    that endpoint answers for one slot, this answers for everyone currently (or
    recently) holding authority, so a console can show N connected agents instead
    of pretending there is only ever one. Each entry is a summary; fetch
    `GET /warrant/{warrant_id}` for the grant-level detail on one, so this list
    stays cheap regardless of how many agents are live.
    """
    active_id = state.active_warrant.warrant_id if state.active_warrant is not None else None
    warrants = STORE.list_warrants(limit=limit)
    return {
        "warrants": [_warrant_summary(w, active_id=active_id) for w in warrants],
        "active_warrant_id": active_id,
        "count": len(warrants),
    }


@app.get("/warrant/{warrant_id}")
async def get_warrant(warrant_id: str) -> dict[str, Any]:
    """Grant-level detail for one warrant named by id -- root or delegated.

    The lazy-loaded counterpart to `GET /warrants`: that endpoint lists the fleet
    cheaply, this answers "show me exactly what this one holds and how much of it
    is spent" for whichever entry a caller picked.
    """
    warrant = STORE.get_warrant(warrant_id)
    if warrant is None:
        raise HTTPException(
            status_code=404,
            detail=f"no warrant {warrant_id!r} on this broker (never issued here, "
            "or issued before a restart of a store that was not this one)",
        )
    return {
        "warrant": warrant.model_dump(mode="json"),
        "used": STORE.used_list(warrant),
        "closed": STORE.is_closed(warrant.warrant_id),
        "live": STORE.is_closed(warrant.warrant_id) is None and warrant.expires_at > time.time(),
    }


@app.post("/call")
async def call(req: CallRequest, x_warrant: str = Header(default="")) -> JSONResponse:
    """The enforcement point. Every agent action in the system passes through here."""
    if not x_warrant:
        return JSONResponse(
            status_code=403,
            content={"ok": False, "reason": "no warrant presented", "op": req.op, "resource": "?"},
        )

    try:
        warrant = decode(x_warrant)
    except Exception:
        return JSONResponse(
            status_code=403,
            content={"ok": False, "reason": "malformed warrant", "op": req.op, "resource": "?"},
        )

    # CLOSURE, CHECKED FIRST. Before sealing and before `evaluate()`, because a closed
    # warrant is not authority to be evaluated -- there is nothing left to decide about it,
    # and no combination of grants, budget or TTL can make it live again. This is the check
    # that makes /close and /revoke mean anything: without it, taking authority back would
    # be a note in the ledger that the enforcement point never read.
    #
    # Ahead of sealing, deliberately. Sealing exists because an agent that has begun acting
    # has begun consuming untrusted content; a warrant that cannot act has not begun
    # anything. If a closed token sealed the task it named, anyone holding a dead token
    # could keep a task sealed for as long as they liked by replaying it, which would be an
    # `/mint`-denial-of-service handed out with every closure.
    closure = _closure_denial(warrant)
    if closure is not None:
        op = CATALOG.get(req.op)
        resource = op.resource_of(req.args) if op else "?"
        state.record(
            AuditEntry(
                principal=warrant.principal,
                agent=warrant.agent,
                task_id=warrant.task_id,
                warrant_id=warrant.warrant_id,
                op=req.op,
                resource=resource,
                args=req.args,
                decision="DENY",
                reason=closure,
            )
        )
        return JSONResponse(
            status_code=403,
            content={"ok": False, "reason": closure, "op": req.op, "resource": resource},
        )

    # The task is now under way. Sealing happens here, before the decision, because
    # what seals a task is the attempt to act -- not whether the attempt succeeded.
    # An agent that reads a ticket and is then denied has still read the ticket.
    #
    # The whole ancestry is sealed, not just the token presented. A sub-agent acting on
    # a delegated child has begun the *parent's* task -- same task_id, same principal --
    # so leaving the root unsealed would let an agent read untrusted content through a
    # child and then have the operator re-derive the root as if nothing had happened.
    # `chain_of` degrades to [warrant_id] for anything the ledger has no record of.
    for warrant_id in LEDGER.chain_of(warrant.warrant_id):
        STORE.mark_acted(warrant_id)

    op = CATALOG.get(req.op)
    resource = op.resource_of(req.args) if op else "?"
    # chain=LEDGER is what makes a delegated warrant usable at all: without it
    # `evaluate()` refuses anything naming a parent, because a signature alone cannot
    # tell a legitimate attenuation from a forgery.
    decision = evaluate(
        warrant, req.op, req.args, STORE.used_map(warrant.warrant_id), chain=LEDGER
    )

    entry = AuditEntry(
        principal=warrant.principal,
        agent=warrant.agent,
        task_id=warrant.task_id,
        warrant_id=warrant.warrant_id,
        op=req.op,
        resource=resource,
        args=req.args,
        decision="ALLOW" if decision.allowed else "DENY",
        reason=decision.reason,
    )

    if not decision.allowed:
        state.record(entry)
        return JSONResponse(
            status_code=403,
            content={"ok": False, "reason": decision.reason, "op": req.op, "resource": resource},
        )

    assert op is not None  # evaluate() rejects unknown ops before we get here
    # Debit before forwarding, and durably. A spend that is only recorded after the
    # upstream answers is a spend that a crash mid-call gives back.
    if decision.grant_index is not None:
        STORE.spend(warrant.warrant_id, decision.grant_index)

    # MCP wrap (and any other out-of-process forwarder) asks the broker to decide
    # without attaching an HTTP credential. The caller performs the real call.
    if req.authorize_only:
        state.record(entry)
        return JSONResponse(
            status_code=200,
            content={
                "ok": True,
                "authorized": True,
                "op": req.op,
                "resource": resource,
                "reason": decision.reason,
            },
        )

    status, data = await _forward(op, req.args)
    entry.upstream_status = status
    state.record(entry)
    return JSONResponse(status_code=200, content={"ok": True, "status": status, "data": data})


async def _forward(op, args: dict[str, Any]) -> tuple[int, Any]:
    """Attach the real credential for this service and forward."""
    path = op.upstream_path(args)
    consumed = {name for name in args if "{" + name + "}" in op.path}
    remaining = {k: v for k, v in args.items() if k not in consumed}
    url = SERVICE_BASE[op.service] + path
    headers = {"Authorization": f"Bearer {credential_for(op.service)}"}

    try:
        if op.method == "GET":
            response = await app.state.http.get(url, params=remaining, headers=headers)
        else:
            response = await app.state.http.request(
                op.method, url, json=remaining, headers=headers
            )
    except httpx.RequestError as exc:
        return 502, {"error": f"upstream unreachable: {exc}"}

    try:
        return response.status_code, response.json()
    except ValueError:
        return response.status_code, {"raw": response.text}


@app.get("/audit")
async def get_audit(warrant_id: str | None = None, limit: int | None = None) -> dict[str, Any]:
    """The audit trail, oldest first. `warrant_id` scopes it to one warrant's history --
    the same attribution query `Store.audit_for_warrant()` exists for -- so a console
    can back-fill "everything this agent has done" without pulling the whole log and
    filtering client-side once the log is large.
    """
    if warrant_id:
        entries = STORE.audit_for_warrant(warrant_id)
        if limit is not None:
            entries = entries[-max(0, limit) :]
    else:
        entries = STORE.all_audit(limit=limit)
    return {"entries": [e.model_dump(mode="json") for e in entries]}


@app.get("/audit/stream")
async def audit_stream():
    queue: asyncio.Queue[AuditEntry] = asyncio.Queue()
    state.subscribers.append(queue)

    async def events():
        try:
            while True:
                entry = await queue.get()
                yield {"data": entry.model_dump_json()}
        finally:
            if queue in state.subscribers:
                state.subscribers.remove(queue)

    return EventSourceResponse(events())


@app.get("/")
async def index():
    if UI_FILE.exists():
        return FileResponse(UI_FILE)
    return JSONResponse({"status": "broker up", "ui": "not built yet"})


@app.get("/console")
async def console():
    if UI_CONSOLE_FILE.exists():
        return FileResponse(UI_CONSOLE_FILE)
    return JSONResponse({"status": "broker up", "console": "not built yet"})


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    return {
        "ok": True,
        "operations": len(CATALOG),
        "audit_entries": STORE.audit_count(),
        "closed_warrants": STORE.closure_count(),
        "store": STORE.db_path,
    }
