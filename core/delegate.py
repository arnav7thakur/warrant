"""Attenuated delegation: a warrant holder handing a *narrower slice* of its own
authority to a sub-agent.

This is the difference between a gate and an authority system. A gate answers "may this
call go through". An authority system additionally answers "may this holder give some of
what it has to someone else, and what stops it giving more than it has".

The whole rule is one sentence: **authority only ever attenuates**. Every dimension of a
child grant must be equal to or narrower than the parent's -- operation, resource,
argument bounds, use budget, expiry -- and the child must not be able to reach anything
the parent could not reach. `attenuate()` is the only way to construct a child, and it
raises `AttenuationError` naming the exact dimension it refused on.

Three things here are worth reading the comments for:

  1. The "unenforceable parent" rule (`_ATT_UNENFORCEABLE`). `core.enforce` refuses a
     wildcard resource on a mutating op, which makes such a grant *dead* -- it can never
     authorize anything. Narrowing `refunds.create order:*` to `refunds.create order:9999`
     is syntactically an attenuation and semantically an escalation: the child can move
     money the parent structurally could not. We reject it. Attenuation is defined on
     *effective* authority, not on the shape of the string.

  2. Budget is not free (`reserve=`). Enforcement counts uses per (warrant_id, grant
     index). A child warrant has its own id, so it gets its own counter -- meaning naive
     delegation *multiplies* the budget instead of dividing it. The issuer must debit the
     parent at delegation time. That is what `reserve=True` does, and a broker endpoint
     must always pass it.

  3. Chain verification (`DelegationLedger`). A child is signed by the same key as its
     parent, so it verifies standalone -- the signature proves "the broker signed this",
     never "this was legitimately attenuated from something". See the class docstring for
     what actually prevents forgery here and what does not.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .catalog import CATALOG
from .enforce import use_key
from .models import Constraint, Grant, Warrant
from .sign import sign, verify

# Chains are capped. Depth is O(1) to carry and makes both the cap and cycle detection
# trivial; see the note on `Warrant.depth` in the report for why we carry depth + parent
# rather than the full ancestor list.
MAX_DELEGATION_DEPTH = 5

# Dimension names. These are the contract of the error: a caller (or a broker endpoint
# returning 403) can branch on `err.dimension` instead of parsing prose.
_ATT_SIGNATURE = "signature"
_ATT_CHAIN = "chain"
_ATT_GRANTS = "grants"
_ATT_DEPTH = "depth"
_ATT_EXPIRY = "expiry"
_ATT_OPERATION = "operation"
_ATT_CATALOG = "operation"
_ATT_RESOURCE = "resource"
_ATT_CONSTRAINT = "constraint"
_ATT_USES = "uses"
_ATT_WILDCARD_MUTATION = "wildcard-mutation"
_ATT_UNENFORCEABLE = "unenforceable-parent"

# How specific a failure is. When several parent grants could have covered a request we
# report the failure from the candidate that got furthest, so the message names the real
# obstacle ("amount 9000 exceeds parent 5000") instead of the first one tried.
_SPECIFICITY = {
    _ATT_OPERATION: 0,
    _ATT_UNENFORCEABLE: 1,
    _ATT_RESOURCE: 2,
    _ATT_CONSTRAINT: 3,
    _ATT_USES: 4,
}


class AttenuationError(Exception):
    """Refusal to issue a child warrant, naming the dimension that was widened."""

    def __init__(self, dimension: str, message: str, *, grant_index: int | None = None):
        self.dimension = dimension
        self.grant_index = grant_index
        where = f"requested grant {grant_index}: " if grant_index is not None else ""
        self.reason = f"{where}{message}"
        super().__init__(f"[{dimension}] {self.reason}")


# --------------------------------------------------------------------------------------
# dimension comparisons
# --------------------------------------------------------------------------------------


def is_wildcard(resource: str) -> bool:
    return resource == "*" or resource.endswith(":*")


def resource_narrows(parent: str, child: str) -> bool:
    """True when `child` names the same authority as `parent` or strictly less of it.

    `order:*` -> `order:1234` legal. `order:1234` -> `order:*` is widening. `order:1234`
    -> `order:9999` is not narrowing, it is *sideways*, which is the injection case and
    the one that matters most.
    """
    if parent == child:
        return True
    if parent == "*":
        return True
    if parent.endswith(":*"):
        return child.startswith(parent[:-1])
    return False  # an exact parent resource covers nothing but itself


def _permitted_set(c: Constraint) -> set[str] | None:
    """The categorical value set a constraint allows, or None when it bounds nothing."""
    if c.eq is not None and c.one_of is not None:
        return {c.eq} & set(c.one_of)
    if c.eq is not None:
        return {c.eq}
    if c.one_of is not None:
        return set(c.one_of)
    return None


def constraint_narrows(parent: Constraint, child: Constraint) -> str | None:
    """None when `child` is at least as tight as `parent`, else why it is not.

    A parent bound that simply *vanishes* in the child is the subtle widening: the child
    looks tidier and permits more. Every parent bound must be answered.
    """
    if parent.lte is not None:
        if child.lte is None:
            return f"parent bounds lte={parent.lte} but the child leaves it unbounded"
        if child.lte > parent.lte:
            return f"child lte={child.lte} exceeds parent lte={parent.lte}"
    if parent.gte is not None:
        if child.gte is None:
            return f"parent bounds gte={parent.gte} but the child leaves it unbounded"
        if child.gte < parent.gte:
            return f"child gte={child.gte} falls below parent gte={parent.gte}"

    allowed = _permitted_set(parent)
    if allowed is not None:
        requested = _permitted_set(child)
        if requested is None:
            return "parent restricts this argument to a value set, the child does not"
        if not requested <= allowed:
            extra = sorted(requested - allowed)
            return f"child permits {extra} which the parent does not"
    return None


def _constraints_narrow(parent: Grant, child: Grant) -> str | None:
    """Every argument the parent bounds must be bound at least as tightly by the child.

    The child may bound arguments the parent left free -- that is tightening.
    """
    for arg, bound in parent.constraints.items():
        if arg not in child.constraints:
            return f"parent bounds {arg!r}, the child drops the bound entirely"
        why = constraint_narrows(bound, child.constraints[arg])
        if why is not None:
            return f"constraint on {arg!r}: {why}"
    return None


def _spent_on(parent: Warrant, index: int, spent: dict[str, int] | None) -> int:
    """How much of parent grant `index` is already gone.

    Accepts the broker's own `used` map (keyed by `enforce.use_key`) directly, and also
    tolerates a bare stringified grant index for callers that only have one warrant in
    hand. Anything else is ignored, which fails *open* on budget -- so a broker must pass
    the real map. Called out in the report.
    """
    if not spent:
        return 0
    key = use_key(parent.warrant_id, index)
    if key in spent:
        return int(spent[key])
    return int(spent.get(str(index), 0))


# --------------------------------------------------------------------------------------
# the core operation
# --------------------------------------------------------------------------------------


def attenuation_plan(
    parent: Warrant,
    requested: list[Grant],
    *,
    spent: dict[str, int] | None = None,
) -> list[int]:
    """Check every requested grant against the parent and return, for each, the index of
    the parent grant that covers it. Raises `AttenuationError` on the first violation.

    Separated from `attenuate()` so a broker can dry-run a delegation (to show a human
    what would be handed over) without minting anything, and so `reserve=` knows exactly
    which parent counters to debit.
    """
    if not requested:
        raise AttenuationError(_ATT_GRANTS, "a child warrant with no grants is not authority")

    plan: list[int] = []
    # Budget consumed *within this request*: two child grants drawn from the same parent
    # grant must not each see the full remaining budget.
    consumed: dict[int, int] = {}

    for child_index, child in enumerate(requested):
        if child.uses < 1:
            raise AttenuationError(
                _ATT_USES, f"uses={child.uses} is not a usable budget", grant_index=child_index
            )

        operation = CATALOG.get(child.op)
        if operation is None:
            # Fail closed: without the catalog we cannot know whether the op mutates, so
            # we cannot apply the wildcard rule to it.
            raise AttenuationError(
                _ATT_CATALOG,
                f"{child.op!r} is not in the operation catalog",
                grant_index=child_index,
            )

        # Independent of any parent: enforcement will refuse this shape anyway, and a
        # warrant that carries grants which can never fire is a lie told to whoever reads
        # the audit log.
        if operation.mutating and is_wildcard(child.resource):
            raise AttenuationError(
                _ATT_WILDCARD_MUTATION,
                f"{child.op} is mutating and {child.resource!r} is a wildcard; "
                "wildcards never authorize mutations, at any depth",
                grant_index=child_index,
            )

        candidates = [(i, g) for i, g in enumerate(parent.grants) if g.op == child.op]
        if not candidates:
            held = sorted({g.op for g in parent.grants})
            raise AttenuationError(
                _ATT_OPERATION,
                f"the parent holds no authority for {child.op}; it holds {held}",
                grant_index=child_index,
            )

        best: tuple[int, str, str] | None = None  # (specificity, dimension, message)

        def note(dimension: str, message: str) -> None:
            nonlocal best
            rank = _SPECIFICITY[dimension]
            if best is None or rank >= best[0]:
                best = (rank, dimension, message)

        chosen: int | None = None
        for parent_index, candidate in candidates:
            # (1) A wildcard resource on a mutating op is dead in `core.enforce`. Slicing
            # a live grant out of a dead one is an escalation dressed as narrowing.
            if operation.mutating and is_wildcard(candidate.resource):
                note(
                    _ATT_UNENFORCEABLE,
                    f"parent grant {parent_index} is {candidate.resource!r} on the mutating "
                    f"op {child.op}, which enforcement always refuses; a child cannot hold "
                    "more effective authority than the dead grant it came from",
                )
                continue

            # (2) resource
            if not resource_narrows(candidate.resource, child.resource):
                note(
                    _ATT_RESOURCE,
                    f"{child.resource!r} is not equal to or narrower than the parent's "
                    f"{candidate.resource!r}",
                )
                continue

            # (3) argument constraints
            why = _constraints_narrow(candidate, child)
            if why is not None:
                note(_ATT_CONSTRAINT, why)
                continue

            # (4) use budget, against what is actually left of the parent's
            remaining = candidate.uses - _spent_on(parent, parent_index, spent)
            remaining -= consumed.get(parent_index, 0)
            if child.uses > remaining:
                note(
                    _ATT_USES,
                    f"uses={child.uses} exceeds the parent's remaining budget "
                    f"({max(remaining, 0)} of {candidate.uses} left on grant {parent_index})",
                )
                continue

            chosen = parent_index
            consumed[parent_index] = consumed.get(parent_index, 0) + child.uses
            break

        if chosen is None:
            assert best is not None
            raise AttenuationError(best[1], best[2], grant_index=child_index)
        plan.append(chosen)

    return plan


def attenuate(
    parent: Warrant,
    requested: list[Grant],
    *,
    agent: str,
    ttl_seconds: int,
    spent: dict[str, int] | None = None,
    task_statement: str | None = None,
    ledger: DelegationLedger | None = None,
    reserve: bool = False,
) -> Warrant:
    """Issue a signed child warrant strictly narrower than `parent`, or raise.

    `spent` is the broker's use map (see `enforce.use_key`), so "the child may not exceed
    the parent's budget" means the *remaining* budget, not the original one.

    `reserve=True` debits the parent's counters in `spent` by what the child was given.
    Without it, delegation hands out a fresh budget each time and possession of a parent
    token becomes unlimited authority by repetition. Broker endpoints must pass it.

    `ledger` records the issuance so enforcement can verify the chain later; see
    `DelegationLedger`.
    """
    # An unsigned or tampered parent authorizes nothing, so it can delegate nothing.
    if not verify(parent):
        raise AttenuationError(
            _ATT_SIGNATURE, "the parent warrant's signature is invalid or tampered"
        )

    # Attenuation only ever looks one hop up, so a *valid signature on a parent that was
    # itself never legitimately issued* would let a whole subtree inherit authority that
    # never existed. Checking the parent against the ledger here is what makes the chain
    # transitive: every link was validated at the moment it was created, against a link
    # that had itself been validated.
    if ledger is not None:
        ok, why = ledger.check(parent)
        if not ok:
            raise AttenuationError(_ATT_CHAIN, f"the parent warrant is not delegable: {why}")

    now = time.time()

    if parent.depth + 1 > MAX_DELEGATION_DEPTH:
        raise AttenuationError(
            _ATT_DEPTH,
            f"parent is already at depth {parent.depth}; "
            f"maximum delegation depth is {MAX_DELEGATION_DEPTH}",
        )

    if ttl_seconds <= 0:
        raise AttenuationError(_ATT_EXPIRY, f"ttl_seconds={ttl_seconds} is not a lifetime")

    if now > parent.expires_at:
        raise AttenuationError(
            _ATT_EXPIRY,
            f"the parent expired {int(now - parent.expires_at)}s ago and cannot delegate",
        )

    child_expires = now + ttl_seconds
    if child_expires > parent.expires_at:
        over = int(child_expires - parent.expires_at)
        raise AttenuationError(
            _ATT_EXPIRY,
            f"a {ttl_seconds}s child would outlive the parent by {over}s; "
            "a child expires at or before its parent",
        )

    plan = attenuation_plan(parent, requested, spent=spent)

    child = sign(
        Warrant(
            principal=parent.principal,  # the human stays accountable down the whole chain
            agent=agent,
            task_id=parent.task_id,  # same task; a sub-agent is not a new task
            task_statement=task_statement or f"[delegated from {parent.agent}] {parent.task_statement}",
            grants=[g.model_copy(deep=True) for g in requested],
            expires_at=child_expires,
            parent_id=parent.warrant_id,
            depth=parent.depth + 1,
        )
    )

    # Only now that issuance is certain do we spend the parent's budget.
    if reserve:
        if spent is None:
            raise AttenuationError(
                _ATT_USES, "reserve=True requires the broker's `spent` map to debit"
            )
        for child_index, parent_index in enumerate(plan):
            key = use_key(parent.warrant_id, parent_index)
            spent[key] = spent.get(key, 0) + requested[child_index].uses

    if ledger is not None:
        ledger.register(child)

    return child


# --------------------------------------------------------------------------------------
# chain verification
# --------------------------------------------------------------------------------------


@dataclass
class _Record:
    warrant_id: str
    parent_id: str | None
    depth: int
    expires_at: float
    agent: str
    # The signature of the exact warrant that was issued under this id. Pinning it means
    # the ledger records *which bytes* were authorized, not merely that some warrant with
    # this id existed -- so a re-signed, widened warrant reusing an issued id is caught
    # even though its signature is perfectly valid.
    signature: str = ""
    revoked: bool = False
    children: list[str] = field(default_factory=list)


class DelegationLedger:
    """Issuance record, walked at enforcement time.

    **What a signature proves here, and what it does not.** Parent and child are signed
    with the same key. So `verify(child)` proves only that *the key holder signed this
    object*. It says nothing about whether the object was ever attenuated from anything.
    If the signing key leaked, a forged "child" naming any parent_id and any grants would
    verify perfectly.

    The honest answer to "what prevents that" is in three parts:

    1. **In this system the holder has no key.** Signing lives in the broker; the agent
       holds an opaque token and nothing else. An agent therefore cannot forge a child at
       all -- it must ask the broker, and the broker runs `attenuate()`. Attenuation is
       enforced *at issue time*, by the issuer. That is the actual load-bearing control,
       and it is worth stating plainly rather than dressing up as cryptography.

    2. **This ledger closes the gap that leaves.** Issue-time enforcement is invisible at
       call time: a warrant arriving at `/call` carries a `parent_id` and a signature and
       nothing that ties them together. The ledger makes the issuer's memory part of the
       decision -- a delegated warrant is refused unless this broker actually issued it,
       every ancestor is still alive, and no ancestor has been revoked. It also pins the
       *signature* of what was issued under each id, so a widened warrant re-signed under
       an issued id is refused even though its signature verifies. And `attenuate()`
       checks its parent against the ledger before delegating, which is what makes the
       guarantee transitive rather than one-hop: you cannot bootstrap a subtree from a
       link that was never itself issued. That buys four things a bare signature does
       not: fail-closed on any child this broker never minted, fail-closed on any warrant
       that is not byte-for-byte what was minted, revocation that *cascades* down the
       tree, and no child outliving a parent that was killed early.

    3. **What it still does not guarantee.** The ledger is broker-local state: it does not
       survive a restart, it does not replicate across brokers, and it is not evidence
       anyone else can check. An attacker with the signing key *and* write access to this
       process defeats it -- but such an attacker can mint a root warrant outright, so the
       ledger is not the weak link there. Note also what the walk does *not* re-check: it
       verifies that each ancestor was issued, is alive and is unrevoked, but it does not
       re-run `attenuate()` up the chain, because it does not keep ancestor grants. That
       check happened at issue time and the ledger is trusting its own past self.

    The genuinely stateless answer is different and we do not implement it: give each
    holder its own key, have the *delegator* sign the child, and carry the parent warrant
    (and its parent, recursively) inside the child so a verifier can re-run `attenuate()`
    at every link with no shared state -- macaroons/biscuits/SPKI. That is worth doing,
    and it is a key-management change: the token format grows a chain field and delegation
    stops needing a broker round trip. Under one shared HMAC key it would buy nothing,
    because whoever can forge a link can forge every link. We would rather ship the
    ledger and say so than embed a chain and imply a guarantee the key model cannot back.
    """

    def __init__(self) -> None:
        self._records: dict[str, _Record] = {}

    def register(self, warrant: Warrant) -> None:
        record = _Record(
            warrant_id=warrant.warrant_id,
            parent_id=warrant.parent_id,
            depth=warrant.depth,
            expires_at=warrant.expires_at,
            agent=warrant.agent,
            signature=warrant.signature,
        )
        self._records[warrant.warrant_id] = record
        if warrant.parent_id is not None:
            parent = self._records.get(warrant.parent_id)
            if parent is not None:
                parent.children.append(warrant.warrant_id)

    def revoke(self, warrant_id: str) -> list[str]:
        """Revoke a warrant and everything descended from it. Returns the ids killed.

        Cascading is the point. Authority that was carved out of a warrant cannot outlive
        the decision to take that warrant back.
        """
        killed: list[str] = []
        frontier = [warrant_id]
        while frontier:
            current = frontier.pop()
            record = self._records.get(current)
            if record is None or record.revoked:
                continue
            record.revoked = True
            killed.append(current)
            frontier.extend(record.children)
        return killed

    def descendants(self, warrant_id: str) -> list[str]:
        out: list[str] = []
        frontier = list(self._records.get(warrant_id, _Record("", None, 0, 0.0, "")).children)
        while frontier:
            current = frontier.pop()
            out.append(current)
            record = self._records.get(current)
            if record is not None:
                frontier.extend(record.children)
        return out

    def check(self, warrant: Warrant) -> tuple[bool, str]:
        """The hook `core.enforce.evaluate(..., chain=...)` calls. (ok, reason).

        A root warrant this ledger has never seen is accepted: roots are minted by an
        operator credential and their signature is the whole claim, exactly as before
        delegation existed. A *delegated* warrant is refused unless the ledger knows it.
        """
        now = time.time()

        if warrant.parent_id is None:
            if warrant.depth:
                return False, f"warrant declares depth {warrant.depth} but names no parent"
            record = self._records.get(warrant.warrant_id)
            if record is not None:
                if record.revoked:
                    return False, f"warrant {warrant.warrant_id} has been revoked"
                if record.signature != warrant.signature:
                    return False, (
                        f"warrant {warrant.warrant_id} is not the warrant this broker "
                        "issued under that id"
                    )
            return True, "root warrant"

        record = self._records.get(warrant.warrant_id)
        if record is None:
            return False, (
                f"warrant {warrant.warrant_id} claims parent {warrant.parent_id} but this "
                "broker never issued it; delegated authority must be traceable to an "
                "attenuation this broker performed"
            )
        if record.revoked:
            return False, f"warrant {warrant.warrant_id} has been revoked"
        if record.parent_id != warrant.parent_id or record.depth != warrant.depth:
            return False, "warrant disagrees with the issuance record about its parentage"
        if record.signature != warrant.signature:
            # Valid signature, wrong warrant. Only reachable by something holding the
            # signing key; the ledger still refuses it because it remembers exactly what
            # it authorized under this id.
            return False, (
                f"warrant {warrant.warrant_id} is correctly signed but is not the warrant "
                "this broker issued under that id"
            )

        seen = {warrant.warrant_id}
        child_expiry = warrant.expires_at
        ancestor_id = warrant.parent_id
        hops = 0

        while ancestor_id is not None:
            hops += 1
            if hops > MAX_DELEGATION_DEPTH:
                return False, "delegation chain exceeds the maximum depth"
            if ancestor_id in seen:
                return False, f"delegation chain contains a cycle at {ancestor_id}"
            seen.add(ancestor_id)

            ancestor = self._records.get(ancestor_id)
            if ancestor is None:
                return False, f"ancestor {ancestor_id} is not in the issuance record"
            if ancestor.revoked:
                return False, f"ancestor {ancestor_id} has been revoked"
            if now > ancestor.expires_at:
                return False, (
                    f"ancestor {ancestor_id} expired "
                    f"{int(now - ancestor.expires_at)}s ago; a child cannot outlive its parent"
                )
            if child_expiry > ancestor.expires_at:
                return False, f"warrant outlives ancestor {ancestor_id}"

            ancestor_id = ancestor.parent_id

        return True, f"delegation chain verified across {hops} link(s)"

    # Introspection, for a broker /warrant/chain endpoint or the UI.
    def chain_of(self, warrant_id: str) -> list[str]:
        out = [warrant_id]
        seen = {warrant_id}
        record = self._records.get(warrant_id)
        while record is not None and record.parent_id is not None:
            if record.parent_id in seen:
                break
            out.append(record.parent_id)
            seen.add(record.parent_id)
            record = self._records.get(record.parent_id)
        return out

    def snapshot(self) -> list[dict[str, Any]]:
        return [
            {
                "warrant_id": r.warrant_id,
                "parent_id": r.parent_id,
                "depth": r.depth,
                "agent": r.agent,
                "expires_at": r.expires_at,
                "revoked": r.revoked,
            }
            for r in self._records.values()
        ]
