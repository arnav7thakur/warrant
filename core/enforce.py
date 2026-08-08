"""The enforcement decision.

This is the whole security argument in one function. It runs in the broker, which is
the only process holding upstream credentials. If nothing matches, the call never
reaches an upstream -- there is no fallback path, because the caller has no credential
of its own to retry with.
"""

from __future__ import annotations

import time
from typing import Any

from .catalog import CATALOG
from .models import Decision, Warrant
from .sign import verify


def use_key(warrant_id: str, grant_index: int) -> str:
    return f"{warrant_id}:{grant_index}"


def evaluate(
    warrant: Warrant,
    op_name: str,
    args: dict[str, Any],
    used: dict[str, int],
    *,
    chain: Any = None,
) -> Decision:
    """Decide whether this warrant authorizes this exact call.

    `used` maps use_key() -> times already spent, and is owned by the broker.

    `chain` is an optional verifier for delegated warrants -- anything with
    `.check(warrant) -> (ok, reason)`; in practice `core.delegate.DelegationLedger`.
    It is duck-typed rather than imported so this module keeps depending on nothing but
    the catalog, the models and the signature.

    A signature alone cannot distinguish a legitimately attenuated child from a forged
    one, because both are signed by the same key. So a warrant that *claims* a parent is
    refused outright unless a chain verifier is present to confirm the claim. Failing
    closed here is deliberate: an enforcement point with no view of the issuance record
    has no basis on which to honour delegated authority.
    """
    if not verify(warrant):
        return Decision(allowed=False, reason="warrant signature invalid or tampered")

    if warrant.parent_id is None and warrant.depth:
        return Decision(
            allowed=False,
            reason=f"warrant declares delegation depth {warrant.depth} but names no parent",
        )

    if chain is not None:
        ok, why = chain.check(warrant)
        if not ok:
            return Decision(allowed=False, reason=f"delegation chain rejected: {why}")
    elif warrant.parent_id is not None:
        return Decision(
            allowed=False,
            reason=(
                f"warrant is delegated (parent {warrant.parent_id}) but this enforcement "
                "point has no delegation ledger to verify the chain against; a signature "
                "alone does not prove a child was ever attenuated from its parent"
            ),
        )

    now = time.time()
    if now > warrant.expires_at:
        age = int(now - warrant.expires_at)
        return Decision(allowed=False, reason=f"warrant expired {age}s ago")

    op = CATALOG.get(op_name)
    if op is None:
        return Decision(allowed=False, reason=f"unknown operation {op_name!r}")

    resource = op.resource_of(args)

    # Collect near-misses so a denial explains itself instead of just saying no.
    op_grants = [(i, g) for i, g in enumerate(warrant.grants) if g.op == op_name]
    if not op_grants:
        granted = sorted({g.op for g in warrant.grants})
        return Decision(
            allowed=False,
            reason=f"warrant grants no authority for {op_name}; it covers {granted}",
        )

    resource_mismatch: list[str] = []
    unbounded: list[str] = []
    for index, grant in op_grants:
        # Defence in depth: the enforcement layer does not trust the derivation layer.
        # A wildcard can never authorize a mutation, however the grant came to exist.
        # This is what keeps the model from being the safety mechanism -- a sloppy or
        # manipulated derivation still cannot produce unbounded write authority.
        #
        # Skip rather than return: a warrant holding both a sloppy wildcard grant and a
        # correct narrow one must behave the same whichever order they appear in. The
        # denial below still fires when the wildcard was the only thing on offer.
        if op.mutating and (grant.resource == "*" or grant.resource.endswith(":*")):
            unbounded.append(grant.resource)
            continue

        if not grant.matches_resource(resource):
            resource_mismatch.append(grant.resource)
            continue

        for arg_name, constraint in grant.constraints.items():
            # A bound the caller can skip by leaving the argument out is not a bound.
            # `orders.list` bounded to customer_id=c-anil, called with no arguments,
            # would otherwise sail through and reach every order in the system --
            # and "add a constraint" is one of the ways authority is meant to narrow
            # under delegation, so a skippable bound makes attenuation a lie too.
            if arg_name not in args:
                return Decision(
                    allowed=False,
                    reason=(
                        f"grant bounds {arg_name}, but the call omits it; "
                        "a bounded argument must be supplied"
                    ),
                    grant_index=index,
                )
            ok, why = constraint.check(args[arg_name])
            if not ok:
                return Decision(
                    allowed=False,
                    reason=f"constraint on {arg_name} violated: {why}",
                    grant_index=index,
                )

        spent = used.get(use_key(warrant.warrant_id, index), 0)
        if spent >= grant.uses:
            return Decision(
                allowed=False,
                reason=f"use budget exhausted for {op_name} ({spent}/{grant.uses})",
                grant_index=index,
            )

        return Decision(allowed=True, reason="within warrant", grant_index=index)

    if unbounded and not resource_mismatch:
        return Decision(
            allowed=False,
            reason=(
                f"{op_name} is mutating and this grant is unbounded "
                f"({unbounded[0]}); wildcards never authorize mutations"
            ),
        )

    if unbounded:
        return Decision(
            allowed=False,
            reason=(
                f"{op_name} is granted on {resource_mismatch} and unbounded on "
                f"{unbounded} (which cannot authorize a mutation); "
                f"this call reaches {resource}"
            ),
        )

    return Decision(
        allowed=False,
        reason=(
            f"{op_name} is granted, but only on {resource_mismatch}; "
            f"this call reaches {resource}"
        ),
    )
