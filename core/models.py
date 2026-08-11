"""Wire types shared by every component. Nothing here imports anything else in the project."""

from __future__ import annotations

import time
import uuid
from typing import Any, Literal

from pydantic import BaseModel, Field


def _now() -> float:
    return time.time()


def _uuid() -> str:
    return str(uuid.uuid4())


class Constraint(BaseModel):
    """A bound on a single argument. All present fields must hold."""

    lte: float | None = None
    gte: float | None = None
    eq: str | None = None
    one_of: list[str] | None = None

    def check(self, value: Any) -> tuple[bool, str]:
        if self.lte is not None:
            try:
                if float(value) > self.lte:
                    return False, f"value {value} exceeds limit {self.lte}"
            except (TypeError, ValueError):
                return False, f"value {value!r} is not numeric, cannot bound by lte"
        if self.gte is not None:
            try:
                if float(value) < self.gte:
                    return False, f"value {value} below minimum {self.gte}"
            except (TypeError, ValueError):
                return False, f"value {value!r} is not numeric, cannot bound by gte"
        if self.eq is not None and str(value) != self.eq:
            return False, f"value {value!r} != required {self.eq!r}"
        if self.one_of is not None and str(value) not in self.one_of:
            return False, f"value {value!r} not in {self.one_of}"
        return True, "ok"


class Grant(BaseModel):
    """Authority to perform one operation on one resource, bounded and budgeted.

    `resource` is either exact ("order:1234") or a trailing wildcard ("order:*").
    Wildcards are legal but the derivation step is instructed to avoid them; when one
    appears it is surfaced in the UI as a widened grant.
    """

    op: str
    resource: str
    constraints: dict[str, Constraint] = Field(default_factory=dict)
    uses: int = 1
    justification: str = ""

    def matches_resource(self, resource: str) -> bool:
        if self.resource.endswith(":*"):
            return resource.startswith(self.resource[:-1])
        if self.resource == "*":
            return True
        return self.resource == resource


class Warrant(BaseModel):
    """Scoped, expiring authority for exactly one task.

    Minted from a task statement before the agent runs. The agent holds this and
    nothing else -- no upstream credential ever enters the agent's environment.
    """

    warrant_id: str = Field(default_factory=_uuid)
    principal: str
    agent: str
    task_id: str = Field(default_factory=_uuid)
    task_statement: str
    grants: list[Grant] = Field(default_factory=list)
    issued_at: float = Field(default_factory=_now)
    expires_at: float = 0.0

    # Delegation. A warrant minted by an operator is a root: parent_id None, depth 0.
    # A warrant produced by core.delegate.attenuate() names the warrant it was carved
    # out of. Both are covered by the signature, so neither can be edited after issue.
    #
    # We carry the parent id and the depth rather than the full ancestor list: the depth
    # is what a cap and a cycle check need, and the full chain is reconstructible from
    # the broker's issuance ledger without paying for it in every token. Embedding the
    # whole signed chain only earns its size under per-holder keys -- see the note in
    # core/delegate.py:DelegationLedger.
    parent_id: str | None = None
    depth: int = 0

    signature: str = ""

    def signing_payload(self) -> dict[str, Any]:
        """Everything covered by the signature. Excludes the signature itself."""
        return self.model_dump(exclude={"signature"}, mode="json")


class Decision(BaseModel):
    allowed: bool
    reason: str
    grant_index: int | None = None


class AuditEntry(BaseModel):
    entry_id: str = Field(default_factory=_uuid)
    ts: float = Field(default_factory=_now)
    principal: str
    agent: str
    task_id: str
    warrant_id: str
    op: str
    resource: str
    args: dict[str, Any] = Field(default_factory=dict)
    decision: Literal["ALLOW", "DENY"]
    reason: str
    upstream_status: int | None = None


class CallRequest(BaseModel):
    """What the agent sends to the broker. Note: carries no credential.

    `authorize_only=True` means: enforce and audit (and spend the use budget on
    ALLOW), but do not forward to an HTTP upstream. Used by the MCP wrap path —
    the wrap process holds the upstream MCP connection and performs the call
    itself after the broker says yes.
    """

    op: str
    args: dict[str, Any] = Field(default_factory=dict)
    authorize_only: bool = False


class MintRequest(BaseModel):
    task_statement: str
    principal: str = "human:arnav"
    agent: str = "agent:support-01"
    ttl_seconds: int = 300
    # When set, the broker signs these grants as-is and does not call the LLM.
    # Used for air-gapped / deterministic minting and for demos that must not
    # depend on Gemini being reachable.
    grants: list[Grant] | None = None
