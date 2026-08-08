"""The agent's only outbound surface besides the Anthropic API.

Two calls exist here and nowhere else in this process:

    POST http://127.0.0.1:8100/mint   -> get a warrant token for a task statement
    POST http://127.0.0.1:8100/call   -> ask the broker to perform one operation

No upstream base URL is imported, constructed, or referenced. The agent has no
credential to attach even if it tried.

/mint is here only for the combined operator+agent fallback in `agent.run`. It needs
an operator credential the deployed agent does not have, and the broker refuses it
with 403 without one. In the shape this project argues for, the agent is handed a
token and this client only ever calls /call -- see `demo/session.py`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from core.models import Warrant
from core.sign import decode

from . import BROKER_URL


class BrokerUnreachable(RuntimeError):
    """The broker is not answering. There is no fallback path -- that is the point."""


class BrokerProtocolError(RuntimeError):
    """The broker answered, but not in the shape CONTRACTS.md describes."""


@dataclass
class MintResult:
    warrant: Warrant
    token: str
    derivation_ms: int
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class CallOutcome:
    """One trip through the enforcement point."""

    op: str
    args: dict[str, Any]
    status_code: int
    allowed: bool
    data: Any = None
    reason: str = ""
    resource: str = ""
    upstream_status: int | None = None
    body: Any = None

    @property
    def denied(self) -> bool:
        return self.status_code == 403


class BrokerClient:
    def __init__(self, base_url: str = BROKER_URL, timeout: float = 60.0) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(timeout=timeout)
        self.token: str | None = None

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "BrokerClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- /mint -------------------------------------------------------------

    def mint(
        self,
        task_statement: str,
        principal: str | None = None,
        agent: str | None = None,
        ttl_seconds: int | None = None,
        operator_key: str = "",
    ) -> MintResult:
        payload: dict[str, Any] = {"task_statement": task_statement}
        if principal is not None:
            payload["principal"] = principal
        if agent is not None:
            payload["agent"] = agent
        if ttl_seconds is not None:
            payload["ttl_seconds"] = ttl_seconds

        try:
            response = self._client.post(
                f"{self.base_url}/mint",
                json=payload,
                headers={"X-Operator-Key": operator_key} if operator_key else {},
            )
        except httpx.RequestError as exc:
            raise BrokerUnreachable(
                f"cannot reach the broker at {self.base_url} ({exc.__class__.__name__}). "
                "The agent holds no credentials, so there is no way around it."
            ) from exc

        if response.status_code != 200:
            raise BrokerProtocolError(
                f"POST /mint returned {response.status_code}: {response.text[:500]}"
            )

        body = response.json()
        try:
            warrant = Warrant.model_validate(body["warrant"])
            token = body["token"]
        except Exception as exc:  # noqa: BLE001 - contract violation, report it plainly
            raise BrokerProtocolError(
                f"POST /mint response did not match the contract: {exc}"
            ) from exc

        self.token = token
        return MintResult(
            warrant=warrant,
            token=token,
            derivation_ms=int(body.get("derivation_ms", 0) or 0),
            raw=body,
        )

    # -- a warrant handed in from outside ------------------------------------

    def use_token(self, token: str) -> Warrant:
        """Adopt a token minted by someone else (the operator process).

        This is the normal path. The agent never sees /mint; it is given a warrant
        the way a courier is given a signed docket, and it can read what it holds --
        decoding is not verification, and widening the decoded copy would break the
        signature the broker checks on every call.
        """
        try:
            warrant = decode(token)
        except Exception as exc:  # noqa: BLE001 - a bad token is a startup error
            raise BrokerProtocolError(f"--warrant is not a decodable token: {exc}") from exc
        self.token = token
        return warrant

    # -- /call -------------------------------------------------------------

    def call(self, op: str, args: dict[str, Any]) -> CallOutcome:
        """The one thing every tool handler does. Nothing else happens here."""
        if not self.token:
            raise RuntimeError("no warrant token; mint one before calling")

        try:
            response = self._client.post(
                f"{self.base_url}/call",
                headers={"X-Warrant": self.token},
                json={"op": op, "args": args},
            )
        except httpx.RequestError as exc:
            raise BrokerUnreachable(
                f"cannot reach the broker at {self.base_url} ({exc.__class__.__name__})"
            ) from exc

        try:
            body: Any = response.json()
        except ValueError:
            body = {"raw_text": response.text}

        if isinstance(body, dict):
            allowed = bool(body.get("ok", response.status_code == 200))
            return CallOutcome(
                op=op,
                args=args,
                status_code=response.status_code,
                allowed=allowed and response.status_code == 200,
                data=body.get("data"),
                reason=str(body.get("reason", "") or ""),
                resource=str(body.get("resource", "") or ""),
                upstream_status=body.get("status"),
                body=body,
            )

        return CallOutcome(
            op=op,
            args=args,
            status_code=response.status_code,
            allowed=response.status_code == 200,
            data=body,
            body=body,
        )
