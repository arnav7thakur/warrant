"""Support upstream (port 8102): tickets and customers.

Routes are exactly the `Operation.path` values declared in core/catalog.py for
service="support". State is in-memory.

Ticket t-501's body is read at startup from demo/ticket.txt -- it is never inlined here,
because the injection text lives in exactly one place.

Every route requires `Authorization: Bearer <UPSTREAM_KEY>`.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException

UPSTREAM_KEY = os.environ.get("UPSTREAM_KEY", "real-service-key-abc123")

REPO_ROOT = Path(__file__).resolve().parent.parent
TICKET_BODY_PATH = REPO_ROOT / "demo" / "ticket.txt"


def _load_ticket_body() -> str:
    """Read the ticket body from disk at startup. Fail loudly if it is missing."""
    if not TICKET_BODY_PATH.is_file():
        raise RuntimeError(
            f"Expected the ticket body at {TICKET_BODY_PATH}; it is not there. "
            "support.py refuses to start without it."
        )
    return TICKET_BODY_PATH.read_text(encoding="utf-8")


def require_upstream_key(authorization: str | None = Header(default=None)) -> str:
    """Reject anything that does not carry the real upstream credential."""
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header. Expected 'Bearer <UPSTREAM_KEY>'.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(
            status_code=401,
            detail="Malformed Authorization header. Expected 'Bearer <UPSTREAM_KEY>'.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if token.strip() != UPSTREAM_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid upstream credential.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token.strip()


app = FastAPI(
    title="support",
    description="Tickets and customers.",
    dependencies=[Depends(require_upstream_key)],
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# --------------------------------------------------------------------------- state

CUSTOMERS: dict[str, dict[str, Any]] = {
    "c-anil": {
        "customer_id": "c-anil",
        "name": "Anil Kumar",
        "email": "anil@example.com",
        "tier": "individual",
        "since": "2023-04-11",
        "orders": ["1234"],
    },
    "c-priya": {
        "customer_id": "c-priya",
        "name": "Priya Nair",
        "email": "priya@example.com",
        "tier": "individual",
        "since": "2024-11-02",
        "orders": ["5678"],
    },
    "c-enterprise": {
        "customer_id": "c-enterprise",
        "name": "Meridian Logistics Pvt Ltd",
        "email": "ops@meridianlogistics.example.com",
        "tier": "enterprise",
        "seats": 2400,
        "since": "2021-01-19",
        "orders": ["9999"],
    },
}

TICKETS: dict[str, dict[str, Any]] = {
    "t-501": {
        "ticket_id": "t-501",
        "customer_id": "c-anil",
        "customer_name": "Anil Kumar",
        "subject": "Wrong item received for order 1234",
        "status": "open",
        "priority": "normal",
        "order_id": "1234",
        "created_at": "2026-08-07T11:42:00Z",
        # Untrusted, customer-authored content. Loaded from demo/ticket.txt.
        "body": _load_ticket_body(),
    }
}


# -------------------------------------------------------------------------- routes


@app.get("/tickets/{ticket_id}")
def get_ticket(ticket_id: str) -> dict[str, Any]:
    """tickets.get -- `body` is customer-written and therefore untrusted."""
    ticket = TICKETS.get(ticket_id)
    if ticket is None:
        raise HTTPException(status_code=404, detail=f"No such ticket: {ticket_id}")
    return ticket


@app.get("/customers/{customer_id}")
def get_customer(customer_id: str) -> dict[str, Any]:
    """customers.get"""
    customer = CUSTOMERS.get(customer_id)
    if customer is None:
        raise HTTPException(status_code=404, detail=f"No such customer: {customer_id}")
    return customer
