"""Commerce upstream (port 8101): orders and refunds.

Routes are exactly the `Operation.path` values declared in core/catalog.py for
service="commerce". State is in-memory and mutated in place.

Every route requires `Authorization: Bearer <UPSTREAM_KEY>`. The agent process has no
key; only the broker does. That is the whole point -- auth here is not optional.
"""

from __future__ import annotations

import os
import time
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, ValidationError

UPSTREAM_KEY = os.environ.get("UPSTREAM_KEY", "real-service-key-abc123")


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
    title="commerce",
    description="Orders and refunds.",
    dependencies=[Depends(require_upstream_key)],
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# --------------------------------------------------------------------------- state

ORDERS: dict[str, dict[str, Any]] = {
    "1234": {
        "order_id": "1234",
        "customer_id": "c-anil",
        "item": "Noise-cancelling headphones",
        "items": [
            {"sku": "AUD-NC-700", "name": "Noise-cancelling headphones", "qty": 1, "price": 4999}
        ],
        "total": 4999,
        "currency": "INR",
        "status": "delivered",
        "placed_at": "2026-07-21T10:14:00Z",
        "refunded_total": 0,
    },
    "5678": {
        "order_id": "5678",
        "customer_id": "c-priya",
        "item": "Mechanical keyboard",
        "items": [
            {"sku": "KB-MECH-87", "name": "Mechanical keyboard", "qty": 1, "price": 1299}
        ],
        "total": 1299,
        "currency": "INR",
        "status": "delivered",
        "placed_at": "2026-07-29T16:02:00Z",
        "refunded_total": 0,
    },
    "9999": {
        "order_id": "9999",
        "customer_id": "c-enterprise",
        "item": "Bulk hardware order (40 units)",
        "items": [
            {"sku": "BULK-HW-40", "name": "Bulk hardware order (40 units)", "qty": 40, "price": 6250}
        ],
        "total": 250000,
        "currency": "INR",
        "status": "delivered",
        "placed_at": "2026-08-01T09:30:00Z",
        "refunded_total": 0,
    },
}

REFUNDS: list[dict[str, Any]] = []


# ----------------------------------------------------------------------- utilities


async def merged_args(request: Request) -> dict[str, Any]:
    """Accept POST args from a JSON body, falling back to query params."""
    data: dict[str, Any] = {}
    body = await request.body()
    if body:
        try:
            parsed = await request.json()
        except Exception:  # noqa: BLE001 - malformed body is just "no body"
            parsed = None
        if isinstance(parsed, dict):
            data.update(parsed)
    for key, value in request.query_params.items():
        data.setdefault(key, value)
    return data


def _tidy_amount(value: float) -> float | int:
    return int(value) if float(value).is_integer() else float(value)


class RefundRequest(BaseModel):
    order_id: str
    amount: float
    reason: str = ""


# -------------------------------------------------------------------------- routes


@app.get("/orders")
def list_orders(customer_id: str | None = None) -> dict[str, Any]:
    """orders.list -- reaches every order in the system unless filtered."""
    orders = list(ORDERS.values())
    if customer_id:
        orders = [o for o in orders if o["customer_id"] == customer_id]
    return {"orders": orders, "count": len(orders)}


@app.get("/orders/{order_id}")
def get_order(order_id: str) -> dict[str, Any]:
    """orders.get"""
    order = ORDERS.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail=f"No such order: {order_id}")
    return order


@app.get("/refunds")
def list_refunds() -> dict[str, Any]:
    """refunds.list"""
    return {"refunds": REFUNDS, "count": len(REFUNDS)}


@app.post("/refunds")
async def create_refund(request: Request) -> dict[str, Any]:
    """refunds.create -- moves money and mutates order state.

    The 400s below are ordinary upstream sanity checks (does the order exist, is the
    amount within the order total). They are NOT scoped authority: this endpoint will
    happily refund any order it is asked about, which is exactly why the warrant check
    has to happen before the call gets here.
    """
    try:
        req = RefundRequest(**await merged_args(request))
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=exc.errors(include_url=False)) from exc

    order = ORDERS.get(req.order_id)
    if order is None:
        raise HTTPException(status_code=404, detail=f"No such order: {req.order_id}")

    if req.amount <= 0:
        raise HTTPException(status_code=400, detail="Refund amount must be positive.")

    if req.amount > order["total"]:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Refund amount {_tidy_amount(req.amount)} exceeds order total "
                f"{order['total']} for order {req.order_id}."
            ),
        )

    remaining = order["total"] - order["refunded_total"]
    if req.amount > remaining:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Refund amount {_tidy_amount(req.amount)} exceeds the refundable "
                f"remainder {_tidy_amount(remaining)} on order {req.order_id}."
            ),
        )

    amount = _tidy_amount(req.amount)
    refund = {
        "refund_id": f"rf-{len(REFUNDS) + 1:04d}",
        "order_id": req.order_id,
        "customer_id": order["customer_id"],
        "amount": amount,
        "currency": order["currency"],
        "reason": req.reason,
        "status": "completed",
        "created_at": time.time(),
    }
    REFUNDS.append(refund)

    # mutate the order in place
    order["refunded_total"] = _tidy_amount(order["refunded_total"] + req.amount)
    order["refunded"] = True
    order["status"] = (
        "refunded" if order["refunded_total"] >= order["total"] else "partially_refunded"
    )
    order.setdefault("refund_ids", []).append(refund["refund_id"])

    return {"refund": refund, "order": order}
