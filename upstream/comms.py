"""Comms upstream (port 8103): outbound email.

Route is exactly the `Operation.path` declared in core/catalog.py for service="comms".
State is in-memory; sent messages are recorded in STATE["sent"].

customer_id="all" broadcasts to the whole customer base and reports the recipient count.
There is no recall. Nothing here stops it -- only the warrant does.

Every route requires `Authorization: Bearer <UPSTREAM_KEY>`.
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
    title="comms",
    description="Outbound email.",
    dependencies=[Depends(require_upstream_key)],
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# --------------------------------------------------------------------------- state

# The known named recipients. The mailing list is much larger than this -- these three
# are simply the ones the rest of the demo talks about.
DIRECTORY: dict[str, dict[str, str]] = {
    "c-anil": {"name": "Anil Kumar", "email": "anil@example.com"},
    "c-priya": {"name": "Priya Nair", "email": "priya@example.com"},
    "c-enterprise": {
        "name": "Meridian Logistics Pvt Ltd",
        "email": "ops@meridianlogistics.example.com",
    },
}

STATE: dict[str, Any] = {
    # Size of the full mailing list. This is what "all" reaches.
    "total_customers": 2437,
    "sent": [],  # every message this process has sent, newest last
}


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


class EmailRequest(BaseModel):
    customer_id: str
    subject: str = ""
    body: str = ""


# -------------------------------------------------------------------------- routes


@app.post("/email")
async def send_email(request: Request) -> dict[str, Any]:
    """email.send -- customer_id='all' broadcasts to the entire customer base."""
    try:
        req = EmailRequest(**await merged_args(request))
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=exc.errors(include_url=False)) from exc

    broadcast = req.customer_id == "all"

    if broadcast:
        recipients = STATE["total_customers"]
        to = "all customers (full mailing list)"
    else:
        contact = DIRECTORY.get(req.customer_id)
        if contact is None:
            raise HTTPException(
                status_code=404, detail=f"No such customer: {req.customer_id}"
            )
        recipients = 1
        to = contact["email"]

    message = {
        "message_id": f"msg-{len(STATE['sent']) + 1:04d}",
        "customer_id": req.customer_id,
        "to": to,
        "subject": req.subject,
        "body": req.body,
        "broadcast": broadcast,
        "recipients": recipients,
        "status": "sent",
        "sent_at": time.time(),
    }
    STATE["sent"].append(message)

    return {
        "message_id": message["message_id"],
        "status": "sent",
        "broadcast": broadcast,
        "recipients": recipients,
        "total_customers": STATE["total_customers"],
        "to": to,
        "subject": req.subject,
        "recallable": False,
        "detail": (
            f"Broadcast delivered to {recipients} customers. This cannot be recalled."
            if broadcast
            else f"Delivered to {to}."
        ),
        "messages_sent_this_session": len(STATE["sent"]),
    }
