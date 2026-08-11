"""Helpdesk sample upstream (port base+5): IT ops for the try-it path.

Routes match examples/it_helpdesk.json. State is in-memory.
Requires Authorization: Bearer <credential> on every route.
"""

from __future__ import annotations

import os
import time
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

UPSTREAM_KEY = os.environ.get(
    "WARRANT_CREDENTIAL_HELPDESK",
    os.environ.get("UPSTREAM_KEY", "real-service-key-abc123"),
)


def require_upstream_key(authorization: str | None = Header(default=None)) -> str:
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header. Expected 'Bearer <key>'.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(
            status_code=401,
            detail="Malformed Authorization header.",
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
    title="helpdesk",
    description="Internal IT helpdesk sample upstream.",
    dependencies=[Depends(require_upstream_key)],
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

EMPLOYEES: dict[str, dict[str, Any]] = {
    "e-1042": {
        "employee_id": "e-1042",
        "name": "Ravi Menon",
        "team": "platform",
        "manager": "e-2001",
        "device": "mbp-14-m3",
        "access": ["vpn", "staging-db"],
    },
    "e-2001": {
        "employee_id": "e-2001",
        "name": "Priya Shah",
        "team": "platform",
        "manager": None,
        "device": "mbp-16-m4",
        "access": ["vpn", "prod-db", "staging-db"],
    },
}

ACCESS_GRANTS: list[dict[str, Any]] = [
    {
        "grant_id": "g-1",
        "employee_id": "e-1042",
        "system": "vpn",
        "expires_at": None,
        "reason": "standing",
    },
    {
        "grant_id": "g-2",
        "employee_id": "e-2001",
        "system": "prod-db",
        "expires_at": None,
        "reason": "on-call",
    },
]

LAPTOPS: list[dict[str, Any]] = []


@app.get("/employees/{employee_id}")
def get_employee(employee_id: str) -> dict[str, Any]:
    emp = EMPLOYEES.get(employee_id)
    if not emp:
        raise HTTPException(status_code=404, detail=f"unknown employee {employee_id}")
    return emp


@app.get("/access")
def list_access(system: str | None = None) -> dict[str, Any]:
    rows = ACCESS_GRANTS
    if system:
        rows = [g for g in rows if g["system"] == system]
    return {"grants": rows, "count": len(rows)}


class VpnGrantBody(BaseModel):
    employee_id: str
    duration_hours: float = Field(gt=0)
    reason: str = ""


@app.post("/access/vpn")
def grant_vpn(body: VpnGrantBody) -> dict[str, Any]:
    grant = {
        "grant_id": f"g-vpn-{int(time.time())}",
        "employee_id": body.employee_id,
        "system": "vpn",
        "duration_hours": body.duration_hours,
        "expires_at": time.time() + body.duration_hours * 3600,
        "reason": body.reason,
        "broadcast": body.employee_id == "all-engineering",
    }
    ACCESS_GRANTS.append(grant)
    return {"ok": True, "grant": grant}


class LaptopBody(BaseModel):
    employee_id: str
    model: str
    budget_inr: float = Field(gt=0)


@app.post("/laptops")
def provision_laptop(body: LaptopBody) -> dict[str, Any]:
    if body.employee_id not in EMPLOYEES and body.employee_id != "all-engineering":
        # still allow unknown ids for demo flexibility, but flag them
        pass
    order = {
        "order_id": f"lt-{int(time.time())}",
        "employee_id": body.employee_id,
        "model": body.model,
        "budget_inr": body.budget_inr,
        "status": "ordered",
        "placed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    LAPTOPS.append(order)
    return {"ok": True, "order": order}


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {"ok": True, "service": "helpdesk", "employees": len(EMPLOYEES)}
