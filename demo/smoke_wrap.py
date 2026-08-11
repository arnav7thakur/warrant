"""Smoke the wrap product path: sync is assumed done; mint → allow → deny.

    python -m demo.stack up --profile wrap
    python -m mcp_server.sync --config examples/wrap_mock.json
    python -m demo.smoke_wrap

No Gemini call: uses examples/grants_read_note.json. Exit 0 only if
wrap.notes_get is ALLOWED and wrap.notes_write is DENIED.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import httpx  # noqa: E402

from demo.operator import MintRefused, default_port, load_grants, mint, release  # noqa: E402

GRANTS = _ROOT / "examples" / "grants_read_note.json"
TASK = "Read note n-1 (smoke)"


def main() -> int:
    port = default_port()
    base = f"http://127.0.0.1:{port}"
    try:
        health = httpx.get(f"{base}/healthz", timeout=5.0)
        health.raise_for_status()
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL: broker not up at {base}: {exc}", file=sys.stderr)
        return 1

    ops = httpx.get(f"{base}/catalog", timeout=10.0).json().get("operation_count") or 0
    if ops < 1:
        print(
            "FAIL: catalog empty. Sync first:\n"
            "  python -m mcp_server.sync --config examples/wrap_mock.json",
            file=sys.stderr,
        )
        return 1

    try:
        release(port=port)
        body = mint(TASK, ttl=120, port=port, grants=load_grants(GRANTS))
    except MintRefused as exc:
        print(f"FAIL: mint: {exc}", file=sys.stderr)
        return 1

    token = body["token"]
    headers = {"X-Warrant": token}
    client = httpx.Client(base_url=base, timeout=30.0)

    allow = client.post(
        "/call",
        headers=headers,
        json={"op": "wrap.notes_get", "args": {"note_id": "n-1"}, "authorize_only": True},
    )
    deny = client.post(
        "/call",
        headers=headers,
        json={
            "op": "wrap.notes_write",
            "args": {"note_id": "n-1", "body": "smoke must not write"},
            "authorize_only": True,
        },
    )

    allow_ok = allow.status_code == 200 and allow.json().get("ok") is True
    deny_ok = deny.status_code == 403 and deny.json().get("ok") is False

    print(f"ALLOW wrap.notes_get  -> {allow.status_code} ok={allow.json().get('ok')}")
    print(f"DENY  wrap.notes_write -> {deny.status_code} ok={deny.json().get('ok')}")
    if allow_ok and deny_ok:
        print("smoke_wrap: PASS")
        return 0
    print("smoke_wrap: FAIL", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
