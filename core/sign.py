"""Warrant signing.

HMAC-SHA256 for the prototype. Production wants Ed25519 with the broker holding the
only private key, so warrants are verifiable by anything and forgeable by nothing --
but that is a key-management change, not an architecture change.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os

from .models import Warrant

_SECRET = os.environ.get("WARRANT_SIGNING_KEY", "dev-signing-key-not-for-prod").encode()


def _digest(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(
        hmac.new(_SECRET, canonical, hashlib.sha256).digest()
    ).decode()


def sign(warrant: Warrant) -> Warrant:
    warrant.signature = _digest(warrant.signing_payload())
    return warrant


def verify(warrant: Warrant) -> bool:
    if not warrant.signature:
        return False
    return hmac.compare_digest(warrant.signature, _digest(warrant.signing_payload()))


def encode(warrant: Warrant) -> str:
    """Warrant as an opaque bearer string, for the X-Warrant header."""
    raw = json.dumps(warrant.model_dump(mode="json"), separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode()


def decode(token: str) -> Warrant:
    raw = base64.urlsafe_b64decode(token.encode())
    return Warrant.model_validate(json.loads(raw))
