"""The agent: holds a warrant, holds no credentials.

Every action this process takes goes through the broker at 127.0.0.1:8100, which
checks the call against the warrant before attaching a real key. There is no
upstream URL anywhere in this package, and no upstream credential in its
environment -- `agent.run` asserts that at startup and refuses to run otherwise.
"""

from __future__ import annotations

import os

__all__ = ["BROKER_URL"]

# WARRANT_PORT_BASE lets several isolated stacks run side by side (parallel testing).
# Default 8100 keeps every documented command working unchanged.
BROKER_URL = f"http://127.0.0.1:{os.environ.get('WARRANT_PORT_BASE', '8100')}"
