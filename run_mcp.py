#!/usr/bin/env python3
"""Cursor-safe MCP launcher — does not rely on cwd for imports."""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from mcp_server.server import main

if __name__ == "__main__":
    main()
