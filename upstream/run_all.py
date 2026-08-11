"""Start upstream services declared in core.catalog.SERVICE_PORTS.

    python -m upstream.run_all

Only services that both appear in SERVICE_PORTS and have a known app mapping are
started — so WARRANT_BUILTINS=0 + a helpdesk manifest starts only helpdesk.
"""

from __future__ import annotations

import multiprocessing as mp
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.catalog import SERVICE_PORTS  # noqa: E402

APPS = {
    "commerce": "upstream.commerce:app",
    "support": "upstream.support:app",
    "comms": "upstream.comms:app",
    "helpdesk": "upstream.helpdesk:app",
}


def _serve(import_string: str, port: int, repo_root: str) -> None:
    """Child-process entry point. Must be importable at module top level for spawn."""
    import os

    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    os.chdir(repo_root)

    import uvicorn

    uvicorn.run(import_string, host="127.0.0.1", port=port, log_level="info")


def main() -> int:
    ctx = mp.get_context("spawn")
    procs: list[tuple[str, mp.process.BaseProcess]] = []

    to_start = [
        (service, APPS[service], SERVICE_PORTS[service])
        for service in SERVICE_PORTS
        if service in APPS
    ]
    if not to_start:
        print(
            "[run_all] no known upstreams in SERVICE_PORTS. "
            "Set WARRANT_BUILTINS=1 or load a manifest that declares a mapped service.",
            flush=True,
        )
        return 1

    for service, import_string, port in to_start:
        proc = ctx.Process(
            target=_serve,
            args=(import_string, port, str(REPO_ROOT)),
            name=f"upstream-{service}",
            daemon=False,
        )
        proc.start()
        procs.append((service, proc))
        print(
            f"[run_all] {service:9s} -> http://127.0.0.1:{port}  (pid {proc.pid})",
            flush=True,
        )

    print(f"[run_all] {len(procs)} upstream(s) starting. Ctrl-C to stop.", flush=True)

    try:
        while True:
            for service, proc in procs:
                if not proc.is_alive():
                    print(
                        f"[run_all] {service} exited with code {proc.exitcode}; "
                        "shutting the rest down.",
                        flush=True,
                    )
                    raise SystemExit(proc.exitcode or 1)
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[run_all] stopping...", flush=True)
    finally:
        for service, proc in procs:
            if proc.is_alive():
                proc.terminate()
        for service, proc in procs:
            proc.join(timeout=5)
            if proc.is_alive():
                proc.kill()
            print(f"[run_all] {service} stopped.", flush=True)

    return 0


if __name__ == "__main__":
    mp.freeze_support()
    raise SystemExit(main())
