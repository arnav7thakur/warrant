"""Start, stop, or reset the local stack.

    python -m demo.stack up                 # commerce trio (default)
    python -m demo.stack up --profile wrap      # broker only — sync an MCP next
    python -m demo.stack up --profile helpdesk  # HTTP manifest example
    python -m demo.stack down
    python -m demo.stack audit
    python -m demo.stack status

`up` kills the ports, wipes the broker DB, and restarts broker + upstreams.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
if not PYTHON.exists():
    PYTHON = Path(sys.executable)

PORT_BASE = int(os.environ.get("WARRANT_PORT_BASE") or 8100)
BROKER = f"http://127.0.0.1:{PORT_BASE}"
DB_PATH = os.environ.get("WARRANT_DB") or str(ROOT / f"warrant-{PORT_BASE}.db")

PROFILES = {
    "commerce": {
        "builtins": "1",
        "manifests": "",
        "ports": [PORT_BASE, PORT_BASE + 1, PORT_BASE + 2, PORT_BASE + 3],
        "checks": {
            "broker": f"{BROKER}/healthz",
            "commerce": f"http://127.0.0.1:{PORT_BASE + 1}/orders/1234",
            "support": f"http://127.0.0.1:{PORT_BASE + 2}/tickets/t-501",
            "comms": f"http://127.0.0.1:{PORT_BASE + 3}/email",
        },
        "ready_note": "commerce trio",
    },
    "wrap": {
        "builtins": "0",
        "manifests": "",
        "ports": [PORT_BASE],
        "checks": {
            "broker": f"{BROKER}/healthz",
        },
        "ready_note": "broker only (builtins off) — sync an MCP: python -m mcp_server.sync --config examples/wrap_mock.json",
    },
    "helpdesk": {
        "builtins": "0",
        "manifests": str(ROOT / "examples" / "it_helpdesk.json"),
        "ports": [PORT_BASE, PORT_BASE + 5],
        "checks": {
            "broker": f"{BROKER}/healthz",
            "helpdesk": f"http://127.0.0.1:{PORT_BASE + 5}/healthz",
        },
        "ready_note": "HTTP manifest example (builtins off)",
    },
}


def wipe_db() -> None:
    if DB_PATH == ":memory:":
        print("  WARRANT_DB=:memory: -- broker state is ephemeral, nothing to wipe")
        return
    base = Path(DB_PATH)
    removed = []
    for path in (base, Path(str(base) + "-wal"), Path(str(base) + "-shm")):
        try:
            path.unlink()
            removed.append(path.name)
        except FileNotFoundError:
            pass
        except OSError as exc:
            print(f"  COULD NOT DELETE {path}: {exc}")
            print("  the broker may still be running; `python -m demo.stack down` first")
            raise SystemExit(1) from exc
    print(
        f"  broker DB {base.name}: "
        f"{'deleted ' + ', '.join(removed) if removed else 'already absent'}"
    )


def _all_ports() -> list[int]:
    """Union of ports across profiles so `down` clears either mode."""
    ports: set[int] = {PORT_BASE}
    for profile in PROFILES.values():
        ports.update(profile["ports"])
    # also clear classic commerce offsets even if profile list drifts
    ports.update({PORT_BASE + 1, PORT_BASE + 2, PORT_BASE + 3, PORT_BASE + 5})
    return sorted(ports)


def _pids_on_ports(ports: list[int] | None = None) -> dict[int, int]:
    watch = set(ports or _all_ports())
    found: dict[int, int] = {}
    try:
        out = subprocess.run(
            ["netstat", "-ano", "-p", "TCP"], capture_output=True, text=True, timeout=15
        ).stdout
    except Exception:
        return found
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[3] != "LISTENING":
            continue
        local = parts[1]
        try:
            port = int(local.rsplit(":", 1)[1])
            pid = int(parts[4])
        except ValueError:
            continue
        if port in watch and pid:
            found.setdefault(port, pid)
    return found


def down() -> None:
    pids = _pids_on_ports()
    if not pids:
        print(f"nothing listening on stack ports near {PORT_BASE}")
        return
    for port, pid in sorted(pids.items()):
        subprocess.run(["taskkill", "/PID", str(pid), "/F", "/T"], capture_output=True)
        print(f"  killed pid {pid} (port {port})")
    time.sleep(1.5)


def up(profile_name: str = "commerce") -> int:
    if profile_name not in PROFILES:
        print(f"unknown profile {profile_name!r}; choose from {sorted(PROFILES)}")
        return 2
    profile = PROFILES[profile_name]

    down()
    wipe_db()
    flags = 0x08000000  # CREATE_NO_WINDOW
    env = {
        **os.environ,
        "WARRANT_DB": DB_PATH,
        "WARRANT_BUILTINS": profile["builtins"],
        "WARRANT_MANIFESTS": profile["manifests"],
        "WARRANT_PORT_BASE": str(PORT_BASE),
    }

    subprocess.Popen(
        [str(PYTHON), "-m", "upstream.run_all"], cwd=ROOT, env=env, creationflags=flags
    )
    subprocess.Popen(
        [
            str(PYTHON),
            "-m",
            "uvicorn",
            "broker.app:app",
            "--port",
            str(PORT_BASE),
            "--log-level",
            "warning",
        ],
        cwd=ROOT,
        env=env,
        creationflags=flags,
    )

    deadline = time.time() + 45
    headers = {"Authorization": "Bearer real-service-key-abc123"}
    pending = dict(profile["checks"])

    while pending and time.time() < deadline:
        for name, url in list(pending.items()):
            try:
                httpx.get(url, headers=headers if name != "broker" else None, timeout=2.0)
                print(f"  {name} up")
                pending.pop(name)
            except httpx.RequestError:
                pass
        if pending:
            time.sleep(1.0)

    if pending:
        print(f"\n  FAILED to start: {', '.join(pending)}")
        return 1

    health = httpx.get(f"{BROKER}/healthz", timeout=5).json()
    catalog = httpx.get(f"{BROKER}/catalog", timeout=5).json()
    project = catalog.get("project")
    print(f"\n  clean slate (base {PORT_BASE}): {profile['ready_note']}")
    print(
        f"  broker: {health['audit_entries']} audit entries, "
        f"{catalog.get('operation_count', '?')} ops, "
        f"builtins={catalog.get('builtins')}"
    )
    if project:
        print(
            f"  project: {project.get('name')} "
            f"(namespace={project.get('namespace')}, owner={project.get('owner')})"
        )
    print(f"  store: {health.get('store', DB_PATH)}")
    print(f"  UI: {BROKER}/")
    return 0


def audit() -> int:
    entries = httpx.get(f"{BROKER}/audit", timeout=5).json()["entries"]
    if not entries:
        print("audit is empty")
        return 0
    print(f"{'DECISION':9} {'OP':28} {'RESOURCE':18} REASON")
    print("-" * 110)
    for e in entries:
        print(f"{e['decision']:9} {e['op']:28} {e['resource']:18} {e['reason']}")
    allowed = sum(e["decision"] == "ALLOW" for e in entries)
    print(f"\n{allowed} allowed, {len(entries) - allowed} denied")
    return 0


def status() -> int:
    pids = _pids_on_ports()
    for port in _all_ports():
        print(f"  {port}: {'pid ' + str(pids[port]) if port in pids else 'free'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m demo.stack")
    parser.add_argument(
        "command",
        nargs="?",
        default="up",
        choices=["up", "down", "audit", "status"],
    )
    parser.add_argument(
        "--profile",
        default="commerce",
        choices=sorted(PROFILES),
        help="Stack profile for `up` (default: commerce)",
    )
    args = parser.parse_args(argv)

    if args.command == "up":
        return up(args.profile)
    if args.command == "down":
        down()
        return 0
    if args.command == "audit":
        return audit()
    if args.command == "status":
        return status()
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
