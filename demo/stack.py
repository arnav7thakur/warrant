"""Start, stop, or reset the whole stack. Use this between demo runs.

The upstreams keep their state in memory, so killing them un-refunds order 1234. The
broker does not: since `broker/store.py` it keeps the audit log, the use budgets, the
active warrant and the seal in SQLite, on purpose -- a `uses=1` warrant that a restart
made spendable again was a real bypass, and it is closed. So a restart alone is *not* a
clean slate any more; it would leave a fresh order 1234 sitting next to a warrant whose
budget is already spent, which is the worst of both.

`up` therefore deletes the broker's database before starting, and that is what makes the
slate genuinely clean: orders un-refunded, audit empty, budgets unspent, nothing sealed.
Do not try to demo twice without it.

The database lives at $WARRANT_DB if set, otherwise `warrant-<PORT_BASE>.db` beside the
repo root -- per port base, so two stacks running side by side do not share one file and
resetting one does not wipe the other. `up` passes the same path to the broker it
starts, so the file it deletes is always the file the broker will use.

    python -m demo.stack up        # fresh start (kills the ports, wipes the broker DB)
    python -m demo.stack down      # stop everything (leaves the DB on disk)
    python -m demo.stack audit     # dump the audit log
    python -m demo.stack status    # what is listening
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"

# Set WARRANT_PORT_BASE to run an isolated stack alongside others. Default 8100.
PORT_BASE = int(os.environ.get("WARRANT_PORT_BASE") or 8100)
BROKER = f"http://127.0.0.1:{PORT_BASE}"
PORTS = [PORT_BASE, PORT_BASE + 1, PORT_BASE + 2, PORT_BASE + 3]

# The broker's durable state. Per port base by default so parallel stacks get their own
# file: sharing one would mean `up` on base 8300 wiping the audit log of the stack on
# 8100, and two brokers enforcing each other's use budgets.
DB_PATH = os.environ.get("WARRANT_DB") or str(ROOT / f"warrant-{PORT_BASE}.db")


def wipe_db() -> None:
    """Delete the broker's database, WAL and shared-memory sidecars included.

    Call this only after `down()`. SQLite in WAL mode keeps `-wal` and `-shm` beside the
    main file; removing the main file alone can leave a live WAL that resurrects the very
    audit entries and spend counters we meant to clear.
    """
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
            # Almost always "still locked": a broker survived `down()`. Say so loudly --
            # continuing would start a demo on top of last run's spent budgets.
            print(f"  COULD NOT DELETE {path}: {exc}")
            print("  the broker may still be running; `python -m demo.stack down` first")
            raise SystemExit(1) from exc
    print(f"  broker DB {base.name}: {'deleted ' + ', '.join(removed) if removed else 'already absent'}")


def _pids_on_ports() -> dict[int, int]:
    """port -> pid, via netstat (no external deps, works on stock Windows)."""
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
        if port in PORTS and pid:
            found.setdefault(port, pid)
    return found


def down() -> None:
    pids = _pids_on_ports()
    if not pids:
        print(f"nothing listening on {PORTS[0]}-{PORTS[-1]}")
        return
    for port, pid in sorted(pids.items()):
        subprocess.run(["taskkill", "/PID", str(pid), "/F", "/T"], capture_output=True)
        print(f"  killed pid {pid} (port {port})")
    time.sleep(1.5)


def up() -> int:
    down()
    wipe_db()
    flags = 0x08000000  # CREATE_NO_WINDOW
    # Hand the broker the exact path we just deleted. Without this it would fall back to
    # store.py's own default and quietly use a different file from the one being reset.
    env = {**os.environ, "WARRANT_DB": DB_PATH}
    subprocess.Popen(
        [str(PYTHON), "-m", "upstream.run_all"], cwd=ROOT, env=env, creationflags=flags
    )
    subprocess.Popen(
        [str(PYTHON), "-m", "uvicorn", "broker.app:app",
         "--port", str(PORT_BASE), "--log-level", "warning"],
        cwd=ROOT, env=env, creationflags=flags,
    )

    deadline = time.time() + 45
    checks = {
        "broker": f"{BROKER}/healthz",
        "commerce": f"http://127.0.0.1:{PORT_BASE + 1}/orders/1234",
        "support": f"http://127.0.0.1:{PORT_BASE + 2}/tickets/t-501",
        "comms": f"http://127.0.0.1:{PORT_BASE + 3}/email",
    }
    headers = {"Authorization": "Bearer real-service-key-abc123"}
    pending = dict(checks)

    while pending and time.time() < deadline:
        for name, url in list(pending.items()):
            try:
                # 401/405 both prove the service is up and enforcing.
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

    order = httpx.get(
        f"http://127.0.0.1:{PORT_BASE + 1}/orders/1234", headers=headers, timeout=5
    ).json()
    health = httpx.get(f"{BROKER}/healthz", timeout=5).json()
    print(f"\n  clean slate (base {PORT_BASE}): order 1234 "
          f"status={order['status']} refunded={order['refunded_total']}")
    print(f"  broker state reset: {health['audit_entries']} audit entries, "
          f"no active warrant, every use budget unspent, nothing sealed")
    print(f"  store: {health.get('store', DB_PATH)}")
    print(f"  UI: {BROKER}/")
    return 0


def audit() -> int:
    entries = httpx.get(f"{BROKER}/audit", timeout=5).json()["entries"]
    if not entries:
        print("audit is empty")
        return 0
    print(f"{'DECISION':9} {'OP':17} {'RESOURCE':18} REASON")
    print("-" * 110)
    for e in entries:
        print(f"{e['decision']:9} {e['op']:17} {e['resource']:18} {e['reason']}")
    allowed = sum(e["decision"] == "ALLOW" for e in entries)
    print(f"\n{allowed} allowed, {len(entries) - allowed} denied")
    return 0


def status() -> int:
    pids = _pids_on_ports()
    for port in PORTS:
        print(f"  {port}: {'pid ' + str(pids[port]) if port in pids else 'free'}")
    return 0


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "up"
    if command == "up":
        raise SystemExit(up())
    if command == "down":
        down()
        raise SystemExit(0)
    if command == "audit":
        raise SystemExit(audit())
    if command == "status":
        raise SystemExit(status())
    print(__doc__)
    raise SystemExit(2)
