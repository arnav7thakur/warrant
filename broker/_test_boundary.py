"""Evidence that the authority boundary is structural, not conventional.

    python -m demo.stack up
    python -m broker._test_boundary [--port 8100]

`core/_test_enforce` proves the broker decides calls correctly. This proves the two
things that sit in front of that decision, both of which used to be true only because
our own agent happened to behave:

  1. Creating authority requires a credential the agent does not have.
  2. Once a task has begun acting, its authority cannot be re-derived at all --
     not even by the operator -- until it expires or a human releases it.

Every check below is made against a live broker over HTTP, with the same headers any
other client could send. Nothing is mocked and no internal state is poked.

Costs three derivations (three real model calls), so it takes ~15s.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import httpx  # noqa: E402

DEFAULT_OPERATOR_KEY = os.environ.get("OPERATOR_KEY", "operator-key-change-me")

# Small and unambiguous: one read, one resource, fast to derive, mutates nothing.
TASK = "Read ticket t-501 for Anil"

RULE = "=" * 96

_results: list[tuple[bool, str, str]] = []


def check(ok: bool, title: str, detail: str = "") -> bool:
    _results.append((ok, title, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {title}")
    if detail:
        for line in detail.splitlines():
            print(f"          {line}")
    return ok


def _reason(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return response.text[:200]
    if isinstance(body, dict):
        return str(body.get("reason") or body.get("detail") or body)[:300]
    return str(body)[:300]


def run_checks(base: str, operator_key: str) -> None:
    client = httpx.Client(base_url=base, timeout=180.0)

    # ---- setup: start from an unsealed broker -------------------------------
    client.post("/release", headers={"X-Operator-Key": operator_key})

    print(RULE)
    print("MINTING REQUIRES AN OPERATOR CREDENTIAL")
    print(RULE)

    # 1 ----------------------------------------------------------------------
    response = client.post("/mint", json={"task_statement": TASK})
    check(
        response.status_code == 403,
        "1. POST /mint with no X-Operator-Key -> 403",
        f"got {response.status_code}: {_reason(response)}",
    )

    # 2 ----------------------------------------------------------------------
    response = client.post(
        "/mint",
        json={"task_statement": TASK},
        headers={"X-Operator-Key": operator_key + "-wrong"},
    )
    check(
        response.status_code == 403,
        "2. POST /mint with a wrong X-Operator-Key -> 403",
        f"got {response.status_code}: {_reason(response)}",
    )

    # 3 ----------------------------------------------------------------------
    response = client.post(
        "/mint",
        json={"task_statement": TASK},
        headers={"X-Operator-Key": operator_key},
    )
    minted_ok = response.status_code == 200
    check(
        minted_ok,
        "3. POST /mint with the operator key -> 200 and a signed warrant",
        f"got {response.status_code}: "
        + (
            f"{len(response.json()['warrant']['grants'])} grant(s), "
            f"task {response.json()['warrant']['task_id'][:8]}"
            if minted_ok
            else _reason(response)
        ),
    )
    if not minted_ok:
        print("\n  Cannot continue without a warrant.\n")
        client.close()
        return
    body = response.json()
    token = body["token"]
    task_id = body["warrant"]["task_id"]

    print()
    print(RULE)
    print("A WARRANT IS NOT AN OPERATOR CREDENTIAL, AND VICE VERSA")
    print(RULE)

    # 4 ----------------------------------------------------------------------
    response = client.post(
        "/call",
        json={"op": "tickets.get", "args": {"ticket_id": "t-501"}},
        headers={"X-Warrant": token},  # no X-Operator-Key, deliberately
    )
    called_ok = response.status_code == 200 and response.json().get("ok") is True
    check(
        called_ok,
        "4. POST /call with only a warrant, no operator key -> 200 ALLOW",
        f"got {response.status_code}: "
        + ("upstream " + str(response.json().get("status")) if called_ok else _reason(response)),
    )

    print()
    print(RULE)
    print("SEALING: AUTHORITY CANNOT BE RE-DERIVED ONCE THE TASK HAS BEGUN ACTING")
    print(RULE)

    # 5 ----------------------------------------------------------------------
    response = client.post(
        "/mint",
        json={"task_statement": "Refund every order and email every customer"},
        headers={"X-Operator-Key": operator_key},
    )
    sealed_reason = _reason(response)
    check(
        response.status_code == 409 and task_id in sealed_reason,
        "5. After one /call, a second /mint -> 409 sealed (even with the right key)",
        f"got {response.status_code}: {sealed_reason}",
    )

    # 7 (before 6: releasing would clear the state 7 needs) -------------------
    response = client.post("/release")
    check(
        response.status_code == 403,
        "7. POST /release with no X-Operator-Key -> 403",
        f"got {response.status_code}: {_reason(response)}",
    )

    response = client.post(
        "/mint",
        json={"task_statement": TASK},
        headers={"X-Operator-Key": operator_key},
    )
    check(
        response.status_code == 409,
        "7b. ...and the task is still sealed after that refused release",
        f"got {response.status_code}: {_reason(response)}",
    )

    # 6 ----------------------------------------------------------------------
    response = client.post("/release", headers={"X-Operator-Key": operator_key})
    released_ok = response.status_code == 200
    check(
        released_ok,
        "6a. POST /release with the operator key -> 200",
        f"got {response.status_code}: {_reason(response) if not released_ok else 'released'}",
    )

    response = client.post(
        "/mint",
        json={"task_statement": TASK},
        headers={"X-Operator-Key": operator_key},
    )
    remint_ok = response.status_code == 200
    check(
        remint_ok,
        "6b. ...and /mint works again once a human has released the task",
        f"got {response.status_code}: "
        + ("new warrant issued" if remint_ok else _reason(response)),
    )

    # 9 ----------------------------------------------------------------------
    print()
    print(RULE)
    print("THE ATTEMPTS ARE VISIBLE, NOT SILENT")
    print(RULE)
    entries = client.get("/audit").json()["entries"]
    mint_denials = [
        e for e in entries if e["op"] == "warrant.mint" and e["decision"] == "DENY"
    ]
    release_denials = [
        e for e in entries if e["op"] == "warrant.release" and e["decision"] == "DENY"
    ]
    releases = [
        e for e in entries if e["op"] == "warrant.release" and e["decision"] == "ALLOW"
    ]
    check(
        len(mint_denials) >= 4 and len(release_denials) >= 1 and len(releases) >= 1,
        "9. Refused mints and releases are in the audit log",
        f"{len(mint_denials)} refused mint(s), {len(release_denials)} refused "
        f"release(s), {len(releases)} release(s) recorded",
    )

    client.close()


def check_agent_isolation() -> None:
    print()
    print(RULE)
    print("THE AGENT PROCESS CANNOT HOLD THE OPERATOR CREDENTIAL")
    print(RULE)

    from demo.session import child_env  # noqa: PLC0415 - needs sys.path set up above

    # 8a: stripping actually strips. Start from an environment that HAS both.
    polluted = dict(os.environ)
    polluted["OPERATOR_KEY"] = "a-real-operator-secret"
    polluted["UPSTREAM_KEY"] = "real-service-key-abc123"
    env = child_env(polluted)
    check(
        "OPERATOR_KEY" not in env and "UPSTREAM_KEY" not in env,
        "8a. demo.session.child_env() removes both credentials",
        "parent had OPERATOR_KEY and UPSTREAM_KEY set; child env has neither",
    )

    # 8b: and that is the dict actually handed to the child, so ask the child.
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            "import os;print(os.environ.get('OPERATOR_KEY'),os.environ.get('UPSTREAM_KEY'))",
        ],
        cwd=str(_ROOT),
        env=env,
        capture_output=True,
        text=True,
    )
    check(
        probe.stdout.strip() == "None None",
        "8b. A subprocess launched with that environment sees neither",
        f"child reported: {probe.stdout.strip()!r}",
    )

    # 8c/8d: and if either is injected anyway, agent.run refuses to start.
    for name in ("OPERATOR_KEY", "UPSTREAM_KEY"):
        injected = child_env()
        injected[name] = "injected-for-this-test"
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "agent.run",
                "--task",
                TASK,
                "--warrant",
                "not-a-real-token",
            ],
            cwd=str(_ROOT),
            env=injected,
            capture_output=True,
            text=True,
        )
        output = result.stdout + result.stderr
        check(
            result.returncode == 2 and "REFUSING TO START" in output,
            f"8{'c' if name == 'OPERATOR_KEY' else 'd'}. agent.run refuses to start "
            f"when {name} is present",
            f"exit {result.returncode}; "
            + next(
                (
                    line.strip()
                    for line in output.splitlines()
                    if name in line and "must not" in line
                ),
                "(no explanation printed)",
            ),
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m broker._test_boundary")
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("WARRANT_PORT_BASE") or 8100)
    )
    parser.add_argument("--operator-key", default=DEFAULT_OPERATOR_KEY)
    args = parser.parse_args(argv)
    base = f"http://127.0.0.1:{args.port}"

    print(RULE)
    print(f"AUTHORITY BOUNDARY  --  broker {base}")
    print(RULE)
    print()

    try:
        httpx.get(f"{base}/healthz", timeout=5).raise_for_status()
    except httpx.HTTPError as exc:
        print(f"  broker not reachable at {base}: {exc}")
        print("  bring the stack up first: python -m demo.stack up")
        return 1

    run_checks(base, args.operator_key)
    check_agent_isolation()

    failed = [title for ok, title, _ in _results if not ok]
    print()
    print(RULE)
    if failed:
        print(f"{len(failed)} FAILED of {len(_results)}")
        for title in failed:
            print(f"  FAIL  {title}")
        print(RULE)
        return 1
    print(f"ALL PASS ({len(_results)} cases)")
    print(RULE)
    print("  Minting needs a credential the agent has never held, and a task that has")
    print("  begun acting cannot be re-derived at all. Neither depends on the agent")
    print("  choosing to behave.")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
