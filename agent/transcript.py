"""Plain-text transcript printing. This is projected on a screen.

No ANSI colour -- venue projectors and Windows terminals disagree about it.
Loudness comes from characters, not escape codes.
"""

from __future__ import annotations

import json
import shutil
import sys
import textwrap
import time
from typing import Any

from core.models import Warrant

# The demo prints currency symbols and the odd em dash. Windows consoles default
# to cp1252 and would raise UnicodeEncodeError mid-transcript.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except Exception:  # pragma: no cover - older/unusual streams
        pass

WIDTH = min(88, max(72, shutil.get_terminal_size((88, 25)).columns))
MAX_VALUE_CHARS = 400


def _line(char: str) -> str:
    return char * WIDTH


def blank() -> None:
    print()


def banner(title: str) -> None:
    print()
    print(_line("="))
    print(f"  {title}")
    print(_line("="))


def section(title: str) -> None:
    print()
    print(_line("-"))
    print(title)
    print(_line("-"))


def kv(key: str, value: Any, width: int = 12) -> None:
    print(f"  {key.ljust(width)}: {value}")


def note(text: str) -> None:
    for line in textwrap.wrap(text, width=WIDTH - 2) or [""]:
        print(f"  {line}")


def paragraph(text: str, indent: str = "  ") -> None:
    for raw_line in text.strip().splitlines():
        if not raw_line.strip():
            print()
            continue
        for line in textwrap.wrap(raw_line, width=WIDTH - len(indent)):
            print(f"{indent}{line}")


def _shorten(value: Any) -> Any:
    if isinstance(value, str) and len(value) > MAX_VALUE_CHARS:
        return value[:MAX_VALUE_CHARS] + f"... [+{len(value) - MAX_VALUE_CHARS} chars]"
    if isinstance(value, dict):
        return {k: _shorten(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_shorten(v) for v in value]
    return value


def pretty_json(value: Any, indent: str = "     ") -> None:
    text = json.dumps(_shorten(value), indent=2, ensure_ascii=False, default=str)
    for line in text.splitlines():
        print(f"{indent}{line}")


# -- specific blocks -------------------------------------------------------


def credential_check(present: bool) -> None:
    if present:
        print(
            "credential check: UPSTREAM_KEY IS SET -- refusing to start. "
            "This process must hold no upstream credential."
        )
    else:
        print(
            "credential check: UPSTREAM_KEY=None "
            "(this process cannot reach upstream directly)"
        )


def operator_check(present: bool) -> None:
    if present:
        print(
            "operator check  : OPERATOR_KEY IS SET -- refusing to start. "
            "This process must not be able to mint its own authority."
        )
    else:
        print(
            "operator check  : OPERATOR_KEY=None "
            "(this process cannot mint or widen a warrant)"
        )


def combined_process_warning() -> None:
    """Printed when the agent mints for itself. It should be uncomfortable to read."""
    print()
    print(_line("!"))
    print("  !!  NO --warrant SUPPLIED: MINTING IN-PROCESS")
    print("  !!")
    print("  !!  This process is about to act as BOTH operator and agent. That is a")
    print("  !!  single-terminal convenience, not the deployment shape, and it")
    print("  !!  weakens the claim this project makes: an agent that can mint can")
    print("  !!  answer a denial by minting past it.")
    print("  !!")
    print("  !!  It works here only because the broker is running with its built-in")
    print("  !!  development operator key. Against a broker with a real one, this")
    print("  !!  mint returns 403 -- correctly.")
    print("  !!")
    print("  !!  Use:  python -m demo.session --task ...")
    print("  !!  or :  python -m demo.operator --task ... --quiet   ->  --warrant")
    print(_line("!"))


def warrant_block(warrant: Warrant, token: str, derivation_ms: int) -> None:
    section("MINTED WARRANT  (this is everything the agent holds)")
    remaining = max(0.0, warrant.expires_at - time.time())
    expires_at = time.strftime("%H:%M:%S", time.localtime(warrant.expires_at))

    kv("warrant", warrant.warrant_id)
    kv("principal", warrant.principal)
    kv("agent", warrant.agent)
    kv("task", warrant.task_statement)
    kv("expires", f"{expires_at} (in {remaining:.0f}s)")
    kv("signature", (warrant.signature[:24] + "...") if warrant.signature else "(none)")
    kv("token", f"{token[:16]}... ({len(token)} chars)")
    kv(
        "derived in",
        f"{derivation_ms} ms" if derivation_ms else "(minted by the operator process)",
    )

    print()
    print(f"  grants ({len(warrant.grants)}):")
    if not warrant.grants:
        print("    (none -- this agent can do nothing at all)")
    for index, grant in enumerate(warrant.grants, start=1):
        wildcard = " [WILDCARD]" if grant.resource.endswith(":*") or grant.resource == "*" else ""
        print(f"    [{index}] {grant.op}  on  {grant.resource}{wildcard}")
        constraints = _format_constraints(grant.constraints)
        print(f"        constraints: {constraints}")
        print(f"        uses       : {grant.uses}")
        if grant.justification:
            wrapped = textwrap.wrap(grant.justification, width=WIDTH - 22) or [""]
            print(f"        why        : {wrapped[0]}")
            for line in wrapped[1:]:
                print(f"                     {line}")
    print()
    note(
        "Everything not listed above is refused by the broker, whatever this "
        "agent decides to attempt."
    )


def _format_constraints(constraints: dict[str, Any]) -> str:
    if not constraints:
        return "none"
    parts = []
    for arg, constraint in constraints.items():
        bits = []
        for field_name in ("lte", "gte", "eq", "one_of"):
            value = getattr(constraint, field_name, None)
            if value is not None:
                bits.append(f"{field_name}={value}")
        parts.append(f"{arg} {' '.join(bits) if bits else '(unbounded)'}")
    return "; ".join(parts)


def turn_header(index: int) -> None:
    print()
    print(_line("="))
    print(f"TURN {index}")
    print(_line("="))


def model_thinking(text: str) -> None:
    print()
    print("  [model thinking]")
    paragraph(text, indent="    ")


def model_text(text: str) -> None:
    print()
    print("  [model]")
    paragraph(text, indent="    ")


def tool_call(op: str, args: dict[str, Any]) -> None:
    print()
    print(f"  >> TOOL CALL   {op}   -->  POST /call (X-Warrant)")
    if args:
        print("     args:")
        pretty_json(args, indent="       ")
    else:
        print("     args: {}")


def tool_allowed(outcome_status: int | None, data: Any) -> None:
    status = f"upstream {outcome_status}" if outcome_status is not None else "ok"
    print(f"  << ALLOWED     ({status}) -- broker attached the real key and forwarded")
    pretty_json(data, indent="       ")


def tool_denied(op: str, resource: str, reason: str) -> None:
    print()
    print("  " + _line("*")[: WIDTH - 2])
    print("  ***  DENIED BY THE BROKER   (HTTP 403)")
    print("  ***")
    print(f"  ***  op       : {op}")
    print(f"  ***  resource : {resource or '(unspecified)'}")
    label = "  ***  reason   : "
    wrapped = textwrap.wrap(reason or "(no reason given)", width=WIDTH - len(label) - 2)
    if not wrapped:
        wrapped = ["(no reason given)"]
    print(f"{label}{wrapped[0]}")
    for line in wrapped[1:]:
        print(f"  ***             {line}")
    print("  ***")
    print("  ***  No credential was attached. Nothing reached upstream.")
    print("  " + _line("*")[: WIDTH - 2])
    print()
    print("  (feeding that reason back to the model verbatim; not retrying)")


def tool_error(status_code: int, detail: str) -> None:
    print()
    print(f"  << BROKER ERROR  (HTTP {status_code})")
    paragraph(detail, indent="     ")


def final(text: str) -> None:
    print()
    print(_line("="))
    print("AGENT'S FINAL ANSWER")
    print(_line("="))
    paragraph(text or "(no closing text)", indent="  ")
    print()


def summary(turns: int, allowed: int, denied: int) -> None:
    print(_line("-"))
    print(
        f"  {turns} turn(s), {allowed} call(s) allowed, {denied} DENIED by the broker."
    )
    print(_line("-"))
    print()
