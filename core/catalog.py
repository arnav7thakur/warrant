"""The operation registry: single source of truth for what exists and what it touches.

Every component reads this. The derivation step sees `describe_for_model()`, the broker
uses `resource_of()` to decide what a call is actually reaching for, and the upstream
services implement the routes.

The built-in operations are still declared inline below, but `CATALOG` is now a registry
rather than a literal: a third party can add operations at runtime with `register()`, or
from a JSON file with `load_manifest()`, without editing this module. That is the whole
point -- "declare your operations and inherit derivation, enforcement and audit" is only
true if declaring does not mean patching our source.

Two invariants make that safe for the code that already imports us:

  * `CATALOG`, `SERVICE_PORTS` and `SERVICE_BASE` are mutated in place, never rebound.
    `from core.catalog import CATALOG` in enforce.py, derive.py, tools.py and the broker
    binds the same dict object, so a late registration is visible everywhere at once.
  * Every declaration -- built-in or third-party -- goes through the same validator.
    A declaration that could never be authorized, or that would fail confusingly at call
    time, is refused at registration with a message that says which rule and why.
"""

from __future__ import annotations

import difflib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class CatalogError(ValueError):
    """A declaration was refused. The message names the rule and how to satisfy it."""


class Operation(BaseModel):
    # extra="forbid": a misspelled field is a silently wrong declaration -- `resourse_type`
    # would leave the op unscoped, which is exactly the failure mode this file exists to
    # prevent. Refuse it at registration instead.
    model_config = ConfigDict(extra="forbid")

    op: str
    method: str
    path: str  # upstream path template, e.g. "/orders/{order_id}"
    service: str  # which upstream owns it
    mutating: bool
    resource_type: str | None  # "order", "customer", None for unscoped ops
    resource_param: str | None  # which arg carries the resource id
    args: dict[str, str] = Field(default_factory=dict)  # arg -> human description
    constrainable: list[str] = Field(default_factory=list)  # args worth bounding
    broadcast_values: list[str] = Field(default_factory=list)  # values that fan out
    description: str = ""

    def resource_of(self, args: dict[str, Any]) -> str:
        """The resource identity this specific call reaches for.

        Broadcast values get their own namespace rather than living in the resource
        type's. "email every customer" is not a bigger version of "email one customer";
        it is a different act, and a grant over customers must not silently cover it.
        Without this, a widened grant of customer:* would prefix-match customer:all.
        """
        if self.resource_type is None or self.resource_param is None:
            return "*"
        value = args.get(self.resource_param)
        if value is None:
            return f"{self.resource_type}:<missing>"
        if str(value) in self.broadcast_values:
            return f"broadcast:{value}"
        return f"{self.resource_type}:{value}"

    def upstream_path(self, args: dict[str, Any]) -> str:
        path = self.path
        for key, value in args.items():
            path = path.replace("{" + key + "}", str(value))
        return path


# --------------------------------------------------------------------------------------
# Services
#
# WARRANT_PORT_BASE shifts the whole stack so several can run side by side without
# colliding. Broker sits on the base; upstreams on the next three. Default 8100.
# --------------------------------------------------------------------------------------

PORT_BASE = int(os.environ.get("WARRANT_PORT_BASE") or 8100)

_BUILTIN_SERVICE_PORTS: dict[str, int] = {
    "commerce": PORT_BASE + 1,
    "support": PORT_BASE + 2,
    "comms": PORT_BASE + 3,
}
_BUILTIN_SERVICE_BASE: dict[str, str] = {
    name: f"http://127.0.0.1:{port}" for name, port in _BUILTIN_SERVICE_PORTS.items()
}

# Live service maps. Populated with the commerce trio only when builtins are on;
# adopter manifests declare their own services when WARRANT_BUILTINS=0.
SERVICE_PORTS: dict[str, int] = {}
SERVICE_BASE: dict[str, str] = {}

# Per-service upstream credentials. Looked up by the broker on forward.
# Env WARRANT_CREDENTIAL_<SERVICE> (service uppercased, hyphens -> underscores)
# wins; otherwise UPSTREAM_KEY is the shared fallback so existing demos keep working.
SERVICE_CREDENTIALS: dict[str, str] = {}

# Project metadata from loaded manifests (name, namespace, owner, …). UI reads this.
PROJECTS: list[dict[str, Any]] = []


def builtins_enabled() -> bool:
    """Whether the shipped commerce/support/comms catalog is installed at import."""
    raw = os.environ.get("WARRANT_BUILTINS", "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


def credential_for(service: str) -> str:
    """The bearer token the broker attaches when forwarding to `service`."""
    if service in SERVICE_CREDENTIALS:
        return SERVICE_CREDENTIALS[service]
    env_key = "WARRANT_CREDENTIAL_" + service.upper().replace("-", "_")
    from_env = os.environ.get(env_key)
    if from_env:
        return from_env
    return os.environ.get("UPSTREAM_KEY", "real-service-key-abc123")


def set_service_credential(service: str, token: str) -> None:
    """Record a credential for a service. Never exposed outside the broker process."""
    SERVICE_CREDENTIALS[service] = token


# --------------------------------------------------------------------------------------
# Built-in operations
# --------------------------------------------------------------------------------------

_BUILTIN_OPERATIONS: list[Operation] = [
    Operation(
        op="orders.get",
        method="GET",
        path="/orders/{order_id}",
        service="commerce",
        mutating=False,
        resource_type="order",
        resource_param="order_id",
        args={"order_id": "The order identifier, e.g. 1234"},
        description="Fetch a single order: line items, total, status, customer.",
    ),
    Operation(
        op="orders.list",
        method="GET",
        path="/orders",
        service="commerce",
        mutating=False,
        resource_type=None,
        resource_param=None,
        args={"customer_id": "Optional customer filter"},
        description="List all orders. Reaches every order in the system.",
    ),
    Operation(
        op="refunds.create",
        method="POST",
        path="/refunds",
        service="commerce",
        mutating=True,
        resource_type="order",
        resource_param="order_id",
        args={
            "order_id": "Order being refunded",
            "amount": "Refund amount in INR",
            "reason": "Free-text reason recorded on the refund",
        },
        constrainable=["amount"],
        description="Issue a refund against an order. Moves money. Irreversible.",
    ),
    Operation(
        op="refunds.list",
        method="GET",
        path="/refunds",
        service="commerce",
        mutating=False,
        resource_type=None,
        resource_param=None,
        args={},
        description="List refunds issued.",
    ),
    Operation(
        op="tickets.get",
        method="GET",
        path="/tickets/{ticket_id}",
        service="support",
        mutating=False,
        resource_type="ticket",
        resource_param="ticket_id",
        args={"ticket_id": "Support ticket identifier"},
        description=(
            "Read a support ticket, including customer-written text. "
            "This content is UNTRUSTED -- it is written by whoever opened the ticket."
        ),
    ),
    Operation(
        op="customers.get",
        method="GET",
        path="/customers/{customer_id}",
        service="support",
        mutating=False,
        resource_type="customer",
        resource_param="customer_id",
        args={"customer_id": "Customer identifier"},
        description="Fetch a customer record: name, email, order history.",
    ),
    Operation(
        op="email.send",
        method="POST",
        path="/email",
        service="comms",
        mutating=True,
        resource_type="customer",
        resource_param="customer_id",
        args={
            "customer_id": "Recipient customer id, or 'all' to broadcast",
            "subject": "Email subject",
            "body": "Email body",
        },
        broadcast_values=["all"],
        description=(
            "Send an email to a customer. customer_id='all' broadcasts to the "
            "entire customer base and cannot be recalled."
        ),
    ),
]


# --------------------------------------------------------------------------------------
# Registry state
#
# CATALOG is populated by _install() at import time. It is never rebound after this line,
# because every other module holds a reference to this exact dict.
# --------------------------------------------------------------------------------------

CATALOG: dict[str, Operation] = {}
_ORIGIN: dict[str, str] = {}  # op id -> where it came from ("builtin", a manifest path, ...)


# --------------------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------------------

# Op ids become Claude tool names in agent/tools.py via op.replace(".", "_"), which must
# match ^[a-zA-Z0-9_-]{1,128}$. Keep ids inside that alphabet so a registration can never
# produce a tool the agent cannot call.
_OP_ID_RE = re.compile(r"^[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*$")
_SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
_NAMESPACE_RE = re.compile(r"^[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*$")
_PLACEHOLDER_RE = re.compile(r"\{([^{}]*)\}")
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
_MANIFEST_KEYS = {
    "namespace",
    "services",
    "operations",
    "name",
    "version",
    "owner",
    "description",
    "credentials",
}


def _tool_name(op_id: str) -> str:
    """Mirrors agent.tools.tool_name_for. Duplicated so core stays free of agent imports."""
    return op_id.replace(".", "_")


def _suggest(name: str, options: Iterable[str]) -> str:
    close = difflib.get_close_matches(name, list(options), n=1, cutoff=0.6)
    return f" Did you mean {close[0]!r}?" if close else ""


def _explain_validation(op_id: str, exc: ValidationError) -> str:
    """Turn a pydantic ValidationError into something a catalog author can act on."""
    lines = [f"operation {op_id!r} is not a valid declaration:"]
    known = sorted(Operation.model_fields)
    for err in exc.errors():
        field = ".".join(str(part) for part in err["loc"]) or "<root>"
        if err["type"] == "extra_forbidden":
            lines.append(
                f"  - unknown field {field!r}.{_suggest(field, known)} "
                f"Known fields: {known}."
            )
        elif err["type"] == "missing":
            lines.append(f"  - required field {field!r} is missing.")
        else:
            lines.append(f"  - field {field!r}: {err['msg']}.")
    return "\n".join(lines)


def _check_semantics(op: Operation, taken: Mapping[str, str], services: set[str]) -> None:
    """Every rule that pydantic cannot express. Raises CatalogError, never returns False."""
    op_id = op.op

    if not _OP_ID_RE.match(op_id) or len(op_id) > 128:
        raise CatalogError(
            f"invalid operation id {op_id!r}: ids must be dotted alphanumeric segments "
            "(e.g. 'helpdesk.vpn.grant'), at most 128 characters. They are turned into "
            "agent tool names by replacing '.' with '_', which only permits [A-Za-z0-9_-]."
        )

    if op_id in taken:
        raise CatalogError(
            f"duplicate operation id {op_id!r}: already registered by {taken[op_id]}. "
            "Two operations cannot share an id -- a grant names an op, so a collision "
            "would make the same warrant authorize two different upstream calls. "
            "Register under a namespace to keep the ids apart."
        )

    # op.replace('.', '_') must stay injective, or two ops collapse to one agent tool.
    my_tool = _tool_name(op_id)
    for other, origin in taken.items():
        if _tool_name(other) == my_tool:
            raise CatalogError(
                f"operation id {op_id!r} collides with {other!r} (from {origin}) once "
                f"dots become underscores: both render as the agent tool {my_tool!r}. "
                "Avoid mixing '.' and '_' at the same position in op ids."
            )

    if op.method.upper() not in _METHODS:
        raise CatalogError(
            f"operation {op_id!r}: method {op.method!r} is not one of {sorted(_METHODS)}."
        )

    if not op.path.startswith("/"):
        raise CatalogError(
            f"operation {op_id!r}: path {op.path!r} must be an absolute upstream path "
            "starting with '/', e.g. '/employees/{employee_id}'."
        )

    placeholders = [p for p in _PLACEHOLDER_RE.findall(op.path)]
    for placeholder in placeholders:
        if placeholder not in op.args:
            raise CatalogError(
                f"operation {op_id!r}: path {op.path!r} interpolates {{{placeholder}}} "
                f"but {placeholder!r} is not one of its args {sorted(op.args)}."
                f"{_suggest(placeholder, op.args)} "
                "The broker fills path templates from the call args; an unfilled "
                "placeholder would be forwarded upstream literally."
            )

    if op.service not in services:
        raise CatalogError(
            f"operation {op_id!r}: unknown service {op.service!r}. Known services are "
            f"{sorted(services)}. Declare its base URL in the manifest's \"services\" "
            "map (or pass services= to register()) -- the broker resolves "
            "SERVICE_BASE[op.service] when forwarding, and would fail with a KeyError "
            "at call time instead of here."
        )

    # --- resource scoping -------------------------------------------------------------
    if (op.resource_type is None) != (op.resource_param is None):
        present, missing = (
            ("resource_type", "resource_param")
            if op.resource_param is None
            else ("resource_param", "resource_type")
        )
        raise CatalogError(
            f"operation {op_id!r}: {present} is set but {missing} is not. "
            "resource_of() needs both -- a type to name the resource and a param to read "
            "its id from the call args -- or neither (an unscoped, read-only operation)."
        )

    if op.resource_param is not None and op.resource_param not in op.args:
        raise CatalogError(
            f"operation {op_id!r}: resource_param {op.resource_param!r} is not one of its "
            f"args {sorted(op.args)}.{_suggest(op.resource_param, op.args)} "
            "resource_of() reads the resource id out of the call args, so the param must "
            "be an argument the caller actually sends; otherwise every call would report "
            f"'{op.resource_type}:<missing>' and match no grant."
        )

    if op.mutating and op.resource_type is None:
        raise CatalogError(
            f"operation {op_id!r} is declared mutating=True with resource_type=None, "
            "which is an operation that no warrant could ever authorize.\n"
            "  Why: resource_of() returns '*' for an unscoped operation, and "
            "core/enforce.py refuses '*' and '<type>:*' on any mutating op -- a wildcard "
            "never authorizes a mutation. Every call to this op would be denied with "
            "'wildcards never authorize mutations', which reads like an enforcement bug "
            "rather than a declaration error.\n"
            "  Fix: give it a resource_type and a resource_param naming the arg that "
            "carries the id it changes (so grants can be scoped to one of them), or "
            "declare mutating=False if it does not change state."
        )

    if op.broadcast_values and op.resource_param is None:
        raise CatalogError(
            f"operation {op_id!r}: broadcast_values {op.broadcast_values} are meaningless "
            "without a resource_param -- they are matched against the value of that arg."
        )

    # --- constrainable ----------------------------------------------------------------
    seen_constrainable: set[str] = set()
    for arg in op.constrainable:
        if arg not in op.args:
            raise CatalogError(
                f"operation {op_id!r}: constrainable lists {arg!r}, which is not one of "
                f"its args {sorted(op.args)}.{_suggest(arg, op.args)} "
                "Constraints are checked against call args by name; a constraint on an "
                "argument that does not exist can never be evaluated, so declaring it "
                "would advertise a bound the broker cannot enforce."
            )
        if arg in seen_constrainable:
            raise CatalogError(
                f"operation {op_id!r}: {arg!r} listed twice in constrainable."
            )
        seen_constrainable.add(arg)


def _normalise_services(
    services: Mapping[str, Any] | None, where: str
) -> dict[str, tuple[int | None, str]]:
    """Resolve a manifest's service map to {name: (port_or_None, base_url)}.

    A value may be an int (a port offset from WARRANT_PORT_BASE, keeping a registered
    service inside the same side-by-side-stack scheme as the built-ins) or a full base URL.
    """
    resolved: dict[str, tuple[int | None, str]] = {}
    for name, value in (services or {}).items():
        if not isinstance(name, str) or not _SERVICE_RE.match(name):
            raise CatalogError(f"{where}: invalid service name {name!r}.")
        if isinstance(value, bool) or value is None:
            raise CatalogError(
                f"{where}: service {name!r} must map to a base URL string or an integer "
                f"port offset from WARRANT_PORT_BASE, got {value!r}."
            )
        if isinstance(value, int):
            port = PORT_BASE + value
            resolved[name] = (port, f"http://127.0.0.1:{port}")
        elif isinstance(value, str) and value.startswith(("http://", "https://")):
            resolved[name] = (None, value.rstrip("/"))
        else:
            raise CatalogError(
                f"{where}: service {name!r} must map to an http(s) base URL or an integer "
                f"port offset from WARRANT_PORT_BASE, got {value!r}."
            )

        # Re-pointing an existing service is refused. The broker attaches the real
        # upstream credential when it forwards; letting a registration move `commerce`
        # to another host would hand that credential to whoever registered.
        existing = SERVICE_BASE.get(name)
        if existing is not None and existing != resolved[name][1]:
            raise CatalogError(
                f"{where}: service {name!r} is already registered at {existing} and "
                f"cannot be repointed to {resolved[name][1]}. The broker sends the "
                "upstream credential to this address; redefining an existing service "
                "would redirect it. Use a different service name."
            )
    return resolved


# --------------------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------------------


def _build_operation(raw: Any, namespace: str | None, where: str) -> Operation:
    if isinstance(raw, Operation):
        data = raw.model_dump()
    elif isinstance(raw, Mapping):
        data = dict(raw)
    else:
        raise CatalogError(
            f"{where}: expected an operation object, got {type(raw).__name__}."
        )

    op_id = data.get("op")
    if not isinstance(op_id, str) or not op_id.strip():
        raise CatalogError(f"{where}: operation is missing a string 'op' id.")
    op_id = op_id.strip()

    if namespace:
        if op_id == namespace or op_id.startswith(namespace + "."):
            raise CatalogError(
                f"{where}: operation id {op_id!r} already carries the namespace "
                f"{namespace!r}. Declare ids bare (e.g. 'vpn.grant'); the namespace is "
                f"prefixed on load, which would otherwise give "
                f"{namespace + '.' + op_id!r}."
            )
        data["op"] = f"{namespace}.{op_id}"

    try:
        return Operation(**data)
    except ValidationError as exc:
        raise CatalogError(_explain_validation(data["op"], exc)) from None


def register(
    operations: Iterable[Any],
    *,
    namespace: str | None = None,
    services: Mapping[str, Any] | None = None,
    source: str = "runtime",
    project: Mapping[str, Any] | None = None,
    credentials: Mapping[str, str] | None = None,
) -> list[str]:
    """Add operations to the live catalog. All-or-nothing.

    `operations` is an iterable of dicts (or Operation instances). `namespace`, if given,
    is prefixed onto every op id so two teams can register without colliding. `services`
    declares base URLs for any upstream this batch introduces.

    `credentials` optionally maps service name -> bearer token for broker forwarding.
    Prefer env `WARRANT_CREDENTIAL_<SERVICE>` in production; this field is for local
    try-it manifests only and must never be committed with real secrets.

    Nothing is installed unless every operation validates -- a half-loaded manifest is
    worse than a rejected one, because the missing half is invisible.

    Returns the ids that were registered.
    """
    if namespace is not None:
        namespace = namespace.strip()
        if not namespace or not _NAMESPACE_RE.match(namespace):
            raise CatalogError(
                f"invalid namespace {namespace!r}: use dotted alphanumeric segments, "
                "e.g. 'helpdesk' or 'acme.billing'."
            )

    where = f"{source}" if namespace is None else f"{source} (namespace {namespace!r})"
    pending_services = _normalise_services(services, where)

    if credentials is not None:
        if not isinstance(credentials, Mapping):
            raise CatalogError(f"{where}: 'credentials' must be an object of service -> token.")
        for svc, token in credentials.items():
            if not isinstance(svc, str) or not isinstance(token, str) or not token.strip():
                raise CatalogError(
                    f"{where}: credentials[{svc!r}] must be a non-empty string bearer token."
                )
            if svc not in pending_services and svc not in SERVICE_BASE:
                raise CatalogError(
                    f"{where}: credentials reference unknown service {svc!r}. "
                    "Declare it under 'services' first."
                )

    known_services = set(SERVICE_BASE) | set(pending_services)
    taken: dict[str, str] = dict(_ORIGIN)
    built: list[Operation] = []

    for raw in operations:
        op = _build_operation(raw, namespace, where)
        _check_semantics(op, taken, known_services)
        taken[op.op] = where  # collisions inside one batch are caught too
        built.append(op)

    if not built and not pending_services:
        raise CatalogError(f"{where}: no operations to register.")

    # Commit. Mutate in place -- other modules hold these exact dict objects.
    for name, (port, base) in pending_services.items():
        if port is not None:
            SERVICE_PORTS[name] = port
        SERVICE_BASE[name] = base
    if credentials:
        for name, token in credentials.items():
            SERVICE_CREDENTIALS[name] = token.strip()
    for op in built:
        CATALOG[op.op] = op
        _ORIGIN[op.op] = where

    if project or namespace:
        meta = {
            "name": (project or {}).get("name") or namespace or "untitled",
            "namespace": namespace,
            "owner": (project or {}).get("owner"),
            "version": (project or {}).get("version"),
            "description": (project or {}).get("description"),
            "source": source,
            "operations": [op.op for op in built],
        }
        # Replace an existing entry for the same namespace so re-register refreshes meta.
        PROJECTS[:] = [p for p in PROJECTS if p.get("namespace") != namespace]
        PROJECTS.append(meta)

    return [op.op for op in built]


def load_manifest(path: str | Path, *, namespace: str | None = None) -> list[str]:
    """Register the operations declared in a JSON manifest.

    This is the onboarding path: a team ships a file, the broker loads it, and their
    operations inherit derivation, enforcement and audit without a line of our code
    changing. Manifest shape:

        {
          "namespace": "helpdesk",                        // optional, prefixes every id
          "services":  {"helpdesk": 5},                    // port offset, or a base URL
          "operations": [ { ...Operation fields, bare id... } ]
        }

    A bare JSON list of operations is also accepted. `namespace=` overrides the
    manifest's own namespace, which is how the same file can be loaded twice under
    different prefixes.
    """
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CatalogError(f"cannot read manifest {path}: {exc}") from None

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CatalogError(f"manifest {path} is not valid JSON: {exc}") from None

    if isinstance(data, list):
        data = {"operations": data}
    if not isinstance(data, dict):
        raise CatalogError(
            f"manifest {path}: expected an object with an 'operations' list, or a list "
            f"of operations, got {type(data).__name__}."
        )

    unknown = sorted(set(data) - _MANIFEST_KEYS)
    if unknown:
        raise CatalogError(
            f"manifest {path}: unknown top-level key(s) {unknown}."
            f"{_suggest(unknown[0], _MANIFEST_KEYS)} "
            f"Known keys: {sorted(_MANIFEST_KEYS)}."
        )

    operations = data.get("operations")
    if not isinstance(operations, list):
        raise CatalogError(f"manifest {path}: 'operations' must be a list.")

    if namespace is None:
        namespace = data.get("namespace")
    if namespace is not None and not isinstance(namespace, str):
        raise CatalogError(f"manifest {path}: 'namespace' must be a string.")

    services = data.get("services")
    if services is not None and not isinstance(services, dict):
        raise CatalogError(f"manifest {path}: 'services' must be an object.")

    credentials = data.get("credentials")
    if credentials is not None and not isinstance(credentials, dict):
        raise CatalogError(f"manifest {path}: 'credentials' must be an object.")

    project = {
        "name": data.get("name"),
        "owner": data.get("owner"),
        "version": data.get("version"),
        "description": data.get("description"),
    }

    return register(
        operations,
        namespace=namespace,
        services=services,
        source=str(path),
        project=project,
        credentials=credentials,
    )


def reset_to_builtin() -> None:
    """Drop every runtime registration and restore the shipped catalog.

    Tests use this to get back to a known state. Mutates in place for the same reason
    register() does. Always restores builtins regardless of WARRANT_BUILTINS — tests
    need a known wall.
    """
    CATALOG.clear()
    _ORIGIN.clear()
    PROJECTS.clear()
    SERVICE_CREDENTIALS.clear()
    SERVICE_PORTS.clear()
    SERVICE_PORTS.update(_BUILTIN_SERVICE_PORTS)
    SERVICE_BASE.clear()
    SERVICE_BASE.update(_BUILTIN_SERVICE_BASE)
    _install_builtins()


def origin_of(op_id: str) -> str | None:
    """Where an operation was declared. Useful in audit and in collision messages."""
    return _ORIGIN.get(op_id)


def registered_namespaces() -> list[str]:
    """Namespaces currently present, inferred from op ids. Built-ins report as bare."""
    return sorted({op_id.split(".")[0] for op_id in CATALOG if "." in op_id})


def _install_builtins() -> None:
    # Built-ins go through the same validator as anyone else -- if the rules below could
    # not accept our own catalog, they would be the wrong rules. Note the absent
    # namespace: existing ids stay bare ('refunds.create', not 'builtin.refunds.create'),
    # so every warrant, prompt and test written against them keeps working.
    for op in _BUILTIN_OPERATIONS:
        _check_semantics(op, _ORIGIN, set(SERVICE_BASE))
        CATALOG[op.op] = op
        _ORIGIN[op.op] = "builtin"


def _autoload_from_env() -> None:
    """WARRANT_MANIFESTS=path1;path2 loads third-party manifests at import.

    This is the no-code onboarding path: an operator points the env var at a manifest and
    the whole stack -- broker, derivation, agent tools, audit -- picks the operations up
    on next boot. Failures raise rather than warn: a stack that silently booted without
    half its catalog would deny calls for reasons nobody could explain.
    """
    raw = os.environ.get("WARRANT_MANIFESTS", "").strip()
    for entry in raw.split(os.pathsep):
        entry = entry.strip()
        if entry:
            load_manifest(entry)


def _boot_registry() -> None:
    """Install builtins (unless WARRANT_BUILTINS=0) then autoload manifests."""
    if builtins_enabled():
        SERVICE_PORTS.update(_BUILTIN_SERVICE_PORTS)
        SERVICE_BASE.update(_BUILTIN_SERVICE_BASE)
        _install_builtins()
    _autoload_from_env()


_boot_registry()


# --------------------------------------------------------------------------------------
# Views over the catalog
# --------------------------------------------------------------------------------------


def describe_for_model() -> str:
    """Catalog rendered for the derivation prompt."""
    lines = []
    for op in CATALOG.values():
        kind = "MUTATING" if op.mutating else "read-only"
        lines.append(f"- {op.op} ({kind}) -- {op.description}")
        if op.args:
            for arg, desc in op.args.items():
                bound = " [constrainable]" if arg in op.constrainable else ""
                lines.append(f"    {arg}: {desc}{bound}")
        if op.resource_type:
            lines.append(
                f"    resource identity: {op.resource_type}:<{op.resource_param}>"
            )
        else:
            lines.append("    resource identity: * (this operation is not resource-scoped)")
    return "\n".join(lines)


def full_surface() -> list[dict[str, Any]]:
    """What a plain API key would permit: everything, unbounded. Used by the scope-diff UI."""
    return [
        {
            "op": op.op,
            "resource": "* (any)",
            "constraints": "none",
            "uses": "unlimited",
            "mutating": op.mutating,
        }
        for op in CATALOG.values()
    ]


def projects_view() -> list[dict[str, Any]]:
    """Registered project metadata for the UI /catalog response."""
    return list(PROJECTS)


def catalog_meta() -> dict[str, Any]:
    """Top-level catalog summary the UI uses for branding and filters."""
    return {
        "builtins": builtins_enabled() and any(
            _ORIGIN.get(op) == "builtin" for op in CATALOG
        ),
        "namespaces": registered_namespaces(),
        "projects": projects_view(),
        "operation_count": len(CATALOG),
    }
