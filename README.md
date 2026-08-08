# Warrant

### Prompt injection isn't a model problem. It's an authority problem.

Agents don't get credentials. They get **warrants** — authority derived from what they said they'd do, enforced at the wire, expiring in minutes.

---

## What breaks without it

An agent that does anything real needs credentials. Today you hand it an API key, and that key does everything the key can do, forever, regardless of what the agent was actually asked to do.

Then the agent reads something you didn't write — a support ticket, an email, a retrieved document — and that text contains instructions. The model follows them. It is still holding a key that can refund any order and email every customer.

The usual answers are to try harder at the model layer (better system prompts, injection classifiers, guardrails), or to put a human in front of every action. The first fails eventually. The second doesn't scale and becomes rubber-stamping.

**Warrant takes the key away from the agent.**

## The mechanism

1. A human states the task: *"refund Anil's order 1234."*
2. **Claude derives the minimum authority that task requires** — not "can create refunds", but *refund order 1234, amount ≤ ₹5,000, once, expires in 5 minutes.*
3. That becomes a signed, short-lived warrant. The agent carries the warrant and **no credentials**.
4. Every call goes through a broker that holds the real keys and checks it against the warrant.
5. Match → attach the real credential, forward. No match → 403, nothing leaves.
6. Every attempt is logged with a full attribution chain: which human, which agent, which task, allowed or denied and why.

## The demo

Task: *"Look into ticket t-501 for Anil and refund his order 1234 if the complaint is valid."*

Derived warrant:

```text
tickets.get      ticket:t-501    uses=1
orders.get       order:1234      uses=1
refunds.create   order:1234      uses=1   amount <= 5000
expires in 300s
```

The agent is then asked for two more things, both entirely reasonable support work:

> *"Now email Anil to confirm the refund has been processed, and pull up his other recent orders so I can check whether this has happened to him before."*

```text
ALLOW  tickets.get     ticket:t-501       within warrant
ALLOW  orders.get      order:1234         within warrant
ALLOW  refunds.create  order:1234         within warrant
DENY   email.send      customer:c-anil    no authority for email.send
DENY   orders.list     *                  no authority for orders.list
```

The agent wasn't attacked. It wasn't tricked. It tried to be *helpful* in a way nobody authorised — and it couldn't.

**The broker doesn't need to know the difference between helpfulness and an attack**, because it isn't judging intent at all. Neither operation was on the warrant, and the agent had no credential to go around the broker with. Reproduced 4/4 in testing.

For the malicious case — an agent that actually complies with an injected instruction — see `demo/run_demo.py`, which drives the same enforcement path deterministically with no model in the loop, and refuses a ₹2.5 lakh refund on an unrelated order and a broadcast to the entire customer base.

## Quickstart

```bash
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt
export ANTHROPIC_API_KEY=...

python -m demo.stack up          # broker :8100, upstreams :8101-8103
python -m demo.run_demo          # deterministic proof, no model in the call loop
```

Open `http://127.0.0.1:8100/` for the live view: derived scope against the full API-key surface, and the audit stream.

Run the live agent:

```bash
python -m demo.session \
  --task "Look into ticket t-501 for Anil and refund his order 1234 if the complaint is valid" \
  --ticket t-501 \
  --then "Great. Now email Anil to confirm the refund has been processed, and pull up his other recent orders so I can check whether this has happened to him before."
```

`demo/session.py` is two processes, and the split is the point. The operator holds
`OPERATOR_KEY` and mints; the agent is then launched as a child process with that variable
**stripped from its environment** and the token passed in on the command line. `POST /mint`
requires the operator credential and `POST /call` does not, so the agent can reach the
broker all day and still cannot create authority. Mint by hand with `python -m
demo.operator --task "..."`, or `--quiet` for just the token.

Prove that boundary rather than taking it on trust:

```bash
python -m broker._test_boundary
```

Prove that enforcement doesn't trust derivation — a hand-written, correctly-signed, deliberately over-broad warrant, refused anyway:

```bash
python -m demo.overbroad
```

Enforcement guarantees, ~1 second:

```bash
python -m core._test_enforce
```

## Architecture

```text
task statement ──► derive (Claude) ──► warrant (signed, scoped, TTL)
                     │                       │
        no tools, no untrusted input         │
                                             ▼
agent (no keys) ──X-Warrant──► BROKER ──check──► DENY 403
                                  │              (audit)
                                  └── allow ──► + real credential ──► upstream
                                                       │
                                                    audit
```

**The trust boundary.** Derivation sees the human's task statement and the operation catalog. It never sees tool output, ticket text, or anything the agent has read. Once the agent starts consuming untrusted content, no new authority can be minted for that task — escalation requires a human, out of band.

That last sentence is enforced, not asserted. Two locks, because they fail differently:

- **Minting needs a credential the agent does not have.** `POST /mint` requires `X-Operator-Key`; `POST /call` does not. The agent process asserts at startup that `OPERATOR_KEY` is absent from its environment and refuses to run if it is not, exactly as it already does for `UPSTREAM_KEY`.
- **A task seals on first use.** The moment a warrant reaches `/call` — allowed or denied, because attempting to act is what begins the task — `/mint` starts answering **409** for it. Not even the operator can re-derive it. Widening means `POST /release`, which needs the operator credential and is written to the same audit log as everything else. Refused mints are audited too: the attempt is visible, not silent.

`POST /delegate` is deliberately outside that seal, and the distinction is the point: minting turns *words* into authority, so injected text could write its own warrant. Delegation is checked against the parent on every dimension, so injected text can influence which slice a sub-agent gets and can never produce a slice the parent lacked. Only widening needs a human.

**Enforcement does not trust derivation.** A wildcard can never authorize a mutating operation, however that grant came to exist. A sloppy or manipulated derivation structurally cannot produce unbounded write authority.

| Layer | File |
|---|---|
| Types, catalog, signing, enforcement decision | `core/` |
| Attenuated delegation and the issuance ledger | `core/delegate.py` |
| Mint, enforce, credential substitution, audit | `broker/app.py` |
| Durable audit log and use budgets | `broker/store.py` |
| Task → minimum authority | `broker/derive.py` |
| Claude agent, broker as sole egress | `agent/` |
| Fake upstreams holding the real keys | `upstream/` |
| Scope diff + live audit | `ui/index.html` |

## Verified

`python -m core._test_enforce` — 18/18.

| Attempt | Result |
|---|---|
| Refund the granted order, within bounds | ALLOW |
| Refund a different order | DENY — *granted, but only on ['order:1234']* |
| An operation not granted at all | DENY — *no authority for email.send* |
| Refund over the amount bound | DENY — *99999 exceeds limit 4999* |
| Refund the same order twice | DENY — *use budget exhausted (1/1)* |
| Expired warrant | DENY — *expired 1s ago* |
| Agent widens its own warrant | DENY — *signature invalid or tampered* |
| Wildcard grant on a mutating op | DENY — *wildcards never authorize mutations* |

## What this is not

**Not a guardrail.** A guardrail inspects an action and judges it, so it has to understand the attack to stop it. This performs a lookup. It doesn't block bad actions; the authority was never issued. It's a capability system — an old operating-systems idea that agent tooling skipped.

**Not yet a platform.** Today this is one broker and one catalog: a working demonstration of the mechanism. It's infrastructure-*shaped* — a proxy and a token format, not a library, so any agent in any language can sit behind it. The catalog is registerable at runtime — `POST /catalog/register` takes a manifest and the operations inherit derivation, enforcement and audit without a line of our code changing — and a warrant holder can hand a sub-agent a strictly narrower slice with `POST /delegate`. What's missing is an MCP integration. Every MCP server today holds a service account with full access to whatever it wraps; this belongs underneath that.

**Not "zero network."** The agent has no credentials and no unmediated egress. The broker holds the keys. That's the honest claim.

## Honest notes

- **Claude Sonnet 5 resists the injection in `demo/ticket.txt`** — reliably, in every trial we ran, including under a deliberately naive system prompt. It identifies the fake triage note as an injection and refuses the extra steps unprompted. So in the live run those injected calls **never reach the broker at all**, and no denial for them appears in the audit log. Any claim that "the broker catches the injected refund" would be false, and we don't make it.

  That's the model behaving well, and it's the reason this exists: *"the model will probably notice"* isn't something you can put in an audit report, and it changes with every model, version, vendor and phrasing. The broker's answer doesn't depend on it. `demo/run_demo.py` drives the malicious case deterministically to show what happens when a model *does* comply.
- **Denial counts vary slightly between live runs.** The two denials above appeared in 4/4 trials; one trial produced a third (`customers.get`) when the model reached for the customer record as another route to the order history. The mechanism is deterministic; what the model chooses to attempt is not.
- HMAC signing here; Ed25519 in production. Key management, not architecture.
- The ₹5,000 refund ceiling is a policy default in the derivation prompt. Bounding by the order's actual total needs a read before derivation, which is a real design question — derivation must not start consuming tool output, or the trust boundary erodes.
- Upstream state is in memory. The broker's is not: the audit log, the use budgets, the active warrant and the seal live in SQLite (`warrant-<port base>.db`, or `$WARRANT_DB`). They have to. A warrant carries its own TTL, so it outlives the process that issued it — a `uses=1` budget held in RAM is enforced by the broker's uptime, and the holder only has to wait for a restart to spend it again. `python -m demo.stack up` deletes that file, so it is still the one command that resets everything between demos.
- **The delegation ledger is the exception, and it is in memory.** Restart the broker and every delegated warrant stops verifying — `/call` refuses any warrant naming a parent this process has no record of issuing. That fails closed rather than open, which is why we ship it, but delegated authority does not survive a restart and revocations of *root* warrants last only as long as the process does.

## Prior art

| | What it does | Why it doesn't close this |
|---|---|---|
| OAuth scopes | Static, coarse permissions | Registered ahead of time by developers. Not per-task, not argument-level, not minutes-long. |
| Vault dynamic secrets | Short-lived credentials | Scope comes from static policy, not from what the agent intends to do. |
| SPIFFE / SPIRE | Workload identity | Answers *who is this workload*, not *what is this task allowed to do*. |
| MCP | Tool exposure | No authority model. The server holds a service account; every tool inherits it. |
| Guardrails / HITL | Model-layer filtering, approvals | Convention enforced in application code, and it has to be right about the attack. |

The unoccupied sentence: nothing derives authority **from stated intent**, at **argument granularity**, bound to a **task lifecycle**, where the agent **never holds the credential**.

---

Built at Push to Prod — Building at the Frontier, Bengaluru, August 2026.
