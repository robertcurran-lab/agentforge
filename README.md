# AgentForge

Inspectable software-engineering workflows with explicit capability decisions,
owned by `robertcurran-lab`. The first CPU-compatible slice validates task graphs,
state snapshots and symbolic allowlists, then explains admission decisions. It
preview executes no commands and edits no code. A separate fixed-workload Linux
isolation probe is described below; no general agent runner is provided.

## Run and test

Python 3.12+; no runtime dependencies, model downloads, GPU or API keys. From this
repository root:

```sh
python -m agentforge examples/workflow.json --allowlist examples/allowlist.json --states examples/states.json
python -m unittest discover -s tests -v
python -m pip install -r requirements-dev.txt
ruff check agentforge tests
ruff format --check agentforge tests
mypy
```

A workflow has exactly `version` (integer 1) and `tasks` (1–1,000 records). Each
task has exactly `name`, `needs`, `capabilities`. Names are lowercase identifiers;
dependencies and capabilities are unique lists. Known symbolic capabilities are
`repo.read`, `repo.write`, `tests.run`. Unknown names, capabilities, dependencies,
duplicate task names and cycles fail validation.

The allowlist is an explicit JSON string list; an empty list denies every
requested capability. States map exactly every task to `pending`, `running`,
`succeeded`, `failed` or `cancelled`. A pending task is eligible only if all needs
succeeded and capabilities are allowed. Running/succeeded snapshots require those
conditions too. A snapshot is caller-supplied data, not proof of actual execution.
Library callers use `Workflow.parse(document).preview(allowed, states)` and
`transition(current, target)`; terminal states cannot restart and pending cannot
jump directly to succeeded. Retries, persistence and execution are not implemented.

The preview reports `eligible`, `capability_denied`, `dependency_blocked` or
`not_pending`, with denied capabilities. Every report has `executed: false`.
CLI exit 0 means a valid preview, including denial; **it never means authority to
execute**. Invalid inputs exit 2 with no partial stdout. Each file is capped at
1 MiB, with duplicate JSON keys and nonfinite constants rejected.

## Architecture and scope

`agentforge/policy.py` contains immutable parsed task records, graph validation,
transition checks and preview policy. `__main__.py` validates bounded JSON files.
Tests cover deny default, dependencies, malformed inputs, transition boundaries,
mutable-input detachment and real CLI calls. CPU CI checks Python 3.12–3.14,
lint and strict typing; consult actual checks for results.

There is no LLM, tool runner, repository analysis, test generation, code review,
shell execution, OS isolation, trace storage, API or dashboard. Symbolic policy is
not security isolation. Next: review contracts and threat model, then implement a
separately isolated bounded execution adapter and attack tests before adding model
planning or UI. No performance or autonomous-development success claims exist.

See [architecture](docs/architecture.md), [specification](docs/specification.json),
[contributing](CONTRIBUTING.md), [security](SECURITY.md) and [changes](CHANGELOG.md).
MIT licensed. Original synthetic examples only; no private code is included.
Prepared by Codex with the repository owner's authorization. Genuine independent
review is still required; authenticated pushes are not independent human reviews.

## Fixed-workload isolation investigation

A Linux-only conformance probe is available via `python -m agentforge.isolation
boundaries`. It runs only bundled synthetic workloads, not caller commands.
Unsupported hosts deny execution without fallback; dedicated Linux CI requires
real boundary tests. This is not a general-purpose agent runner or production
sandbox. See [execution boundary](docs/execution-boundary.md) for enforced and
unsupported restrictions, lifecycle, tests and platform requirements.

## Redacted probe records

`python -m agentforge.isolation boundaries --record-only` emits a bounded,
versioned lifecycle record with raw captured-byte SHA-256 and bundled-probe
provenance. No stdout/stderr content, host paths or environment values are exported.
`read_record` validates saved records; valid structure is not execution attestation.
See [probe records](docs/probe-records.md) for schema, privacy and lifecycle rules.
