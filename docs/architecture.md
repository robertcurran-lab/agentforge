# Architecture decision 001: pure workflow and capability preview

The implemented core validates a version-1 workflow of 1–1,000 named tasks, unique
explicit dependencies, and unique capability strings from repo.read, repo.write,
tests.run. Cycles, duplicate names and unknown dependencies are rejected. Parsing
copies mutable caller data into frozen task records. These symbolic capabilities
do not expose actual repositories, test commands or tools.

A preview accepts an explicit allowlist (empty denies every requested capability)
and a complete state map. Pending work is eligible only when all dependencies
succeeded and every requested capability is allowed. Other outcomes explain
permission denial, dependency blocking or a nonpending state. Started/succeeded
snapshots must have permissions and satisfied dependencies. Inputs are trusted
snapshots, not cryptographic evidence that execution occurred. Every preview says
executed=false; eligibility does not execute, reserve or authorize a process.

Valid transitions are pending -> running/cancelled; running ->
succeeded/failed/cancelled. Terminal tasks cannot restart and pending cannot jump
to succeeded. The transition function validates one event, not an audit chain.
No retries are implemented; new attempts will need explicit bounded attempt IDs.

The CLI reads three strict JSON files, max 1 MiB each, rejects duplicate keys and
nonfinite constants, validates all inputs and emits one complete preview. Invalid
input exits 2 with no stdout. Success exits 0 even when capabilities are denied:
this is an inspection command, not a permission-enforcement CLI. Consumers must
inspect each reason; do not interpret exit 0 as authority to run commands.

No shell, network, tool executor, sandbox, model planner, API, dashboard, persistent
traces or code editing exists. Future execution must enforce resource/path/network
capabilities at the OS boundary and pass attack/timeout/cancellation tests before
generated code is permitted. Application policy alone cannot provide isolation.
