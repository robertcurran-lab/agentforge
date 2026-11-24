# Security

The workflow preview only parses workflows and previews symbolic decisions. It
executes no commands, tests, model calls, tools or network requests. Capabilities are
labels, not an execution sandbox. Do not use a successful CLI exit as permission
to execute a task; denial decisions also exit 0. External snapshots are unverified.
The CLI bounds each JSON file to 1 MiB; use trusted regular files, not named pipes.
No private vulnerability-report channel is configured. Do not put credentials,
private source code or sensitive tasks in public issues. Any future runner needs
separate OS isolation, path/network restrictions and bounded execution; it is not
safe merely because a policy preview labels a task eligible.

The separate fixed-workload Linux probe starts bundled synthetic processes inside
bubblewrap namespaces only; unsupported hosts fail closed. No arbitrary command
API is provided. The host kernel/runtime remain trusted; memory limits, disk
quotas and seccomp hardening are not implemented. See docs/execution-boundary.md.

Use the isolation CLI's `--record-only` option for redacted trace export. Normal
diagnostic reports still contain bounded raw output. Records omit raw output and
host paths but hashes can identify known bytes. A validated record is an
unauthenticated declaration; execution_attested remains false.

Opt-in record persistence validates before writing, rejects symlink components
and nonregular read targets, uses mode-0600 staging and atomically links a complete
new file without replacement. Trust parent-directory ownership and local POSIX
filesystem semantics. A killed process may orphan private staging; post-publication
sync errors may leave a complete valid output. No execution attestation is added.

Trace summaries read only an explicit bounded list of strict no-symlink regular
files. Source hashes bind the same bytes parsed, not a signed execution identity
or cross-file atomic snapshot. Summaries omit paths/raw payloads; their digests can
still fingerprint known records. Durations are unauthenticated declarations.
