# Execution boundary investigation and fixed-workload prototype

## Threat model and scope

Goal: test whether a fixed synthetic workload is isolated from a host-only canary,
host loopback listener and inherited environment, and whether timeout, output and
cancellation handling terminate its process tree. The host kernel, installed system
runtime, repository source and supervisor are trusted. No arbitrary shell, command,
planner output, repository code or user-selected workspace is accepted.

The prototype requires Linux `/usr/bin/bwrap` and system `/usr/bin/python3`.
Bubblewrap creates mount, network and PID namespaces; read-only system runtime
directories and one disposable writable workspace are exposed. Other host paths
are absent, environment is cleared, capabilities dropped and a new session used.
The syscall/kernel attack surface is shared; no VM boundary, seccomp policy,
memory limit, disk quota or general hostile-code safety is claimed. Runtime paths
are intentionally visible and may contain system-wide metadata.

The project deliberately has no macOS or Windows adapter. A missing executable,
unsupported host or failed backend denies execution. No unrestricted fallback,
namespace-policy relaxation or host-security change is performed. Local macOS tests
verify denial; required Linux CI must execute real boundary tests or fail.

## Alternatives and primary references

- Linux bubblewrap: small explicit namespace/mount interface; selected for this
  fixed conformance probe. The command arguments determine the boundary, not the
  tool name alone. [Official documentation](https://github.com/containers/bubblewrap/blob/main/README.md)
  and [command reference](https://github.com/containers/bubblewrap/blob/main/bwrap.xml).
- Container/VM-based worker: a candidate for a future general executor, adding
  packaging/runtime dependencies. No local container daemon is available in the
  audited environment; none was installed or provisioned for this task.
- macOS/Windows OS-specific adapters: deferred until platform-native enforcement
  and comparable conformance tests can be implemented. A subprocess timeout alone
  is not an acceptable substitute.

## Adapter contract

`run_probe(scenario, timeout=3, output_limit=8192, cancel=None)` accepts only the
bundled smoke/boundaries/wait/flood/descendants scenarios. Timeout is finite in
(0,10] seconds; captured output is capped at 512–65,536 bytes. Cancellation uses a
threading.Event. No caller-provided command, environment, mount or shell string is
accepted. The supervisor reaps the process and kills its process group on exit;
PID namespace teardown additionally contains detached test descendants.

Trace states are requested, optionally started (observed from the fixed workload),
then succeeded/failed/denied/timeout/output_limit/cancelled. A denied launch never
reports started. Trace output is diagnostic, not signed or persistent evidence.
The conformance canary and environment sentinel are synthetic, never real secrets.

## Run and verify

```sh
python -m agentforge.isolation boundaries
python -m agentforge.isolation descendants --timeout 0.6
```

Exit 0 indicates the workload exited successfully; inspect the boundary checks,
not just the exit code. Exit 3 means a denied/failed/bounded termination; invalid
arguments or supervisor setup errors exit 2. Unsupported hosts emit a denied JSON
result. No production execution API is exposed.

The dedicated Ubuntu 22.04 CI job installs the distro bubblewrap package and sets
AGENTFORGE_REQUIRE_SANDBOX=1. If namespaces are unavailable it fails rather than
silently skipping. Tests attempt outside-file reads/writes, symlink escape, host
/etc access, host-listener connection and secret inheritance, plus flooding,
cancellation and timeout. A detached fixed child would write a marker after one
second; the timeout test verifies that marker never appears after teardown. This
is a bounded conformance observation, not proof against all descendant strategies.

The bundled boundary workload emits every check and exits nonzero if any check is
false. The supervisor therefore reports a started workload failure, rather than
success, for an observed boundary failure. Successful process completion alone is
not a general isolation guarantee; the fixed checks remain limited conformance
observations on the current host/runtime.
