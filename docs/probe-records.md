# Versioned redacted execution records

Every `run_probe` result now includes a strict version-1 `record`. For an export
that omits raw stdout/stderr, diagnostic reasons, command lines, host paths and
inherited environment values:

```sh
python -m agentforge.isolation boundaries --record-only
```

Save that stdout as one JSON record and validate it with
`agentforge.trace.read_record(path)`. The reader caps input at 8 KiB, requires
strict UTF-8, rejects duplicate keys/nonfinite constants and returns a detached
validated copy. The ordinary diagnostic report still includes raw bounded output;
use `--record-only` when exporting or sharing observations. No trace file is
implicitly written, appended, uploaded, signed or registered as a human review.

## Schema and lifecycle

A record has exactly schema_version=1, scenario, limits, elapsed_ns, events,
capture, observations, process_returncode, probe_sha256 and execution_attested.
Scenario is one bundled fixed workload. Limits preserve the validated supervisor
wall timeout and output-byte cap. Elapsed nanoseconds measure the local supervisor
interval, including cleanup; they are not historical wall-clock timestamps.

Events have contiguous zero-based sequence numbers and one kind each: requested,
optional started, then exactly one terminal outcome. Success and workload failure
require observed start; denial cannot include it. Timeout/output-limit/cancellation
may occur before or after start. Success requires process exit zero; workload
failure requires a nonzero process exit. The process return code is null when
nothing was launched/captured. A backend can exit zero without a workload start
marker and still be denied: backend exit alone is not proof the workload ran.

Capture is null for pre-launch denial/cancellation, otherwise it contains the raw
captured-byte count, lowercase SHA-256 and redacted=true. The count cannot exceed
the declared cap. Zero bytes require the empty-byte digest. Hashing/counting happens
before invalid UTF-8 is replaced for human diagnostics, preventing a decoded-text
hash from being mistaken for raw-byte provenance. SHA-256 is not encryption;
a digest can identify known output and is not a secrecy guarantee.

The bundled fixed probe's source bytes are hashed before launching and recorded
as probe_sha256. This identifies the intended local workload source, not the
installed runtime, kernel or binary versions. Source files and host runtime must
remain trusted and unchanged during execution. Observations contain only optional
boolean canary/descendant results; unknown observation payloads are rejected.

## Trust boundary

`execution_attested` is always false, including on locally observed successful
runs. A structurally valid imported record is an unauthenticated declaration;
anyone can construct it. Validation proves neither execution, correct provenance,
secure isolation nor the truth of claimed checks. The records are bounded
inspection artifacts, not cryptographic attestations or permission grants.

The existing fixed-workload, Linux-only and fail-closed restrictions remain. The
mandatory Linux CI job exercises real isolation while validating generated records;
unsupported local hosts test the denied path without claiming boundary coverage.
