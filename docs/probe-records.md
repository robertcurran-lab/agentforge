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

## Opt-in local persistence and validation CLI

```sh
python -m agentforge.isolation smoke --record-only --record-output trace.json
python -m agentforge.trace trace.json
```

The first command explicitly saves only the redacted record; `--record-only`
also keeps stdout redacted. Without `--record-only`, the usual stdout report can
still contain bounded raw diagnostics even though the saved file is redacted.
A denied unsupported-host probe can save a valid denial record and still exits 3.
Saving/validation errors exit 2 with no partial stdout. The probe runs before the
save is attempted; an output conflict does not undo an already completed probe.
No output file is written unless `--record-output` is supplied.

`write_record(path, value)` validates and serializes the entire bounded record
before filesystem mutation. Parents must already exist. The POSIX implementation
opens each canonical parent component with no-follow directory descriptors,
rejecting symlinks, dot/parent segments and empty components. Paths are not expanded
or normalized through symlinks. Use a plain relative filename or a physical
absolute path, not aliases such as macOS `/tmp` when it is a symlink. Unsupported
platforms fail rather than falling back to weaker writes. Readers likewise refuse
symlinks and nonregular files, including FIFOs without blocking.

Within the selected parent directory, a random exclusive private staging file is
created with mode 0600, fully written and fsynced. A same-directory hard link
publishes it atomically without replacing an existing destination, followed by
directory fsync and staging cleanup. No overwrite option exists. Existing files,
symlinks and directories are conflicts; concurrent writers have at most one
winner, whose complete valid record remains intact. The reader preserves its
8 KiB bound and strict UTF-8/schema validation; the validation CLI prints only a
fully validated redacted record, never a partial document.

## Filesystem trust and durability limits

This is for trusted local POSIX filesystems with hard-link, no-follow and fsync
semantics, not network filesystems, adversarial directory owners or arbitrary
hostile execution. Private file mode does not replace correct parent ownership.
No directories, external files or preexisting records are deleted or replaced.
Ordinary write/prepublication errors remove staging and leave no final output.
After publication, an fsync or cleanup error can leave a complete valid final file;
inspect and validate it before retrying rather than assuming an error means no
file exists. Sudden process death can orphan a hidden mode-0600 staging file;
the intended destination is never exposed partially. Such staging files are not
published trace records; cleanup after an abrupt kill is an explicit operator task.
Power-loss durability remains filesystem/hardware dependent, not an attestation.

Tests exercise a real eight-writer race, injected short-write and fsync failures,
a target appearing at publication, a real child exiting before publication,
permissions, path/symlink/FIFO rejection, strict bounded validation, redaction and
CLI roundtrips. Real Linux isolation CI remains mandatory and unchanged in scope.
