# Unreleased

Initial CPU-compatible workflow validation and capability preview foundation. No public release or production readiness claim.

Unreleased: execution threat model, Linux fixed-workload isolation probe, bounded
process supervision and mandatory real namespace-conformance CI.

Unreleased: strict version-1 redacted probe records, lifecycle/return-code
validation, raw-byte output hashes, bundled-probe provenance and record-only CLI.

Unreleased: opt-in atomic no-clobber private record persistence, symlink-safe
bounded regular-file reads and a strict redacted record validation CLI.

Unreleased: bounded deterministic trace aggregation, same-read source digest
binding, duplicate rejection and redacted status/duration summary CLI.

Unreleased: explicitly capability-gated bounded workspace read, digest-only
default, opt-in strict UTF-8, same-read provenance and ordinary mutation checks.

- Add explicit private workspace-read tracing with a separate strict metadata-only
  schema; preserve subprocess probe records and capability-gated source reading.

- Fail the fixed boundary workload when any emitted boundary check is false, so
  normal probe and redacted-trace outcomes cannot label that workload succeeded.

- Add bounded permission-gated workspace read batches with complete per-entry
  outcomes, conservative aggregate growth-detection budget and strict redacted records.

- Add bounded read-only mixed activity summaries with strict existing schemas,
  same-read/canonical digests, duplicate rejection and distinct per-kind accounting.
