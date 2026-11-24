# Bounded redacted run-history summary

```sh
python -m agentforge.trace_summary first.json second.json
```

The CLI accepts an explicit list of 1–100 trace files, never a directory, glob
crawler, service endpoint or command to execute. Each input uses the existing
strict version-1 regular-file reader: no symlink components, no FIFO/device reads,
8 KiB maximum per file, strict UTF-8/JSON and complete schema/lifecycle validation.
It reads each input once and returns both its validated record and SHA-256 of
those same bytes through `read_record_snapshot`. No separate reread is used to
claim provenance for potentially changed content.

The summary contains terminal-status counts, scenario counts, integer declared
elapsed-duration total/minimum/maximum, captured-byte totals and configured
input/output bounds. Entries are sorted by raw source digest, making input order
irrelevant. Paths, raw captured output, observation payloads, prompts and arbitrary
fields are omitted. No output file is created automatically; stdout contains a
complete JSON summary only after every input passes. Exit 0 means valid summary
construction, not successful workload execution; denied and failed records count
as their actual declared statuses. Invalid/missing input exits 2 with no partial
stdout. File-read errors do not echo the supplied path to stderr.

Repeated input paths, identical raw-byte digests and identical canonical JSON
records with different whitespace/key ordering are rejected rather than counted
twice. Canonical declaration hashes are separate from raw-byte provenance hashes.
Different declarations are not proof of distinct runs: changing metadata can
produce another valid record, and no signed run identity or authenticity check is
provided. The summary always reports execution_attested=false.

Durations summarize unauthenticated declared supervisor observations, not signed
execution proof, actual aggregate CPU time, GPU measurements or wall-clock history.
Integer totals are exact in Python and can exceed JavaScript's exact-number range;
consumers must preserve JSON integer precision. No dates or historical activity
are invented. The raw input cap is 100 × 8 KiB, while schema constraints also bound
the parsed records and fixed-field summary. No invalid record is silently skipped.

Trust the source files, parent ownership and local POSIX filesystem as required
by the persistence contract. A digest binds bytes read, not an atomic snapshot
across files or a proof that a workload executed. Hashes can fingerprint known
records and are not encryption. Different live files can change between reads;
freeze the chosen history before summarizing. No background collection, resume,
directory scanning, network access, signing or command runner is introduced.

Tests include a saved denied fixed-probe record on macOS, clearly labeled synthetic
record declarations for lifecycle totals, exact one-read/hash binding, duplicate
paths/copies/hard links/reencoding, strict invalid/oversized records, FIFO/symlink
rejection, exact large-duration integers and CLI redaction/failure behavior. The
existing mandatory Linux namespace-conformance job remains unchanged in scope.
