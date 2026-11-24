# Bounded workspace read batches

```sh
python -m agentforge.batch_read --root /trusted/workspace first.txt second.txt --allow repo.read --record /trusted/reports/new-batch.json
```

`read_batch(root, paths, *, allowed, include_text=False, max_bytes=65535,
total_budget=1048576)` composes the existing read-only workspace snapshot tool.
Explicit repo.read authorization is checked before filesystem access. The complete
request requires1–16 distinct canonical relative string paths and finite integer
bounds (bool rejected). Invalid request structure fails before any open. Existing
secret/control-path exclusions, no-follow regular-file checks, hardlink rejection,
size bounds and ordinary mutation checks remain in effect for each entry.

The aggregate **workspace payload read reservation** is
`len(paths) * (max_bytes + 1) <= total_budget <= 1 MiB`. The extra byte per entry
accounts for actual growth-detection reads, including failed reads. This conservative
reservation is checked before work, regardless of actual file sizes. Default16
entries fit exactly1 MiB. Per-file payload ceiling is1–1048575 bytes. The tool does
not recycle failed/unused reservations or retry reads. Metadata operations and the
explicit record write are outside the payload-byte budget.

Independent entries retain index, succeeded/denied/failed status, coarse read error
stage/type and successful snapshots. Expected failures do not drop later entries.
Missing files become io failures; path exclusions become permission denials;
invalid UTF-8 with explicit text requested becomes validation failure. The API's
include_text=true returns text to its caller; that text may contain private data.
Default API snapshots contain only digest/size metadata. Input paths stay in the
caller request rather than result entries.

`run_batch(..., record=NEW_PATH)` and CLI always publish/return **metadata only**,
even with --include-text (which requests UTF-8 reading/validation, not text export).
A separate strict schema includes exact counts and bounded reservations; individual
entries contain only index/status/hash/size/coarse errors. No root/path, content,
question, error message or raw exception class name enters the record. Digests,
sizes and statuses still disclose metadata. No execution attestation is claimed.
Records cap at16 KiB; strict read_record/validate_record reject unknown fields,
malformed counts/hashes, raw text, invalid indices or error/status inconsistencies.

Publication reuses private no-clobber descriptor-anchored atomic persistence.
No partial success record is returned on publication failure; reads may already have
occurred. Existing/racing destinations are preserved. Process death can leave
private staging files; a post-publication sync failure can leave a complete file.
These are separate sequential reads, **not an atomic multi-file snapshot**, general
OS sandbox, secret-free-root guarantee or defense against all hostile host races.
Trusted stable root, caller grants, runtime and local filesystem remain required.
No shell, network, process execution or workspace writes are introduced. Only the
explicit requested record is written. CLI exits0 for all success,1 for retained
entry failures,2 for authorization/configuration/publication failure with no partial
stdout. No paid resources or deployment are needed.
