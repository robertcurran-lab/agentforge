# Mixed redacted activity summaries

```sh
python -m agentforge.activity_summary PROBE_RECORD READ_RECORD BATCH_RECORD
```

Reads explicit saved probe, workspace-read and workspace-read-batch records without
rerunning operations. Reuses each version1 validator; missing kind is accepted only
as a valid strict probe schema. Unknown/malformed kinds fail. Existing probe-only
trace_summary remains unchanged.

All inputs are validated before JSON success. At most100 files are accepted. The
common reader consumes at most16385 bytes/file (16KiB plus detection byte), for at
most1,638,500 bytes across a maximum invocation. Accepted raw records retain their
kind-specific caps: probe8KiB, single read4KiB, batch16KiB. Whitespace counts too.
No-follow descriptor operations reject leaf/ancestor symlinks and nonregular files;
FIFOs without writers cannot block the reader. This is not a timeout for slow
regular files or protection against a hostile/mutating host. Inputs must be stable.

Repeated canonical absolute path spellings, identical raw byte snapshots and
identical canonical declarations are rejected instead of counted twice. Digests
identify the exact bytes read and canonical JSON, not authentic event identities.
Two genuinely separate activities with identical declarations cannot be reliably
distinguished; this tool rejects that ambiguity rather than manufacturing IDs.

Reports expose only known kinds, counts/statuses, declared durations/byte totals and
record hashes. Input names/paths, content, raw errors and per-file snapshot digests
are omitted. Probe terminal counts describe records; single-read status counts
also describe records; batch status counts describe retained entries, not batch
records. Separate record counts preserve that distinction.

Probe output bytes sum declared capture bytes; workspace snapshot bytes sum only
successful declared snapshots. Failed reads can have consumed bytes not represented
in snapshots, so this is not total I/O or resource accounting. Inapplicable byte
fields are null. Probe/single-read durations aggregate declared elapsed observations;
batch records have no duration field and remain null, never invented zero. No
global combined duration or success percentage hides these different units.

CLI0 means declarations were summarized, not that all operations succeeded. Invalid
inputs return2 with coarse errors and no partial stdout. Sources are never modified.
Execution_attested remains false. No OS isolation, secret-free root, model execution,
runtime authenticity, security verdict, network call or paid service is established.
