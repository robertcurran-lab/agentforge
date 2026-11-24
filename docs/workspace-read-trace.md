# Redacted workspace-read records

```sh
python -m agentforge.read_trace --root /absolute/trusted/workspace README.md --allow repo.read --record /absolute/private/new-record.json
```

`run_read(root, relative_path, *, record, allowed, include_text=False,
max_bytes=65536)` composes the existing capability-gated bounded byte snapshot
reader with explicit private trace publication. It returns and prints only the
validated record, never file contents. `--include-text` requests strict UTF-8
validation but decoded text is discarded. It does not grant additional authority.
All workspace reader path/secret-name exclusions, no-follow regular-file checks,
hardlink restrictions and ordinary mutation detection continue to apply.

The independent `workspace-read` schema version 1 records only succeeded/denied/
failed, elapsed nanoseconds, configured byte bound, text-requested boolean and,
for success, byte count and same-read SHA256. It never contains root/relative
paths, raw contents, arbitrary error messages, capability lists, subprocess exit
codes or bundled-probe fields. Denial includes capability/path/host permission
rejection; failure includes other expected I/O, bounds and UTF-8 errors. Neither
status proves the absence of any earlier host operation. Existing subprocess
probe schema remains unchanged. `execution_attested=false`: imported records
are declarations, not runtime proofs.

`validate_record` rejects unknown fields, inconsistent snapshots, booleans as
integers and invalid digest/size/duration limits. `read_record` reuses bounded
POSIX no-follow reading, strict JSON duplicate/nonfinite rejection and 4 KiB cap.
Publication reuses the atomic mode-0600 no-clobber record publisher. Existing
files/symlinks are not replaced. A source read may already have happened before
record publication fails; no transactional read or rollback is promised. Abrupt
death can leave private staging files; post-publication sync failure can leave
a complete record despite an error. Invalid reporting bounds fail before reading.

CLI exits 0 for a successfully recorded successful read, 1 for a recorded denial
or read failure, and 2 for invalid reporting configuration or publication failure,
without partial success stdout. Generic errors do not echo paths/messages.

Host/runtime and workspace ownership remain trusted. This is not an OS sandbox,
a source snapshot, cryptographic attestation or a secret-free guarantee. Digests,
file sizes and timing can still reveal information: store records privately and
review before sharing. No network, shell or arbitrary executable is invoked.
Only the explicitly requested trace file is written; source files stay unchanged.
