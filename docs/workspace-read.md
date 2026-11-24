# Explicit bounded workspace read

```sh
python -m agentforge.workspace_read --root trusted-project source/example.py --allow repo.read
python -m agentforge.workspace_read --root trusted-project source/example.py --allow repo.read --include-text
```

`read_snapshot(root, relative_path, allowed=["repo.read"], include_text=False,
max_bytes=65536)` performs one bounded local read. The capability grant is a trusted
caller's explicit policy declaration, not a token, authenticated authorization or
OS security boundary. Missing repo.read, unknown labels, malformed or duplicate
allowlists fail before opening any path. Other globally known capability labels
do not grant this tool any write, test, command or network behavior.

The root must be an existing trusted directory, never the filesystem root. A plain
relative root or physical absolute root is allowed; `.` means the current trusted
workspace. Symlink root/parent components, trailing/empty/dot/parent segments,
absolute requested paths, backslashes and NULs are rejected. Files are reached
through no-follow directory descriptors and opened read-only/nonblocking. Only
regular files with exactly one hard link are accepted: aliases through hard links
are conservatively denied rather than assumed contained. Missing files and all
unsupported POSIX operations fail; there is no weaker fallback.

Repository-control `.git` components (including worktree .git files), .env/.env.*,
common credential directories and key filenames are denied even in digest mode.
The finite case-insensitive exclusions include .aws, .ssh, .envrc, .netrc, .npmrc,
.pypirc, id_rsa/id_dsa/id_ecdsa/id_ed25519, credentials/credentials.json and .pem/.key
suffixes. .gitignore is not a .git control component. These conservative names may
exclude harmless files; they do not discover secrets in ordinary source names,
renamed credential files, comments or other payloads. No real secret is read in
the tests. Select a suitable root and review content before explicitly exporting.

Default output contains only tool/capability/version metadata, byte limit, raw-byte
count, SHA-256, text_included=false and mutation_observed=false. It omits even the
relative filename and host absolute root. Text appears only with explicit opt-in,
requires strict UTF-8, and is returned unchanged from the same byte snapshot used
for the digest/count. Digest-only mode can describe bounded binary files without
claiming UTF-8 validity. A digest can fingerprint known files; it is not encryption.
The configurable limit is 1 byte–1 MiB; file growth cannot produce an oversized
returned snapshot. No file write, process execution or network request occurs.
Reading may update filesystem access-time metadata; source bytes are not changed.

Pre/post descriptor checks compare device/inode/mode/link count/size/mtime/ctime;
a final no-follow name check also detects ordinary replacement/unlink. Byte length
must match the initial size. Changed files fail instead of returning a mixed read.
These are ordinary mutation checks, not an atomic filesystem snapshot, lock,
proof against a malicious host, all adversarial races, shared writable parents,
privileged timestamp manipulation or future changes after the checks. Descriptor
anchoring is path handling, not an OS sandbox. Trust the host, runtime, root owner
and local filesystem; no production or arbitrary-code safety is claimed.

The separate CLI emits a completed JSON result on success (exit 0), or exit 2 with
no partial stdout for any denial/invalid input/I/O error. Error diagnostics omit
host file paths. Text opt-in can of course reveal paths or sensitive text present
inside the selected file: it is an explicit export, not automatic content scrubbing.
No probe events or probe trace-schema records are manufactured for this tool.

Tests cover actual read-only files, digest/text routing, denial before any open,
synthetic secret/control names, symlinks/hardlinks/FIFOs/directories, limits and
invalid UTF-8, same-read provenance, ordinary mutation/growth/replacement, root
safety and CLI failures. Existing mandatory actual Linux isolation CI stays intact.
