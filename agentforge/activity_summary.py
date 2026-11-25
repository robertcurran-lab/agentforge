"""Read-only summaries of explicit redacted activity declarations."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import batch_read, read_trace, trace
from .record_files import _read_bytes

MAX_INPUTS = 100
MAX_RECORD_BYTES = batch_read.MAX_RECORD_BYTES
MAX_TOTAL_READ_BYTES = MAX_INPUTS * (MAX_RECORD_BYTES + 1)
KINDS = ("probe", "workspace-read", "workspace-read-batch")
READ_STATUSES = ("succeeded", "denied", "failed")


def _parse(raw: bytes) -> tuple[str, dict[str, Any]]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=trace._pairs,
            parse_constant=trace._constant,
        )
    except RecursionError as exc:
        raise ValueError("activity JSON nesting too deep") from exc
    if not isinstance(value, dict):
        raise ValueError("activity record must be an object")
    if "kind" not in value:
        if len(raw) > trace.MAX_RECORD_BYTES:
            raise ValueError("probe record exceeds byte limit")
        return "probe", trace.validate_record(value)
    if value["kind"] == "workspace-read":
        if len(raw) > read_trace.MAX_RECORD_BYTES:
            raise ValueError("read record exceeds byte limit")
        return "workspace-read", read_trace.validate_record(value)
    if value["kind"] == "workspace-read-batch":
        return "workspace-read-batch", batch_read.validate_record(value)
    raise ValueError("unknown activity record kind")


def summarize(paths: Sequence[str | Path]) -> dict[str, Any]:
    """Validate all inputs, retaining schema distinctions and declared byte meaning.

    Hashes identify the same bytes read, not authentic events. Repeated raw or
    canonical declarations are rejected, not silently deduplicated or counted twice.
    """
    if isinstance(paths, (str, bytes)) or not 1 <= len(paths) <= MAX_INPUTS:
        raise ValueError("activity summary requires 1 to 100 explicit files")
    identities = set()
    for path in paths:
        if not isinstance(path, (str, Path)):
            raise ValueError("activity input must be an explicit path")
        identity = os.path.abspath(path)
        if identity in identities:
            raise ValueError("duplicate input path")
        identities.add(identity)
    raw_hashes: set[str] = set()
    canonical_hashes: set[str] = set()
    buckets: dict[str, dict[str, Any]] = {
        kind: {
            "records": 0,
            "status_counts": dict.fromkeys(
                sorted(trace.TERMINALS) if kind == "probe" else READ_STATUSES, 0
            ),
            "declared_output_bytes": 0 if kind == "probe" else None,
            "declared_snapshot_bytes": None if kind == "probe" else 0,
            "elapsed_ns": None,
        }
        for kind in KINDS
    }
    durations: dict[str, list[int]] = {kind: [] for kind in KINDS}
    entries = []
    for path in paths:
        raw = _read_bytes(path, MAX_RECORD_BYTES)
        if len(raw) > MAX_RECORD_BYTES:
            raise ValueError("activity record exceeds 16 KiB")
        kind, record = _parse(raw)
        raw_hash = hashlib.sha256(raw).hexdigest()
        canonical = json.dumps(
            record, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        canonical_hash = hashlib.sha256(canonical).hexdigest()
        if raw_hash in raw_hashes or canonical_hash in canonical_hashes:
            raise ValueError("duplicate raw or canonical activity declaration")
        raw_hashes.add(raw_hash)
        canonical_hashes.add(canonical_hash)
        bucket = buckets[kind]
        bucket["records"] += 1
        counts: dict[str, int] = dict.fromkeys(bucket["status_counts"], 0)
        output_bytes: int | None = None
        snapshot_bytes: int | None = None
        elapsed = None
        if kind == "probe":
            counts[record["events"][-1]["kind"]] = 1
            output_bytes = record["capture"]["bytes"] if record["capture"] else 0
            elapsed = record["elapsed_ns"]
        elif kind == "workspace-read":
            counts[record["status"]] = 1
            snapshot_bytes = record["snapshot"]["bytes"] if record["snapshot"] else 0
            elapsed = record["elapsed_ns"]
        else:
            counts.update(record["counts"])
            snapshot_bytes = sum(
                entry["snapshot"]["bytes"]
                for entry in record["entries"]
                if entry["status"] == "succeeded"
            )
        for status, count in counts.items():
            bucket["status_counts"][status] += count
        if output_bytes is not None:
            bucket["declared_output_bytes"] += output_bytes
        if snapshot_bytes is not None:
            bucket["declared_snapshot_bytes"] += snapshot_bytes
        if elapsed is not None:
            durations[kind].append(elapsed)
        entries.append(
            {
                "source_sha256": raw_hash,
                "record_sha256": canonical_hash,
                "kind": kind,
                "status_counts": counts,
                "elapsed_ns": elapsed,
                "declared_output_bytes": output_bytes,
                "declared_snapshot_bytes": snapshot_bytes,
            }
        )
    for kind, values in durations.items():
        if values:
            buckets[kind]["elapsed_ns"] = {
                "total": sum(values),
                "minimum": min(values),
                "maximum": max(values),
            }
    return {
        "schema_version": 1,
        "kind": "redacted-activity-summary",
        "execution_attested": False,
        "records": len(entries),
        "by_kind": buckets,
        "entries": sorted(entries, key=lambda row: row["source_sha256"]),
        "interpretation": (
            "declared observations; batch statuses count entries; "
            "durations unavailable for batches"
        ),
        "input_bounds": {
            "max_records": MAX_INPUTS,
            "max_record_bytes": MAX_RECORD_BYTES,
            "max_total_read_bytes": MAX_TOTAL_READ_BYTES,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("records", nargs="+")
    args = parser.parse_args()
    try:
        report = summarize(args.records)
    except (OSError, ValueError):
        print(
            "Activity summary failed: check explicit bounded record files.",
            file=sys.stderr,
        )
        return 2
    print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
