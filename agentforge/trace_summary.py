"""Bounded summaries of explicit redacted trace files, not execution attestations."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .trace import MAX_RECORD_BYTES, TERMINALS, read_record_snapshot

MAX_INPUTS = 100


def summarize(paths: Sequence[str | Path]) -> dict[str, Any]:
    """Read and validate every explicit file before returning any summary.

    Duplicate path names, identical byte snapshots and equivalent records encoded
    differently are rejected, not counted twice. The hashes identify record bytes
    and canonical declarations, neither of which authenticates an observed run.
    """
    if isinstance(paths, (str, bytes)) or not 1 <= len(paths) <= MAX_INPUTS:
        raise ValueError("summary requires 1 to 100 explicit trace files")
    identities: set[str] = set()
    for path in paths:
        if not isinstance(path, (str, Path)):
            raise ValueError("trace inputs must be explicit file paths")
        identity = os.path.abspath(path)
        if identity in identities:
            raise ValueError("duplicate input path")
        identities.add(identity)
    raw_hashes: set[str] = set()
    record_hashes: set[str] = set()
    records = []
    counts = {terminal: 0 for terminal in sorted(TERMINALS)}
    scenario_counts: dict[str, int] = {}
    durations = []
    captured_bytes = 0
    for path in paths:
        record, raw_hash = read_record_snapshot(path)
        encoded = json.dumps(
            record, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        record_hash = hashlib.sha256(encoded).hexdigest()
        if raw_hash in raw_hashes:
            raise ValueError("duplicate raw trace digest")
        if record_hash in record_hashes:
            raise ValueError("duplicate canonical trace declaration")
        raw_hashes.add(raw_hash)
        record_hashes.add(record_hash)
        terminal = record["events"][-1]["kind"]
        counts[terminal] += 1
        scenario = record["scenario"]
        scenario_counts[scenario] = scenario_counts.get(scenario, 0) + 1
        elapsed = record["elapsed_ns"]
        durations.append(elapsed)
        capture = record["capture"]
        captured = capture["bytes"] if capture is not None else 0
        captured_bytes += captured
        records.append(
            {
                "source_sha256": raw_hash,
                "record_sha256": record_hash,
                "scenario": scenario,
                "terminal": terminal,
                "started": len(record["events"]) == 3,
                "elapsed_ns": elapsed,
                "captured_bytes": captured,
                "limits": record["limits"],
            }
        )
    records.sort(key=lambda row: row["source_sha256"])
    return {
        "schema_version": 1,
        "kind": "redacted-trace-summary",
        "execution_attested": False,
        "duration_interpretation": (
            "declared supervisor observations, not signed execution evidence"
        ),
        "records": len(records),
        "terminal_counts": counts,
        "scenario_counts": dict(sorted(scenario_counts.items())),
        "elapsed_ns": {
            "total": sum(durations),
            "minimum": min(durations),
            "maximum": max(durations),
        },
        "captured_bytes_total": captured_bytes,
        "input_bounds": {
            "max_records": MAX_INPUTS,
            "bytes_per_record": MAX_RECORD_BYTES,
        },
        "entries": records,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("records", nargs="+")
    args = parser.parse_args()
    try:
        report = summarize(args.records)
    except OSError:
        print("trace summary failed: input could not be read safely", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"trace summary failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
