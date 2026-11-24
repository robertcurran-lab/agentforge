"""Bounded independent workspace snapshots and metadata-only batch records."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from .record_files import _publish_bytes, _read_bytes
from .trace import _constant, _object, _pairs
from .workspace_read import HARD_MAX_BYTES, _authorize, _components, read_snapshot

MAX_FILES = 16
MAX_RECORD_BYTES = 16384


def _configuration(paths: list[str], max_bytes: int, total_budget: int) -> None:
    if not isinstance(paths, list) or not 1 <= len(paths) <= MAX_FILES:
        raise ValueError("batch requires 1 to 16 paths")
    if any(not isinstance(path, str) for path in paths):
        raise ValueError("paths must be strings")
    for path in paths:
        _components(path)
    if len(set(paths)) != len(paths):
        raise ValueError("duplicate batch paths")
    if type(max_bytes) is not int or not 1 <= max_bytes < HARD_MAX_BYTES:
        raise ValueError("invalid per-file byte limit")
    if type(total_budget) is not int or not 2 <= total_budget <= HARD_MAX_BYTES:
        raise ValueError("invalid total read budget")
    if len(paths) * (max_bytes + 1) > total_budget:
        raise ValueError("requested read reservations exceed total budget")


def read_batch(
    root: str | Path,
    paths: list[str],
    *,
    allowed: list[str],
    include_text: bool = False,
    max_bytes: int = 65535,
    total_budget: int = HARD_MAX_BYTES,
) -> list[dict[str, Any]]:
    """Read independently; reserve limit+1 per file including growth detection.

    Text is returned only to explicit API callers. No atomic snapshot, host
    isolation or secret-free workspace is claimed. Failed entries are retained.
    """
    _authorize(allowed)
    _configuration(paths, max_bytes, total_budget)
    if type(include_text) is not bool:
        raise ValueError("include_text must be a boolean")
    entries = []
    for index, path in enumerate(paths):
        entry: dict[str, Any] = {
            "index": index,
            "status": "failed",
            "snapshot": None,
            "error": None,
        }
        try:
            entry["snapshot"] = read_snapshot(
                root,
                path,
                allowed=allowed,
                include_text=include_text,
                max_bytes=max_bytes,
            )
        except PermissionError:
            entry.update(status="denied", error={"stage": "read", "type": "permission"})
        except OSError:
            entry["error"] = {"stage": "read", "type": "io"}
        except ValueError:
            entry["error"] = {"stage": "read", "type": "validation"}
        else:
            entry["status"] = "succeeded"
        entries.append(entry)
    return entries


def validate_record(value: Any) -> dict[str, Any]:
    row = _object(
        value,
        {
            "schema_version",
            "kind",
            "max_bytes",
            "total_budget",
            "reserved_bytes",
            "text_requested",
            "execution_attested",
            "entries",
            "counts",
        },
        "batch record",
    )
    if type(row["schema_version"]) is not int or row["schema_version"] != 1:
        raise ValueError("unsupported batch version")
    if row["kind"] != "workspace-read-batch" or row["execution_attested"] is not False:
        raise ValueError("invalid batch declaration")
    entries = row["entries"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_FILES:
        raise ValueError("invalid entry count")
    _configuration(
        [str(i) for i in range(len(entries))], row["max_bytes"], row["total_budget"]
    )
    if type(row["reserved_bytes"]) is not int or row["reserved_bytes"] != len(
        entries
    ) * (row["max_bytes"] + 1):
        raise ValueError("invalid read reservations")
    if type(row["text_requested"]) is not bool:
        raise ValueError("invalid text declaration")
    counts = {"succeeded": 0, "denied": 0, "failed": 0}
    for index, value in enumerate(entries):
        entry = _object(value, {"index", "status", "snapshot", "error"}, "batch entry")
        if type(entry["index"]) is not int or entry["index"] != index:
            raise ValueError("invalid entry index")
        if not isinstance(entry["status"], str) or entry["status"] not in counts:
            raise ValueError("invalid entry status")
        counts[entry["status"]] += 1
        if entry["status"] == "succeeded":
            snapshot = _object(entry["snapshot"], {"bytes", "sha256"}, "batch snapshot")
            if (
                type(snapshot["bytes"]) is not int
                or not 0 <= snapshot["bytes"] <= row["max_bytes"]
            ):
                raise ValueError("invalid snapshot size")
            if not isinstance(snapshot["sha256"], str) or not re.fullmatch(
                r"[0-9a-f]{64}", snapshot["sha256"]
            ):
                raise ValueError("invalid snapshot hash")
            if (
                snapshot["bytes"] == 0
                and snapshot["sha256"] != hashlib.sha256(b"").hexdigest()
            ):
                raise ValueError("invalid empty snapshot digest")
            if entry["error"] is not None:
                raise ValueError("success cannot contain error")
        else:
            if entry["snapshot"] is not None:
                raise ValueError("failure cannot contain snapshot")
            error = _object(entry["error"], {"stage", "type"}, "batch error")
            expected = (
                ("permission",) if entry["status"] == "denied" else ("io", "validation")
            )
            if error["stage"] != "read" or error["type"] not in expected:
                raise ValueError("invalid coarse read error")
    declared = _object(row["counts"], set(counts), "batch counts")
    if any(type(declared[k]) is not int or declared[k] != n for k, n in counts.items()):
        raise ValueError("invalid batch accounting")
    raw = json.dumps(row, sort_keys=True, allow_nan=False).encode()
    if len(raw) > MAX_RECORD_BYTES:
        raise ValueError("batch record exceeds 16 KiB")
    detached: dict[str, Any] = json.loads(raw)
    return detached


def read_record(path: str | Path) -> dict[str, Any]:
    raw = _read_bytes(path, MAX_RECORD_BYTES)
    if len(raw) > MAX_RECORD_BYTES:
        raise ValueError("batch record exceeds 16 KiB")
    try:
        value = json.loads(
            raw.decode(), object_pairs_hook=_pairs, parse_constant=_constant
        )
    except RecursionError as exc:
        raise ValueError("batch record nesting too deep") from exc
    return validate_record(value)


def run_batch(
    root: str | Path,
    paths: list[str],
    *,
    record: str | Path,
    allowed: list[str],
    include_text: bool = False,
    max_bytes: int = 65535,
    total_budget: int = HARD_MAX_BYTES,
) -> dict[str, Any]:
    entries = read_batch(
        root,
        paths,
        allowed=allowed,
        include_text=include_text,
        max_bytes=max_bytes,
        total_budget=total_budget,
    )
    redacted = []
    counts = {"succeeded": 0, "denied": 0, "failed": 0}
    for entry in entries:
        counts[entry["status"]] += 1
        snapshot = entry["snapshot"]
        redacted.append(
            dict(
                entry,
                snapshot=None
                if snapshot is None
                else {"bytes": snapshot["bytes"], "sha256": snapshot["sha256"]},
            )
        )
    row = validate_record(
        {
            "schema_version": 1,
            "kind": "workspace-read-batch",
            "max_bytes": max_bytes,
            "total_budget": total_budget,
            "reserved_bytes": len(paths) * (max_bytes + 1),
            "text_requested": include_text,
            "execution_attested": False,
            "entries": redacted,
            "counts": counts,
        }
    )
    _publish_bytes(record, (json.dumps(row, sort_keys=True) + "\n").encode())
    return row


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("paths", nargs="+")
    parser.add_argument("--record", required=True)
    parser.add_argument("--allow", action="append", default=[])
    parser.add_argument("--include-text", action="store_true")
    parser.add_argument("--max-bytes", type=int, default=65535)
    parser.add_argument("--total-budget", type=int, default=HARD_MAX_BYTES)
    args = parser.parse_args()
    try:
        row = run_batch(
            args.root,
            args.paths,
            record=args.record,
            allowed=args.allow,
            include_text=args.include_text,
            max_bytes=args.max_bytes,
            total_budget=args.total_budget,
        )
    except (OSError, ValueError):
        print(
            "Batch failed: check permission, options and record destination.",
            file=sys.stderr,
        )
        return 2
    print(json.dumps(row, sort_keys=True))
    return 0 if row["counts"]["succeeded"] == len(row["entries"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
