"""Redacted records for capability-gated local workspace reads."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

from .record_files import _publish_bytes, _read_bytes
from .trace import _constant, _object, _pairs
from .workspace_read import HARD_MAX_BYTES, read_snapshot

MAX_RECORD_BYTES = 4096


def validate_record(value: Any) -> dict[str, Any]:
    """Validate declarations, not runtime authenticity or secret-free provenance."""
    row = _object(
        value,
        {
            "schema_version",
            "kind",
            "status",
            "elapsed_ns",
            "max_bytes",
            "text_requested",
            "snapshot",
            "execution_attested",
        },
        "read record",
    )
    if type(row["schema_version"]) is not int or row["schema_version"] != 1:
        raise ValueError("unsupported read trace version")
    if row["kind"] != "workspace-read" or row["execution_attested"] is not False:
        raise ValueError("invalid read trace declaration")
    if row["status"] not in ("succeeded", "denied", "failed"):
        raise ValueError("invalid read status")
    if type(row["elapsed_ns"]) is not int or not 0 <= row["elapsed_ns"] <= 2**63 - 1:
        raise ValueError("invalid read duration")
    if type(row["max_bytes"]) is not int or not 1 <= row["max_bytes"] <= HARD_MAX_BYTES:
        raise ValueError("invalid read limit")
    if type(row["text_requested"]) is not bool:
        raise ValueError("invalid text declaration")
    snapshot = row["snapshot"]
    if row["status"] == "succeeded":
        snapshot = _object(snapshot, {"bytes", "sha256"}, "read snapshot")
        if (
            type(snapshot["bytes"]) is not int
            or not 0 <= snapshot["bytes"] <= row["max_bytes"]
        ):
            raise ValueError("invalid snapshot size")
        if not isinstance(snapshot["sha256"], str) or not re.fullmatch(
            r"[0-9a-f]{64}", snapshot["sha256"]
        ):
            raise ValueError("invalid snapshot digest")
        if (
            snapshot["bytes"] == 0
            and snapshot["sha256"] != hashlib.sha256(b"").hexdigest()
        ):
            raise ValueError("invalid empty snapshot digest")
    elif snapshot is not None:
        raise ValueError("unsuccessful read cannot expose snapshot metadata")
    raw = json.dumps(row, sort_keys=True, allow_nan=False).encode("utf-8")
    if len(raw) > MAX_RECORD_BYTES:
        raise ValueError("read record exceeds 4 KiB")
    detached: dict[str, Any] = json.loads(raw)
    return detached


def read_record(path: str | Path) -> dict[str, Any]:
    raw = _read_bytes(path, MAX_RECORD_BYTES)
    if len(raw) > MAX_RECORD_BYTES:
        raise ValueError("read record exceeds 4 KiB")
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant
        )
    except RecursionError as exc:
        raise ValueError("read record nesting is too deep") from exc
    return validate_record(value)


def run_read(
    root: str | Path,
    relative_path: str,
    *,
    record: str | Path,
    allowed: list[str],
    include_text: bool = False,
    max_bytes: int = 65536,
) -> dict[str, Any]:
    """Perform one read and publish metadata only; never return raw content.

    Invalid reporting configuration fails before reading. Expected read failures
    become coarse outcomes; no exception message or filename enters the record.
    Publication failure raises and does not return a successful trace. A read can
    already have occurred before publication fails; no transactional read is claimed.
    """
    base = {
        "schema_version": 1,
        "kind": "workspace-read",
        "status": "failed",
        "elapsed_ns": 0,
        "max_bytes": max_bytes,
        "text_requested": include_text,
        "snapshot": None,
        "execution_attested": False,
    }
    validate_record(base)
    start = time.monotonic_ns()
    try:
        result = read_snapshot(
            root,
            relative_path,
            allowed=allowed,
            include_text=include_text,
            max_bytes=max_bytes,
        )
    except PermissionError:
        base["status"] = "denied"
    except (OSError, ValueError):
        base["status"] = "failed"
    else:
        base["status"] = "succeeded"
        base["snapshot"] = {"bytes": result["bytes"], "sha256": result["sha256"]}
    base["elapsed_ns"] = time.monotonic_ns() - start
    row = validate_record(base)
    _publish_bytes(
        record, (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
    )
    return row


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("path")
    parser.add_argument("--record", required=True)
    parser.add_argument("--allow", action="append", default=[])
    parser.add_argument("--include-text", action="store_true")
    parser.add_argument("--max-bytes", type=int, default=65536)
    args = parser.parse_args()
    try:
        row = run_read(
            args.root,
            args.path,
            record=args.record,
            allowed=args.allow,
            include_text=args.include_text,
            max_bytes=args.max_bytes,
        )
    except (OSError, ValueError):
        print(
            "Read trace failed: invalid configuration or record destination.",
            file=sys.stderr,
        )
        return 2
    print(json.dumps(row, sort_keys=True))
    return 0 if row["status"] == "succeeded" else 1


if __name__ == "__main__":
    raise SystemExit(main())
