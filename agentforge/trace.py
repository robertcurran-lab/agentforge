"""Strict redacted probe records; validation is not execution attestation."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path
from typing import Any

from .record_files import _publish_bytes, _read_bytes

SCENARIOS = frozenset({"smoke", "boundaries", "wait", "flood", "descendants"})
TERMINALS = frozenset(
    {"succeeded", "failed", "denied", "timeout", "output_limit", "cancelled"}
)
MAX_RECORD_BYTES = 8192


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"invalid {label} fields")
    return value


def validate_record(value: Any) -> dict[str, Any]:
    """Validate declared record structure and return a detached copy.

    No record, whether local or imported, proves that a workload actually ran.
    Sequence numbers describe event order, not wall-clock dates or signatures.
    """
    row = _object(
        value,
        {
            "schema_version",
            "scenario",
            "limits",
            "elapsed_ns",
            "events",
            "capture",
            "observations",
            "execution_attested",
            "process_returncode",
            "probe_sha256",
        },
        "record",
    )
    if type(row["schema_version"]) is not int or row["schema_version"] != 1:
        raise ValueError("unsupported trace schema")
    if not isinstance(row["scenario"], str) or row["scenario"] not in SCENARIOS:
        raise ValueError("invalid trace scenario")
    if not isinstance(row["probe_sha256"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", row["probe_sha256"]
    ):
        raise ValueError("invalid bundled-probe SHA-256")
    if row["execution_attested"] is not False:
        raise ValueError("trace records cannot attest execution")
    if type(row["elapsed_ns"]) is not int or not 0 <= row["elapsed_ns"] <= 2**63 - 1:
        raise ValueError("invalid elapsed duration")
    limits = _object(row["limits"], {"timeout_seconds", "output_bytes"}, "limits")
    timeout = limits["timeout_seconds"]
    if (
        type(timeout) not in (int, float)
        or not 0 < timeout <= 10
        or not math.isfinite(timeout)
    ):
        raise ValueError("invalid trace timeout")
    maximum = limits["output_bytes"]
    if type(maximum) is not int or not 512 <= maximum <= 65536:
        raise ValueError("invalid output limit")
    events = row["events"]
    if not isinstance(events, list) or len(events) not in (2, 3):
        raise ValueError(
            "trace requires request, optional start and one terminal event"
        )
    kinds = []
    for index, event in enumerate(events):
        event = _object(event, {"sequence", "kind"}, "event")
        if type(event["sequence"]) is not int or event["sequence"] != index:
            raise ValueError("event sequence must be contiguous from zero")
        if not isinstance(event["kind"], str):
            raise ValueError("event kind must be a string")
        kinds.append(event["kind"])
    terminal = kinds[-1]
    if terminal not in TERMINALS or kinds[0] != "requested":
        raise ValueError("invalid lifecycle endpoints")
    started = len(kinds) == 3
    if started and kinds[1] != "started":
        raise ValueError("invalid intermediate lifecycle event")
    if terminal in {"succeeded", "failed"} and not started:
        raise ValueError("success or workload failure requires observed start")
    if terminal == "denied" and started:
        raise ValueError("denied execution cannot have started")
    code = row["process_returncode"]
    if code is not None and (type(code) is not int or not -255 <= code <= 255):
        raise ValueError("invalid process return code")
    if terminal == "succeeded" and code != 0:
        raise ValueError("success requires process exit zero")
    if terminal == "failed" and (code is None or code == 0):
        raise ValueError("workload failure requires a nonzero process exit")
    capture = row["capture"]
    if capture is not None:
        if code is None:
            raise ValueError("captured launch requires a process return code")
        capture = _object(capture, {"bytes", "sha256", "redacted"}, "capture")
        if type(capture["bytes"]) is not int or not 0 <= capture["bytes"] <= maximum:
            raise ValueError("captured bytes exceed the declared bound")
        if not isinstance(capture["sha256"], str) or not re.fullmatch(
            r"[0-9a-f]{64}", capture["sha256"]
        ):
            raise ValueError("invalid capture SHA-256")
        if (
            capture["bytes"] == 0
            and capture["sha256"] != hashlib.sha256(b"").hexdigest()
        ):
            raise ValueError("empty capture requires the empty-byte digest")
        if capture["redacted"] is not True:
            raise ValueError("records must omit raw captured output")
    elif code is not None or started or terminal in {"timeout", "output_limit"}:
        raise ValueError("started or bounded execution requires capture provenance")
    observations = _object(
        row["observations"],
        {"host_canary_unchanged", "descendant_marker_absent"},
        "observations",
    )
    if any(
        value is not None and type(value) is not bool for value in observations.values()
    ):
        raise ValueError("observations must be boolean or null")
    if observations["descendant_marker_absent"] is not None and (
        row["scenario"] != "descendants" or not started
    ):
        raise ValueError("descendant observation requires the started descendant probe")
    if observations["host_canary_unchanged"] is not None and capture is None:
        raise ValueError("canary observation requires a captured launch")
    detached: dict[str, Any] = json.loads(json.dumps(row, allow_nan=False))
    if len(json.dumps(detached, sort_keys=True).encode("utf-8")) > MAX_RECORD_BYTES:
        raise ValueError("trace record exceeds 8 KiB")
    return detached


def record_result(
    result: dict[str, Any],
    *,
    scenario: str,
    timeout: float,
    output_limit: int,
    elapsed_ns: int,
    probe_sha256: str,
) -> dict[str, Any]:
    """Build a redacted record from supervisor observations, without attestation."""
    capture = None
    if "output_sha256" in result:
        capture = {
            "bytes": result["captured_bytes"],
            "sha256": result["output_sha256"],
            "redacted": True,
        }
    return validate_record(
        {
            "schema_version": 1,
            "scenario": scenario,
            "limits": {"timeout_seconds": timeout, "output_bytes": output_limit},
            "elapsed_ns": elapsed_ns,
            "events": [
                {"sequence": index, "kind": kind}
                for index, kind in enumerate(result["trace"])
            ],
            "capture": capture,
            "observations": {
                key: result.get(key)
                for key in ("host_canary_unchanged", "descendant_marker_absent")
            },
            "execution_attested": False,
            "process_returncode": result.get("returncode"),
            "probe_sha256": probe_sha256,
        }
    )


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ValueError("non-finite JSON constant")


def read_record_snapshot(path: str | Path) -> tuple[dict[str, Any], str]:
    """Validate and hash the same bounded byte snapshot, never rereading a path."""
    raw = _read_bytes(path, MAX_RECORD_BYTES)
    if len(raw) > MAX_RECORD_BYTES:
        raise ValueError("trace record exceeds 8 KiB")
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant
        )
    except RecursionError as exc:
        raise ValueError("trace nesting is too deep") from exc
    return validate_record(value), hashlib.sha256(raw).hexdigest()


def read_record(path: str | Path) -> dict[str, Any]:
    """Read one bounded strict UTF-8 record, not an executable instruction file."""
    return read_record_snapshot(path)[0]


def write_record(path: str | Path, value: Any) -> None:
    """Validate first, then publish a mode-0600 no-clobber complete record."""
    record = validate_record(value)
    payload = (
        json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("utf-8")
    if len(payload) > MAX_RECORD_BYTES:
        raise ValueError("trace record exceeds 8 KiB")
    _publish_bytes(path, payload)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate one bounded redacted probe record"
    )
    parser.add_argument("record")
    args = parser.parse_args()
    try:
        record = read_record(args.record)
    except (OSError, ValueError) as exc:
        print(f"trace validation failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(record, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
