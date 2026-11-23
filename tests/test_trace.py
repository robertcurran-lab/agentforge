import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agentforge.isolation import _capture, run_probe
from agentforge.trace import (
    MAX_RECORD_BYTES,
    read_record,
    record_result,
    validate_record,
)


def captured(status="succeeded", started=True, code=0):
    output = b"synthetic secret /private/host/path\n"
    return {
        "trace": ["requested"] + (["started"] if started else []) + [status],
        "returncode": code,
        "captured_bytes": len(output),
        "output_sha256": hashlib.sha256(output).hexdigest(),
        "output": output.decode(),
        "host_canary_unchanged": True,
    }


class TraceTests(unittest.TestCase):
    def record(self, result=None, scenario="smoke"):
        return record_result(
            captured() if result is None else result,
            scenario=scenario,
            timeout=3,
            output_limit=8192,
            elapsed_ns=123,
            probe_sha256="a" * 64,
        )

    def test_success_record_is_redacted_not_attested_and_detached(self):
        result = captured()
        row = self.record(result)
        self.assertFalse(row["execution_attested"])
        self.assertEqual(row["process_returncode"], 0)
        self.assertNotIn("secret", json.dumps(row))
        self.assertNotIn("/private", json.dumps(row))
        self.assertNotIn("output", row)
        self.assertEqual(row["capture"]["sha256"], result["output_sha256"])
        result["trace"][0] = "forged"
        self.assertEqual(row["events"][0]["kind"], "requested")

    def test_denied_and_pre_cancelled_records_have_no_capture_or_start(self):
        for status in ["denied", "cancelled"]:
            result = {"trace": ["requested", status], "reason": "private host path"}
            row = self.record(result)
            self.assertIsNone(row["capture"])
            self.assertIsNone(row["process_returncode"])
            self.assertNotIn("private", json.dumps(row))

    def test_timeout_cancellation_output_and_failure_lifecycles(self):
        for status, code in [
            ("timeout", -9),
            ("cancelled", -9),
            ("output_limit", -9),
            ("failed", 1),
        ]:
            with self.subTest(status=status):
                row = self.record(captured(status, code=code))
                self.assertEqual(row["events"][-1]["kind"], status)
        self.record(captured("timeout", started=False, code=-9))

    def test_contradictory_lifecycle_and_exit_codes_are_rejected(self):
        for result in [
            captured("succeeded", False),
            captured("denied", True, 1),
            captured("succeeded", True, 1),
            captured("failed", True, 0),
        ]:
            with self.subTest(result=result), self.assertRaises(ValueError):
                self.record(result)
        for kinds in [
            ["requested", "started", "started", "succeeded"],
            ["started", "succeeded"],
            ["requested", "running"],
            ["requested", "cancelled", "succeeded"],
        ]:
            row = self.record()
            row["events"] = [
                {"sequence": i, "kind": kind} for i, kind in enumerate(kinds)
            ]
            with self.subTest(kinds=kinds), self.assertRaises(ValueError):
                validate_record(row)

    def test_unknown_fields_versions_attestation_and_observations_fail(self):
        row = self.record()
        for field, value in [
            ("schema_version", True),
            ("schema_version", 2),
            ("execution_attested", True),
            ("elapsed_ns", -1),
            ("process_returncode", False),
            ("output", "secret"),
        ]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_record(dict(row, **{field: value}))
        row["events"][0]["sequence"] = True
        with self.assertRaises(ValueError):
            validate_record(row)
        row = self.record()
        row["observations"]["descendant_marker_absent"] = True
        with self.assertRaises(ValueError):
            validate_record(row)

    def test_capture_limits_hashes_and_redaction_marker(self):
        for field, value in [
            ("bytes", True),
            ("bytes", 8193),
            ("sha256", "a" * 63),
            ("redacted", False),
            ("raw", "secret"),
        ]:
            row = self.record()
            row["capture"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_record(row)
        for timeout in [True, float("nan"), float("inf"), 11]:
            row = self.record()
            row["limits"]["timeout_seconds"] = timeout
            with self.assertRaises(ValueError):
                validate_record(row)

    def test_raw_invalid_utf8_capture_is_counted_and_hashed_before_replacement(self):
        raw = b"\xff" * 1024
        status, _, text, started, count, digest = _capture(
            [sys.executable, "-c", "import os; os.write(1,b'\\xff'*1024)"],
            timeout=3,
            limit=512,
            cancel=None,
        )
        self.assertEqual(status, "output_limit")
        self.assertFalse(started)
        self.assertEqual(count, 512)
        self.assertEqual(digest, hashlib.sha256(raw[:512]).hexdigest())
        self.assertGreater(len(text.encode()), count)

    def test_strict_bounded_record_reader(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "trace.json"
            row = self.record()
            path.write_text(json.dumps(row))
            self.assertEqual(read_record(path), row)
            for raw in [
                b'{"schema_version":1,"schema_version":1}',
                b'{"x":NaN}',
                b"\xff",
                json.dumps(row).encode("utf-16"),
                b" " * (MAX_RECORD_BYTES + 1),
            ]:
                path.write_bytes(raw)
                with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                    read_record(path)

    def test_actual_unsupported_probe_and_record_only_cli(self):
        with patch("agentforge.isolation.sys.platform", "unsupported"):
            result = run_probe("smoke")
        self.assertEqual(validate_record(result["record"]), result["record"])
        self.assertEqual(result["record"]["events"][-1]["kind"], "denied")
        process = subprocess.run(
            [sys.executable, "-m", "agentforge.isolation", "smoke", "--record-only"],
            capture_output=True,
            text=True,
        )
        self.assertIn(process.returncode, (0, 3), process.stderr)
        record = validate_record(json.loads(process.stdout))
        self.assertFalse(record["execution_attested"])
        self.assertNotIn("output", record)


if __name__ == "__main__":
    unittest.main()
