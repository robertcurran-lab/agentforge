import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agentforge.isolation import run_probe
from agentforge.trace import (
    MAX_RECORD_BYTES,
    read_record_snapshot,
    record_result,
    write_record,
)
from agentforge.trace_summary import MAX_INPUTS, summarize


def synthetic_record(status, duration, *, started=True, scenario="smoke"):
    """Test declarations only, not evidence that these workloads executed."""
    result = {"trace": ["requested"] + (["started"] if started else []) + [status]}
    if started or status in {"timeout", "output_limit"}:
        result.update(
            returncode=0 if status == "succeeded" else -9,
            captured_bytes=0,
            output_sha256=hashlib.sha256(b"").hexdigest(),
        )
    return record_result(
        result,
        scenario=scenario,
        timeout=3,
        output_limit=8192,
        elapsed_ns=duration,
        probe_sha256="a" * 64,
    )


class SummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def save(self, name, row):
        path = self.root / name
        write_record(path, row)
        return path

    def test_status_duration_bounds_and_deterministic_input_order(self):
        paths = [
            self.save(
                status + ".json",
                synthetic_record(status, index + 1, started=status != "denied"),
            )
            for index, status in enumerate(
                [
                    "succeeded",
                    "failed",
                    "denied",
                    "timeout",
                    "output_limit",
                    "cancelled",
                ]
            )
        ]
        report = summarize(paths)
        self.assertEqual(report, summarize(list(reversed(paths))))
        self.assertEqual(report["records"], 6)
        self.assertTrue(all(count == 1 for count in report["terminal_counts"].values()))
        self.assertEqual(
            report["elapsed_ns"], {"total": 21, "minimum": 1, "maximum": 6}
        )
        self.assertEqual(report["input_bounds"]["bytes_per_record"], MAX_RECORD_BYTES)
        self.assertFalse(report["execution_attested"])
        self.assertEqual(
            [row["source_sha256"] for row in report["entries"]],
            sorted(hashlib.sha256(path.read_bytes()).hexdigest() for path in paths),
        )

    def test_saved_actual_denied_probe_can_be_summarized_without_execution_claim(self):
        if sys.platform == "darwin":
            row = run_probe("smoke")["record"]
        else:
            with patch("agentforge.isolation.sys.platform", "unsupported"):
                row = run_probe("smoke")["record"]
        path = self.save("observed-denial.json", row)
        report = summarize([path])
        self.assertEqual(report["terminal_counts"]["denied"], 1)
        self.assertFalse(report["entries"][0]["started"])
        self.assertFalse(report["execution_attested"])

    def test_source_digest_uses_exact_same_read_snapshot(self):
        row = synthetic_record("denied", 1, started=False)
        raw = json.dumps(row, indent=2).encode()
        different = json.dumps(dict(row, elapsed_ns=999)).encode()
        with patch(
            "agentforge.trace._read_bytes", side_effect=[raw, different]
        ) as reader:
            report = summarize([self.root / "not-opened.json"])
        self.assertEqual(reader.call_count, 1)
        self.assertEqual(
            report["entries"][0]["source_sha256"], hashlib.sha256(raw).hexdigest()
        )
        self.assertEqual(report["elapsed_ns"]["total"], 1)
        with patch("agentforge.trace._read_bytes", return_value=raw):
            record, digest = read_record_snapshot("ignored")
        self.assertEqual(record, row)
        self.assertEqual(digest, hashlib.sha256(raw).hexdigest())

    def test_duplicate_path_raw_digest_and_reencoded_declaration_are_rejected(self):
        row = synthetic_record("denied", 1, started=False)
        first = self.save("first.json", row)
        with self.assertRaisesRegex(ValueError, "duplicate input path"):
            summarize([first, first])
        copied = self.root / "copy.json"
        copied.write_bytes(first.read_bytes())
        with self.assertRaisesRegex(ValueError, "duplicate raw trace digest"):
            summarize([first, copied])
        pretty = self.root / "pretty.json"
        pretty.write_text(json.dumps(row, indent=2))
        with self.assertRaisesRegex(ValueError, "duplicate canonical"):
            summarize([first, pretty])
        linked = self.root / "linked.json"
        os.link(first, linked)
        with self.assertRaisesRegex(ValueError, "duplicate raw"):
            summarize([first, linked])

    def test_zero_many_inputs_and_missing_files_fail(self):
        for inputs in [[], ["ignored"] * (MAX_INPUTS + 1), "not-a-list"]:
            with self.assertRaises(ValueError):
                summarize(inputs)
        with self.assertRaises(OSError):
            summarize([self.root / "missing.json"])

    def test_malformed_inconsistent_oversized_inputs_are_not_skipped(self):
        valid = self.save("valid.json", synthetic_record("denied", 1, started=False))
        invalid = self.root / "invalid.json"
        malformed = synthetic_record("succeeded", 2)
        malformed["process_returncode"] = 1
        for raw in [
            b"\xff",
            b'{"x":NaN}',
            b'{"schema_version":1,"schema_version":1}',
            json.dumps(malformed).encode(),
            b" " * (MAX_RECORD_BYTES + 1),
        ]:
            invalid.write_bytes(raw)
            with self.subTest(raw=raw[:30]), self.assertRaises(ValueError):
                summarize([valid, invalid])

    def test_symlink_directory_fifo_paths_are_rejected_without_crawling(self):
        path = self.save("valid.json", synthetic_record("denied", 1, started=False))
        alias = self.root / "alias.json"
        alias.symlink_to(path)
        for invalid in [alias, self.root]:
            with self.assertRaises((OSError, ValueError)):
                summarize([invalid])
        fifo = self.root / "pipe"
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            summarize([fifo])

    def test_report_omits_paths_raw_values_and_arbitrary_observations(self):
        path = self.save("private-prompt-secret.json", synthetic_record("succeeded", 1))
        report = json.dumps(summarize([path]))
        self.assertNotIn("private", report)
        self.assertNotIn("secret", report)
        self.assertNotIn(str(self.root), report)
        self.assertNotIn('"output"', report)
        self.assertNotIn('"observations"', report)

    def test_large_declared_durations_are_exact_integer_observations(self):
        first = self.save(
            "a.json", synthetic_record("denied", 2**63 - 1, started=False)
        )
        second = self.save(
            "b.json", synthetic_record("cancelled", 2**63 - 2, started=False)
        )
        report = summarize([first, second])
        self.assertEqual(report["elapsed_ns"]["total"], 2**64 - 3)
        self.assertIs(type(report["elapsed_ns"]["total"]), int)

    def test_cli_roundtrip_redaction_and_failure_have_no_partial_stdout(self):
        path = self.save("one.json", synthetic_record("denied", 1, started=False))
        command = [sys.executable, "-m", "agentforge.trace_summary", str(path)]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), summarize([path]))
        for extra in [str(path), str(self.root / "private-missing.json")]:
            failure = subprocess.run(command + [extra], capture_output=True, text=True)
            self.assertEqual(failure.returncode, 2)
            self.assertEqual(failure.stdout, "")
            self.assertNotIn(str(self.root), failure.stderr)


if __name__ == "__main__":
    unittest.main()
