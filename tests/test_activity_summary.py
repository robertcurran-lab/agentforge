import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agentforge.activity_summary import MAX_RECORD_BYTES, summarize
from agentforge.batch_read import run_batch
from agentforge.isolation import run_probe
from agentforge.read_trace import run_read
from agentforge.trace import write_record


class ActivitySummaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        (self.workspace / "note.txt").write_text("private-content-marker")
        self.paths = []

    def fixtures(self):
        with patch("agentforge.isolation.sys.platform", "unsupported"):
            record = run_probe("smoke")["record"]
        probe = self.root / "probe.json"
        write_record(probe, record)
        success = self.root / "success.json"
        run_read(
            self.workspace,
            "note.txt",
            record=success,
            allowed=["repo.read"],
            include_text=True,
        )
        denied = self.root / "denied.json"
        run_read(self.workspace, "note.txt", record=denied, allowed=[])
        failed = self.root / "failed.json"
        run_read(self.workspace, "missing", record=failed, allowed=["repo.read"])
        batch = self.root / "batch.json"
        run_batch(
            self.workspace,
            ["note.txt", "missing", ".env"],
            record=batch,
            allowed=["repo.read"],
            include_text=True,
        )
        return [probe, success, denied, failed, batch]

    def test_real_records_keep_kind_status_bytes_and_duration_semantics(self):
        paths = self.fixtures()
        before = {p: p.read_bytes() for p in paths}
        report = summarize(paths)
        self.assertEqual(report, summarize(list(reversed(paths))))
        self.assertEqual(report["records"], 5)
        kinds = report["by_kind"]
        self.assertEqual(kinds["probe"]["status_counts"]["denied"], 1)
        self.assertEqual(
            kinds["workspace-read"]["status_counts"],
            {"succeeded": 1, "denied": 1, "failed": 1},
        )
        self.assertEqual(
            kinds["workspace-read-batch"]["status_counts"],
            {"succeeded": 1, "denied": 1, "failed": 1},
        )
        self.assertIsNone(kinds["workspace-read-batch"]["elapsed_ns"])
        self.assertEqual(
            kinds["workspace-read"]["declared_snapshot_bytes"],
            len(b"private-content-marker"),
        )
        self.assertEqual(
            kinds["workspace-read-batch"]["declared_snapshot_bytes"],
            len(b"private-content-marker"),
        )
        self.assertIsNone(kinds["probe"]["declared_snapshot_bytes"])
        self.assertIsNone(kinds["workspace-read"]["declared_output_bytes"])
        self.assertFalse(report["execution_attested"])
        text = json.dumps(report)
        for marker in [
            "private-content-marker",
            str(self.workspace),
            "note.txt",
            "missing",
            ".env",
        ]:
            self.assertNotIn(marker, text)
        self.assertEqual(before, {p: p.read_bytes() for p in paths})

    def test_repeated_paths_raw_and_canonical_declarations_rejected(self):
        path = self.fixtures()[1]
        with self.assertRaises(ValueError):
            summarize([path, path])
        copied = self.root / "copied.json"
        copied.write_bytes(path.read_bytes())
        with self.assertRaises(ValueError):
            summarize([path, copied])
        row = json.loads(path.read_text())
        copied.write_text(json.dumps(dict(reversed(list(row.items()))), indent=4))
        self.assertNotEqual(copied.read_bytes(), path.read_bytes())
        with self.assertRaises(ValueError):
            summarize([path, copied])

    def test_same_read_hash_and_single_read(self):
        import hashlib

        raw = self.fixtures()[1].read_bytes()
        with patch(
            "agentforge.activity_summary._read_bytes", return_value=raw
        ) as reader:
            report = summarize(["synthetic-record.json"])
        reader.assert_called_once_with("synthetic-record.json", MAX_RECORD_BYTES)
        self.assertEqual(
            report["entries"][0]["source_sha256"], hashlib.sha256(raw).hexdigest()
        )

    def test_unknown_kind_invalid_schema_duplicate_keys_and_nonfinite_rejected(self):
        path = self.root / "invalid.json"
        for text in [
            '{"kind":"unknown"}',
            '{"kind":[]}',
            "[]",
            '{"kind":"workspace-read","kind":"workspace-read"}',
            '{"value":NaN}',
            '{"scenario":"smoke"}',
        ]:
            path.write_text(text)
            with self.assertRaises(ValueError):
                summarize([path])

    def test_bounds_and_kind_specific_raw_limits(self):
        paths = self.fixtures()
        for value in [[], "one.json", [1], paths * 21]:
            with self.assertRaises(ValueError):
                summarize(value)
        with patch("agentforge.activity_summary.MAX_RECORD_BYTES", 10):
            with self.assertRaises(ValueError):
                summarize([paths[0]])
        raw = paths[1].read_bytes()
        paths[1].write_bytes(raw + b" " * 4096)
        with self.assertRaises(ValueError):
            summarize([paths[1]])

    def test_fifo_symlink_and_cli_fail_without_partial_or_path_disclosure(self):
        path = self.fixtures()[0]
        alias = self.root / "alias.json"
        alias.symlink_to(path)
        with self.assertRaises(OSError):
            summarize([alias])
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        result = subprocess.run(
            [sys.executable, "-m", "agentforge.activity_summary", str(fifo)],
            capture_output=True,
            text=True,
            timeout=3,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertNotIn(str(self.root), result.stderr)

    def test_actual_cli_succeeds_with_mixed_saved_records(self):
        paths = self.fixtures()
        result = subprocess.run(
            [sys.executable, "-m", "agentforge.activity_summary", *map(str, paths)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), summarize(paths))
