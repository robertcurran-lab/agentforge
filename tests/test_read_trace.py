import hashlib
import json
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agentforge.read_trace import read_record, run_read, validate_record


class ReadTraceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.source = self.workspace / "private-name.txt"
        self.source.write_text("private-content-marker")
        self.record = self.root / "record.json"

    def run_read(self, **kwargs):
        options = dict(record=self.record, allowed=["repo.read"])
        options.update(kwargs)
        return run_read(self.workspace, self.source.name, **options)

    def test_success_same_read_metadata_without_content_or_paths(self):
        row = self.run_read(include_text=True)
        self.assertEqual(row["status"], "succeeded")
        self.assertEqual(
            row["snapshot"],
            {
                "bytes": 22,
                "sha256": hashlib.sha256(self.source.read_bytes()).hexdigest(),
            },
        )
        self.assertEqual(read_record(self.record), row)
        raw = self.record.read_text()
        for marker in [str(self.root), self.source.name, "private-content-marker"]:
            self.assertNotIn(marker, raw)
        self.assertFalse(row["execution_attested"])
        self.assertEqual(stat.S_IMODE(self.record.stat().st_mode), 0o600)

    def test_capability_denial_precedes_source_opens(self):
        with patch(
            "agentforge.workspace_read.os.open", side_effect=AssertionError("opened")
        ):
            # The record publisher also opens files; patch only the actual source call.
            with patch("agentforge.read_trace._publish_bytes") as publish:
                row = self.run_read(allowed=[])
        self.assertEqual(row["status"], "denied")
        self.assertIsNone(row["snapshot"])
        self.assertEqual(publish.call_count, 1)

    def test_failure_and_denial_messages_are_redacted(self):
        for failure, status in [
            (PermissionError("secret-path"), "denied"),
            (OSError("private-host-error"), "failed"),
            (ValueError("private-utf8-error"), "failed"),
        ]:
            with self.subTest(status=status):
                self.record.unlink(missing_ok=True)
                with patch("agentforge.read_trace.read_snapshot", side_effect=failure):
                    row = self.run_read()
                self.assertEqual(row["status"], status)
                self.assertIsNone(row["snapshot"])
                self.assertNotIn(str(failure), self.record.read_text())

    def test_missing_invalid_utf8_and_byte_limit(self):
        self.source.unlink()
        self.assertEqual(self.run_read()["status"], "failed")
        self.record.unlink()
        self.source.write_bytes(b"\xff")
        self.assertEqual(self.run_read(include_text=True)["status"], "failed")
        self.record.unlink()
        self.source.write_bytes(b"123")
        self.assertEqual(self.run_read(max_bytes=2)["status"], "failed")

    def test_invalid_reporting_config_does_not_read_or_publish(self):
        with patch("agentforge.read_trace.read_snapshot") as read:
            for kwargs in [{"max_bytes": True}, {"max_bytes": 0}, {"include_text": 1}]:
                with self.assertRaises(ValueError):
                    self.run_read(**kwargs)
            read.assert_not_called()
        self.assertFalse(self.record.exists())

    def test_publication_failure_never_returns_success(self):
        self.record.write_text("keep")
        with self.assertRaises(FileExistsError):
            self.run_read()
        self.assertEqual(self.record.read_text(), "keep")
        with patch("agentforge.read_trace._publish_bytes", side_effect=OSError("disk")):
            with self.assertRaises(OSError):
                self.run_read()
        self.assertEqual(self.source.read_text(), "private-content-marker")

    def test_strict_schema_unknown_fields_bad_types_and_duplicate_keys(self):
        row = self.run_read()
        for change in [
            {"path": "secret"},
            {"schema_version": True},
            {"execution_attested": True},
            {"elapsed_ns": True},
            {"status": "denied"},
            {"snapshot": {"bytes": True, "sha256": "0" * 64}},
        ]:
            with self.assertRaises(ValueError):
                validate_record(dict(row, **change))
        self.record.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaises(ValueError):
            read_record(self.record)

    def test_cli_metadata_only_exit_status_and_no_partial_success(self):
        args = [
            sys.executable,
            "-m",
            "agentforge.read_trace",
            "--root",
            str(self.workspace),
            self.source.name,
            "--record",
            str(self.record),
            "--allow",
            "repo.read",
        ]
        done = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout)["status"], "succeeded")
        self.assertNotIn("private-content-marker", done.stdout)
        conflict = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(conflict.returncode, 2)
        self.assertEqual(conflict.stdout, "")
        self.record.unlink()
        denied = subprocess.run(args[:-2], capture_output=True, text=True)
        self.assertEqual(denied.returncode, 1)
        self.assertEqual(json.loads(denied.stdout)["status"], "denied")
