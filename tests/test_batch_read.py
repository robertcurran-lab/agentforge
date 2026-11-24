import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agentforge.batch_read import read_batch, read_record, run_batch, validate_record


class BatchReadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        (self.root / "one.txt").write_text("private-content-marker")
        (self.root / "two.txt").write_bytes(b"abc")
        self.record = self.root / "record.json"

    def run_batch(self, paths=None, **kwargs):
        return run_batch(
            self.root,
            paths or ["one.txt", "two.txt"],
            record=self.record,
            allowed=["repo.read"],
            **kwargs,
        )

    def test_actual_bytes_text_optin_and_private_redacted_record(self):
        entries = read_batch(self.root, ["one.txt", "two.txt"], allowed=["repo.read"])
        self.assertNotIn("text", entries[0]["snapshot"])
        text = read_batch(
            self.root, ["one.txt"], allowed=["repo.read"], include_text=True
        )
        self.assertEqual(text[0]["snapshot"]["text"], "private-content-marker")
        row = self.run_batch(include_text=True)
        self.assertEqual(row["counts"], {"succeeded": 2, "denied": 0, "failed": 0})
        self.assertEqual(
            row["entries"][1]["snapshot"]["sha256"], hashlib.sha256(b"abc").hexdigest()
        )
        encoded = self.record.read_text()
        for marker in ("private-content-marker", "one.txt", "two.txt", str(self.root)):
            self.assertNotIn(marker, encoded)
        self.assertEqual(read_record(self.record), row)
        self.assertEqual(stat.S_IMODE(self.record.stat().st_mode), 0o600)

    def test_capabilities_and_configuration_denied_before_any_open(self):
        with patch("os.open", side_effect=AssertionError("filesystem opened")):
            with self.assertRaises(PermissionError):
                read_batch(self.root, ["one.txt"], allowed=[])
            for paths, options in [
                (["one.txt"] * 2, {}),
                (["../outside"], {}),
                (["one.txt"] * 17, {}),
                (["one.txt"], {"max_bytes": True}),
                (["one.txt"], {"total_budget": 10}),
                (["one.txt"], {"include_text": 1}),
            ]:
                with self.assertRaises(ValueError):
                    read_batch(self.root, paths, allowed=["repo.read"], **options)

    def test_retained_denial_missing_validation_and_success(self):
        (self.root / "binary").write_bytes(b"\xff")
        row = self.run_batch(
            [".env", "missing", "binary", "two.txt"], include_text=True
        )
        self.assertEqual(row["counts"], {"succeeded": 1, "denied": 1, "failed": 2})
        self.assertEqual([r["index"] for r in row["entries"]], list(range(4)))
        self.assertEqual(
            [r["error"]["type"] for r in row["entries"][:3]],
            ["permission", "io", "validation"],
        )
        self.assertEqual(sum(row["counts"].values()), 4)

    def test_reserved_budget_bounds_all_growth_detection_reads(self):
        (self.root / "one.txt").write_bytes(b"abc")
        (self.root / "two.txt").write_bytes(b"def")
        calls = []
        original = os.read

        def observed(fd, length):
            raw = original(fd, length)
            calls.append(len(raw))
            return raw

        with patch("agentforge.workspace_read.os.read", side_effect=observed):
            row = self.run_batch(max_bytes=3, total_budget=8)
        self.assertEqual(row["reserved_bytes"], 8)
        self.assertLessEqual(sum(calls), 8)
        with self.assertRaises(ValueError):
            read_batch(
                self.root,
                ["one.txt", "two.txt"],
                allowed=["repo.read"],
                max_bytes=3,
                total_budget=7,
            )

    def test_failed_special_files_and_symlinks_do_not_block(self):
        os.mkfifo(self.root / "pipe")
        (self.root / "link").symlink_to(self.root / "two.txt")
        row = self.run_batch(["pipe", "link", "two.txt"])
        self.assertEqual(row["counts"]["succeeded"], 1)
        self.assertEqual(row["counts"]["failed"], 2)

    def test_no_overwrite_publication_failure_does_not_report_success(self):
        self.record.write_text("keep")
        with self.assertRaises(FileExistsError):
            self.run_batch()
        self.assertEqual(self.record.read_text(), "keep")
        self.record.unlink()
        with patch(
            "agentforge.batch_read._publish_bytes",
            side_effect=OSError("secret-error-marker"),
        ):
            with self.assertRaises(OSError):
                self.run_batch()
        self.assertFalse(self.record.exists())

    def test_strict_record_validation(self):
        row = self.run_batch()
        for field, value in [
            ("reserved_bytes", True),
            ("text_requested", 1),
            ("execution_attested", True),
            ("extra", "secret"),
        ]:
            bad = dict(row, **{field: value})
            with self.assertRaises(ValueError):
                validate_record(bad)
        bad = json.loads(json.dumps(row))
        bad["entries"][0]["snapshot"]["text"] = "secret"
        with self.assertRaises(ValueError):
            validate_record(bad)
        bad = json.loads(json.dumps(row))
        bad["counts"]["succeeded"] = 1
        with self.assertRaises(ValueError):
            validate_record(bad)

    def test_cli_metadata_only_exit_codes_and_source_immutability(self):
        original = (self.root / "one.txt").read_bytes()
        args = [
            sys.executable,
            "-m",
            "agentforge.batch_read",
            "--root",
            str(self.root),
            "one.txt",
            "missing",
            "--record",
            str(self.record),
            "--allow",
            "repo.read",
            "--include-text",
        ]
        done = subprocess.run(args, capture_output=True, text=True, timeout=10)
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertEqual(json.loads(done.stdout)["counts"]["failed"], 1)
        self.assertNotIn("private-content-marker", done.stdout)
        conflict = subprocess.run(args, capture_output=True, text=True, timeout=10)
        self.assertEqual(conflict.returncode, 2)
        self.assertEqual(conflict.stdout, "")
        self.assertNotIn(str(self.root), conflict.stderr)
        self.assertEqual((self.root / "one.txt").read_bytes(), original)
