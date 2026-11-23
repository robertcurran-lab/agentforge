import concurrent.futures
import copy
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from agentforge.isolation import run_probe
from agentforge.trace import MAX_RECORD_BYTES, read_record, write_record


def record():
    with patch("agentforge.isolation.sys.platform", "unsupported"):
        return run_probe("smoke")["record"]


class RecordFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.destination = self.root / "record.json"
        self.record = record()

    def test_complete_private_roundtrip_and_no_overwrite(self):
        write_record(self.destination, self.record)
        before = self.destination.read_bytes()
        self.assertEqual(read_record(self.destination), self.record)
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o600)
        with self.assertRaises(FileExistsError):
            write_record(self.destination, self.record)
        self.assertEqual(self.destination.read_bytes(), before)
        self.assertEqual(list(self.root.iterdir()), [self.destination])

    def test_eight_concurrent_writers_publish_one_complete_winner(self):
        barrier = threading.Barrier(8)

        def publish(index):
            row = copy.deepcopy(self.record)
            row["elapsed_ns"] = index
            barrier.wait(timeout=10)
            try:
                write_record(self.destination, row)
                return index
            except FileExistsError:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            winners = [
                value for value in pool.map(publish, range(8)) if value is not None
            ]
        self.assertEqual(len(winners), 1)
        self.assertEqual(read_record(self.destination)["elapsed_ns"], winners[0])
        self.assertEqual(list(self.root.iterdir()), [self.destination])

    def test_invalid_record_never_touches_output(self):
        row = dict(self.record, output="secret")
        with patch(
            "agentforge.trace._publish_bytes",
            side_effect=AssertionError("must not write"),
        ):
            with self.assertRaises(ValueError):
                write_record(self.destination, row)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_partial_write_and_prepublication_sync_failure_leave_no_destination(self):
        real_write = os.write
        calls = 0

        def interrupted(fd, payload):
            nonlocal calls
            calls += 1
            if calls == 1:
                return real_write(fd, payload[:13])
            raise OSError("injected write interruption")

        with patch("agentforge.record_files.os.write", side_effect=interrupted):
            with self.assertRaises(OSError):
                write_record(self.destination, self.record)
        self.assertEqual(list(self.root.iterdir()), [])
        real_sync = os.fsync

        def fail_file_sync(fd):
            if stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("injected file fsync failure")
            real_sync(fd)

        with patch("agentforge.record_files.os.fsync", side_effect=fail_file_sync):
            with self.assertRaises(OSError):
                write_record(self.destination, self.record)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_conflict_created_at_publication_is_never_overwritten(self):
        real_link = os.link

        def competing(src, dst, **options):
            self.destination.write_bytes(b"existing winner")
            return real_link(src, dst, **options)

        with patch("agentforge.record_files.os.link", side_effect=competing):
            with self.assertRaises(FileExistsError):
                write_record(self.destination, self.record)
        self.assertEqual(self.destination.read_bytes(), b"existing winner")
        self.assertEqual(list(self.root.iterdir()), [self.destination])

    def test_symlinks_parent_escape_nonregular_and_missing_parent_are_rejected(self):
        target = self.root / "existing.json"
        target.write_text("original")
        self.destination.symlink_to(target)
        with self.assertRaises(FileExistsError):
            write_record(self.destination, self.record)
        with self.assertRaises(OSError):
            read_record(self.destination)
        self.assertEqual(target.read_text(), "original")
        folder = self.root / "real"
        folder.mkdir()
        alias = self.root / "alias"
        alias.symlink_to(folder)
        for path in [
            alias / "new.json",
            str(self.root) + "/real/../escape.json",
            self.root / "missing" / "new.json",
        ]:
            with self.subTest(path=path), self.assertRaises((OSError, ValueError)):
                write_record(path, self.record)
        fifo = self.root / "pipe"
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            read_record(fifo)
        with self.assertRaises((OSError, ValueError)):
            read_record(folder)

    def test_postpublication_sync_failure_can_leave_only_complete_valid_record(self):
        real_sync = os.fsync

        def fail_directory_sync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("injected directory sync failure")
            real_sync(fd)

        with patch("agentforge.record_files.os.fsync", side_effect=fail_directory_sync):
            with self.assertRaises(OSError):
                write_record(self.destination, self.record)
        self.assertEqual(read_record(self.destination), self.record)
        self.assertEqual(list(self.root.iterdir()), [self.destination])

    def test_process_death_before_publication_leaves_no_final_path(self):
        code = """import json,os,sys
from agentforge.trace import write_record
from agentforge import record_files
record_files.os.link=lambda *a,**k: os._exit(23)
write_record(sys.argv[1],json.loads(sys.stdin.read()))
"""
        child = subprocess.run(
            [sys.executable, "-c", code, str(self.destination)],
            input=json.dumps(self.record),
            capture_output=True,
            text=True,
        )
        self.assertEqual(child.returncode, 23, child.stderr)
        self.assertFalse(self.destination.exists())
        remaining = list(self.root.iterdir())
        self.assertEqual(len(remaining), 1)
        self.assertTrue(remaining[0].name.startswith(".agentforge-record-"))
        self.assertEqual(stat.S_IMODE(remaining[0].stat().st_mode), 0o600)
        self.assertEqual(read_record(remaining[0]), self.record)

    def test_validation_cli_and_opt_in_probe_output_are_redacted(self):
        probe = subprocess.run(
            [
                sys.executable,
                "-m",
                "agentforge.isolation",
                "smoke",
                "--record-only",
                "--record-output",
                str(self.destination),
            ],
            capture_output=True,
            text=True,
        )
        self.assertIn(probe.returncode, (0, 3), probe.stderr)
        self.assertEqual(read_record(self.destination), json.loads(probe.stdout))
        validator = subprocess.run(
            [sys.executable, "-m", "agentforge.trace", str(self.destination)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(validator.returncode, 0, validator.stderr)
        self.assertNotIn('"output":', validator.stdout)
        self.assertNotIn(str(self.root), validator.stdout)
        self.assertFalse(json.loads(validator.stdout)["execution_attested"])
        before = self.destination.read_bytes()
        conflict = subprocess.run(
            [
                sys.executable,
                "-m",
                "agentforge.isolation",
                "smoke",
                "--record-only",
                "--record-output",
                str(self.destination),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(conflict.returncode, 2)
        self.assertEqual(conflict.stdout, "")
        self.assertEqual(self.destination.read_bytes(), before)
        self.destination.write_bytes(b" " * (MAX_RECORD_BYTES + 1))
        failure = subprocess.run(
            [sys.executable, "-m", "agentforge.trace", str(self.destination)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(failure.returncode, 2)
        self.assertEqual(failure.stdout, "")


if __name__ == "__main__":
    unittest.main()
