import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agentforge.workspace_read import HARD_MAX_BYTES, _read_bounded, read_snapshot


class WorkspaceReadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root / "source").mkdir()
        self.path = self.root / "source" / "sample.txt"
        self.raw = "Original λ content\r\n".encode()
        self.path.write_bytes(self.raw)

    def read(self, path="source/sample.txt", **options):
        return read_snapshot(self.root, path, allowed=["repo.read"], **options)

    def test_default_metadata_and_opt_in_utf8_bind_same_unchanged_bytes(self):
        metadata = self.read()
        text = self.read(include_text=True)
        self.assertNotIn("text", metadata)
        self.assertFalse(metadata["text_included"])
        self.assertEqual(metadata["sha256"], hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(text["sha256"], metadata["sha256"])
        self.assertEqual(text["bytes"], len(self.raw))
        self.assertEqual(text["text"], self.raw.decode())
        self.assertEqual(self.path.read_bytes(), self.raw)
        self.assertNotIn(str(self.root), json.dumps(metadata))
        self.assertNotIn("source/sample", json.dumps(metadata))
        self.assertNotIn("trace", metadata)
        self.assertFalse(metadata["mutation_observed"])

    def test_capability_denial_precedes_every_open(self):
        for allowed in [
            [],
            ["repo.write"],
            ["repo.read", "shell"],
            ["repo.read", "repo.read"],
            [1],
            "repo.read",
        ]:
            with (
                self.subTest(allowed=allowed),
                patch(
                    "agentforge.workspace_read.os.open",
                    side_effect=AssertionError("must not open"),
                ),
            ):
                with self.assertRaises(PermissionError):
                    read_snapshot(self.root, "source/sample.txt", allowed=allowed)

    def test_secret_and_repository_control_names_deny_before_open(self):
        for relative in [
            ".git",
            ".git/config",
            "nested/.GiT",
            ".env",
            ".env.local",
            "folder/.ENV.production",
            ".aws/credentials",
            ".ssh/id_ed25519",
            "private.pem",
            "private.key",
            ".netrc",
        ]:
            with (
                self.subTest(relative=relative),
                patch(
                    "agentforge.workspace_read.os.open",
                    side_effect=AssertionError("must not open"),
                ),
            ):
                with self.assertRaises(PermissionError):
                    self.read(relative, include_text=True)
                with self.assertRaises(PermissionError):
                    self.read(relative)
        with patch(
            "agentforge.workspace_read.os.open",
            side_effect=AssertionError("must not open"),
        ):
            with self.assertRaises(PermissionError):
                read_snapshot(self.root / ".git", "config", allowed=["repo.read"])
        # Public repository metadata is not confused with a .git component.
        (self.root / ".gitignore").write_bytes(b"*.pyc\n")
        self.assertEqual(self.read(".gitignore")["bytes"], 6)

    def test_path_escape_absolute_and_root_safety(self):
        for relative in [
            "/etc/passwd",
            "../outside",
            "source/../sample.txt",
            "./source/sample.txt",
            "source//sample.txt",
            "source\\sample.txt",
            "",
            "source/sample.txt\x00",
        ]:
            with self.subTest(relative=relative), self.assertRaises(ValueError):
                self.read(relative)
        for root in ["", "/", str(self.root) + "/../elsewhere", str(self.root) + "/"]:
            with self.subTest(root=root), self.assertRaises(ValueError):
                read_snapshot(root, "sample.txt", allowed=["repo.read"])
        with (
            patch("agentforge.workspace_read.os.path.abspath", return_value="/"),
            patch(
                "agentforge.workspace_read.os.open",
                side_effect=AssertionError("must not open"),
            ),
        ):
            with self.assertRaises(ValueError):
                read_snapshot(".", "sample.txt", allowed=["repo.read"])
        alias = self.root / "root-alias"
        alias.symlink_to(self.root / "source")
        with self.assertRaises(OSError):
            read_snapshot(alias, "sample.txt", allowed=["repo.read"])

    def test_symlink_hardlink_fifo_and_directory_policies(self):
        (self.root / "alias-file").symlink_to(self.path)
        (self.root / "alias-folder").symlink_to(self.root / "source")
        for relative in ["alias-file", "alias-folder/sample.txt"]:
            with self.subTest(relative=relative), self.assertRaises(OSError):
                self.read(relative)
        os.link(self.path, self.root / "hardlink")
        with patch(
            "agentforge.workspace_read._read_bounded",
            side_effect=AssertionError("must not read"),
        ):
            with self.assertRaises(PermissionError):
                self.read("hardlink")
        os.mkfifo(self.root / "pipe")
        for relative in ["pipe", "source"]:
            with self.subTest(relative=relative), self.assertRaises(ValueError):
                self.read(relative)

    def test_byte_limits_and_text_opt_in_validation(self):
        for limit in [True, 0, HARD_MAX_BYTES + 1]:
            with self.assertRaises(ValueError):
                self.read(max_bytes=limit)
        with self.assertRaises(ValueError):
            self.read(max_bytes=len(self.raw) - 1)
        self.assertEqual(self.read(max_bytes=len(self.raw))["bytes"], len(self.raw))
        self.path.write_bytes(b"\xff\x00")
        self.assertEqual(self.read()["sha256"], hashlib.sha256(b"\xff\x00").hexdigest())
        with self.assertRaisesRegex(ValueError, "UTF-8"):
            self.read(include_text=True)
        with self.assertRaises(ValueError):
            self.read(include_text=1)

    def test_same_read_snapshot_not_a_second_hash_read(self):
        with patch(
            "agentforge.workspace_read._read_bounded", wraps=_read_bounded
        ) as reader:
            report = self.read(include_text=True)
        self.assertEqual(reader.call_count, 1)
        self.assertEqual(
            report["sha256"], hashlib.sha256(report["text"].encode()).hexdigest()
        )

    def test_ordinary_mutation_and_final_name_replacement_are_detected(self):
        def mutate(descriptor, limit):
            result = _read_bounded(descriptor, limit)
            self.path.write_bytes(b"changed content")
            return result

        with patch("agentforge.workspace_read._read_bounded", side_effect=mutate):
            with self.assertRaisesRegex(ValueError, "changed during"):
                self.read()
        self.path.write_bytes(self.raw)

        def replace(descriptor, limit):
            result = _read_bounded(descriptor, limit)
            replacement = self.root / "replacement"
            replacement.write_bytes(self.raw)
            os.replace(replacement, self.path)
            return result

        with patch("agentforge.workspace_read._read_bounded", side_effect=replace):
            with self.assertRaisesRegex(ValueError, "changed during"):
                self.read()

    def test_growth_during_read_never_exceeds_returned_bound(self):
        def grow(descriptor, limit):
            self.path.write_bytes(self.raw + b"x" * 100)
            return _read_bounded(descriptor, limit)

        with patch("agentforge.workspace_read._read_bounded", side_effect=grow):
            with self.assertRaises(ValueError):
                self.read(max_bytes=len(self.raw))

    def test_cli_denial_metadata_text_and_redacted_errors(self):
        command = [
            sys.executable,
            "-m",
            "agentforge.workspace_read",
            "--root",
            str(self.root),
            "source/sample.txt",
        ]
        denied = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(denied.returncode, 2)
        self.assertEqual(denied.stdout, "")
        self.assertNotIn(str(self.root), denied.stderr)
        metadata = subprocess.run(
            command + ["--allow", "repo.read"], capture_output=True, text=True
        )
        self.assertEqual(metadata.returncode, 0, metadata.stderr)
        self.assertNotIn("text", json.loads(metadata.stdout))
        self.assertNotIn(str(self.root), metadata.stdout)
        text = subprocess.run(
            command + ["--allow", "repo.read", "--include-text"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(text.returncode, 0, text.stderr)
        self.assertEqual(json.loads(text.stdout)["text"], self.raw.decode())
        unknown = subprocess.run(
            command + ["--allow", "repo.read", "--allow", "network"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(unknown.returncode, 2)
        self.assertEqual(unknown.stdout, "")


if __name__ == "__main__":
    unittest.main()
