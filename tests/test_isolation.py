import io
import json
import os
import subprocess
import sys
import threading
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from agentforge.fixed_probe import main as fixed_probe_main
from agentforge.isolation import run_probe
from agentforge.trace import validate_record


class AdmissionTests(unittest.TestCase):
    def test_unsupported_host_never_starts_a_process(self):
        with (
            patch("agentforge.isolation.sys.platform", "unsupported"),
            patch(
                "agentforge.isolation.subprocess.Popen",
                side_effect=AssertionError("must not execute"),
            ),
        ):
            report = run_probe("boundaries")
        self.assertEqual(report["status"], "denied")
        self.assertEqual(report["trace"], ["requested", "denied"])
        self.assertFalse(report["started"])

    def test_fixed_scenarios_and_resource_limits_only(self):
        for scenario in ["shell", "../../escape", ["smoke"]]:
            with self.assertRaises(ValueError):
                run_probe(scenario)
        for timeout in [True, 0, -1, float("inf"), float("nan"), 11]:
            with self.assertRaises(ValueError):
                run_probe("smoke", timeout=timeout)
        for limit in [True, 0, 65537]:
            with self.assertRaises(ValueError):
                run_probe("smoke", output_limit=limit)

    def test_pre_cancelled_probe_does_not_launch(self):
        event = threading.Event()
        event.set()
        with patch(
            "agentforge.isolation.subprocess.Popen",
            side_effect=AssertionError("must not execute"),
        ):
            report = run_probe("smoke", cancel=event)
        self.assertEqual(report["status"], "cancelled")
        self.assertFalse(report["started"])

    def test_cli_reports_boundary_status(self):
        result = subprocess.run(
            [sys.executable, "-m", "agentforge.isolation"],
            capture_output=True,
            text=True,
        )
        report = json.loads(result.stdout)
        self.assertIn(result.returncode, (0, 3), result.stderr)
        self.assertEqual(result.returncode == 0, report["status"] == "succeeded")
        if sys.platform != "linux":
            self.assertEqual(report["status"], "denied")


class FixedBoundaryOutcomeTests(unittest.TestCase):
    def run_boundaries(self, allow_outside_read):
        class SyntheticPath:
            def __init__(self, value):
                self.value = value

            def read_text(self):
                if self.value == "/synthetic-outside" and allow_outside_read:
                    return "unexpected accessible content"
                raise PermissionError("synthetic blocked operation")

            def write_text(self, value):
                if self.value == "/workspace/result":
                    return len(value)
                raise PermissionError("synthetic blocked operation")

        output = io.StringIO()
        with (
            patch("agentforge.fixed_probe.Path", SyntheticPath),
            patch(
                "agentforge.fixed_probe.socket.create_connection",
                side_effect=OSError("synthetic isolated network"),
            ),
            patch(
                "agentforge.fixed_probe.sys.argv",
                ["probe.py", "boundaries", "/synthetic-outside", "1234"],
            ),
            patch.dict(os.environ, {}, clear=True),
            redirect_stdout(output),
        ):
            code = 0
            try:
                fixed_probe_main()
            except SystemExit as exc:
                code = exc.code
        return code, json.loads(output.getvalue().splitlines()[-1])["checks"]

    def test_failed_boundary_exits_nonzero_after_emitting_check_results(self):
        code, checks = self.run_boundaries(allow_outside_read=True)
        self.assertEqual(code, 1)
        self.assertFalse(checks["read_outside_blocked"])
        self.assertEqual(sum(not value for value in checks.values()), 1)

    def test_all_successful_boundaries_exit_zero(self):
        code, checks = self.run_boundaries(allow_outside_read=False)
        self.assertEqual(code, 0)
        self.assertEqual(len(checks), 7)
        self.assertTrue(all(checks.values()))


class RealIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        report = run_probe("smoke")
        if report["status"] != "succeeded":
            message = "isolation unavailable: " + json.dumps(report)
            if os.environ.get("AGENTFORGE_REQUIRE_SANDBOX") == "1":
                raise AssertionError(message)
            raise unittest.SkipTest(message)

    def test_real_filesystem_network_and_environment_boundaries(self):
        with patch.dict(
            os.environ, {"AGENTFORGE_TEST_SECRET": "synthetic-do-not-inherit"}
        ):
            report = run_probe("boundaries")
        self.assertEqual(report["status"], "succeeded", report)
        self.assertEqual(validate_record(report["record"]), report["record"])
        self.assertTrue(report["record"]["capture"]["redacted"])
        self.assertTrue(report["host_canary_unchanged"])
        self.assertEqual(report["trace"], ["requested", "started", "succeeded"])
        checks = json.loads(report["output"].splitlines()[-1])["checks"]
        self.assertEqual(len(checks), 7)
        self.assertTrue(all(checks.values()), checks)

    def test_timeout_and_detached_descendant_cleanup(self):
        report = run_probe("descendants", timeout=0.6)
        self.assertEqual(report["status"], "timeout", report)
        self.assertTrue(report["started"])
        self.assertTrue(report["descendant_marker_absent"], report)
        self.assertTrue(report["host_canary_unchanged"])

    def test_output_is_bounded(self):
        report = run_probe("flood", output_limit=1024)
        self.assertEqual(report["status"], "output_limit", report)
        self.assertTrue(report["started"])
        self.assertLessEqual(report["captured_bytes"], 1024)

    def test_cancellation_after_start(self):
        event = threading.Event()
        timer = threading.Timer(0.5, event.set)
        timer.start()
        try:
            report = run_probe("wait", cancel=event)
        finally:
            timer.cancel()
        self.assertEqual(report["status"], "cancelled", report)
        self.assertTrue(report["started"])


if __name__ == "__main__":
    unittest.main()
