import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agentforge.policy import Workflow, transition


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.document = {
            "version": 1,
            "tasks": [
                {"name": "inspect", "needs": [], "capabilities": ["repo.read"]},
                {"name": "test", "needs": ["inspect"], "capabilities": ["tests.run"]},
            ],
        }
        self.states = {"inspect": "pending", "test": "pending"}

    def test_deny_default_and_explicit_allow(self):
        workflow = Workflow.parse(self.document)
        self.assertEqual(
            workflow.preview([], self.states)["decisions"][0]["reason"],
            "capability_denied",
        )
        report = workflow.preview(["repo.read", "tests.run"], self.states)
        self.assertFalse(report["executed"])
        self.assertEqual(
            [row["reason"] for row in report["decisions"]],
            ["eligible", "dependency_blocked"],
        )

    def test_progression_and_failure(self):
        workflow = Workflow.parse(self.document)
        for state, expected in [
            ("succeeded", "eligible"),
            ("failed", "dependency_blocked"),
            ("cancelled", "dependency_blocked"),
        ]:
            self.states["inspect"] = state
            self.assertEqual(
                workflow.preview(["repo.read", "tests.run"], self.states)["decisions"][
                    1
                ]["reason"],
                expected,
            )

    def test_started_work_requires_dependencies_and_permissions(self):
        workflow = Workflow.parse(self.document)
        for state in ["running", "succeeded"]:
            with self.assertRaises(ValueError):
                workflow.preview(
                    ["repo.read", "tests.run"], {"inspect": "pending", "test": state}
                )
            with self.assertRaises(ValueError):
                workflow.preview([], {"inspect": state, "test": "pending"})

    def test_terminal_and_invalid_transitions(self):
        self.assertEqual(transition("pending", "running"), "running")
        self.assertEqual(transition("running", "cancelled"), "cancelled")
        for source, target in [
            ("pending", "succeeded"),
            ("failed", "running"),
            ("succeeded", "pending"),
            ("unknown", "running"),
        ]:
            with (
                self.subTest(source=source, target=target),
                self.assertRaises(ValueError),
            ):
                transition(source, target)

    def test_invalid_capabilities_and_state_maps(self):
        workflow = Workflow.parse(self.document)
        for allowed in [["shell"], ["repo.read", "repo.read"], [1], "repo.read"]:
            with self.assertRaises(ValueError):
                workflow.preview(allowed, self.states)
        for states in [
            {},
            dict(self.states, extra="pending"),
            dict(self.states, inspect=[]),
            dict(self.states, inspect="unknown"),
        ]:
            with self.assertRaises(ValueError):
                workflow.preview([], states)

    def test_schema_errors(self):
        for doc in [
            {},
            dict(self.document, version=True),
            dict(self.document, tasks=[]),
            dict(self.document, extra=True),
        ]:
            with self.assertRaises(ValueError):
                Workflow.parse(doc)
        for changes in [
            {"capabilities": ["shell"]},
            {"capabilities": ["repo.read", "repo.read"]},
            {"needs": ["missing"]},
            {"needs": ["inspect"]},
            {"name": "../escape"},
        ]:
            doc = copy.deepcopy(self.document)
            doc["tasks"][0].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                Workflow.parse(doc)

    def test_cycles_duplicate_names_and_dependencies(self):
        for tasks in [
            [self.document["tasks"][0]] * 2,
            [
                {"name": "a", "needs": ["b"], "capabilities": []},
                {"name": "b", "needs": ["a"], "capabilities": []},
            ],
            [
                self.document["tasks"][0],
                {"name": "b", "needs": ["inspect", "inspect"], "capabilities": []},
            ],
        ]:
            with self.assertRaises(ValueError):
                Workflow.parse({"version": 1, "tasks": tasks})

    def test_parse_detaches_mutable_input(self):
        workflow = Workflow.parse(self.document)
        self.document["tasks"][0]["capabilities"].append("shell")
        self.document["tasks"][0]["needs"].append("missing")
        self.assertEqual(
            workflow.preview(["repo.read"], self.states)["decisions"][0]["reason"],
            "eligible",
        )

    def test_cli_and_no_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = [
                root / name for name in ["workflow.json", "allow.json", "states.json"]
            ]
            for path, value in zip(
                paths, [self.document, [], self.states], strict=True
            ):
                path.write_text(json.dumps(value))
            cmd = [
                sys.executable,
                "-m",
                "agentforge",
                str(paths[0]),
                "--allowlist",
                str(paths[1]),
                "--states",
                str(paths[2]),
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertFalse(report["executed"])
            self.assertEqual(report["decisions"][0]["reason"], "capability_denied")
            paths[0].write_text('{"version":1,"version":1,"tasks":[]}')
            result = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertIn("duplicate JSON key", result.stderr)


if __name__ == "__main__":
    unittest.main()
