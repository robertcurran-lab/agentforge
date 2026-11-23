"""Pure capability decisions are not an OS isolation or execution boundary."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

CAPABILITIES = frozenset({"repo.read", "repo.write", "tests.run"})
STATES = frozenset({"pending", "running", "succeeded", "failed", "cancelled"})
TRANSITIONS = {
    "pending": frozenset({"running", "cancelled"}),
    "running": frozenset({"succeeded", "failed", "cancelled"}),
    "succeeded": frozenset(),
    "failed": frozenset(),
    "cancelled": frozenset(),
}


def transition(current: str, target: str) -> str:
    """Validate an event transition, without persisting or claiming execution."""
    if current not in TRANSITIONS or target not in TRANSITIONS[current]:
        raise ValueError("invalid state transition")
    return target


def _strings(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


@dataclass(frozen=True)
class Task:
    name: str
    needs: tuple[str, ...]
    capabilities: frozenset[str]


@dataclass(frozen=True)
class Workflow:
    tasks: tuple[Task, ...]

    @classmethod
    def parse(cls, document: Any) -> Workflow:
        if not isinstance(document, dict) or set(document) != {"version", "tasks"}:
            raise ValueError("workflow requires version and tasks")
        if type(document["version"]) is not int or document["version"] != 1:
            raise ValueError("unsupported workflow version")
        rows = document["tasks"]
        if not isinstance(rows, list) or not 1 <= len(rows) <= 1000:
            raise ValueError("workflow requires 1 to 1000 tasks")
        tasks = []
        for row in rows:
            if not isinstance(row, dict) or set(row) != {
                "name",
                "needs",
                "capabilities",
            }:
                raise ValueError("invalid task fields")
            name, needs, caps = row["name"], row["needs"], row["capabilities"]
            if not isinstance(name, str) or not re.fullmatch(
                r"[a-z][a-z0-9_-]{0,63}", name
            ):
                raise ValueError("invalid task name")
            if not _strings(needs) or len(needs) != len(set(needs)):
                raise ValueError("dependencies must be unique names")
            if not _strings(caps) or len(caps) != len(set(caps)):
                raise ValueError("capabilities must be a unique string list")
            if not set(caps) <= CAPABILITIES:
                raise ValueError("unknown capability")
            tasks.append(Task(name, tuple(needs), frozenset(caps)))
        names = {task.name for task in tasks}
        if len(names) != len(tasks):
            raise ValueError("duplicate task name")
        if any(not set(task.needs) <= names for task in tasks):
            raise ValueError("unknown dependency")
        remaining = list(tasks)
        visited: set[str] = set()
        while remaining:
            ready = [task for task in remaining if set(task.needs) <= visited]
            if not ready:
                raise ValueError("dependency cycle")
            visited.update(task.name for task in ready)
            remaining = [task for task in remaining if task.name not in visited]
        return cls(tuple(tasks))

    def preview(self, allowed: list[str], states: dict[str, str]) -> dict[str, Any]:
        """Explain admission decisions, never execute or reserve a task."""
        if (
            not _strings(allowed)
            or len(allowed) != len(set(allowed))
            or not set(allowed) <= CAPABILITIES
        ):
            raise ValueError("invalid capability allowlist")
        if not isinstance(states, dict) or set(states) != {
            task.name for task in self.tasks
        }:
            raise ValueError("states must cover exactly the workflow tasks")
        if any(
            not isinstance(state, str) or state not in STATES
            for state in states.values()
        ):
            raise ValueError("unknown task state")
        for task in self.tasks:
            if states[task.name] in {"running", "succeeded"} and (
                any(states[name] != "succeeded" for name in task.needs)
                or not task.capabilities <= set(allowed)
            ):
                raise ValueError(
                    "started task lacks satisfied dependencies or permissions"
                )
        decisions = []
        for task in self.tasks:
            denied = sorted(task.capabilities - set(allowed))
            if states[task.name] != "pending":
                reason = "not_pending"
            elif denied:
                reason = "capability_denied"
            elif any(states[name] != "succeeded" for name in task.needs):
                reason = "dependency_blocked"
            else:
                reason = "eligible"
            decisions.append({"task": task.name, "reason": reason, "denied": denied})
        return {"schema_version": 1, "executed": False, "decisions": decisions}
