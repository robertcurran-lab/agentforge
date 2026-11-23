"""Preview a workflow without executing tools or commands."""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .policy import Workflow


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON key")
        obj[key] = value
    return obj


def _constant(value: str) -> None:
    raise ValueError("non-finite JSON constant")


def _load(path: str) -> Any:
    with Path(path).open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("file exceeds 1 MiB")
    try:
        return json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)
    except RecursionError as exc:
        raise ValueError("JSON nesting is too deep") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workflow")
    parser.add_argument("--allowlist", required=True)
    parser.add_argument("--states", required=True)
    args = parser.parse_args()
    try:
        report = Workflow.parse(_load(args.workflow)).preview(
            _load(args.allowlist), _load(args.states)
        )
    except (OSError, ValueError) as exc:
        print(f"preview failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
