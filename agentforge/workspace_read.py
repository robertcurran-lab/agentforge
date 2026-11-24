"""Capability-gated bounded workspace byte snapshots; not an OS sandbox."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

from .policy import CAPABILITIES
from .record_files import _directory

HARD_MAX_BYTES = 1024 * 1024
DENIED_NAMES = frozenset(
    {
        ".git",
        ".aws",
        ".ssh",
        ".env",
        ".envrc",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "credentials",
        "credentials.json",
    }
)


def _authorize(allowed: list[str]) -> None:
    if not isinstance(allowed, list) or any(
        not isinstance(value, str) for value in allowed
    ):
        raise PermissionError("capabilities require an explicit string allowlist")
    if len(allowed) != len(set(allowed)) or not set(allowed) <= CAPABILITIES:
        raise PermissionError("unknown or duplicate capability declaration")
    if "repo.read" not in allowed:
        raise PermissionError("repo.read capability is required")


def _components(value: str) -> list[str]:
    if not value or "\x00" in value or "\\" in value:
        raise ValueError("invalid workspace path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("workspace paths require canonical relative components")
    return parts


def _exclude(parts: list[str]) -> None:
    for part in parts:
        name = part.lower()
        if (
            name in DENIED_NAMES
            or name.startswith(".env.")
            or name.endswith((".pem", ".key"))
        ):
            raise PermissionError(
                "repository-control and obvious secret paths are excluded"
            )


def _stamp(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_bounded(descriptor: int, limit: int) -> bytes:
    chunks = []
    total = 0
    while total <= limit:
        chunk = os.read(descriptor, min(65536, limit + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    if total > limit:
        raise ValueError("workspace file exceeds byte limit")
    return b"".join(chunks)


def read_snapshot(
    root: str | Path,
    relative_path: str,
    *,
    allowed: list[str],
    include_text: bool = False,
    max_bytes: int = 65536,
) -> dict[str, Any]:
    """Read one bounded file using a trusted caller's explicit repo.read grant.

    Root ownership and host/runtime are trusted. Timestamp/inode checks detect
    ordinary mutation, not all adversarial races or hidden secret aliases.
    """
    _authorize(allowed)
    if type(include_text) is not bool:
        raise ValueError("include_text must be a boolean")
    if type(max_bytes) is not int or not 1 <= max_bytes <= HARD_MAX_BYTES:
        raise ValueError("max_bytes must be an integer from 1 to 1048576")
    if not isinstance(relative_path, str):
        raise ValueError("relative_path must be a string")
    parts = _components(relative_path)
    _exclude(parts)
    if not isinstance(root, (str, Path)):
        raise ValueError("root must be an explicit local directory")
    root_text = os.fspath(root)
    if not root_text or root_text == "/" or "\x00" in root_text or "\\" in root_text:
        raise ValueError("invalid workspace root")
    # Check the caller's complete lexical root, including cwd when root is '.'.
    absolute_root = os.path.abspath(root_text)
    if absolute_root == "/":
        raise ValueError("filesystem root is not a workspace")
    _exclude([part for part in absolute_root.split("/") if part])
    root_file = "anchor" if root_text == "." else root_text + "/anchor"
    with _directory(root_file) as (root_descriptor, _):
        descriptor = os.dup(root_descriptor)
        try:
            for part in parts[:-1]:
                following = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = following
            file_descriptor = os.open(
                parts[-1],
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=descriptor,
            )
            try:
                before = os.fstat(file_descriptor)
                if not stat.S_ISREG(before.st_mode):
                    raise ValueError("workspace input must be a regular file")
                if before.st_nlink != 1:
                    raise PermissionError(
                        "multiply-linked workspace files are excluded"
                    )
                if before.st_size > max_bytes:
                    raise ValueError("workspace file exceeds byte limit")
                raw = _read_bounded(file_descriptor, max_bytes)
                after = os.fstat(file_descriptor)
                named = os.stat(parts[-1], dir_fd=descriptor, follow_symlinks=False)
                if (
                    _stamp(before) != _stamp(after)
                    or _stamp(after) != _stamp(named)
                    or len(raw) != before.st_size
                ):
                    raise ValueError("workspace file changed during read")
            finally:
                os.close(file_descriptor)
        finally:
            os.close(descriptor)
    result: dict[str, Any] = {
        "schema_version": 1,
        "tool": "workspace.read",
        "capability": "repo.read",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "max_bytes": max_bytes,
        "text_included": include_text,
        "mutation_observed": False,
    }
    if include_text:
        try:
            result["text"] = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError("workspace text is not valid UTF-8") from exc
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("path")
    parser.add_argument("--allow", action="append", default=[])
    parser.add_argument("--include-text", action="store_true")
    parser.add_argument("--max-bytes", type=int, default=65536)
    args = parser.parse_args()
    try:
        result = read_snapshot(
            args.root,
            args.path,
            allowed=args.allow,
            include_text=args.include_text,
            max_bytes=args.max_bytes,
        )
    except OSError:
        print(
            "workspace read failed: denied or unavailable local file", file=sys.stderr
        )
        return 2
    except ValueError as exc:
        print(f"workspace read failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
