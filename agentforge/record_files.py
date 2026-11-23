"""POSIX no-clobber file operations for validated redacted records."""

from __future__ import annotations

import os
import secrets
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def _directory(path: str | Path) -> Iterator[tuple[int, str]]:
    """Anchor each parent component by descriptor; never follow a symlink."""
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise OSError("safe record files require POSIX no-follow directory descriptors")
    text = os.fspath(path)
    if not text or "\x00" in text or "\\" in text:
        raise ValueError("invalid record path")
    absolute = text.startswith("/")
    parts = text.split("/")[1:] if absolute else text.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("record path requires canonical components")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open("/" if absolute else ".", flags)
    try:
        for component in parts[:-1]:
            following = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = following
        yield descriptor, parts[-1]
    finally:
        os.close(descriptor)


def _read_bytes(path: str | Path, maximum: int) -> bytes:
    with _directory(path) as (directory, name):
        descriptor = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError("trace input must be a regular file")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                return stream.read(maximum + 1)
        finally:
            os.close(descriptor)


def _publish_bytes(path: str | Path, payload: bytes) -> None:
    """Publish one complete file atomically, without replacing any existing name.

    A post-publication fsync error can leave a complete valid destination. Abrupt
    process death before cleanup can leave a private staging file. No fallback to
    non-atomic writes, replacement or permissive files is attempted.
    """
    with _directory(path) as (directory, name):
        try:
            os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError("record destination already exists")
        temporary = ".agentforge-record-" + secrets.token_hex(16)
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        try:
            os.fchmod(descriptor, 0o600)
            remaining = memoryview(payload)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("record write made no progress")
                remaining = remaining[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.link(
                temporary,
                name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
                follow_symlinks=False,
            )
            os.fsync(directory)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.unlink(temporary, dir_fd=directory)
            os.fsync(directory)
