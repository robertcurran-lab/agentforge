"""Fail-closed Linux bubblewrap conformance probe; no arbitrary command interface."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from .trace import SCENARIOS, record_result, write_record


def _capture(
    command: list[str], *, timeout: float, limit: int, cancel: threading.Event | None
) -> tuple[str, int, str, bool, int, str]:
    """Bound merged stdout/stderr and always reap the isolated process group."""
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        start_new_session=True,
    )
    assert process.stdout is not None
    captured = bytearray()
    status = "exited"
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                if cancel is not None and cancel.is_set():
                    status = "cancelled"
                    break
                if time.monotonic() >= deadline:
                    status = "timeout"
                    break
                for key, _ in selector.select(
                    min(0.05, max(0, deadline - time.monotonic()))
                ):
                    block = os.read(key.fd, 4096)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    remaining = limit - len(captured)
                    captured.extend(block[:remaining])
                    if len(block) > remaining:
                        status = "output_limit"
                        break
                if status == "output_limit":
                    break
    finally:
        # Also clean up a live group when its initial process exited normally.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
        process.stdout.close()
    text = captured.decode("utf-8", errors="replace")
    started = text.startswith('{"event": "started"}\n')
    return (
        status,
        process.returncode,
        text,
        started,
        len(captured),
        hashlib.sha256(captured).hexdigest(),
    )


def _run_probe(
    scenario: str,
    *,
    timeout: float = 3,
    output_limit: int = 8192,
    cancel: threading.Event | None = None,
) -> dict[str, Any]:
    """Run only bundled fixed probes in a new disposable workspace.

    Unsupported hosts deny execution. Runtime directories are intentionally exposed
    read-only; this is a conformance prototype, not a general hostile-code runner.
    """
    if not isinstance(scenario, str) or scenario not in SCENARIOS:
        raise ValueError("unknown fixed scenario")
    if (
        type(timeout) not in (int, float)
        or not 0 < timeout <= 10
        or not math.isfinite(timeout)
    ):
        raise ValueError("timeout must be finite in (0,10]")
    if type(output_limit) is not int or not 512 <= output_limit <= 65536:
        raise ValueError("output_limit must be an integer from 512 to 65536")
    trace = ["requested"]
    if cancel is not None and cancel.is_set():
        return {"status": "cancelled", "trace": trace + ["cancelled"], "started": False}
    if sys.platform != "linux" or not Path("/usr/bin/bwrap").is_file():
        return {
            "status": "denied",
            "trace": trace + ["denied"],
            "started": False,
            "reason": "Linux /usr/bin/bwrap is required; no unrestricted fallback",
        }
    with tempfile.TemporaryDirectory(prefix="agentforge-probe-") as directory:
        root = Path(directory)
        workspace = root / "workspace"
        workspace.mkdir()
        outside = root / "host-only-canary"
        outside.write_text("synthetic canary")
        (workspace / "escape").symlink_to(outside)
        # Confirm the host listener is reachable before testing network isolation.
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(4)
            port = server.getsockname()[1]
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                pass
            command = [
                "/usr/bin/bwrap",
                "--unshare-all",
                "--die-with-parent",
                "--new-session",
                "--cap-drop",
                "ALL",
                "--clearenv",
                "--setenv",
                "PATH",
                "/usr/bin:/bin",
                "--setenv",
                "LANG",
                "C",
            ]
            for runtime in ["/usr", "/lib", "/lib64", "/bin"]:
                if Path(runtime).is_dir():
                    command += ["--ro-bind", runtime, runtime]
            command += [
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
                "--bind",
                str(workspace),
                "/workspace",
                "--ro-bind",
                str(Path(__file__).with_name("fixed_probe.py").resolve()),
                "/probe.py",
                "--chdir",
                "/workspace",
                "--",
                "/usr/bin/python3",
                "-I",
                "-S",
                "/probe.py",
                scenario,
                str(outside),
                str(port),
            ]
            try:
                status, code, output, started, captured_bytes, output_sha256 = _capture(
                    command, timeout=timeout, limit=output_limit, cancel=cancel
                )
            except OSError:
                return {
                    "status": "denied",
                    "trace": trace + ["denied"],
                    "started": False,
                    "reason": "isolation backend could not be started",
                }
        if started:
            trace.append("started")
        if status == "exited":
            status = (
                "succeeded"
                if started and code == 0
                else ("failed" if started else "denied")
            )
        result: dict[str, Any] = {
            "status": status,
            "trace": trace + [status],
            "started": started,
            "returncode": code,
            "output": output,
            "captured_bytes": captured_bytes,
            "output_sha256": output_sha256,
        }
        if scenario == "descendants" and started:
            # The detached fixed child would write this marker after one second.
            time.sleep(1.2)
            result["descendant_marker_absent"] = not (
                workspace / "delayed-marker"
            ).exists()
        result["host_canary_unchanged"] = outside.read_text() == "synthetic canary"
        return result


def run_probe(
    scenario: str,
    *,
    timeout: float = 3,
    output_limit: int = 8192,
    cancel: threading.Event | None = None,
) -> dict[str, Any]:
    """Run a fixed probe and attach a validated redacted observation record."""
    probe_sha256 = hashlib.sha256(
        Path(__file__).with_name("fixed_probe.py").read_bytes()
    ).hexdigest()
    started_ns = time.monotonic_ns()
    result = _run_probe(
        scenario, timeout=timeout, output_limit=output_limit, cancel=cancel
    )
    result["record"] = record_result(
        result,
        scenario=scenario,
        timeout=timeout,
        output_limit=output_limit,
        elapsed_ns=time.monotonic_ns() - started_ns,
        probe_sha256=probe_sha256,
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "scenario", choices=sorted(SCENARIOS), nargs="?", default="boundaries"
    )
    parser.add_argument("--timeout", type=float, default=3)
    parser.add_argument("--output-limit", type=int, default=8192)
    parser.add_argument(
        "--record-only",
        action="store_true",
        help="emit only redacted versioned trace metadata",
    )
    parser.add_argument(
        "--record-output", help="publish a redacted record to a new no-clobber file"
    )
    args = parser.parse_args()
    try:
        result = run_probe(
            args.scenario, timeout=args.timeout, output_limit=args.output_limit
        )
        if args.record_output is not None:
            write_record(args.record_output, result["record"])
    except (OSError, ValueError) as exc:
        print(f"probe failed: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            result["record"] if args.record_only else result, sort_keys=True, indent=2
        )
    )
    return 0 if result["status"] == "succeeded" else 3


if __name__ == "__main__":
    raise SystemExit(main())
