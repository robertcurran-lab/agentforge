"""Fixed synthetic workloads for isolation tests; not a command execution API."""

import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path


def main() -> None:
    mode = sys.argv[1]
    if mode == "child":
        time.sleep(1)
        Path("/workspace/delayed-marker").write_text("descendant survived")
        return
    print(json.dumps({"event": "started"}), flush=True)
    if mode == "boundaries":
        outside = Path(sys.argv[2])
        checks = {}
        actions: list[tuple[str, Callable[[], object]]] = [
            ("read_outside_blocked", lambda: outside.read_text()),
            ("write_outside_blocked", lambda: outside.write_text("overwrite")),
            ("symlink_escape_blocked", lambda: Path("/workspace/escape").read_text()),
            ("host_etc_blocked", lambda: Path("/etc/passwd").read_text()),
        ]
        for name, action in actions:
            try:
                action()
                checks[name] = False
            except OSError:
                checks[name] = True
        try:
            with socket.create_connection(("127.0.0.1", int(sys.argv[3])), timeout=0.5):
                checks["network_blocked"] = False
        except OSError:
            checks["network_blocked"] = True
        checks["secret_absent"] = "AGENTFORGE_TEST_SECRET" not in os.environ
        Path("/workspace/result").write_text("synthetic result")
        checks["workspace_writable"] = True
        print(json.dumps({"checks": checks}), flush=True)
    elif mode == "flood":
        while True:
            os.write(1, b"x" * 4096)
    elif mode == "descendants":
        subprocess.Popen(
            [sys.executable, "-I", "-S", "/probe.py", "child"],
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(30)
    elif mode == "wait":
        time.sleep(30)
    elif mode == "smoke":
        print(json.dumps({"smoke": True}), flush=True)
    else:
        raise ValueError("unknown fixed workload")


if __name__ == "__main__":
    main()
