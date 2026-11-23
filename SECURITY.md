# Security

This project only parses workflows and previews symbolic decisions. No commands,
tests, model calls, tool invocations or network requests execute. Capabilities are
labels, not an execution sandbox. Do not use a successful CLI exit as permission
to execute a task; denial decisions also exit 0. External snapshots are unverified.
The CLI bounds each JSON file to 1 MiB; use trusted regular files, not named pipes.
No private vulnerability-report channel is configured. Do not put credentials,
private source code or sensitive tasks in public issues. Any future runner needs
separate OS isolation, path/network restrictions and bounded execution; it is not
safe merely because a policy preview labels a task eligible.
