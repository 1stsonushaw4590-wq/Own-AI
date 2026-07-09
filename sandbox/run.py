#!/usr/bin/env python3
"""Safe execution sandbox for model-generated code.
Runs a submitted script with resource limits, no network, and a timeout.
This is a thin local wrapper; the real isolation comes from the Docker
run flags (--network none, --read-only, seccomp)."""
import sys
import subprocess
import resource
import os

LIMIT_CPU_SECONDS = int(os.environ.get("SANDBOX_CPU", "15"))
LIMIT_MEM_BYTES = int(os.environ.get("SANDBOX_MEM", str(256 * 1024 * 1024)))
LIMIT_FILES = int(os.environ.get("SANDBOX_FSIZE", str(1 * 1024 * 1024)))


def main():
    if len(sys.argv) < 2:
        print("usage: run.py <script.py> [args...]", file=sys.stderr)
        sys.exit(2)

    def setlimits():
        resource.setrlimit(resource.RLIMIT_CPU, (LIMIT_CPU_SECONDS, LIMIT_CPU_SECONDS + 2))
        resource.setrlimit(resource.RLIMIT_AS, (LIMIT_MEM_BYTES, LIMIT_MEM_BYTES))
        resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT_FILES, LIMIT_FILES))

    try:
        result = subprocess.run(
            [sys.executable, *sys.argv[1:]],
            preexec_fn=setlimits,
            capture_output=True,
            text=True,
            timeout=LIMIT_CPU_SECONDS + 5,
        )
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        sys.exit(result.returncode)
    except subprocess.TimeoutExpired:
        print("TIMEOUT: execution exceeded CPU limit", file=sys.stderr)
        sys.exit(124)
    except Exception as e:  # noqa
        print(f"SANDBOX_ERROR: {e}", file=sys.stderr)
        sys.exit(125)


if __name__ == "__main__":
    main()
