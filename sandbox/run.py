#!/usr/bin/env python3
"""Safe execution sandbox for model-generated code and commands.
Runs a submitted script with resource limits, no network, and a timeout.
Supports Python scripts (.py) and shell commands (.sh / --shell).
Real isolation comes from Docker run flags (--network none, --read-only, seccomp)."""
import sys
import subprocess
import resource
import os
import stat
import http.server
import json
import threading

LIMIT_CPU_SECONDS = int(os.environ.get("SANDBOX_CPU", "15"))
LIMIT_MEM_BYTES = int(os.environ.get("SANDBOX_MEM", str(256 * 1024 * 1024)))
LIMIT_FILES = int(os.environ.get("SANDBOX_FSIZE", str(1 * 1024 * 1024)))


def run_code(args):
    """Execute code with resource limits."""
    def setlimits():
        resource.setrlimit(resource.RLIMIT_CPU, (LIMIT_CPU_SECONDS, LIMIT_CPU_SECONDS + 2))
        resource.setrlimit(resource.RLIMIT_AS, (LIMIT_MEM_BYTES, LIMIT_MEM_BYTES))
        resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT_FILES, LIMIT_FILES))

    try:
        result = subprocess.run(
            args,
            preexec_fn=setlimits,
            capture_output=True,
            text=True,
            timeout=LIMIT_CPU_SECONDS + 5,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "TIMEOUT: execution exceeded CPU limit"
    except Exception as e:
        return 125, "", f"SANDBOX_ERROR: {e}"


def cli_main():
    """CLI entry point (used when invoked directly with arguments)."""
    if len(sys.argv) < 2:
        print("usage: run.py <script.py|--shell script.sh|--cmd 'command'>", file=sys.stderr)
        sys.exit(2)

    if sys.argv[1] == "--shell":
        args = ["bash", sys.argv[2]] + sys.argv[3:]
    elif sys.argv[1] == "--cmd":
        args = ["bash", "-c", sys.argv[2]] + sys.argv[3:]
    else:
        args = [sys.executable] + sys.argv[1:]

    rc, out, err = run_code(args)
    sys.stdout.write(out)
    sys.stderr.write(err)
    sys.exit(rc)


class SandboxHandler(http.server.BaseHTTPRequestHandler):
    """HTTP server that accepts code execution requests."""

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len)
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, {"error": "invalid JSON"})
            return

        code = data.get("code", "")
        lang = data.get("lang", "python")

        if not code.strip():
            self._respond(400, {"error": "empty code"})
            return

        # Write temp file and execute
        import tempfile
        suffix = ".sh" if lang == "bash" else ".py"
        with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False) as f:
            f.write(code)
            tmp = f.name

        try:
            if lang == "bash":
                args = ["bash", tmp]
            else:
                args = [sys.executable, tmp]
            rc, out, err = run_code(args)
            self._respond(200, {
                "returncode": rc,
                "stdout": out,
                "stderr": err,
            })
        finally:
            os.unlink(tmp)

    def _respond(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def log_message(self, format, *args):
        pass  # suppress logs


def serve_main():
    """Run as an HTTP server (used when run without args)."""
    port = int(os.environ.get("SANDBOX_PORT", "8002"))
    server = http.server.HTTPServer(("0.0.0.0", port), SandboxHandler)
    print(f"Sandbox server listening on port {port}", file=sys.stderr)
    server.serve_forever()


if __name__ == "__main__":
    if "--serve" in sys.argv or len(sys.argv) == 1:
        serve_main()
    else:
        cli_main()
