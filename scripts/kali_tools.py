#!/usr/bin/env python3
"""Kali Linux tool integration for CyberLLM.

Provides a clean interface for the model/toolkit to invoke
Kali security tools (nmap, sqlmap, hydra, john, etc.)
via the Docker sandbox HTTP API.

Usage:
    from kali_tools import run_tool

    # Run on host directly (requires Kali host)
    rc, out, err = run_tool("nmap", "-sV", "scanme.nmap.org")

    # Run in sandbox (isolated, no network)
    rc, out, err = run_tool("nmap", "--version", sandbox=True)
"""

import json
import subprocess
import urllib.request
import urllib.error
import os
import shutil
import shlex

SANDBOX_URL = os.environ.get("SANDBOX_URL", "http://localhost:8002")


def run_tool(tool, *args, sandbox=False, timeout=30):
    """Execute a Kali tool and return (returncode, stdout, stderr).

    If sandbox=True, executes inside the Docker sandbox (no network).
    Otherwise runs on the host directly.
    """
    if sandbox:
        return _run_in_sandbox(tool, args, timeout)
    else:
        return _run_on_host(tool, args, timeout)


def _run_on_host(tool, args, timeout):
    """Run tool directly on the host."""
    if not shutil.which(tool):
        return -1, "", f"Tool '{tool}' not found on host"
    cmd = [tool] + list(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "TIMEOUT"
    except Exception as e:
        return -2, "", str(e)


def _run_in_sandbox(tool, args, timeout):
    """Run tool inside the Docker sandbox via HTTP API."""
    cmd = " ".join([tool] + [shlex.quote(a) for a in args])
    payload = json.dumps({"code": cmd, "lang": "bash"}).encode()
    req = urllib.request.Request(
        SANDBOX_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=timeout + 5)
        data = json.loads(resp.read())
        return data.get("returncode", -1), data.get("stdout", ""), data.get("stderr", "")
    except urllib.error.URLError as e:
        return -3, "", f"Sandbox unavailable: {e}"
    except Exception as e:
        return -4, "", str(e)


def scan_ports(target, ports="1-1000", sandbox=False):
    """Quick port scan wrapper around nmap."""
    return run_tool("nmap", "-sV", "-p", ports, target, sandbox=sandbox)


def sqlmap_scan(target, sandbox=False):
    """Quick SQL injection scan."""
    return run_tool("sqlmap", "-u", target, "--batch", "--random-agent",
                    sandbox=sandbox)


def dir_scan(target, wordlist="/usr/share/dirb/wordlists/common.txt", sandbox=False):
    """Directory brute-force."""
    return run_tool("dirb", target, wordlist, sandbox=sandbox)


if __name__ == "__main__":
    import sys
    import shlex
    if len(sys.argv) < 2:
        print("Usage: kali_tools.py <tool> [args...] [--sandbox]")
        sys.exit(1)
    args = sys.argv[1:]
    sandbox = "--sandbox" in args
    if sandbox:
        args.remove("--sandbox")
    tool = args[0]
    tool_args = args[1:]
    rc, out, err = run_tool(tool, *tool_args, sandbox=sandbox)
    print(out, end="")
    print(err, end="", file=sys.stderr)
    sys.exit(rc)
