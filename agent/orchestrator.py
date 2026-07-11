#!/usr/bin/env python3
"""Minimal local cyber-agent orchestrator.

Loads tool specs from tools.json, talks to a llama.cpp `llama-server`
(OpenAI-compatible /v1/chat/completions), enforces the scope guardrail
before any active-tool execution, and runs tools via subprocess with a
timeout + output capture.

Stdlib only (no third-party deps). Not the performance-critical path — the
LLM inference (llama.cpp C++ lib) and tool execution (fork/exec) are; this
loop just orchestrates, so Python is acceptable here.

Usage:
  python3 orchestrator.py --base-url http://127.0.0.1:8080/v1 \
      --model cyber-llm --tools tools/tools.json --scope config/scope.json
"""
import argparse
import json
import subprocess
import sys
import urllib.request

SYSTEM_PROMPT = (
    "You are a cybersecurity assistant operating inside an authorized-scope "
    "agent. Use the provided tools to investigate authorized targets only. "
    "For each step, either call one tool or give a final answer. Never invent "
    "tool output. When a tool returns data, reason over it and decide the next "
    "step (more tools, or a final written report)."
)


def chat(base_url, model, messages, tools):
    payload = {
        "model": model,
        "messages": messages,
        "tools": tools,
        "tool_choice": "auto",
        "stream": False,
        "temperature": 0.2,
        "max_tokens": 1024,
    }
    req = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode())


def load_scope(path):
    if not path:
        return set()
    with open(path) as f:
        data = json.load(f)
    return set(data.get("allowed_targets", []))


def in_scope(scope, target):
    if not scope:
        return False
    return target in scope


def execute(tool, args, scope):
    # Scope guardrail: active tools require an authorized target.
    if tool.get("scope_guardrail"):
        target = args.get("target") or args.get("host") or args.get("path") or ""
        if not in_scope(scope, target):
            return (1, f"REJECTED by scope guardrail: '{target}' is not in the authorized scope file.")
    cmd = tool["command"]
    for k, v in args.items():
        cmd = cmd.replace("{" + k + "}", str(v))
    # Safe substitutions for scan_type / ssl flags used in templates.
    cmd = cmd.replace("{scan_type_flag}", {"syn": "-sS", "connect": "-sT", "service": "-sV"}.get(args.get("scan_type", "connect"), "-sT"))
    cmd = cmd.replace("{ssl_flag}", " -ssl" if args.get("ssl") else "")
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                               timeout=tool.get("timeout_sec", 300))
        out = (proc.stdout or "") + (proc.stderr or "")
        return (proc.returncode, out[:4000])
    except subprocess.TimeoutExpired:
        return (124, "TIMEOUT")


def run(base_url, model, tools_path, scope_path, user_prompt, max_steps=8):
    with open(tools_path) as f:
        tools = json.load(f)["tools"]
    scope = load_scope(scope_path)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]
    for step in range(max_steps):
        resp = chat(base_url, model, messages, tools)
        msg = resp["choices"][0]["message"]
        if not msg.get("tool_calls"):
            return msg.get("content", "")
        messages.append({"role": "assistant", "content": msg.get("content", ""),
                         "tool_calls": msg["tool_calls"]})
        for tc in msg["tool_calls"]:
            fn = tc["function"]
            name = fn["name"]
            args = json.loads(fn.get("arguments", "{}"))
            spec = next((t for t in tools if t["function"]["name"] == name), None)
            if not spec:
                result = "unknown tool"
                rc = 1
            else:
                rc, result = execute(spec["function"], args, scope)
            messages.append({
                "role": "tool",
                "tool_call_id": tc["id"],
                "content": f"[exit {rc}]\n{result}",
            })
    return "(max steps reached)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:8080/v1")
    ap.add_argument("--model", default="cyber-llm")
    ap.add_argument("--tools", default="tools/tools.json")
    ap.add_argument("--scope", default="config/scope.json")
    ap.add_argument("--prompt", required=True)
    ap.add_argument("--max-steps", type=int, default=8)
    args = ap.parse_args()
    print(run(args.base_url, args.model, args.tools, args.scope,
              args.prompt, args.max_steps))


if __name__ == "__main__":
    main()
