# Scope Guardrail (middleware contract)

A thin middleware layer MUST run **before** any active-tool call (recon, vuln
scan, exploitation) is executed by the orchestrator. It is the single gate
between the LLM's tool-calling decision and the actual `fork`/`exec`.

## Rules

1. **Whitelist check** — the target (host/IP/URL/range) must be present in an
   authorized-scope file (e.g. `agent/config/scope.json`) before the call runs.
   Anything not explicitly listed is rejected with a clear message.
2. **Tool class gating** — `passive` tools (semgrep on local code you own) need
   no network authorization; `active` tools (nmap/nikto/nuclei/sqlmap/hydra)
   require `network: true` AND a matching scope entry.
3. **No out-of-scope escalation** — the model may configure an *existing* tool
   (e.g. sqlmap against an authorized host) but must never generate novel
   exploit payloads. Configuration only; no code writing for offensive capability.
4. **Timeout + capture** — every call runs under `timeout` with stdout/stderr
   captured; structured output (`-oX`/`-oJ`) is parsed, never shell-evaluated.
5. **Audit log** — record (tool, args, target, returncode, truncated output)
   for every call.

## Why

The model is helpful and will comply with security requests; the guardrail, not
the model, is the enforcement point for authorized use. Keep it as plain code
(C/C++ daemon or Python middleware) outside the LLM's control path.
