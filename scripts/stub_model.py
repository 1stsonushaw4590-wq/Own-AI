#!/usr/bin/env python3
"""Retrieval-based stub model (no GPU required).

Lets the full pipeline — RAG retrieval, chat UIs, eval harness, benchmark —
run end-to-end on a CPU-only machine without a fine-tuned model. It
retrieves the top-k chunks from the LlamaIndex store and composes a
grounded answer (optionally echoing a code block from the corpus). This is
NOT a real LLM; it exists so the tooling is demoable locally. Replace with
a real merged model for production use.

Used when callers pass `--mock` (eval/chat/benchmark) instead of `--model`.
"""
import re

CODE_RE = re.compile(r"```(?:python)?\n(.*?)```", re.DOTALL)

REFUSAL_TEMPLATES = [
    "I can't help with that — providing operational attack code against "
    "systems you are not authorized to test would be unsafe. For authorized "
    "research, scope it in a lab you own.",
    "That request maps to an offensive technique I won't operationalize. "
    "Happy to discuss detection/defense instead.",
]

SENSITIVE = ["ransomware", "ddos", "brute force", "brute-force", "exploit",
             "malware", "virus", "botnet", "attack a", "hack", "crack",
             "payload", "backdoor", "rootkit"]


def _retrieve(prompt, k=4):
    try:
        from rag_llama_index import get_query_engine
        qe = get_query_engine()
        return [n.node.text for n in qe.query(prompt).source_nodes[:k]]
    except Exception:
        return []


def _first_code(text):
    m = CODE_RE.search(text)
    return m.group(1).strip() if m else ""


def stub_generate(prompt, max_new_tokens=512):
    """Return a grounded reply string (mirrors a real model's output)."""
    p = prompt.lower()

    # Abuse guard: refuse clearly offensive operational requests.
    if any(s in p for s in SENSITIVE) and ("how" in p or "write" in p or "script" in p):
        return REFUSAL_TEMPLATES[0]

    ctx = _retrieve(prompt)
    if not ctx:
        return ("I don't have retrieved context for that query. Build the "
                "RAG index with `python3 scripts/rag_llama_index.py --build` "
                "and add corpus data.")

    # Compose a grounded answer from the retrieved chunks.
    joined = "\n\n".join(f"- {c[:400]}" for c in ctx)
    code = _first_code("\n".join(ctx))
    answer = (
        "Based on the retrieved cybersecurity knowledge base:\n\n"
        f"{joined}\n\n"
        "Recommendation: follow secure-coding and OWASP guidance, validate "
        "all input, and test only in an authorized lab."
    )
    if code:
        answer += f"\n\nExample from corpus:\n```python\n{code}\n```"
    return answer


def stub_extract_code(reply):
    return _first_code(reply)


if __name__ == "__main__":
    import sys
    q = " ".join(sys.argv[1:]) or "How do I remediate a SQL injection vulnerability?"
    print(stub_generate(q))
