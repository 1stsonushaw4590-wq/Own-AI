#!/usr/bin/env python3
"""Local chat UI for the fine-tuned cyber model, with sandbox-backed
code execution.

- Loads the merged model via transformers (works on the GPU host; on this
  CPU-only Kali box it will be slow — use it on the cloud instance).
- Detects fenced ```python code blocks in model replies and offers a
  "Run in sandbox" button that executes them in the isolated Docker
  container (--network none, read-only, dropped caps).
- Refuses/flags replies that map to offensive ATT&CK techniques without a
  stated authorized-scope context, using scripts/attack_map.py index.

Usage:
  python3 scripts/chat_ui.py --model outputs/qwen25-coder-7b-cyber/merged \
      --host 0.0.0.0 --port 7860
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

CODE_RE = re.compile(r"```(?:python)?\n(.*?)```", re.DOTALL)

# ATT&CK techniques we treat as "offensive-only" and require explicit
# authorized-scope context before allowing sandbox execution.
SENSITIVE_TECHNIQUES = {
    "T1059",  # command & scripting interpreter
    "T1078",  # valid accounts
    "T1110",  # brute force
    "T1490",  # inhibit system recovery (ransomware)
    "T1491",  # defacement
    "T1498",  # network DoS
    "T1505",  # malicious code in artifacts
    "T1190",  # exploit public-facing app
    "T1219",  # remote access tools
}


def load_attack_index():
    p = os.path.join("data", "attack", "index.json")
    if os.path.exists(p):
        with open(p) as f:
            return json.load(f)
    return None


# RAG (optional). Prefer LlamaIndex; fall back to the simple FAISS retriever.
try:
    from llama_index.core.query_engine import RetrieverQueryEngine
    from rag_llama_index import get_query_engine
    _RAG_AVAILABLE = True
    _RAG_BACKEND = "llama_index"
except Exception:  # noqa
    try:
        from rag_query import rag_answer, load_rag
        _RAG_AVAILABLE = True
        _RAG_BACKEND = "faiss"
    except Exception:  # noqa
        _RAG_AVAILABLE = False
        _RAG_BACKEND = None


def generate(model, prompt, max_new_tokens=768):
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM
    tok = AutoTokenizer.from_pretrained(model)
    mdl = AutoModelForCausalLM.from_pretrained(model, torch_dtype="auto", device_map="auto")
    messages = [{"role": "user", "content": prompt}]
    inp = tok.apply_chat_template(messages, return_tensors="pt").to(mdl.device)
    out = mdl.generate(inp, max_new_tokens=max_new_tokens, do_sample=True,
                       temperature=0.6, top_p=0.9, pad_token_id=tok.eos_token_id)
    return tok.decode(out[0][inp.shape[1]:], skip_special_tokens=True)


def run_sandbox(code, timeout=25):
    if not code.strip():
        return "(no code to run)"
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(code)
        path = f.name
    try:
        proc = subprocess.run(
            ["docker", "run", "--rm", "--network", "none", "--read-only",
             "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
             "--memory", "256m", "--cpus", "1.0",
             "-v", f"{path}:/sandbox/code.py:ro",
             "cyber-llm-sandbox:latest", "/sandbox/code.py"],
            capture_output=True, text=True, timeout=timeout,
        )
        out = (proc.stdout + proc.stderr).strip()
        return f"[exit {proc.returncode}]\n{out}" if out else f"[exit {proc.returncode}] (no output)"
    except subprocess.TimeoutExpired:
        return "TIMEOUT: execution exceeded CPU limit"
    except FileNotFoundError:
        return "ERROR: docker not found. Build sandbox image first."
    except Exception as e:  # noqa
        return f"ERROR: {e}"
    finally:
        os.unlink(path)


def check_scope(reply, attack_idx):
    """Flag generated content that maps to sensitive ATT&CK techniques."""
    if not attack_idx:
        return [], True
    tags = set()
    for tid in SENSITIVE_TECHNIQUES:
        info = attack_idx["techniques"].get(tid)
        if not info:
            continue
        if info["name"].lower() in reply.lower():
            tags.add(tid)
    authorized = "authorized" in reply.lower() or "scope" in reply.lower() \
        or "i own" in reply.lower() or "lab" in reply.lower()
    return sorted(tags), authorized


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", help="path to merged model dir")
    ap.add_argument("--mock", action="store_true",
                    help="use retrieval-based stub (no GPU/model needed)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=7860)
    ap.add_argument("--max-tokens", type=int, default=768)
    ap.add_argument("--no-ui", action="store_true",
                    help="run a one-shot CLI chat instead of Gradio")
    args = ap.parse_args()

    attack_idx = load_attack_index()

    if args.mock:
        from stub_model import stub_generate
        gen = stub_generate
        print("Using stub model (no GPU).")
    else:
        if not args.model:
            print("ERROR: provide --model <dir> or --mock", file=sys.stderr)
            sys.exit(2)
        print(f"Loading model {args.model} ...")
        gen = lambda p: generate(args.model, p, args.max_tokens)

    rag_engine = get_query_engine() if _RAG_AVAILABLE else None
    if rag_engine:
        print(f"RAG enabled ({_RAG_BACKEND}): retrieving grounded context.")
    else:
        print("RAG disabled (no index). Build one with: "
              "python3 scripts/rag_llama_index.py --build")

    def respond(prompt):
        if rag_engine:
            nodes = rag_engine.query(prompt).source_nodes
            ctx = [n.node.text for n in nodes]
            grounded = (
                "Use ONLY the context to answer. Cite source ids. "
                "Never provide unauthorized attack code.\n\nCONTEXT:\n"
                + "\n\n".join(f"[{i+1}] {c[:800]}" for i, c in enumerate(ctx))
                + f"\n\nQUESTION: {prompt}\n\nANSWER:"
            )
            reply = gen(grounded)
        else:
            reply = gen(prompt)
        code = "\n".join(CODE_RE.findall(reply))
        tags, authorized = check_scope(reply, attack_idx)
        warn = ""
        if tags and not authorized:
            warn = (f"\n\n⚠ This reply references sensitive ATT&CK techniques "
                    f"{tags}. Only run generated code in the sandbox against "
                    f"systems you are authorized to test.")
        return reply + warn, code

    if args.no_ui:
        print("CLI chat (type 'exit'). Code blocks are NOT auto-run.")
        while True:
            try:
                p = input("\nyou> ")
            except EOFError:
                break
            if p.strip() in ("exit", "quit"):
                break
            reply, code = respond(p)
            print("\nmodel>", reply)
            if code:
                if input("run in sandbox? (y/N) ").strip().lower() == "y":
                    print(run_sandbox(code))
        return

    try:
        import gradio as gr
    except ImportError:
        print("gradio not installed. Run: pip install gradio  (or use --no-ui)")
        sys.exit(1)

    with gr.Blocks(title="Cyber-LLM Chat") as ui:
        gr.Markdown("# Cyber-LLM — sandbox-backed security assistant\n"
                    "Generated code runs only in an isolated Docker sandbox.")
        chatbot = gr.Chatbot(height=500)
        msg = gr.Textbox(label="Prompt", placeholder="Ask about a vuln, remediation, secure code...")
        run_btn = gr.Button("Run last code block in sandbox")
        sand_out = gr.Textbox(label="Sandbox output", interactive=False)

        state = gr.State([])

        def user_fn(prompt, history):
            history = history + [[prompt, None]]
            return "", history

        def bot_fn(history):
            prompt = history[-1][0]
            reply, _ = respond(prompt)
            history[-1][1] = reply
            return history

        def exec_fn(history):
            last = history[-1][1] if history else ""
            code = "\n".join(CODE_RE.findall(last))
            return run_sandbox(code)

        msg.submit(user_fn, [msg, chatbot], [msg, chatbot]).then(
            bot_fn, chatbot, chatbot)
        run_btn.click(exec_fn, chatbot, sand_out)

    ui.launch(server_name=args.host, server_port=args.port)


if __name__ == "__main__":
    main()
