#!/usr/bin/env python3
"""Streamlit chat UI — RAG-grounded, sandbox-backed cybersecurity assistant.

Alternative to the Gradio UI (chat_ui.py). Retrieves grounded context from
the LlamaIndex store, generates with the merged model, and lets you run any
generated ```python block in the isolated Docker sandbox.

Usage:
  pip install streamlit
  docker build -t cyber-llm-sandbox:latest -f docker/Dockerfile.sandbox .
  streamlit run scripts/chat_streamlit.py -- --model outputs/qwen25-coder-7b-cyber/merged
"""
import argparse
import re
import subprocess
import tempfile
from pathlib import Path

import streamlit as st

REPO_ROOT = Path(__file__).resolve().parent.parent
SANDBOX_IMAGE = "cyber-llm-sandbox:latest"
CODE_RE = re.compile(r"```(?:python)?\n(.*?)```", re.DOTALL)


def parse_args():
    # Streamlit injects its own args; parse only what's after "--"
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="")
    ap.add_argument("--mock", action="store_true",
                    help="use retrieval-based stub (no GPU/model needed)")
    ap.add_argument("--max-tokens", type=int, default=768)
    known, _ = ap.parse_known_args()
    return known


def load_rag():
    try:
        from rag_llama_index import get_query_engine
        return get_query_engine()
    except Exception:
        return None


@st.cache_resource(show_spinner="Loading model…")
def load_model(model_path, max_tokens):
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM
    tok = AutoTokenizer.from_pretrained(model_path)
    mdl = AutoModelForCausalLM.from_pretrained(
        model_path, torch_dtype="auto", device_map="auto")
    return tok, mdl


def generate(tok_mdl, prompt, max_tokens):
    tok, mdl = tok_mdl
    messages = [{"role": "user", "content": prompt}]
    inp = tok.apply_chat_template(messages, return_tensors="pt").to(mdl.device)
    out = mdl.generate(inp, max_new_tokens=max_tokens, do_sample=True,
                       temperature=0.6, top_p=0.9, pad_token_id=tok.eos_token_id)
    return tok.decode(out[0][inp.shape[1]:], skip_special_tokens=True)


def run_sandbox(code, timeout=25):
    if not code.strip():
        return "(no code)"
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(code)
        path = f.name
    try:
        proc = subprocess.run(
            ["docker", "run", "--rm", "--network", "none", "--read-only",
             "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
             "--memory", "256m", "--cpus", "1.0",
             "-v", f"{path}:/sandbox/code.py:ro",
             SANDBOX_IMAGE, "/sandbox/code.py"],
            capture_output=True, text=True, timeout=timeout)
        out = (proc.stdout + proc.stderr).strip()
        return f"[exit {proc.returncode}]\n{out}" if out else f"[exit {proc.returncode}]"
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    except FileNotFoundError:
        return "ERROR: docker not found."
    except Exception as e:  # noqa
        return f"ERROR: {e}"
    finally:
        Path(path).unlink(missing_ok=True)


def main():
    args = parse_args()
    st.set_page_config(page_title="Cyber-LLM", page_icon="🛡️")
    st.title("🛡️ Cyber-LLM Assistant")
    st.caption("RAG-grounded · sandbox-backed · for authorized security research")

    if not args.model:
        st.warning("Pass --model <merged-model-dir> after `--`.")
        return

    rag = load_rag()
    if rag is None:
        st.info("RAG index not found — running without retrieval. "
                "Build it with `python3 scripts/rag_llama_index.py --build`.")

    if args.mock:
        from stub_model import stub_generate
        st.success("Using stub model (no GPU).")
        tok_mdl = None
    else:
        if not args.model:
            st.warning("Pass --model <merged-model-dir> after `--`, or use --mock.")
            return
        tok_mdl = load_model(args.model, args.max_tokens)

    if "history" not in st.session_state:
        st.session_state.history = []

    for role, msg in st.session_state.history:
        st.chat_message(role).write(msg)

    if prompt := st.chat_input("Ask about a vuln, remediation, or secure code…"):
        st.chat_message("user").write(prompt)
        st.session_state.history.append(("user", prompt))

        with st.chat_message("assistant"):
            if rag is not None:
                nodes = rag.query(prompt).source_nodes
                ctx = [n.node.text for n in nodes]
                grounded = (
                    "Use ONLY the context to answer. Cite source ids. "
                    "Never provide unauthorized attack code.\n\nCONTEXT:\n"
                    + "\n\n".join(f"[{i+1}] {c[:800]}" for i, c in enumerate(ctx))
                    + f"\n\nQUESTION: {prompt}\n\nANSWER:"
                )
                with st.expander(f"Retrieved {len(ctx)} context chunk(s)"):
                    for i, c in enumerate(ctx):
                        st.write(f"**[{i+1}]** {c[:300]}…")
            else:
                grounded = prompt

            if tok_mdl is None:
                reply = stub_generate(grounded)
            else:
                reply = generate(tok_mdl, grounded, args.max_tokens)
            st.write(reply)
            st.session_state.history.append(("assistant", reply))

            code = "\n".join(CODE_RE.findall(reply))
            if code:
                if st.button("▶ Run generated code in sandbox"):
                    out = run_sandbox(code)
                    st.code(out, language="text")


if __name__ == "__main__":
    main()
