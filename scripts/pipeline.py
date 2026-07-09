#!/usr/bin/env python3
"""Unified pipeline CLI for cyber-llm.

Orchestrates the full workflow:
  prepare  -> attack index + corpus + HF dataset
  index    -> LlamaIndex retrieval store
  train    -> PEFT QLoRA fine-tune (GPU host)
  eval     -> CyberSecEval-style eval
  serve    -> Ollama / vLLM serving
  status   -> show what's been built

Usage:
  python3 scripts/pipeline.py prepare
  python3 scripts/pipeline.py index
  python3 scripts/pipeline.py train  --model Qwen/Qwen2.5-Coder-7B-Instruct
  python3 scripts/pipeline.py eval   --model outputs/.../merged
  python3 scripts/pipeline.py serve  --model outputs/.../merged --backend ollama
  python3 scripts/pipeline.py status
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPTS = REPO / "scripts"


def _run(cmd, label=""):
    t0 = time.time()
    if label:
        print(f"\n{'='*60}\n  {label}\n{'='*60}")
    print("+", " ".join(str(c) for c in cmd), flush=True)
    r = subprocess.run(cmd, cwd=REPO)
    dt = time.time() - t0
    if r.returncode != 0:
        print(f"FAILED (exit {r.returncode}, {dt:.1f}s)", file=sys.stderr)
        sys.exit(r.returncode)
    print(f"OK ({dt:.1f}s)")


def cmd_prepare(args):
    _run([sys.executable, str(SCRIPTS / "attack_map.py"), "--refresh"],
         "Step 1: Download + index MITRE ATT&CK")
    _run([str(SCRIPTS / "build_corpus.sh")],
         "Step 2: Scrape CVE/CWE/HF -> cyber_train.jsonl")
    _run([sys.executable, str(SCRIPTS / "dataset_manager.py"), "--build"],
         "Step 3: Build HF dataset + ATT&CK tagging")


def cmd_index(args):
    _run([sys.executable, str(SCRIPTS / "rag_llama_index.py"), "--build"],
         "Building LlamaIndex retrieval store")


def cmd_train(args):
    _run([sys.executable, str(SCRIPTS / "finetune_peft.py"),
          "--model", args.model, "--output", args.output],
         f"Fine-tuning {args.model} -> {args.output}")


def cmd_eval(args):
    cmd = [sys.executable, str(SCRIPTS / "eval.py"),
           "--out", args.out]
    if args.mock:
        cmd += ["--mock"]
    else:
        cmd += ["--model", args.model]
    _run(cmd, f"Evaluating {'stub' if args.mock else args.model}")


def cmd_serve(args):
    script = "serve_ollama.sh" if args.backend == "ollama" else "serve_vllm.sh"
    _run(["bash", str(SCRIPTS / script), args.model, str(args.port)],
         f"Serving via {args.backend} on :{args.port}")


def cmd_status(args):
    print("=== Cyber-LLM project status ===\n")
    checks = [
        ("ATT&CK index", REPO / "data" / "attack" / "index.json"),
        ("Corpus", REPO / "data" / "processed" / "cyber_train.jsonl"),
        ("HF dataset", REPO / "data" / "hf_dataset" / "state.json"),
        ("LlamaIndex store", REPO / "data" / "llama_index" / "docstore.json"),
        ("Sandbox image", None),  # checked via docker
        ("Qwen2.5-Coder merged", REPO / "outputs" / "qwen25-coder-7b-cyber" / "merged"),
        ("DeepSeek-Coder merged", REPO / "outputs" / "deepseek-coder-6.7b-cyber" / "merged"),
        ("Llama-3.1 merged", REPO / "outputs" / "llama31-8b-cyber" / "merged"),
    ]
    for name, path in checks:
        if path is None:
            try:
                subprocess.run(["docker", "image", "inspect", "cyber-llm-sandbox:latest"],
                               capture_output=True, check=True)
                print(f"  [OK] {name}")
            except Exception:
                print(f"  [--] {name}  (build with: make sandbox-build)")
        elif path.exists():
            print(f"  [OK] {name}")
        else:
            print(f"  [--] {name}")

    # Docker daemon
    try:
        subprocess.run(["docker", "info"], capture_output=True, check=True)
        print(f"\n  Docker daemon: running")
    except Exception:
        print(f"\n  Docker daemon: NOT running (sudo usermod -aG docker $USER)")

    # Ollama
    try:
        subprocess.run(["ollama", "--version"], capture_output=True, check=True)
        print(f"  Ollama: installed")
    except Exception:
        print(f"  Ollama: not installed")


def main():
    ap = argparse.ArgumentParser(
        prog="pipeline.py",
        description="Cyber-LLM unified pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python3 scripts/pipeline.py prepare\n"
               "  python3 scripts/pipeline.py eval --mock\n"
               "  python3 scripts/pipeline.py status\n",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("prepare", help="attack index + corpus + HF dataset")
    p.set_defaults(func=cmd_prepare)

    p = sub.add_parser("index", help="build LlamaIndex retrieval store")
    p.set_defaults(func=cmd_index)

    p = sub.add_parser("train", help="PEFT QLoRA fine-tune (GPU host)")
    p.add_argument("--model", default="Qwen/Qwen2.5-Coder-7B-Instruct")
    p.add_argument("--output", default="outputs/qwen25-coder-7b-cyber")
    p.set_defaults(func=cmd_train)

    p = sub.add_parser("eval", help="CyberSecEval-style eval")
    p.add_argument("--model", help="path to merged model dir")
    p.add_argument("--mock", action="store_true",
                   help="use retrieval-based stub (no GPU)")
    p.add_argument("--out", default="outputs/eval_results.json")
    p.set_defaults(func=cmd_eval)

    p = sub.add_parser("serve", help="serve merged model (ollama/vllm)")
    p.add_argument("--model", required=True)
    p.add_argument("--backend", choices=["ollama", "vllm"], default="ollama")
    p.add_argument("--port", type=int, default=8000)
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("status", help="show what's been built")
    p.set_defaults(func=cmd_status)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
