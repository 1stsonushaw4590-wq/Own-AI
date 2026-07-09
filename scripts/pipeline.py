#!/usr/bin/env python3
"""Unified pipeline CLI for cyber-llm.

Orchestrates the full workflow:
  prepare  -> attack index + corpus + HF dataset
  index    -> LlamaIndex retrieval store
  train    -> PEFT QLoRA fine-tune (GPU host)
  eval     -> CyberSecEval-style eval
  serve    -> Ollama / vLLM serving

Usage:
  python3 scripts/pipeline.py prepare
  python3 scripts/pipeline.py index
  python3 scripts/pipeline.py train  --model Qwen/Qwen2.5-Coder-7B-Instruct
  python3 scripts/pipeline.py eval   --model outputs/.../merged
  python3 scripts/pipeline.py serve  --model outputs/.../merged --backend ollama
"""
import argparse
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPTS = REPO / "scripts"


def _run(cmd):
    print("+", " ".join(str(c) for c in cmd))
    subprocess.run(cmd, check=True, cwd=REPO)


def cmd_prepare(args):
    _run([sys.executable, str(SCRIPTS / "attack_map.py"), "--refresh"])
    _run([sys.executable, str(SCRIPTS / "build_corpus.sh")])
    _run([sys.executable, str(SCRIPTS / "dataset_manager.py"), "--build"])


def cmd_index(args):
    _run([sys.executable, str(SCRIPTS / "rag_llama_index.py"), "--build"])


def cmd_train(args):
    _run([sys.executable, str(SCRIPTS / "finetune_peft.py"),
          "--model", args.model, "--output", args.output])


def cmd_eval(args):
    _run([sys.executable, str(SCRIPTS / "eval.py"),
          "--model", args.model, "--out", args.out])


def cmd_serve(args):
    script = "serve_ollama.sh" if args.backend == "ollama" else "serve_vllm.sh"
    _run(["bash", str(SCRIPTS / script), args.model, str(args.port)])


def main():
    ap = argparse.ArgumentParser(prog="pipeline.py")
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
    p.add_argument("--model", required=True)
    p.add_argument("--out", default="outputs/eval_results.json")
    p.set_defaults(func=cmd_eval)

    p = sub.add_parser("serve", help="serve merged model (ollama/vllm)")
    p.add_argument("--model", required=True)
    p.add_argument("--backend", choices=["ollama", "vllm"], default="ollama")
    p.add_argument("--port", type=int, default=8000)
    p.set_defaults(func=cmd_serve)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
