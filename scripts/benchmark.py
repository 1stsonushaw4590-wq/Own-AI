#!/usr/bin/env python3
"""Multi-model benchmark: compare Qwen2.5-Coder, DeepSeek-Coder, and Llama
on the CyberSecEval-style harness.

Runs `scripts/eval.py` for each merged model dir and prints a comparison
table of benign utility vs abuse resistance.

Usage:
  python3 scripts/benchmark.py \
      --models outputs/qwen25-coder-7b-cyber/merged \
               outputs/deepseek-coder-6.7b-cyber/merged \
               outputs/llama31-8b-cyber/merged \
      --out outputs/benchmark.json
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
EVAL = REPO / "scripts" / "eval.py"


def run_eval(model_dir, out_path):
    # HF Hub model IDs contain "/"; only require a local path to exist.
    if "/" not in model_dir and not Path(model_dir).exists():
        return {"model": model_dir, "error": "merged model not found"}
    r = subprocess.run(
        [sys.executable, str(EVAL), "--model", model_dir, "--out", str(out_path)],
        cwd=REPO, capture_output=True, text=True,
    )
    if r.returncode != 0:
        return {"model": model_dir, "error": r.stderr[-500:]}
    try:
        return json.loads(Path(out_path).read_text())
    except Exception as e:  # noqa
        return {"model": model_dir, "error": str(e)}


def summarize(results):
    print("\n=== Benchmark: benign utility vs abuse resistance ===")
    print(f"{'model':<40} {'benign':<14} {'abuse_safe':<14}")
    print("-" * 70)
    for r in results:
        name = Path(r.get("model", "?")).parent.name or r.get("model")
        if "error" in r:
            print(f"{name:<40} ERROR: {r['error'][:40]}")
            continue
        print(f"{name:<40} {r['benign_utility']:<14} {r['abuse_resistance']:<14}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", help="paths to merged model dirs")
    ap.add_argument("--mock", action="store_true",
                    help="benchmark the stub model (no GPU) for all 3 names")
    ap.add_argument("--out", default="outputs/benchmark.json")
    args = ap.parse_args()

    if args.mock:
        args.models = [
            "outputs/qwen25-coder-7b-cyber/merged",
            "outputs/deepseek-coder-6.7b-cyber/merged",
            "outputs/llama31-8b-cyber/merged",
        ]
    elif not args.models:
        print("ERROR: provide --models <dirs...> or --mock", file=sys.stderr)
        sys.exit(2)

    os.makedirs(REPO / "outputs", exist_ok=True)
    results = []
    for m in args.models:
        out_path = REPO / "outputs" / f"eval_{Path(m).parent.name or 'model'}.json"
        print(f">> Evaluating {m}")
        if args.mock:
            r = subprocess.run(
                [sys.executable, str(EVAL), "--mock", "--out", str(out_path)],
                cwd=REPO, capture_output=True, text=True,
            )
            if r.returncode != 0:
                results.append({"model": m, "error": r.stderr[-500:]})
            else:
                results.append(json.loads(Path(out_path).read_text()))
        else:
            results.append(run_eval(m, out_path))

    aggregated = {"models": results}
    Path(args.out).write_text(json.dumps(aggregated, indent=2))
    summarize(results)
    print(f"\nFull results -> {args.out}")


if __name__ == "__main__":
    main()
