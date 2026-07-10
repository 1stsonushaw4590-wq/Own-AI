#!/usr/bin/env python3
"""
Merge LoRA adapter from CPU training with base model.

Usage:
  python3 training/merge_cpu.py \
    --base Qwen/Qwen2.5-Coder-0.5B-Instruct \
    --adapter outputs/qwen25-coder-0.5b-cyber/adapter \
    --output outputs/qwen25-coder-0.5b-cyber/merged
"""

import os
import sys
import argparse
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="Qwen/Qwen2.5-Coder-0.5B-Instruct")
    parser.add_argument("--adapter", default="outputs/qwen25-coder-0.5b-cyber/adapter")
    parser.add_argument("--output", default="outputs/qwen25-coder-0.5b-cyber/merged")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"Device: {device}")
    print(f"Loading base model: {args.base}")

    tokenizer = AutoTokenizer.from_pretrained(args.base, trust_remote_code=True)

    model = AutoModelForCausalLM.from_pretrained(
        args.base,
        torch_dtype=torch.float32,
        trust_remote_code=True,
    )

    if os.path.exists(args.adapter):
        print(f"Loading adapter: {args.adapter}")
        model = PeftModel.from_pretrained(model, args.adapter)
        print("Merging adapter with base model...")
        model = model.merge_and_unload()
    else:
        print(f"Warning: adapter not found at {args.adapter}, saving base model only")

    print(f"Saving merged model to: {args.output}")
    model.save_pretrained(args.output, safe_serialization=True)
    tokenizer.save_pretrained(args.output)

    print("Done! Merged model saved to:", args.output)


if __name__ == "__main__":
    main()
