#!/usr/bin/env python3
"""
Merge LoRA adapter with base model and quantize to GGUF.
Usage:
    python3 merge_and_quantize.py \
        --base Qwen/Qwen2.5-Coder-7B-Instruct \
        --adapter outputs/qwen25-coder-7b-cyber/adapter \
        --output outputs/qwen25-coder-7b-cyber/merged \
        --gguf outputs/qwen25-coder-7b-cyber/gguf \
        --quant q4_k_m
"""

import os
import sys
import argparse
import subprocess
import shutil
from pathlib import Path


def merge_and_save(base_model: str, adapter_path: str, output_path: str):
    """Merge LoRA adapter with base model and save."""
    print(f"Loading base model: {base_model}")
    from transformers import AutoTokenizer, AutoModelForCausalLM
    import torch
    from peft import PeftModel

    tokenizer = AutoTokenizer.from_pretrained(base_model, trust_remote_code=True)
    tokenizer.pad_token = tokenizer.eos_token

    print(f"Loading base model in FP16...")
    model = AutoModelForCausalLM.from_pretrained(
        base_model,
        torch_dtype=torch.float16,
        device_map="auto",
        trust_remote_code=True,
    )

    print(f"Loading adapter: {adapter_path}")
    model = PeftModel.from_pretrained(model, adapter_path)

    print("Merging adapter...")
    model = model.merge_and_unload()

    print(f"Saving merged model to: {output_path}")
    model.save_pretrained(output_path, safe_serialization=True)
    tokenizer.save_pretrained(output_path)

    print("Merge complete!")


def convert_to_gguf(model_path: str, gguf_path: str, quant_type: str):
    """Convert HF model to GGUF using llama.cpp."""
    print(f"Converting to GGUF: {gguf_path}")

    # Find llama.cpp convert script
    llama_cpp_paths = [
        "/tmp/opencode/llama.cpp/convert_hf_to_gguf.py",
        "/usr/local/llama.cpp/convert_hf_to_gguf.py",
        os.path.expanduser("~/llama.cpp/convert_hf_to_gguf.py"),
        "/opt/llama.cpp/convert_hf_to_gguf.py",
    ]

    convert_script = None
    for p in llama_cpp_paths:
        if os.path.exists(p):
            convert_script = p
            break

    if not convert_script:
        # Try to find in llama.cpp repo
        result = subprocess.run(
            ["find", "/", "-name", "convert_hf_to_gguf.py", "-type", "f", "2>/dev/null"],
            capture_output=True, text=True, timeout=30
        )
        if result.stdout.strip():
            convert_script = result.stdout.strip().split('\n')[0]

    if not convert_script:
        print("ERROR: convert_hf_to_gguf.py not found!")
        print("Please install llama.cpp: git clone https://github.com/ggerganov/llama.cpp")
        sys.exit(1)

    print(f"Using convert script: {convert_script}")

    os.makedirs(gguf_path, exist_ok=True)
    output_file = os.path.join(gguf_path, f"cyber-llm-{quant_type}.gguf")

    # Convert to f16 first
    f16_path = os.path.join(gguf_path, "cyber-llm-f16.gguf")
    cmd = [
        sys.executable, convert_script,
        model_path,
        "--outfile", f16_path,
        "--outtype", "f16",
    ]

    print(f"Converting to f16: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        print(f"Conversion failed: {result.stderr}")
        sys.exit(1)

    print("f16 conversion done, quantizing...")

    # Quantize using llama-quantize
    llama_quantize = None
    for p in [
        "/tmp/opencode/llama.cpp/build/bin/llama-quantize",
        "/usr/local/llama.cpp/build/bin/llama-quantize",
        os.path.expanduser("~/llama.cpp/build/bin/llama-quantize"),
    ]:
        if os.path.exists(p):
            llama_quantize = p
            break

    if not llama_quantize:
        result = subprocess.run(
            ["find", "/", "-name", "llama-quantize", "-type", "f", "2>/dev/null"],
            capture_output=True, text=True, timeout=30
        )
        if result.stdout.strip():
            llama_quantize = result.stdout.strip().split('\n')[0]

    if not llama_quantize:
        print("ERROR: llama-quantize not found! Build llama.cpp first.")
        sys.exit(1)

    print(f"Quantizing to {quant_type}...")
    cmd = [llama_quantize, f16_path, output_file, quant_type]
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        print(f"Quantization failed: {result.stderr}")
        sys.exit(1)

    # Cleanup f16
    if os.path.exists(f16_path):
        os.remove(f16_path)

    print(f"GGUF model saved: {output_file}")
    print(f"Size: {os.path.getsize(output_file) / 1024 / 1024:.1f} MB")


def main():
    parser = argparse.ArgumentParser(description="Merge LoRA and quantize to GGUF")
    parser.add_argument("--base", required=True, help="Base model name or path")
    parser.add_argument("--adapter", required=True, help="LoRA adapter path")
    parser.add_argument("--output", required=True, help="Merged model output path")
    parser.add_argument("--gguf", required=True, help="GGUF output directory")
    parser.add_argument("--quant", default="q4_k_m", choices=[
        "q4_k_m", "q4_k_s", "q5_k_m", "q5_k_s", "q6_k", "q8_0", "f16"
    ], help="Quantization type")

    args = parser.parse_args()

    # Merge
    merge_and_save(args.base, args.adapter, args.output)

    # Convert to GGUF
    convert_to_gguf(args.output, args.gguf, args.quant)

    print("\n✅ Done!")
    print(f"Merged model: {args.output}")
    print(f"GGUF model: {args.gguf}/cyber-llm-{args.quant}.gguf")


if __name__ == "__main__":
    main()