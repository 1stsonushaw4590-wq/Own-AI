#!/usr/bin/env python3
"""
Merge LoRA adapters with base model and quantize to GGUF.

Steps:
1. Load base model (4-bit)
2. Load and merge LoRA adapter
3. Save merged model in FP16
4. Convert to GGUF Q4_K_M via llama.cpp

Usage:
  python3 merge_and_quantize.py \
    --base Qwen/Qwen2.5-Coder-7B-Instruct \
    --adapter /outputs/adapter \
    --output /outputs/merged \
    --gguf /outputs/gguf
"""

import os
import argparse
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
from peft import PeftModel


def merge_and_save(base_model_name, adapter_path, output_path):
    print(f"Loading base model: {base_model_name}")
    tokenizer = AutoTokenizer.from_pretrained(base_model_name, trust_remote_code=True)

    model = AutoModelForCausalLM.from_pretrained(
        base_model_name,
        torch_dtype=torch.bfloat16,
        device_map="auto",
        trust_remote_code=True,
    )

    print(f"Loading adapter from: {adapter_path}")
    model = PeftModel.from_pretrained(model, adapter_path)

    print("Merging adapter with base model...")
    model = model.merge_and_unload()

    print(f"Saving merged model to: {output_path}")
    model.save_pretrained(output_path, safe_serialization=True)
    tokenizer.save_pretrained(output_path)
    print("Merge complete!")

    return output_path


def convert_to_gguf(model_path, gguf_path, llama_cpp_path="/opt/llama.cpp"):
    """Convert HF model to GGUF using llama.cpp."""
    import subprocess

    convert_script = os.path.join(llama_cpp_path, "convert_hf_to_gguf.py")
    if not os.path.exists(convert_script):
        print(f"Warning: {convert_script} not found. Skipping GGUF conversion.")
        print(f"To convert manually: python3 {convert_script} {model_path} --outfile {gguf_path}/cyber-llm-q4_k_m.gguf --outtype q4_k_m")
        return

    os.makedirs(gguf_path, exist_ok=True)
    output_file = os.path.join(gguf_path, "cyber-llm-q4_k_m.gguf")

    cmd = [
        "python3", convert_script,
        model_path,
        "--outfile", output_file,
        "--outtype", "q4_k_m",
    ]

    print(f"Converting to GGUF: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)
    print(f"GGUF model saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="Qwen/Qwen2.5-Coder-7B-Instruct")
    parser.add_argument("--adapter", default="/outputs/adapter")
    parser.add_argument("--output", default="/outputs/merged")
    parser.add_argument("--gguf", default="/outputs/gguf")
    parser.add_argument("--llama-cpp", default="/opt/llama.cpp")
    parser.add_argument("--skip-gguf", action="store_true")
    args = parser.parse_args()

    merged_path = merge_and_save(args.base, args.adapter, args.output)

    if not args.skip_gguf:
        convert_to_gguf(merged_path, args.gguf, args.llama_cpp)
    else:
        print("Skipping GGUF conversion.")


if __name__ == "__main__":
    main()
