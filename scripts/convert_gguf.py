#!/usr/bin/env python3
"""Convert a merged HF model into a quantized GGUF for local Ollama/vLLM-cpu.

Pipeline:
  1. (optional) download a base or your merged model via snapshot_download
  2. run llama.cpp's convert_hf_to_gguf.py to emit a float16 GGUF
  3. quantize to Q4_K_M with llama-quantize (or llama.cpp python tool)
  4. write a Modelfile and (optionally) `ollama create` it

Requires: git clone of llama.cpp + built quantize binary, OR the python
`llama-cpp-python`/llama.cpp converter on PATH. This runs on CPU; it is
the bridge from a trained (merged) model to local Ollama inference.

Usage:
  python3 scripts/convert_gguf.py \
      --model outputs/qwen25-coder-7b-cyber/merged \
      --out outputs/qwen25-coder-7b-cyber/gguf \
      --llama-cpp /opt/llama.cpp \
      --quant Q4_K_M --ollama-name cyber-llm
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def step(msg):
    print(f"[convert_gguf] {msg}", flush=True)


def download_model(model_id, dest):
    from huggingface_hub import snapshot_download
    step(f"Downloading {model_id} -> {dest}")
    return snapshot_download(repo_id=model_id, local_dir=str(dest))


def convert_to_gguf(model_dir, out_dir, llama_cpp):
    converter = Path(llama_cpp) / "convert_hf_to_gguf.py"
    if not converter.exists():
        # fall back to the pip-installed `llama_cpp` converter if present
        try:
            import llama_cpp
            converter = Path(llama_cpp)  # placeholder; prefer repo converter
        except Exception:
            pass
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    f16 = out_dir / "model-f16.gguf"
    step(f"Converting to f16 GGUF: {f16}")
    subprocess.run(
        [sys.executable, str(converter), str(model_dir), "--outfile", str(f16)],
        check=True,
    )
    return f16


def quantize(f16, quant, llama_cpp):
    quantize_bin = Path(llama_cpp) / "llama-quantize"
    out = f16.with_name(f"model-{quant}.gguf")
    if quantize_bin.exists():
        step(f"Quantizing {f16.name} -> {out.name} ({quant})")
        subprocess.run([str(quantize_bin), str(f16), str(out), quant], check=True)
    else:
        step(f"llama-quantize not found at {quantize_bin}; "
             f"install llama.cpp or use `llama-gguf-split`/`quantize`. "
             f"Leaving f16 GGUF at {f16}")
        out = f16
    return out


def make_ollama(gguf_path, name, system_prompt):
    modelfile = gguf_path.parent / "Modelfile"
    modelfile.write_text(
        f"FROM {gguf_path.name}\n"
        f'SYSTEM "{system_prompt}"\n'
    )
    step(f"Wrote Modelfile -> {modelfile}")
    if shutil.which("ollama"):
        step(f"Creating Ollama model '{name}'")
        subprocess.run(["ollama", "create", name, "-f", str(modelfile)], check=True)
        step(f"Done. Try: ollama run {name}")
    else:
        step("ollama not on PATH; import manually: "
             f"ollama create {name} -f {modelfile}")


SYSTEM = ("You are a cybersecurity assistant for authorized security research. "
          "Use retrieved context when available, cite sources, and never provide "
          "operational attack code against systems you are not authorized to test.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="merged HF model dir or HF id")
    ap.add_argument("--out", default="outputs/gguf")
    ap.add_argument("--llama-cpp", default=os.environ.get("LLAMA_CPP", "/opt/llama.cpp"))
    ap.add_argument("--quant", default="Q4_K_M")
    ap.add_argument("--ollama-name", default="cyber-llm")
    ap.add_argument("--download", action="store_true",
                    help="treat --model as an HF repo id and download it first")
    args = ap.parse_args()

    model_dir = args.model
    if args.download or not Path(args.model).exists():
        model_dir = str(Path(args.out) / "src")
        download_model(args.model, model_dir)

    f16 = convert_to_gguf(model_dir, args.out, args.llama_cpp)
    final = quantize(f16, args.quant, args.llama_cpp)
    make_ollama(final, args.ollama_name, SYSTEM)
    print(json.dumps({"gguf": str(final), "ollama": args.ollama_name}, indent=2))


if __name__ == "__main__":
    main()
