#!/usr/bin/env bash
# Deploy a model with Ollama for local inference.
#
# Accepts either a merged HF model directory OR a .gguf file.
# For a GGUF, we write a Modelfile pointing at it and `ollama create`.
# (To quantize a merged HF model to GGUF first, use scripts/convert_gguf.py.)
#
# Usage:
#   ./scripts/serve_ollama.sh <merged-model-dir | model.gguf> [model-name]
set -euo pipefail

SRC="${1:?model dir or .gguf file}"
NAME="${2:-cyber-llm}"

if [[ "$SRC" == *.gguf ]]; then
  GGUF_DIR=$(dirname "$SRC")
  MODFILE="$GGUF_DIR/Modelfile"
  cat > "$MODFILE" <<EOF
FROM $(basename "$SRC")
SYSTEM You are a cybersecurity assistant for authorized security research. Use retrieved context when available, cite sources, and never provide operational attack code against systems you are not authorized to test.
EOF
  echo "==> Creating Ollama model '$NAME' from GGUF $SRC"
  ollama create "$NAME" -f "$MODFILE"
else
  MODFILE=$(mktemp /tmp/Modfile.XXXXXX)
  cat > "$MODFILE" <<EOF
FROM $SRC
SYSTEM You are a cybersecurity assistant for authorized security research.
Use retrieved context when available, cite sources, and never provide
operational attack code against systems you are not authorized to test.
EOF
  echo "==> Creating Ollama model '$NAME' from $SRC"
  ollama create "$NAME" -f "$MODFILE"
  rm -f "$MODFILE"
fi

echo "==> Done. Try:  ollama run $NAME"
echo "==> Or chat via API:  curl http://localhost:11434/api/chat -d '{...}'"
