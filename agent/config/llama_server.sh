#!/usr/bin/env bash
# Launch the local cyber-LLM as an OpenAI-compatible endpoint via llama.cpp's
# llama-server. Point MODEL at the retrained Q4_K_M GGUF produced by the
# training pipeline (outputs/qwen25-coder-0.5b-cyber/gguf/model-Q4_K_M.gguf).
set -e

MODEL="${MODEL:-outputs/qwen25-coder-0.5b-cyber/gguf/model-Q4_K_M.gguf}"
LLAMA_CPP="${LLAMA_CPP:-/tmp/opencode/llama.cpp}"
THREADS="${THREADS:-$(nproc)}"
PORT="${PORT:-8080}"
HOST="${HOST:-127.0.0.1}"

SERVER_BIN="${LLAMA_CPP}/build/bin/llama-server"
if [ ! -x "$SERVER_BIN" ]; then
  echo "llama-server not built. Building it now..." >&2
  cmake --build "${LLAMA_CPP}/build" --target llama-server -j"$THREADS"
fi

exec "$SERVER_BIN" \
  --model "$MODEL" \
  --alias cyber-llm \
  --host "$HOST" --port "$PORT" \
  --threads "$THREADS" \
  --ctx-size 8192
