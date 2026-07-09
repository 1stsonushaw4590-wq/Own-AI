#!/usr/bin/env bash
# Serve the fine-tuned (merged) model with vLLM for high-throughput local
# inference / OpenAI-compatible API.
#
# Usage: ./scripts/serve_vllm.sh <merged-model-dir> [port]
set -euo pipefail

MERGED="${1:?merged model dir}"
PORT="${2:-8000}"

# vLLM runs on the GPU host. Launch with docker (includes the runtime).
docker run --rm --gpus all --shm-size 16g \
  -p "$PORT:8000" \
  -v "$(realpath "$MERGED"):/model:ro" \
  vllm/vllm-openai:latest \
  --model /model \
  --dtype auto --tensor-parallel-size 1 \
  --max-model-len 4096 --gpu-memory-utilization 0.9 \
  --served-model-name cyber-llm

# After launch, the OpenAI-compatible endpoint is at:
#   http://localhost:$PORT/v1/chat/completions
