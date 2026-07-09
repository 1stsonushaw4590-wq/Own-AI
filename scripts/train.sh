#!/usr/bin/env bash
# Launch a fine-tuning job. Usage:
#   ./scripts/train.sh <qwen25-coder|deepseek-coder|llama31> [cloud|local]
#
# 'cloud' (default when a GPU is present in the target) launches the training
# container with GPU passthrough. On this Kali box without a GPU, use the
# same configs on your RunPod/Lambda instance by copying the repo over.
set -euo pipefail

MODEL="${1:-qwen25-coder}"
TARGET="${2:-cloud}"

case "$MODEL" in
  qwen25-coder) CFG=configs/qwen25-coder-7b.yaml ;;
  deepseek-coder) CFG=configs/deepseek-coder-6.7b.yaml ;;
  llama31) CFG=configs/llama31-8b.yaml ;;
  *) echo "Unknown model: $MODEL"; exit 1 ;;
esac

echo "==> Training $MODEL with config $CFG (target=$TARGET)"

if [ "$TARGET" = "cloud" ]; then
  # For cloud GPU: build & run with nvidia runtime (run this on the GPU host)
  docker compose -f docker/docker-compose.train.yml build
  docker compose -f docker/docker-compose.train.yml run --rm train \
    axolotl train "$CFG"
else
  # Local: prepare dataset only / sanity-check configs (no GPU training)
  echo "Local host has no GPU. Preparing dataset and validating config syntax."
  python3 -c "import yaml,sys; yaml.safe_load(open('$CFG')); print('config OK')"
fi
