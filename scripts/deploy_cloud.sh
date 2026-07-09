#!/usr/bin/env bash
# Deploy to a cloud GPU instance (RunPod / Lambda). Copies the repo over SSH,
# then runs the training container remotely.
#
# Usage:
#   REMOTE=user@host ./scripts/deploy_cloud.sh <model>
set -euo pipefail

REMOTE="${REMOTE:?Set REMOTE=user@host (your cloud GPU instance)}"
MODEL="${1:-qwen25-coder}"
REPO_DIR="/workspace/cyber-llm"

echo "==> Syncing repo to $REMOTE:$REPO_DIR"
ssh "$REMOTE" "mkdir -p $REPO_DIR"
rsync -az --exclude 'outputs' --exclude 'data/processed/prepared' \
  ./ "$REMOTE:$REPO_DIR/"

echo "==> Launching training on remote GPU"
ssh -t "$REMOTE" "cd $REPO_DIR && bash scripts/train.sh $MODEL cloud"
