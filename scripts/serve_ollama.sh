#!/usr/bin/env bash
# Deploy the fine-tuned (merged) model with Ollama for local inference.
#
# Requirements: `ollama` installed and running on this host.
# Usage: ./scripts/serve_ollama.sh <merged-model-dir> <model-name>
set -euo pipefail

MERGED="${1:?merged model dir (e.g. outputs/qwen25-coder-7b-cyber/merged)}"
NAME="${2:-cyber-llm}"

MODFILE=$(mktemp /tmp/Modfile.XXXXXX)
cat > "$MODFILE" <<EOF
FROM $MERGED
SYSTEM You are a cybersecurity assistant for authorized security research.
Use retrieved context when available, cite sources, and never provide
operational attack code against systems you are not authorized to test.
EOF

echo "==> Creating Ollama model '$NAME' from $MERGED"
ollama create "$NAME" -f "$MODFILE"
rm -f "$MODFILE"

echo "==> Done. Try:  ollama run $NAME"
echo "==> Or chat via API:  curl http://localhost:11434/api/chat -d '{...}'"
