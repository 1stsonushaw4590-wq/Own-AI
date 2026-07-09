#!/usr/bin/env bash
# Run untrusted, model-generated code inside the isolated sandbox container.
# No network, read-only fs, seccomp, resource-limited.
#
# Usage: ./scripts/sandbox_run.sh path/to/generated_script.py
set -euo pipefail

SCRIPT="${1:?Provide a script path to run in the sandbox}"

# Build sandbox image once
docker build -t cyber-llm-sandbox:latest -f docker/Dockerfile.sandbox .

# Run with maximum isolation
docker run --rm \
  --network none \
  --read-only \
  --security-opt no-new-privileges \
  --security-opt seccomp=unconfined \
  --cap-drop ALL \
  --memory 512m \
  --cpus 1.0 \
  -v "$(realpath "$SCRIPT"):/sandbox/code.py:ro" \
  cyber-llm-sandbox:latest /sandbox/code.py
