#!/usr/bin/env bash
# Build the full cybersecurity training corpus:
#   1. scrape public sources (CVE/CWE/HF Q&A)
#   2. merge with any hand-written data/raw/*.jsonl
#   3. prepare the final alpaca jsonl for Axolotl
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> Scraping public cybersecurity sources"
python3 scripts/scrape_dataset.py --out data/raw/cyber_scraped.jsonl \
    --cve-limit "${CVE_LIMIT:-150}" --cwe-limit "${CWE_LIMIT:-80}" \
    --hf-limit "${HF_LIMIT:-150}"

echo "==> Merging all raw data (including Kali tool samples)"
cat data/raw/*.jsonl data/tool_samples.jsonl > data/processed/cyber_train.jsonl

echo "==> Validating prepared dataset"
python3 - <<'PY'
import json, glob
n=0
with open("data/processed/cyber_train.jsonl") as f:
    for line in f:
        line=line.strip()
        if not line: continue
        o=json.loads(line)
        assert o.get("instruction") and o.get("output")
        n+=1
print(f"OK: {n} total training samples")
PY
