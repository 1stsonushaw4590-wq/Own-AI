#!/usr/bin/env python3
"""Convert raw cybersecurity samples into Axolotl 'alpaca' JSONL format.

Expected raw input: data/raw/*.jsonl  where each line is:
  {"instruction": "...", "input": "...", "output": "..."}
or a plain text file where each line is a prompt/response pair block.

Output: data/processed/cyber_train.jsonl
"""
import json
import os
import glob

RAW_DIR = "data/raw"
OUT = "data/processed/cyber_train.jsonl"

os.makedirs(os.path.dirname(OUT), exist_ok=True)

records = []
for path in glob.glob(os.path.join(RAW_DIR, "*.jsonl")):
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            rec = {
                "instruction": obj.get("instruction", "").strip(),
                "input": obj.get("input", "").strip(),
                "output": obj.get("output", "").strip(),
            }
            if rec["instruction"] and rec["output"]:
                records.append(rec)

# drop exact duplicates
seen = set()
uniq = []
for r in records:
    key = (r["instruction"], r["input"], r["output"])
    if key not in seen:
        seen.add(key)
        uniq.append(r)

with open(OUT, "w") as f:
    for r in uniq:
        f.write(json.dumps(r) + "\n")

print(f"Wrote {len(uniq)} samples to {OUT}")
