#!/usr/bin/env python3
"""Dataset management with Hugging Face `datasets` + a torch Dataset.

- Loads alpaca-format jsonl (data/processed/cyber_train.jsonl) into a
  HF Dataset, applies ATT&CK technique tagging, and saves to disk as an
  Arrow dataset for fast reuse.
- Exposes `CyberTorchDataset` for PyTorch training loops (PEFT/transformers
  Trainer) and `load_hf_dataset()` for the Trainer directly.

Usage:
  python3 scripts/dataset_manager.py --build
"""
import argparse
import json
import os
from pathlib import Path

from datasets import Dataset, load_from_disk

REPO_ROOT = Path(__file__).resolve().parent.parent
RAW_GLOB = REPO_ROOT / "data" / "raw" / "*.jsonl"
PROCESSED = REPO_ROOT / "data" / "processed" / "cyber_train.jsonl"
HF_DATASET_DIR = REPO_ROOT / "data" / "hf_dataset"
ATTACK_INDEX = REPO_ROOT / "data" / "attack" / "index.json"


def _tag(text):
    """Lightweight ATT&CK keyword tagging (no heavy deps)."""
    if not ATTACK_INDEX.exists():
        return []
    idx = json.loads(ATTACK_INDEX.read_text())
    text_l = text.lower()
    hits = []
    for tid, info in idx["techniques"].items():
        name = info["name"].lower()
        if name and name in text_l:
            hits.append(tid)
        elif any(k in text_l for k in info.get("keywords", [])[:3] if len(k) > 8):
            hits.append(tid)
        if len(hits) >= 12:
            break
    return sorted(set(hits))


def build():
    rows = []
    files = [PROCESSED] + [str(p) for p in (REPO_ROOT / "data" / "raw").glob("*.jsonl")]
    seen = set()
    for src in files:
        p = Path(src)
        if not p.exists():
            continue
        with open(p) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                except json.JSONDecodeError:
                    continue
                instr = o.get("instruction", "").strip()
                inp = o.get("input", "").strip()
                out = o.get("output", "").strip()
                if not instr or not out:
                    continue
                key = (instr, inp, out)
                if key in seen:
                    continue
                seen.add(key)
                text = " ".join([instr, inp, out])
                rows.append({
                    "instruction": instr,
                    "input": inp,
                    "output": out,
                    "attack_techniques": _tag(text),
                })
    ds = Dataset.from_list(rows)
    Path(HF_DATASET_DIR).mkdir(parents=True, exist_ok=True)
    ds.save_to_disk(HF_DATASET_DIR)
    print(f"Built HF dataset: {len(ds)} rows -> {HF_DATASET_DIR}")
    return ds


def load_hf_dataset(split="train"):
    return load_from_disk(HF_DATASET_DIR)[split]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", action="store_true", help="build HF dataset from raw jsonl")
    args = ap.parse_args()
    if args.build:
        build()
    else:
        print("Use --build to create the HF dataset.")
