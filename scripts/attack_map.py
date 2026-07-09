#!/usr/bin/env python3
"""MITRE ATT&CK mapping layer.

- Downloads the official ATT&CK Enterprise tactics/techniques STIX bundle
  (public, Creative Commons) and indexes it locally.
- Provides lookup by technique ID (T1059), name (Command and Scripting
  Interpreter), and keyword search.
- Tags free-text (model output, CVE descriptions) with related techniques.

Usage:
  python3 scripts/attack_map.py --refresh          # download + index
  python3 scripts/attack_map.py --id T1059         # lookup
  python3 scripts/attack_map.py --search "lateral movement"
  python3 scripts/attack_map.py --tag-file data/raw/sample.jsonl
"""
import argparse
import json
import os
import re
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = REPO_ROOT / "data" / "attack"
INDEX_PATH = CACHE_DIR / "index.json"
STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

# Technique name -> short description we store. Type fallbacks.
OBJECT_TYPES = {"attack-pattern", "x-mitre-tactic"}


def _download():
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Downloading ATT&CK STIX from {STIX_URL}")
    req = urllib.request.Request(STIX_URL, headers={"User-Agent": "cyber-llm"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = json.loads(r.read().decode("utf-8"))
    return data


def _build_index(data):
    idx = {"tactics": {}, "techniques": {}}
    for obj in data.get("objects", []):
        t = obj.get("type")
        if t == "x-mitre-tactic":
            tid = obj.get("x_mitre_shortname", "")
            idx["tactics"][tid] = {
                "name": obj.get("name", ""),
                "description": (obj.get("description", "") or "")[:300],
            }
        elif t == "attack-pattern":
            ext = obj.get("external_references", [])
            attack_id = next((e.get("external_id") for e in ext
                              if e.get("source_name") == "mitre-attack"), None)
            if not attack_id:
                continue
            name = obj.get("name", "")
            desc = (obj.get("description", "") or "")[:400]
            tactics = [k.get("x_mitre_shortname") for k in obj.get("kill_chain_phases", [])
                       if k.get("kill_chain_name") == "mitre-attack"]
            idx["techniques"][attack_id] = {
                "name": name,
                "description": desc,
                "tactics": tactics,
                "keywords": re.findall(r"[a-zA-Z][a-zA-Z\-]{4,}", (name + " " + desc).lower()),
            }
    with open(INDEX_PATH, "w") as f:
        json.dump(idx, f, indent=2)
    print(f"Indexed {len(idx['techniques'])} techniques, "
          f"{len(idx['tactics'])} tactics -> {INDEX_PATH}")
    return idx


def load_index(force=False):
    if force or not INDEX_PATH.exists():
        data = _download()
        return _build_index(data)
    with open(INDEX_PATH) as f:
        return json.load(f)


def lookup(idx, attack_id):
    return idx["techniques"].get(attack_id.upper())


def search(idx, query, limit=5):
    q = query.lower()
    scored = []
    for tid, info in idx["techniques"].items():
        if q in info["name"].lower() or q in info["description"].lower():
            scored.append((tid, info, 2))
        elif any(q in k for k in info["keywords"]):
            scored.append((tid, info, 1))
    scored.sort(key=lambda x: x[2], reverse=True)
    return [(tid, info) for tid, info, _ in scored[:limit]]


def _tactic_str(tactics):
    return ", ".join(t for t in (tactics or []) if t)


# Words too generic to be useful signals for tagging.
_STOPWORDS = {
    "attack", "using", "system", "command", "code", "data", "file", "files",
    "process", "service", "network", "user", "users", "account", "access",
    "windows", "linux", "remote", "local", "execution", "malware", "software",
    "security", "vulnerability", "exploit", "server", "application", "script",
    "password", "authentication", "information", "target", "technique", "tool",
    "tools", "behavior", "common", "adversary", "mitre", "impact", "defense",
    "detection", "persistence", "execution", "lateral", "movement", "scope",
}


def _keywords(info):
    return [k for k in info.get("keywords", []) if k not in _STOPWORDS and len(k) > 7]


def tag_text(idx, text, max_hits=12):
    text_l = text.lower()
    scored = []
    for tid, info in idx["techniques"].items():
        name = info["name"].lower()
        if name and name in text_l:
            scored.append((tid, 3))
            continue
        for k in _keywords(info):
            # require word-boundary-ish match (avoid substrings of long words)
            if re.search(r"\b" + re.escape(k) + r"\b", text_l):
                scored.append((tid, 2))
                break
    # sort by score desc, then by id for stability
    scored.sort(key=lambda x: (-x[1], x[0]))
    seen = set()
    out = []
    for tid, _ in scored:
        if tid not in seen:
            seen.add(tid)
            out.append(tid)
        if len(out) >= max_hits:
            break
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--refresh", action="store_true", help="re-download STIX + rebuild index")
    ap.add_argument("--id", help="lookup a technique by ATT&CK ID (T1059)")
    ap.add_argument("--search", help="keyword search techniques")
    ap.add_argument("--tag-file", help="tag every line of a jsonl file with technique IDs")
    ap.add_argument("--tag-text", help="tag a raw string")
    args = ap.parse_args()

    idx = load_index(force=args.refresh)

    if args.id:
        r = lookup(idx, args.id)
        print(json.dumps(r, indent=2) if r else f"No technique {args.id}")
    if args.search:
        for tid, info in search(idx, args.search):
            print(f"{tid}: {info['name']}  [{_tactic_str(info['tactics'])}]")
    if args.tag_text:
        print(tag_text(idx, args.tag_text))
    if args.tag_file:
        out = args.tag_file + ".tagged.jsonl"
        with open(args.tag_file) as fin, open(out, "w") as fout:
            for line in fin:
                line = line.strip()
                if not line:
                    continue
                o = json.loads(line)
                blob = " ".join(str(o.get(k, "")) for k in ("instruction", "input", "output"))
                o["attack_techniques"] = tag_text(idx, blob)
                fout.write(json.dumps(o) + "\n")
        print(f"Tagged -> {out}")


if __name__ == "__main__":
    main()
