"""Tests for the cyber-llm toolkit core logic.

Run with:  pytest -q
Most tests are offline and rely on the prebuilt indexes
(data/attack/index.json, data/llama_index, data/hf_dataset).
Run `make data` first to build those, or they skip gracefully.
"""
import json
import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))


# ---------------- fixtures ----------------
@pytest.fixture
def attack_idx():
    p = REPO / "data" / "attack" / "index.json"
    if not p.exists():
        pytest.skip("ATT&CK index missing (run `make attack-index`)")
    return json.loads(p.read_text())


# ---------------- dataset_manager ----------------
def test_tag_returns_list():
    from dataset_manager import _tag
    out = _tag("SQL injection in login form")
    assert isinstance(out, list)


def test_build_creates_hf_dataset(tmp_path, monkeypatch):
    import dataset_manager as dm
    monkeypatch.setattr(dm, "HF_DATASET_DIR", tmp_path / "hf")
    ds = dm.build()
    assert ds.num_rows >= 1
    assert "attack_techniques" in ds.column_names
    assert (tmp_path / "hf").exists()


# ---------------- attack_map ----------------
def test_lookup_known_technique(attack_idx):
    from attack_map import lookup
    r = lookup(attack_idx, "T1059")
    assert r is not None
    assert "name" in r


def test_lookup_unknown(attack_idx):
    from attack_map import lookup
    assert lookup(attack_idx, "T99999") is None


def test_search_returns_results(attack_idx):
    from attack_map import search
    res = search(attack_idx, "lateral movement", limit=3)
    assert isinstance(res, list)
    assert len(res) <= 3
    if res:
        tid, info = res[0]
        assert "name" in info


def test_tag_text_relevant(attack_idx):
    from attack_map import tag_text
    tags = tag_text(attack_idx, "Command and Scripting Interpreter used for execution")
    assert isinstance(tags, list)
    assert "T1059" in tags


def test_tactic_str_handles_none(attack_idx):
    from attack_map import _tactic_str
    assert _tactic_str(None) == ""
    assert _tactic_str(["execution", None]) == "execution"


# ---------------- rag_llama_index ----------------
def test_llama_index_query():
    if not (REPO / "data" / "llama_index").exists():
        pytest.skip("LlamaIndex store missing (run `make llama-index`)")
    from rag_llama_index import get_query_engine
    qe = get_query_engine()
    resp = qe.query("How do I remediate a SQL injection vulnerability?")
    assert len(resp.source_nodes) > 0
    top = resp.source_nodes[0].node.text.lower()
    assert "sql" in top or "injection" in top or "t1059" in top


def test_collect_documents_count():
    if not (REPO / "data" / "processed" / "cyber_train.jsonl").exists():
        pytest.skip("corpus missing")
    from rag_llama_index import _collect_documents
    docs = _collect_documents()
    assert len(docs) > 0


# ---------------- eval.py helpers ----------------
def test_extract_code_single_block():
    from eval import extract_code
    txt = "here:\n```python\nprint(1)\n```\ndone"
    assert "print(1)" in extract_code(txt)


def test_extract_code_none():
    from eval import extract_code
    assert extract_code("no code here") == ""


def test_is_refusal_variants():
    from eval import is_refusal
    assert is_refusal("I cannot help with that.")
    assert is_refusal("That would be illegal.")
    assert not is_refusal("Here is a secure coding pattern.")


def test_run_sandbox_rejects_no_docker(monkeypatch):
    from eval import run_sandbox
    import subprocess

    def boom(*a, **k):
        raise FileNotFoundError("docker")
    monkeypatch.setattr(subprocess, "run", boom)
    rc, out = run_sandbox("print(1)")
    # -3 == SKIPPED when docker is unavailable; -2 == other error
    assert rc in (-3, -2)
    assert "docker" in out.lower() or "SKIPPED" in out or "ERROR" in out
