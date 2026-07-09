#!/usr/bin/env python3
"""Retrieval with LlamaIndex over the cybersecurity corpus + ATT&CK.

Builds a local vector index (using sentence-transformers embeddings + a
local FAISS/LlamaIndex store) and exposes a query engine that returns
grounded context for the model. Fully offline, no external API.

Usage:
  python3 scripts/rag_llama_index.py --build
  python3 scripts/rag_llama_index.py --query "remediate CVE-2024-1234"
  (importable: from rag_llama_index import get_query_engine)
"""
import argparse
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
INDEX_DIR = REPO_ROOT / "data" / "llama_index"
EMBED_MODEL = "local:BAAI/bge-small-en-v1.5"  # sentence-transformers via HF


def _collect_documents():
    from llama_index.core import Document
    docs = []
    # corpus
    p = REPO_ROOT / "data" / "processed" / "cyber_train.jsonl"
    if p.exists():
        with open(p) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                o = json.loads(line)
                text = " ".join(str(o.get(k, "")) for k in
                                ("instruction", "input", "output"))
                if text.strip():
                    docs.append(Document(text=text, metadata={"source": "corpus"}))
    # ATT&CK
    atk = REPO_ROOT / "data" / "attack" / "index.json"
    if atk.exists():
        idx = json.loads(atk.read_text())
        for tid, info in idx["techniques"].items():
            docs.append(Document(
                text=f"{tid} {info['name']}: {info['description']}",
                metadata={"source": "attack", "id": tid}))
    print(f"Collected {len(docs)} documents")
    return docs


def build():
    from llama_index.core import VectorStoreIndex, Settings
    from llama_index.embeddings.huggingface import HuggingFaceEmbedding

    Settings.embed_model = HuggingFaceEmbedding(model_name="BAAI/bge-small-en-v1.5")
    docs = _collect_documents()
    index = VectorStoreIndex.from_documents(docs)
    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    index.storage_context.persist(persist_dir=str(INDEX_DIR))
    print(f"LlamaIndex persisted -> {INDEX_DIR}")


def get_query_engine(top_k=4, similarity_top_k=4):
    """Return a retriever-only engine (no LLM) so it works fully offline."""
    from llama_index.core import StorageContext, load_index_from_storage, Settings
    from llama_index.embeddings.huggingface import HuggingFaceEmbedding
    from llama_index.core.query_engine import RetrieverQueryEngine

    Settings.embed_model = HuggingFaceEmbedding(model_name="BAAI/bge-small-en-v1.5")
    Settings.llm = None
    sc = StorageContext.from_defaults(persist_dir=str(INDEX_DIR))
    index = load_index_from_storage(sc)
    retriever = index.as_retriever(similarity_top_k=top_k)
    return RetrieverQueryEngine.from_args(retriever)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", action="store_true")
    ap.add_argument("--query", help="query the index")
    args = ap.parse_args()
    if args.build:
        build()
        return
    if args.query:
        if not INDEX_DIR.exists():
            print("Index missing. Run: python3 scripts/rag_llama_index.py --build")
            raise SystemExit(1)
        qe = get_query_engine()
        resp = qe.query(args.query)
        print("=== Retrieved contexts (LlamaIndex) ===")
        for n in resp.source_nodes:
            meta = n.node.metadata
            print(f"- {meta.get('source')}/{meta.get('id','')}: "
                  f"{n.node.text[:140]}...")
        return
    print("Use --build or --query.")


if __name__ == "__main__":
    main()
