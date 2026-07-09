#!/usr/bin/env python3
"""RAG retrieval + grounded generation for the cyber model.

Retrieves the top-k most relevant corpus / ATT&CK chunks for a query and
builds a grounded prompt so the fine-tuned model answers with citations to
your data instead of hallucinating.

Usage:
  python3 scripts/rag_query.py "How do I remediate CVE-2024-1234?"
  (or imported by chat_ui.py)
"""
import json
import os
from pathlib import Path

INDEX_DIR = Path("data/rag")
EMBED_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
_TOP_K = 4


def load_rag():
    """Return a retriever function, or None if index is missing."""
    import faiss
    from sentence_transformers import SentenceTransformer
    idx_path = INDEX_DIR / "index.faiss"
    docs_path = INDEX_DIR / "docs.json"
    if not idx_path.exists() or not docs_path.exists():
        return None
    index = faiss.read_index(str(idx_path))
    docs = json.loads(docs_path.read_text())
    model = SentenceTransformer(EMBED_MODEL)

    def retrieve(query, k=_TOP_K):
        q = model.encode([query], convert_to_numpy=True).astype("float32")
        _, ids = index.search(q, k)
        out = []
        for i in ids[0]:
            if i < 0 or i >= len(docs):
                continue
            out.append(docs[i])
        return out

    return retrieve


def build_prompt(query, contexts):
    sys_part = ("You are a cybersecurity assistant. Use ONLY the retrieved "
                "context below to answer. If the context does not contain the "
                "answer, say you don't know. Cite the source id when relevant. "
                "Never provide operational attack code against systems you are "
                "not authorized to test.")
    ctx = "\n\n".join(
        f"[ctx {i+1}] {c['text'][:800]}" for i, c in enumerate(contexts)
    )
    return f"{sys_part}\n\nCONTEXT:\n{ctx}\n\nQUESTION: {query}\n\nANSWER:"


def rag_answer(generate_fn, query, k=_TOP_K):
    """Retrieve + build prompt + call model generate fn. Returns (answer, ctx)."""
    retrieve = load_rag()
    if retrieve is None:
        # No RAG index: answer directly (warn once via return flag)
        return generate_fn(query), []
    ctx = retrieve(query, k)
    prompt = build_prompt(query, ctx)
    return generate_fn(prompt), ctx


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: rag_query.py <query>")
        raise SystemExit(1)
    query = " ".join(sys.argv[1:])
    retrieve = load_rag()
    if retrieve is None:
        print("RAG index not found. Run: python3 scripts/rag_index.py --build")
        raise SystemExit(1)
    ctx = retrieve(query)
    print("=== Retrieved contexts ===")
    for i, c in enumerate(ctx):
        src = c.get("meta", {})
        print(f"[{i+1}] {src.get('id') or src.get('type') or 'corpus'}: "
              f"{c['text'][:120]}...")
    print("\n=== Grounded prompt ===")
    print(build_prompt(query, ctx))
