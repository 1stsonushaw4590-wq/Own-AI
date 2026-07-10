import httpx
from typing import Optional
from app.core.config import get_settings


class RAGService:
    def __init__(self):
        self.settings = get_settings()
        self.qdrant_url = self.settings.qdrant_url
        self.collection = "cyber_docs"

    async def search(self, query: str, limit: int = 5, threshold: float = 0.5) -> list[dict]:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{self.qdrant_url}/collections/{self.collection}/points/search",
                json={
                    "vector": await self._embed(query),
                    "limit": limit,
                    "with_payload": True,
                },
            )
            resp.raise_for_status()
            results = resp.json().get("result", [])
            return [
                {
                    "id": r["id"],
                    "score": r["score"],
                    "text": r["payload"].get("text", ""),
                    "source": r["payload"].get("source", ""),
                    "metadata": r["payload"].get("metadata", {}),
                }
                for r in results
                if r["score"] >= threshold
            ]

    async def index_document(self, doc_id: str, text: str, metadata: dict) -> bool:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.put(
                f"{self.qdrant_url}/collections/{self.collection}/points",
                json={
                    "points": [
                        {
                            "id": doc_id,
                            "vector": await self._embed(text),
                            "payload": {
                                "text": text,
                                "source": metadata.get("source", ""),
                                "metadata": metadata,
                            },
                        }
                    ]
                },
            )
            return resp.status_code == 200

    async def _embed(self, text: str) -> list[float]:
        from sentence_transformers import SentenceTransformer
        model = SentenceTransformer(self.settings.embedding_model)
        return model.encode(text).tolist()


rag = RAGService()
