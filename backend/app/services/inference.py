import httpx
import json
from typing import AsyncGenerator
from app.core.config import get_settings


class InferenceClient:
    def __init__(self):
        self.settings = get_settings()
        self.base_url = self.settings.inference_url

    async def chat(
        self,
        messages: list[dict],
        model: str = "cyber-llm",
        temperature: float = 0.6,
        max_tokens: int = 2048,
        top_p: float = 0.9,
        stream: bool = False,
    ) -> dict | AsyncGenerator[str, None]:
        url = f"{self.base_url}/v1/chat/completions"
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "top_p": top_p,
            "stream": stream,
        }

        async with httpx.AsyncClient(timeout=120.0) as client:
            if stream:
                return self._stream_chat(client, url, payload)
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            return resp.json()

    async def _stream_chat(
        self, client: httpx.AsyncClient, url: str, payload: dict
    ) -> AsyncGenerator[str, None]:
        async with client.stream("POST", url, json=payload) as resp:
            async for line in resp.aiter_lines():
                if line.startswith("data: "):
                    data = line[6:].strip()
                    if data == "[DONE]":
                        break
                    if data:
                        chunk = json.loads(data)
                        yield chunk

    async def embed(self, texts: list[str]) -> list[list[float]]:
        url = f"{self.base_url}/v1/embeddings"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json={"input": texts, "model": "text-embedding"})
            resp.raise_for_status()
            data = resp.json()
            return [item["embedding"] for item in data["data"]]

    async def health(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/health")
                return resp.status_code == 200
        except Exception:
            return False


inference_client = InferenceClient()
