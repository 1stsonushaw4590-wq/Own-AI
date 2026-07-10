import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import verify_password, create_access_token, hash_password
from app.models.user import User
from app.models.conversation import Conversation, Message
from app.schemas.chat import (
    ChatRequest, ChatResponse, CodeReviewRequest, CodeReviewResponse,
    SandboxExecuteRequest, SandboxExecuteResponse,
)
from app.services.inference import inference_client
from app.services.sandbox import sandbox
from app.services.rag import rag

router = APIRouter()


# ─── Auth ────────────────────────────────────────────────────

@router.post("/auth/register")
async def register(email: str, password: str, db: AsyncSession = Depends(get_db)):
    exists = await db.execute(select(User).where(User.email == email))
    if exists.scalar_one_or_none():
        raise HTTPException(400, "Email already registered")
    user = User(email=email, hashed_password=hash_password(password))
    db.add(user)
    await db.commit()
    return {"message": "User created"}


@router.post("/auth/login")
async def login(email: str, password: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(401, "Invalid credentials")
    token = create_access_token({"sub": str(user.id)})
    return {"access_token": token, "token_type": "bearer"}


# ─── Chat ────────────────────────────────────────────────────

@router.post("/chat/completions")
async def chat_completions(
    req: ChatRequest,
    db: AsyncSession = Depends(get_db),
):
    messages = [{"role": m.role, "content": m.content} for m in req.messages]

    if req.use_rag:
        last_msg = messages[-1]["content"]
        context = await rag.search(last_msg)
        if context:
            ctx_text = "\n\n".join(
                f"[Source: {c['source']}]\n{c['text'][:500]}"
                for c in context[:3]
            )
            messages[-1]["content"] = (
                f"Use the following context to answer.\n\n"
                f"CONTEXT:\n{ctx_text}\n\n"
                f"QUESTION: {last_msg}"
            )

    response = await inference_client.chat(
        messages=messages,
        model=req.model,
        temperature=req.temperature,
        max_tokens=req.max_tokens,
        top_p=req.top_p,
    )

    return response


# ─── Code Review ─────────────────────────────────────────────

@router.post("/code/review", response_model=CodeReviewResponse)
async def code_review(req: CodeReviewRequest):
    prompt = (
        f"Review this {req.language} code for security vulnerabilities, bugs, "
        f"and best practices. Provide specific issues and remediation:\n\n"
        f"```{req.language}\n{req.code}\n```\n\n"
        f"Format: List each issue with severity, location, description, and fix."
    )
    msg = [{"role": "user", "content": prompt}]
    resp = await inference_client.chat(messages=msg, max_tokens=2048)
    content = resp["choices"][0]["message"]["content"]
    return CodeReviewResponse(
        issues=[{"severity": "medium", "description": content[:200]}],
        suggestions=[content],
        secure_score=50,
        explanation=content,
    )


# ─── Sandbox Execution ──────────────────────────────────────

@router.post("/sandbox/execute", response_model=SandboxExecuteResponse)
async def sandbox_execute(req: SandboxExecuteRequest):
    result = await sandbox.execute(
        code=req.code,
        language=req.language,
        timeout=req.timeout,
    )
    return SandboxExecuteResponse(**result)


# ─── RAG Search ─────────────────────────────────────────────

@router.post("/rag/search")
async def rag_search(query: str, limit: int = 5):
    results = await rag.search(query, limit=limit)
    return {"results": results}


# ─── Health ──────────────────────────────────────────────────

@router.get("/health")
async def health():
    inference_ok = await inference_client.health()
    return {
        "status": "ok",
        "inference": "up" if inference_ok else "down",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─── Models ──────────────────────────────────────────────────

@router.get("/models")
async def list_models():
    return {
        "models": [
            {
                "id": "cyber-llm",
                "name": "Cyber Security Foundation Model",
                "provider": "Cyber-LLM",
            }
        ]
    }
