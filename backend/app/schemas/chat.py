from pydantic import BaseModel
from typing import List, Optional


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    model: str = "cyber-llm"
    messages: List[ChatMessage]
    temperature: float = 0.6
    max_tokens: int = 2048
    top_p: float = 0.9
    stream: bool = False
    use_rag: bool = True


class ChatResponse(BaseModel):
    id: str
    model: str
    choices: List[dict]
    usage: dict


class CodeReviewRequest(BaseModel):
    code: str
    language: str = "python"
    context: Optional[str] = None


class CodeReviewResponse(BaseModel):
    issues: List[dict]
    suggestions: List[str]
    secure_score: int
    explanation: str


class SandboxExecuteRequest(BaseModel):
    code: str
    language: str = "python"
    timeout: int = 25


class SandboxExecuteResponse(BaseModel):
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
