"""Shared data models for every stage and endpoint."""
from __future__ import annotations

from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class Decision(str, Enum):
    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"  # allowed after masking / stripping content
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    BLOCK = "BLOCK"

    @property
    def rank(self) -> int:
        return {"ALLOW": 0, "SANITIZE": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}[self.value]

    @staticmethod
    def strictest(*decisions: "Decision") -> "Decision":
        return max(decisions, key=lambda d: d.rank)


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> float:
        return {"low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}[self.value]


class Finding(BaseModel):
    """One thing a stage noticed. Never contains raw PII (only types/hashes)."""

    stage: str
    category: str
    rule_id: str
    severity: Severity
    message: str
    evidence: Optional[str] = None  # short, already-redacted snippet
    view: Optional[str] = None  # which normalized view matched (e.g. "base64_decoded")


class StageResult(BaseModel):
    name: str
    status: Literal["ok", "skipped", "error"] = "ok"
    risk: float = 0.0  # 0..1
    findings: list[Finding] = Field(default_factory=list)
    latency_ms: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None


class Principal(BaseModel):
    user_id: str
    role: str
    tenant: str = "default"
    permissions: list[str] = Field(default_factory=list)
    auth_method: str = "api_key"


class GuardResponse(BaseModel):
    request_id: str
    decision: Decision
    risk_score: float
    reasons: list[str]
    sanitized_text: Optional[str] = None
    stages: list[StageResult]
    latency_ms: float


# ---------- request bodies ----------


class PromptRequest(BaseModel):
    text: str = Field(..., max_length=50_000)
    session_id: Optional[str] = None
    system_prompt: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ContextChunk(BaseModel):
    id: str
    text: str = Field(..., max_length=100_000)
    source: str = "unknown"  # e.g. "sharepoint://finance/q3.pdf"
    source_type: Literal["pdf", "webpage", "email", "database", "upload", "ocr", "tool_output", "api", "other"] = "other"
    trust: Literal["trusted", "internal", "external", "unknown"] = "unknown"


class ContextRequest(BaseModel):
    user_query: str = Field(..., max_length=50_000)
    chunks: list[ContextChunk]
    session_id: Optional[str] = None


class ChunkVerdict(BaseModel):
    id: str
    source: str
    trust: str
    action: Literal["keep", "sanitize", "quarantine"]
    risk: float
    findings: list[Finding]
    sanitized_text: Optional[str] = None


class ContextResponse(BaseModel):
    request_id: str
    decision: Decision
    risk_score: float
    reasons: list[str]
    chunks: list[ChunkVerdict]
    safe_context: str
    latency_ms: float


class ToolCall(BaseModel):
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    session_id: Optional[str] = None
    # ids of retrieved chunks that were in the agent's context when it chose this call
    context_ids: list[str] = Field(default_factory=list)
    justification: Optional[str] = None
    user_request: Optional[str] = None  # the original human request, for intent alignment


class ToolGuardResponse(BaseModel):
    request_id: str
    decision: Decision
    risk_score: float
    reasons: list[str]
    stages: list[StageResult]
    approval_id: Optional[str] = None
    result: Optional[Any] = None  # filled by /v1/tools/execute when executed
    latency_ms: float


class OutputRequest(BaseModel):
    text: str = Field(..., max_length=200_000)
    session_id: Optional[str] = None
    canary: Optional[str] = None  # canary token planted in the system prompt


class RagRequest(BaseModel):
    query: str = Field(..., max_length=10_000)
    session_id: Optional[str] = None
    chunks: Optional[list[ContextChunk]] = None  # bring-your-own retrieval; else demo retriever
    top_k: int = 3


class RagResponse(BaseModel):
    request_id: str
    decision: Decision
    answer: Optional[str]
    reasons: list[str]
    prompt_check: GuardResponse
    context_check: Optional[ContextResponse] = None
    output_check: Optional[GuardResponse] = None
    latency_ms: float
