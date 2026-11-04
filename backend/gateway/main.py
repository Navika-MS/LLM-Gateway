"""FastAPI application: the gateway's HTTP API."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from . import __version__, audit, orchestrator
from .auth import authenticate, require_approver
from .config import get_settings
from .demo_scenarios import SCENARIOS
from .models import (ContextRequest, ContextResponse, Decision, GuardResponse, OutputRequest, Principal, PromptRequest,
                     RagRequest, RagResponse, ToolCall, ToolGuardResponse)
from .policy.engine import load_policy
from .rag import pipeline
from .stages import conversation, ml_classifier
from .tools import hr_env

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

@asynccontextmanager
async def lifespan(_: FastAPI):
    audit.conn()
    hr_env.ensure()
    yield


app = FastAPI(
    lifespan=lifespan,
    title="LLM Guardrail Gateway",
    version=__version__,
    description="Zero-trust security gateway for RAG systems, AI agents and LLM apps.",
)
app.add_middleware(CORSMiddleware, allow_origins=list(get_settings().cors_origins), allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health() -> dict:
    s = get_settings()
    clf = ml_classifier._clf
    return {"status": "ok", "version": __version__,
            "stages": {"ml_mode": s.ml_mode, "ml_loaded": bool(clf), "ml_error": ml_classifier._clf_error,
                       "intent_mode": s.intent_mode, "pii_engine": s.pii_engine, "fail_mode": s.fail_mode, "rag_llm": s.rag_llm}}


@app.get("/v1/whoami")
def whoami(p: Principal = Depends(authenticate)) -> Principal:
    return p


@app.post("/v1/sessions")
def open_session(p: Principal = Depends(authenticate)) -> dict:
    """Open a gateway-owned session bound to the caller. Agents pass its id on every guard call."""
    return {"session_id": conversation.store.open(conversation.owner_key(p)), "ttl_s": conversation.store.ttl}


# ---------------- guard endpoints (use from any app / framework) ----------------

@app.post("/v1/guard/prompt", response_model=GuardResponse)
def guard_prompt(req: PromptRequest, p: Principal = Depends(authenticate)):
    return orchestrator.guard_prompt(req, p)


@app.post("/v1/guard/context", response_model=ContextResponse)
def guard_context(req: ContextRequest, p: Principal = Depends(authenticate)):
    return orchestrator.guard_context(req, p)


@app.post("/v1/guard/output", response_model=GuardResponse)
def guard_output(req: OutputRequest, p: Principal = Depends(authenticate)):
    return orchestrator.guard_output(req, p)


@app.post("/v1/guard/tool", response_model=ToolGuardResponse)
def guard_tool(call: ToolCall, p: Principal = Depends(authenticate)):
    return orchestrator.guard_tool(call, p)


# ---------------- Mode 1: secure RAG ----------------

@app.post("/v1/rag/query", response_model=RagResponse)
def rag_query(req: RagRequest, p: Principal = Depends(authenticate)):
    return pipeline.run(req, p)


# ---------------- Mode 2: guarded tool execution on the demo HR system ----------------

@app.post("/v1/tools/execute", response_model=ToolGuardResponse)
def execute_tool(call: ToolCall, p: Principal = Depends(authenticate)):
    res = orchestrator.guard_tool(call, p, endpoint="/v1/tools/execute")
    if res.decision in (Decision.ALLOW, Decision.SANITIZE):
        try:
            res.result = hr_env.execute(call.tool, call.arguments)
        except Exception as e:
            res.result = {"error": f"{type(e).__name__}: {e}"}
    return res


@app.get("/v1/approvals")
def approvals(status: Optional[str] = None, _: Principal = Depends(require_approver)):
    return audit.list_approvals(status)


@app.post("/v1/approvals/{approval_id}/{action}")
def decide(approval_id: str, action: str, approver: Principal = Depends(require_approver)):
    if action not in {"approve", "reject"}:
        raise HTTPException(400, "action must be approve or reject")
    pending = audit.decide_approval(approval_id, approver, action == "approve")
    if pending is None:
        raise HTTPException(404, "approval not found, already decided, or gateway restarted")
    if action == "reject":
        return {"status": "rejected"}
    requester = Principal(**pending["principal"])
    if requester.user_id == approver.user_id:
        return {"status": "approved", "note": "self-approval recorded; tool not executed (four-eyes rule)"}
    try:
        result = hr_env.execute(pending["tool"], pending["arguments"])
    except Exception as e:
        result = {"error": f"{type(e).__name__}: {e}"}
    return {"status": "approved", "executed": pending["tool"], "result": result}


# ---------------- dashboard data ----------------

@app.get("/v1/audit")
def audit_log(limit: int = 100, decision: Optional[str] = None, p: Principal = Depends(authenticate)):
    tenant = None if p.role == "security_admin" else p.tenant
    return audit.list_events(min(limit, 500), decision, tenant)


@app.get("/v1/stats")
def stats(p: Principal = Depends(authenticate)):
    return audit.stats(None if p.role == "security_admin" else p.tenant)


@app.get("/v1/policy")
def policy(_: Principal = Depends(authenticate)):
    return load_policy()


@app.get("/v1/demo/scenarios")
def scenarios():
    return SCENARIOS


@app.get("/v1/demo/documents")
def documents(_: Principal = Depends(authenticate)):
    return [c.model_dump() for c in pipeline.load_docs(get_settings().docs_dir)]


@app.get("/v1/demo/state")
def demo_state(_: Principal = Depends(authenticate)):
    return {"outbox": hr_env.OUTBOX, "system": hr_env.SYSTEM_STATE, "employees": len(hr_env.search_employees(limit=1000))}


@app.post("/v1/demo/reset")
def demo_reset(_: Principal = Depends(require_approver)):
    hr_env.reset()
    conversation.store.clear()
    return {"status": "reset"}
