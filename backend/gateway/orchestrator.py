"""Pipeline orchestration: runs the stages in order and asks the policy engine for a decision."""
from __future__ import annotations

import time

from . import audit
from .models import (ContextRequest, ContextResponse, Decision, GuardResponse, OutputRequest, Principal,
                     PromptRequest, StageResult, ToolCall, ToolGuardResponse)
from .policy import engine
from .stages import context as ctx_stage
from .stages import conversation, intent, ml_classifier, normalizer, output_guard, pii, signatures
from .tools import guard as tool_guard


def _auth_stage(p: Principal, perm: str) -> StageResult:
    ok = engine.has_permission(p, perm)
    res = StageResult(name="auth", risk=0.0 if ok else 1.0,
                      details={"user": p.user_id, "role": p.role, "tenant": p.tenant, "method": p.auth_method, "permission": perm})
    if not ok:
        from .models import Finding, Severity
        res.findings.append(Finding(stage="auth", category="authorization", rule_id="AUTHZ_DENIED",
                                    severity=Severity.CRITICAL, message=f"role '{p.role}' lacks '{perm}'"))
    return res


def guard_prompt(req: PromptRequest, p: Principal, *, endpoint: str = "/v1/guard/prompt", log: bool = True) -> GuardResponse:
    t0 = time.perf_counter()
    rid = audit.new_id()
    stages: list[StageResult] = [_auth_stage(p, "chat")]

    t = time.perf_counter()
    norm = normalizer.normalize(req.text)
    stages.append(StageResult(name="normalization", risk=0.0, findings=norm.findings,
                              latency_ms=round((time.perf_counter() - t) * 1000, 2),
                              details={"views": list(norm.views), "flags": norm.flags,
                                       "normalized_preview": audit.redact(norm.normalized, 300),
                                       "decoded_preview": {k: audit.redact(v, 200) for k, v in norm.views.items()}}))
    sig = signatures.scan(norm)
    stages.append(sig)
    stages.append(pii.scan(req.text, allowed_entities=engine.pii_allowed(p)))

    hard_block = any(f.severity.value == "critical" and f.category in signatures.ATTACK_CATEGORIES for f in sig.findings)
    if hard_block:
        # the verdict is already BLOCK; a ~100 ms transformer pass cannot change it
        stages.append(StageResult(name="ml_classifier", status="skipped",
                                  details={"reason": "deterministic stage already blocked (fast path)"}))
    else:
        stages.append(ml_classifier.scan(norm))
    if hard_block:
        stages.append(StageResult(name="intent", status="skipped", details={"reason": "deterministic stage already blocked (fast path)"}))
        intents = set(intent.tag_intents(norm.normalized))
    else:
        it = intent.scan(norm.normalized + "\n" + "\n".join(norm.views.values()))
        stages.append(it)
        intents = set(it.details.get("intents", [])) or set(intent.tag_intents(norm.normalized))
    stages.append(conversation.assess(req.session_id, intents, conversation.owner_key(p)))

    if stages[0].findings:
        decision, risk, reasons = Decision.BLOCK, 1.0, [f"not authorized: {stages[0].findings[0].message}"]
    else:
        decision, risk, reasons = engine.evaluate(p, stages)
    conversation.record(req.session_id, intents, decision == Decision.BLOCK, conversation.owner_key(p))

    sanitized = None
    if decision == Decision.SANITIZE:
        sanitized = next(s for s in stages if s.name == "pii").details.get("masked_text")
    elif decision == Decision.ALLOW:
        sanitized = req.text
    latency = round((time.perf_counter() - t0) * 1000, 2)
    if log:
        audit.log_event(request_id=rid, endpoint=endpoint, principal=p, decision=decision, risk=risk, reasons=reasons,
                        findings=[f for s in stages for f in s.findings], input_text=req.text, latency_ms=latency,
                        session_id=req.session_id)
    return GuardResponse(request_id=rid, decision=decision, risk_score=risk, reasons=reasons,
                         sanitized_text=sanitized, stages=stages, latency_ms=latency)


def guard_context(req: ContextRequest, p: Principal, *, log: bool = True) -> ContextResponse:
    t0 = time.perf_counter()
    rid = audit.new_id()
    res, verdicts, safe = ctx_stage.scan(req.chunks, req.user_query)
    quarantined = [v.id for v in verdicts if v.action == "quarantine"]
    if req.session_id:
        try:
            if quarantined or any(v.action == "sanitize" for v in verdicts):
                conversation.store.mark_tainted(req.session_id, quarantined, conversation.owner_key(p))
            else:
                conversation.store.get(req.session_id, conversation.owner_key(p))  # bind the session
        except conversation.SessionOwnerMismatch:
            return ContextResponse(request_id=rid, decision=Decision.BLOCK, risk_score=1.0,
                                   reasons=["session id belongs to a different principal"], chunks=verdicts,
                                   safe_context="", latency_ms=round((time.perf_counter() - t0) * 1000, 2))
    if quarantined or res.details["sanitized"]:
        decision = Decision.SANITIZE
        reasons = [f.message for f in res.findings]
    else:
        decision, reasons = Decision.ALLOW, ["all retrieved chunks passed inspection"]
    if not engine.has_permission(p, "rag:read"):
        decision, reasons, safe = Decision.BLOCK, [f"role '{p.role}' lacks rag:read"], ""
    latency = round((time.perf_counter() - t0) * 1000, 2)
    if log:
        audit.log_event(request_id=rid, endpoint="/v1/guard/context", principal=p, decision=decision, risk=res.risk,
                        reasons=reasons, findings=[f for v in verdicts for f in v.findings] + res.findings,
                        input_text=req.user_query + "\n" + "\n".join(c.text for c in req.chunks), latency_ms=latency,
                        session_id=req.session_id)
    return ContextResponse(request_id=rid, decision=decision, risk_score=res.risk, reasons=reasons,
                           chunks=verdicts, safe_context=safe, latency_ms=latency)


def guard_output(req: OutputRequest, p: Principal, *, log: bool = True, endpoint: str = "/v1/guard/output") -> GuardResponse:
    t0 = time.perf_counter()
    rid = audit.new_id()
    st = output_guard.scan(req.text, allowed_entities=engine.pii_allowed(p), canary=req.canary)
    decision, risk, reasons = engine.evaluate(p, [st])
    cleaned = st.details.get("cleaned_text")
    if decision == Decision.ALLOW and cleaned:
        decision = Decision.SANITIZE
        reasons = [r for r in reasons if r != "all checks passed"] + ["output cleaned (PII masked / external links removed)"]
    latency = round((time.perf_counter() - t0) * 1000, 2)
    if log:
        audit.log_event(request_id=rid, endpoint=endpoint, principal=p, decision=decision, risk=risk, reasons=reasons,
                        findings=st.findings, input_text=req.text, latency_ms=latency, session_id=req.session_id)
    text = None if decision.rank >= Decision.REQUIRE_APPROVAL.rank else (cleaned or req.text)
    return GuardResponse(request_id=rid, decision=decision, risk_score=risk, reasons=reasons,
                         sanitized_text=text, stages=[st], latency_ms=latency)


def guard_tool(call: ToolCall, p: Principal, *, endpoint: str = "/v1/guard/tool") -> ToolGuardResponse:
    t0 = time.perf_counter()
    rid = audit.new_id()
    decision, risk, reasons, stages = tool_guard.guard(call, p)
    approval_id = None
    if decision == Decision.REQUIRE_APPROVAL:
        approval_id = audit.create_approval(request_id=rid, principal=p, tool=call.tool, arguments=call.arguments, reasons=reasons)
    latency = round((time.perf_counter() - t0) * 1000, 2)
    audit.log_event(request_id=rid, endpoint=endpoint, principal=p, decision=decision, risk=risk, reasons=reasons,
                    findings=[f for s in stages for f in s.findings],
                    input_text=f"{call.tool}({call.arguments})", latency_ms=latency, session_id=call.session_id)
    return ToolGuardResponse(request_id=rid, decision=decision, risk_score=risk, reasons=reasons, stages=stages,
                             approval_id=approval_id, latency_ms=latency)
