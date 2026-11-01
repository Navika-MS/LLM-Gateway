"""Stage 5: tool-call and action authorization (Mode 2: agent tool guard).

Even if a malicious instruction slips past every text detector, the agent
still has to *call a tool* to do damage. This guard checks each proposed call:

  registry      unknown tools are denied; some tools are never allowed
  authz         does this principal's role hold the tool permission?
  arguments     bulk/wildcard targets, raw SQL writes, external recipients,
                protected fields, row limits, PII leaving the company
  taint         was the agent's context poisoned (quarantined chunks)?
  alignment     does the action match what the human actually asked for?

The decision is the strictest of all checks. A prompt that passed the text
checks can therefore never, on its own, authorize a destructive action.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any

from ..config import get_settings
from ..models import Decision, Finding, Principal, Severity, StageResult, ToolCall
from ..policy.engine import has_permission, load_policy, pii_allowed
from ..stages import pii, signatures
from ..stages.conversation import store
from ..stages.intent import tag_intents
from ..stages.normalizer import normalize

WILDCARDS = {"*", "all", "%", "any", "everyone", "everything"}
SQL_WRITE = re.compile(r"\b(?:INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|GRANT|REVOKE|ATTACH|DETACH|PRAGMA|VACUUM)\b", re.I)
SQL_SENSITIVE_COLS = re.compile(r"\b(?:aadhaar|pan|bank_account|salary|ifsc|phone)\b|\bSELECT\s+\*", re.I)
EMAIL_RX = re.compile(r"[\w.+-]+@([\w-]+\.[\w.-]+)")

# which user intents justify which tool actions
ACTION_JUSTIFIED_BY = {
    "read": None,  # always aligned
    "query": None,
    "update": {"modification"},
    "delete": {"deletion"},
    "external_send": {"external_transfer", "communication"},
    "export": {"data_staging", "external_transfer"},
    "admin": {"privilege_change"},
    "security_config": {"security_tampering"},
}


def _stage(name: str, findings: list[Finding], risk: float, t0: float, **details) -> StageResult:
    return StageResult(name=name, risk=round(risk, 3), findings=findings, details=details,
                       latency_ms=round((time.perf_counter() - t0) * 1000, 2))


def _f(stage: str, rule: str, sev: Severity, msg: str, cat: str = "tool_policy") -> Finding:
    return Finding(stage=stage, category=cat, rule_id=rule, severity=sev, message=msg)


def _external(addr: str, allowed: list[str]) -> bool:
    m = EMAIL_RX.search(addr or "")
    if not m:
        return True
    dom = m.group(1).lower()
    return not any(dom == d or dom.endswith("." + d) for d in allowed)


def check_arguments(call: ToolCall, cfg: dict, principal: Principal) -> tuple[list[Finding], Decision, dict]:
    st = "tool_arguments"
    a: dict[str, Any] = call.arguments
    out: list[Finding] = []
    d = Decision.ALLOW
    action = cfg["action"]

    def esc(dec: Decision, f: Finding):
        nonlocal d
        out.append(f)
        d = Decision.strictest(d, dec)

    # bulk / wildcard targets
    for key in ("employee_id", "id", "ids", "target", "table", "where"):
        v = a.get(key)
        vals = v if isinstance(v, list) else [v]
        if any(isinstance(x, str) and x.strip().lower() in WILDCARDS for x in vals):
            esc(Decision.BLOCK, _f(st, "ARG_WILDCARD_TARGET", Severity.CRITICAL, f"wildcard target in '{key}' (bulk operation)"))
        if isinstance(v, list) and len(v) > cfg.get("max_records", 10**9):
            esc(Decision.BLOCK, _f(st, "ARG_TOO_MANY_RECORDS", Severity.HIGH, f"{len(v)} records > max {cfg['max_records']}"))

    # numeric limits
    for key, cap in (("limit", cfg.get("max_rows") or cfg.get("max_results")),):
        if cap and isinstance(a.get(key), (int, float)) and a[key] > cap:
            esc(Decision.REQUIRE_APPROVAL, _f(st, "ARG_LIMIT_EXCEEDED", Severity.MEDIUM, f"{key}={a[key]} exceeds {cap}"))

    # protected fields
    if action == "update":
        prot = set(cfg.get("protected_fields", [])) & set((a.get("updates") or {}).keys())
        if prot:
            esc(Decision.REQUIRE_APPROVAL, _f(st, "ARG_PROTECTED_FIELD", Severity.HIGH, f"changes protected field(s): {', '.join(sorted(prot))}"))

    # raw SQL
    if call.tool == "run_sql":
        q = str(a.get("query", ""))
        stmts = [s for s in q.split(";") if s.strip()]
        if len(stmts) > 1:
            esc(Decision.BLOCK, _f(st, "SQL_MULTI_STATEMENT", Severity.CRITICAL, "multiple SQL statements (stacked query)"))
        if SQL_WRITE.search(q) or not q.strip().lower().startswith(("select", "with")):
            esc(Decision.BLOCK, _f(st, "SQL_WRITE_OPERATION", Severity.CRITICAL, "non read-only SQL in a read-only tool", "op_destructive"))
        if SQL_SENSITIVE_COLS.search(q) and not {"PAN", "AADHAAR", "BANK_ACCOUNT"} <= pii_allowed(principal):
            esc(Decision.REQUIRE_APPROVAL, _f(st, "SQL_SENSITIVE_COLUMNS", Severity.HIGH, "query reads sensitive columns (or SELECT *)"))

    # outbound email
    if action == "external_send":
        to = a.get("to", "")
        recipients = to if isinstance(to, list) else [to]
        allowed = cfg.get("allowed_recipient_domains", list(get_settings().internal_email_domains))
        ext = [r for r in recipients if _external(str(r), allowed)]
        if ext:
            esc(Decision.BLOCK, _f(st, "ARG_EXTERNAL_RECIPIENT", Severity.CRITICAL,
                                   f"{len(ext)} recipient(s) outside allowed domains {allowed}", "op_data_exfiltration"))
        if cfg.get("block_high_risk_pii"):
            payload = f"{a.get('subject', '')}\n{a.get('body', '')}"
            hr = pii.scan(payload).details.get("high_risk_entities", [])
            if hr:
                esc(Decision.BLOCK if ext else Decision.REQUIRE_APPROVAL,
                    _f(st, "ARG_PII_IN_MESSAGE", Severity.HIGH, f"message body contains {', '.join(hr)}", "op_data_exfiltration"))

    if action == "export" and set(a.get("fields") or []) & {"aadhaar", "pan", "bank_account", "salary"}:
        esc(Decision.BLOCK, _f(st, "ARG_EXPORT_SENSITIVE", Severity.HIGH, "export includes sensitive identity/financial columns", "op_data_exfiltration"))

    # injection hidden in arguments (e.g. an email body carrying instructions for the next agent)
    text_args = json.dumps(a, ensure_ascii=False)
    sig = signatures.scan(normalize(text_args), stage_name=st)
    for f in sig.findings:
        if f.category in signatures.ATTACK_CATEGORIES:
            esc(Decision.BLOCK, f)
    return out, d, {"argument_keys": sorted(a.keys())}


def guard(call: ToolCall, principal: Principal) -> tuple[Decision, float, list[str], list[StageResult]]:
    pol = load_policy()
    tools = pol["tools"]
    stages: list[StageResult] = []
    reasons: list[str] = []
    decision = Decision.ALLOW

    def bump(dec: Decision, why: str):
        nonlocal decision
        if dec.rank > Decision.ALLOW.rank:
            reasons.append(why)
        decision = Decision.strictest(decision, dec)

    # registry
    t0 = time.perf_counter()
    cfg = tools.get(call.tool)
    if cfg is None:
        stages.append(_stage("tool_registry", [_f("tool_registry", "TOOL_UNKNOWN", Severity.CRITICAL, f"tool '{call.tool}' is not registered")], 1.0, t0))
        bump(Decision.BLOCK, f"unknown tool '{call.tool}' (default deny)")
        return decision, 1.0, reasons, stages
    reg_f = []
    if cfg.get("deny_always"):
        reg_f.append(_f("tool_registry", "TOOL_DENY_ALWAYS", Severity.CRITICAL, f"'{call.tool}' can never be invoked by an agent", "op_security_bypass"))
        bump(Decision.BLOCK, f"'{call.tool}' is never allowed for agents")
    stages.append(_stage("tool_registry", reg_f, 1.0 if reg_f else 0.0, t0, action=cfg["action"], risk_tier=cfg["risk"]))

    # authorization
    t0 = time.perf_counter()
    perm = cfg.get("permission", f"tool:{call.tool}")
    ok = has_permission(principal, perm)
    authz_f = [] if ok else [_f("tool_authz", "AUTHZ_MISSING_PERMISSION", Severity.HIGH, f"role '{principal.role}' lacks {perm}")]
    stages.append(_stage("tool_authz", authz_f, 0.0 if ok else 0.9, t0, role=principal.role, required=perm))
    if not ok:
        bump(Decision.BLOCK, f"role '{principal.role}' is not authorized for {call.tool}")
    if cfg.get("requires_approval"):
        bump(Decision.REQUIRE_APPROVAL, f"{call.tool} ({cfg['risk']} risk) always requires human approval")

    # arguments
    t0 = time.perf_counter()
    arg_f, arg_d, arg_det = check_arguments(call, cfg, principal)
    stages.append(_stage("tool_arguments", arg_f, max((f.severity.weight for f in arg_f), default=0.0), t0, **arg_det))
    if arg_d != Decision.ALLOW:
        bump(arg_d, "argument check: " + "; ".join(f.message for f in arg_f[:3]))

    # taint
    t0 = time.perf_counter()
    taint_f = []
    if call.session_id:
        sess = store.get(call.session_id)
        bad_ctx = set(call.context_ids) & sess.quarantined_ids
        if cfg["action"] in pol["taint_sensitive_actions"]:
            if bad_ctx:
                taint_f.append(_f("tool_taint", "TAINT_QUARANTINED_CONTEXT", Severity.CRITICAL,
                                  f"call was planned with quarantined context {sorted(bad_ctx)}", "indirect_injection"))
                bump(Decision.BLOCK, "agent context contained quarantined (injected) content")
            elif sess.tainted:
                taint_f.append(_f("tool_taint", "TAINT_SESSION", Severity.HIGH, "session ingested untrusted content earlier"))
                bump(Decision.REQUIRE_APPROVAL, "session is tainted by untrusted content; sensitive action needs approval")
    stages.append(_stage("tool_taint", taint_f, max((f.severity.weight for f in taint_f), default=0.0), t0))

    # intent alignment
    t0 = time.perf_counter()
    align_f = []
    needed = ACTION_JUSTIFIED_BY.get(cfg["action"])
    if call.user_request is not None and needed:
        user_intents = set(tag_intents(call.user_request))
        if not (user_intents & needed):
            sev = Severity.CRITICAL if cfg["risk"] == "critical" or cfg["action"] == "external_send" else Severity.HIGH
            align_f.append(_f("tool_alignment", "ALIGN_ACTION_NOT_REQUESTED", sev,
                              f"user asked for {sorted(user_intents) or ['nothing actionable']}, agent wants '{cfg['action']}'"))
            bump(Decision.BLOCK if sev == Severity.CRITICAL else Decision.REQUIRE_APPROVAL,
                 f"action '{cfg['action']}' does not match the user's request")
    stages.append(_stage("tool_alignment", align_f, max((f.severity.weight for f in align_f), default=0.0), t0))

    risk = max((s.risk for s in stages), default=0.0)
    if cfg["risk"] in {"high", "critical"}:
        risk = max(risk, 0.3)
    if not reasons:
        reasons.append(f"{call.tool} permitted for role '{principal.role}'")
    return decision, round(risk, 3), reasons, stages
