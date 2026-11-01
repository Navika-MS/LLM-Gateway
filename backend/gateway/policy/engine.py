"""Python policy engine (MVP). Reads policies.yaml and turns stage results into a decision.

Rules, in order:
  1. Any critical/high finding in an always-block category      -> BLOCK
  2. Operation categories (delete, export, escalate...)         -> role/workflow based
  3. Aggregate risk >= block threshold                          -> BLOCK
  4. Aggregate risk in the uncertain zone                       -> REQUIRE_APPROVAL
  5. A stage errored (fail closed)                              -> REQUIRE_APPROVAL / BLOCK
  6. PII that this role may not transmit                        -> SANITIZE (mask)
  7. Otherwise                                                  -> ALLOW
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from ..config import get_settings
from ..models import Decision, Principal, Severity, StageResult


@lru_cache
def load_policy(path: str | None = None) -> dict[str, Any]:
    p = Path(path or get_settings().policy_file)
    with p.open() as f:
        return yaml.safe_load(f)


def role_cfg(principal: Principal) -> dict[str, Any]:
    return load_policy()["roles"].get(principal.role, {"permissions": [], "pii_allowed": [], "workflows": []})


def has_permission(principal: Principal, perm: str) -> bool:
    perms = set(role_cfg(principal).get("permissions", [])) | set(principal.permissions)
    return "*" in perms or perm in perms


def pii_allowed(principal: Principal) -> set[str]:
    return set(role_cfg(principal).get("pii_allowed", []))


def can_approve(principal: Principal) -> bool:
    return bool(role_cfg(principal).get("can_approve"))


# PII is handled by masking, not by the threat score
NON_THREAT_STAGES = {"pii", "output_pii"}


def aggregate_risk(stages: list[StageResult]) -> float:
    """Noisy-OR over stage risks: independent weak signals add up, one strong signal dominates."""
    p_safe = 1.0
    for s in stages:
        if s.status == "ok" and s.name not in NON_THREAT_STAGES:
            p_safe *= 1 - min(max(s.risk, 0.0), 0.999)
    return round(1 - p_safe, 3)


def evaluate(principal: Principal, stages: list[StageResult], *, pii_stage: str = "pii") -> tuple[Decision, float, list[str]]:
    pol = load_policy()
    th = pol["thresholds"]
    always_block = set(pol["always_block_categories"])
    ops_cfg = pol["operations"]
    workflows = set(role_cfg(principal).get("workflows", []))
    reasons: list[str] = []
    decision = Decision.ALLOW
    findings = [f for s in stages for f in s.findings]

    # 1. attack verdicts
    hard = [f for f in findings if f.category in always_block and f.severity in (Severity.HIGH, Severity.CRITICAL)]
    if hard:
        decision = Decision.BLOCK
        for f in hard[:5]:
            reasons.append(f"[{f.stage}] {f.rule_id}: {f.message}")
    soft = [f for f in findings if f.category in always_block and f.severity == Severity.MEDIUM]

    # 2. operations, decided by role
    for cat in sorted({f.category for f in findings if f.category in ops_cfg}):
        rule = ops_cfg[cat]
        d = Decision(rule["with_workflow"] if cat in workflows else rule["default"])
        why = "authorized workflow, human approval required" if cat in workflows and d == Decision.REQUIRE_APPROVAL \
            else f"role '{principal.role}' has no authorized workflow for it" if cat not in workflows else "never allowed via chat"
        reasons.append(f"operation {cat}: {d.value} ({why})")
        decision = Decision.strictest(decision, d)

    # 3/4. aggregate risk
    risk = aggregate_risk(stages)
    if decision.rank < Decision.BLOCK.rank:
        if risk >= th["block"] and (hard or soft or any(f.category.startswith("op_") for f in findings) or risk >= 0.9):
            decision = Decision.BLOCK
            reasons.append(f"aggregate risk {risk:.2f} ≥ block threshold {th['block']}")
        elif risk >= th["approval"]:
            decision = Decision.strictest(decision, Decision.REQUIRE_APPROVAL)
            reasons.append(f"aggregate risk {risk:.2f} in uncertain zone (≥ {th['approval']}): default deny → approval")
        elif soft:
            decision = Decision.strictest(decision, Decision.REQUIRE_APPROVAL)
            reasons.append(f"suspicious signal: {soft[0].rule_id}")

    # 5. fail closed on errored stages
    errored = [s for s in stages if s.status == "error"]
    if errored:
        names = ", ".join(s.name for s in errored)
        mode = get_settings().fail_mode
        if mode == "strict" or risk >= 0.3:
            target = Decision.BLOCK if risk >= 0.6 else Decision.REQUIRE_APPROVAL
            if target.rank > decision.rank:
                reasons.append(f"fail-closed: stage(s) {names} unavailable")
            decision = Decision.strictest(decision, target)
        else:
            reasons.append(f"warning: stage(s) {names} unavailable; low-risk request allowed (FAIL_MODE=balanced)")

    # 6. PII masking
    pii = next((s for s in stages if s.name == pii_stage), None)
    if decision == Decision.ALLOW and pii and pii.details.get("masked_text"):
        decision = Decision.SANITIZE
        reasons.append("PII masked: " + ", ".join(f"{k}×{v}" for k, v in pii.details.get("entity_counts", {}).items()))

    if not reasons:
        reasons.append("all checks passed")
    return decision, risk, reasons
