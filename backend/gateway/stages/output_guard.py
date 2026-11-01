"""Stage 6: output validation and DLP.

Checks what the model is about to return:
  * PII / secrets the caller's role may not see -> masked
  * canary token from the system prompt         -> prompt leak, BLOCK
  * markdown images / links to non-allowlisted hosts carrying data -> stripped
  * instructions aimed at downstream agents     -> flagged
"""
from __future__ import annotations

import re
import time
from urllib.parse import urlparse

from ..config import get_settings
from ..models import Finding, Severity, StageResult
from . import pii, signatures
from .normalizer import normalize

STAGE = "output_dlp"

MD_IMAGE = re.compile(r"!\[[^\]]*\]\((\s*[^)\s]+)[^)]*\)")
MD_LINK = re.compile(r"(?<!!)\[[^\]]*\]\((\s*https?://[^)\s]+)[^)]*\)")
PROMPT_LEAK = re.compile(r"\b(?:my|the)\s+(?:system\s+prompt|instructions\s+(?:are|say)|hidden\s+instructions)\b.{0,20}[:\"]", re.I)


def _host_allowed(url: str) -> bool:
    host = (urlparse(url.strip()).hostname or "").lower()
    return any(host == d or host.endswith("." + d) for d in get_settings().internal_email_domains)


def scan(text: str, *, allowed_entities: set[str], canary: str | None = None) -> StageResult:
    t0 = time.perf_counter()
    findings: list[Finding] = []
    risk = 0.0
    cleaned = text

    if canary and canary in text:
        findings.append(Finding(stage=STAGE, category="prompt_extraction", rule_id="OUT_CANARY_LEAK", severity=Severity.CRITICAL,
                                message="system-prompt canary token found in model output"))
        risk = 1.0
    if PROMPT_LEAK.search(text):
        findings.append(Finding(stage=STAGE, category="prompt_extraction", rule_id="OUT_PROMPT_DISCLOSURE", severity=Severity.HIGH,
                                message="output appears to disclose system instructions"))
        risk = max(risk, 0.8)

    def _strip(m: re.Match) -> str:
        url = m.group(1)
        if _host_allowed(url):
            return m.group(0)
        findings.append(Finding(stage=STAGE, category="exfiltration", rule_id="OUT_EXTERNAL_RESOURCE",
                                severity=Severity.HIGH if "?" in url else Severity.MEDIUM,
                                message="external image/link removed from output", evidence=(urlparse(url.strip()).hostname or "")[:80]))
        return "[external link removed by gateway]"

    cleaned = MD_IMAGE.sub(_strip, cleaned)
    cleaned = MD_LINK.sub(lambda m: _strip(m) if "?" in m.group(1) else m.group(0), cleaned)
    if cleaned != text:
        risk = max(risk, 0.5)

    sig = signatures.scan(normalize(cleaned), stage_name=STAGE)
    downstream = [f for f in sig.findings if f.category in {"direct_injection", "indirect_injection", "jailbreak"}]
    for f in downstream:
        f.message = "output contains instructions aimed at a downstream model/agent: " + f.message
        f.severity = Severity.MEDIUM  # flagged, the policy treats it as suspicious
    findings += downstream

    pii_res = pii.scan(cleaned, stage_name="output_pii", allowed_entities=allowed_entities)
    findings += pii_res.findings
    if pii_res.details.get("masked_text"):
        cleaned = pii_res.details["masked_text"]

    return StageResult(name=STAGE, risk=round(risk, 3), findings=findings,
                       latency_ms=round((time.perf_counter() - t0) * 1000, 2),
                       details={"cleaned_text": cleaned if cleaned != text else None,
                                "pii_counts": pii_res.details.get("entity_counts", {})})
