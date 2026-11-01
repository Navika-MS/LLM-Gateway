"""Stage 2: ML prompt-injection classifier.

Modes (ML_MODE):
  deberta   - protectai/deberta-v3-base-prompt-injection-v2 on CPU (~0.7 GB RAM).
              Lazy-loaded on first request; long inputs are scored in
              overlapping windows and the max window score is used.
  heuristic - a tiny lexical scorer with no dependencies. Useful for laptops
              without the model, CI, and tests. It is weaker than DeBERTa and
              the benchmark report says so.
  off       - stage skipped.

If the model is configured but fails to load or run, the stage reports
status="error" and the orchestrator applies the fail-closed policy.
"""
from __future__ import annotations

import logging
import math
import re
import threading
import time
from typing import Protocol

from ..config import get_settings
from ..models import Finding, Severity, StageResult
from .normalizer import NormalizedText

log = logging.getLogger(__name__)
STAGE = "ml_classifier"


class Classifier(Protocol):
    name: str

    def score(self, texts: list[str]) -> list[float]:
        """Return P(injection) for each text."""


# ---------------- heuristic fallback ----------------

_CUES: list[tuple[re.Pattern, float]] = [(re.compile(p, re.I), w) for p, w in [
    (r"\bignore\b", 1.6), (r"\bdisregard\b", 1.8), (r"\bforget\b", 0.9), (r"\boverride\b", 1.5),
    (r"\binstructions?\b", 1.1), (r"\bsystem\s+prompt\b", 2.2), (r"\bprevious\b|\bprior\b|\babove\b", 0.7),
    (r"\bjailbr(?:ea|o)k", 2.5), (r"\bunrestricted\b|\bunfiltered\b|\buncensored\b", 2.0),
    (r"\bpretend\b|\broleplay\b|\bact\s+as\b", 0.8), (r"\byou\s+are\s+now\b", 1.6), (r"\bfrom\s+now\s+on\b", 1.0),
    (r"\bno\s+(?:rules|restrictions|limits|filters)\b", 1.8), (r"\breveal\b|\bleak\b", 1.0),
    (r"\bdeveloper\s+mode\b|\bDAN\b", 2.2), (r"\bdo\s+not\s+tell\b|\bwithout\s+telling\b", 1.5),
    (r"\bsecret\b|\bhidden\b|\bconfidential\b", 0.5), (r"\bbypass\b|\bcircumvent\b|\bdisable\b", 1.2),
    (r"\binstead\b", 0.5), (r"\bnew\s+task\b|\bnew\s+instructions\b", 1.6), (r"\bassistant\b|\bAI\b|\bmodel\b", 0.3),
    (r"\bmust\b|\bshall\b", 0.3), (r"[A-Z]{4,}\s*(?:OVERRIDE|NOTICE|INSTRUCTION)", 2.0),
    (r"\bsend\b.{0,40}@", 1.0), (r"\bsafety\b|\bguardrails?\b|\bfilters?\b", 0.6),
]]
_BENIGN = [(re.compile(p, re.I), w) for p, w in [
    (r"\bsummar(?:y|ize|ise)\b", -0.6), (r"\bexplain\b|\bwhat\s+is\b|\bhow\s+do\s+i\b", -0.6),
    (r"\bplease\s+help\b", -0.3), (r"\btypo\b|\bspelling\b|\bformatting\b", -1.2),
    (r"\bignore\s+(?:the\s+)?(?:typos?|formatting|noise|warnings?|case)\b", -2.5),
]]


class HeuristicClassifier:
    name = "heuristic-lexical-v1"

    def score(self, texts: list[str]) -> list[float]:
        out = []
        for t in texts:
            z = -3.2
            for rx, w in _CUES:
                if rx.search(t):
                    z += w
            for rx, w in _BENIGN:
                if rx.search(t):
                    z += w
            out.append(1 / (1 + math.exp(-z)))
        return out


# ---------------- DeBERTa ----------------


class DebertaClassifier:
    def __init__(self, model_id: str):
        self.name = model_id
        from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline  # heavy import
        import torch

        torch.set_num_threads(max(1, min(4, torch.get_num_threads())))
        tok = AutoTokenizer.from_pretrained(model_id)
        model = AutoModelForSequenceClassification.from_pretrained(model_id)
        self._tok = tok
        self._pipe = pipeline("text-classification", model=model, tokenizer=tok, truncation=True, max_length=512, device=-1)
        self._lock = threading.Lock()

    def _windows(self, text: str, size: int = 450, stride: int = 350) -> list[str]:
        ids = self._tok(text, add_special_tokens=False)["input_ids"]
        if len(ids) <= size:
            return [text]
        return [self._tok.decode(ids[i:i + size]) for i in range(0, len(ids), stride)][:16]

    def score(self, texts: list[str]) -> list[float]:
        out = []
        with self._lock:
            for t in texts:
                wins = self._windows(t)
                preds = self._pipe(wins, batch_size=4)
                best = 0.0
                for p in preds:
                    s = p["score"] if p["label"].upper() in {"INJECTION", "LABEL_1", "UNSAFE"} else 1 - p["score"]
                    best = max(best, s)
                out.append(best)
        return out


_clf: Classifier | None = None
_clf_error: str | None = None
_lock = threading.Lock()


def get_classifier() -> Classifier | None:
    global _clf, _clf_error
    mode = get_settings().ml_mode
    if mode == "off":
        return None
    if _clf is not None or _clf_error is not None:
        return _clf
    with _lock:
        if _clf is None and _clf_error is None:
            try:
                _clf = DebertaClassifier(get_settings().ml_model) if mode == "deberta" else HeuristicClassifier()
                log.info("ML classifier ready: %s", _clf.name)
            except Exception as e:  # missing deps, no network, OOM...
                _clf_error = f"{type(e).__name__}: {e}"
                log.error("ML classifier failed to load: %s", _clf_error)
    return _clf


def set_classifier(clf: Classifier | None) -> None:
    """Test hook: inject a mock classifier."""
    global _clf, _clf_error
    _clf, _clf_error = clf, None


def scan(norm: NormalizedText, *, stage_name: str = STAGE, threshold: float | None = None) -> StageResult:
    t0 = time.perf_counter()
    if get_settings().ml_mode == "off":
        return StageResult(name=stage_name, status="skipped", details={"reason": "ML_MODE=off"})
    clf = get_classifier()
    if clf is None:
        return StageResult(name=stage_name, status="error", risk=0.0, error=_clf_error or "classifier unavailable",
                           latency_ms=round((time.perf_counter() - t0) * 1000, 2))
    threshold = threshold if threshold is not None else get_settings().ml_threshold
    views = [(n, v) for n, v in norm.all_views() if v.strip()]
    try:
        scores = clf.score([v for _, v in views])
    except Exception as e:
        return StageResult(name=stage_name, status="error", error=f"{type(e).__name__}: {e}",
                           latency_ms=round((time.perf_counter() - t0) * 1000, 2))
    per_view = {n: round(s, 4) for (n, _), s in zip(views, scores)}
    top_view, top = max(per_view.items(), key=lambda kv: kv[1])
    findings = []
    if top >= threshold:
        findings.append(Finding(
            stage=stage_name, category="ml_injection", rule_id="ML_INJECTION",
            severity=Severity.CRITICAL if top >= 0.97 else Severity.HIGH,
            message=f"classifier P(injection)={top:.2f} ≥ {threshold}", view=top_view,
        ))
    elif top >= threshold * 0.6:
        findings.append(Finding(stage=stage_name, category="ml_injection", rule_id="ML_SUSPICIOUS",
                                severity=Severity.MEDIUM, message=f"classifier P(injection)={top:.2f} (suspicious)", view=top_view))
    return StageResult(
        name=stage_name, risk=round(top, 3), findings=findings,
        latency_ms=round((time.perf_counter() - t0) * 1000, 2),
        details={"model": clf.name, "threshold": threshold, "scores_by_view": per_view},
    )
