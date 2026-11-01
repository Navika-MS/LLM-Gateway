"""PII and sensitive-data detection with Indian + international recognizers.

The regex engine always runs (it has checksum validation for Aadhaar
(Verhoeff), credit cards (Luhn) and PAN structure). When PII_ENGINE=presidio
and Presidio is installed, its NER results (PERSON, LOCATION, ...) are merged in
and our Indian recognizers are registered with it too.

Raw values never leave this module except inside the masked text the caller
asked for. Findings and the audit log only carry the entity type and a keyed
hash token such as <AADHAAR_3f9a1c2e>.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import re
import time
from dataclasses import dataclass
from typing import Callable, Optional

from ..config import get_settings
from ..models import Finding, Severity, StageResult

log = logging.getLogger(__name__)
STAGE = "pii"

# ---------- validators ----------

_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_valid(num: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(num: str) -> str:
    """Compute the check digit to append (used by the demo data generator)."""
    _inv = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][int(ch)]]
    return str(_inv[c])


def luhn_valid(num: str) -> bool:
    total, alt = 0, False
    for ch in reversed(num):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def _aadhaar_ok(v: str) -> bool:
    d = _digits(v)
    return len(d) == 12 and d[0] not in "01" and verhoeff_valid(d)


def _card_ok(v: str) -> bool:
    d = _digits(v)
    return 13 <= len(d) <= 19 and luhn_valid(d) and len(set(d)) > 1


def _iban_ok(v: str) -> bool:
    s = re.sub(r"\s", "", v).upper()
    if not 15 <= len(s) <= 34:
        return False
    r = s[4:] + s[:4]
    n = "".join(str(int(c, 36)) for c in r)
    return int(n) % 97 == 1


# ---------- recognizers ----------


@dataclass(frozen=True)
class Recognizer:
    entity: str
    pattern: re.Pattern
    severity: Severity
    score: float = 0.85
    validator: Optional[Callable[[str], bool]] = None
    group: int = 0


def _rx(p: str, flags=re.I) -> re.Pattern:
    return re.compile(p, flags)


RECOGNIZERS: list[Recognizer] = [
    Recognizer("PRIVATE_KEY", _rx(r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |)PRIVATE KEY-----"), Severity.CRITICAL, 0.99),
    Recognizer("API_SECRET", _rx(r"\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})\b", 0), Severity.CRITICAL, 0.95),
    Recognizer("AADHAAR", _rx(r"(?<![\d-])([2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4})(?![\d-])"), Severity.HIGH, 0.9, _aadhaar_ok, 1),
    Recognizer("PAN", _rx(r"\b([A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z])\b", 0), Severity.HIGH, 0.9, group=1),
    Recognizer("CREDIT_CARD", _rx(r"(?<!\d)((?:\d[ -]?){12,18}\d)(?!\d)"), Severity.HIGH, 0.9, _card_ok, 1),
    Recognizer("IBAN", _rx(r"\b([A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?)\b", 0), Severity.HIGH, 0.85, _iban_ok, 1),
    Recognizer("IFSC", _rx(r"\b([A-Z]{4}0[A-Z0-9]{6})\b", 0), Severity.MEDIUM, 0.8, group=1),
    Recognizer("BANK_ACCOUNT", _rx(r"\b(?:a/?c|acct|account|bank\s+account)(?:\s+(?:no|number|num))?\.?\s*(?:is|:|#|-)?\s*(\d{9,18})\b"), Severity.HIGH, 0.8, group=1),
    Recognizer("US_SSN", _rx(r"\b(?!000|666|9\d\d)(\d{3}-(?!00)\d{2}-(?!0000)\d{4})\b"), Severity.HIGH, 0.85, group=1),
    Recognizer("EMAIL", _rx(r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"), Severity.MEDIUM, 0.95, group=1),
    Recognizer("PHONE_IN", _rx(r"(?<![\d+])((?:\+91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5})(?!\d)"), Severity.MEDIUM, 0.75, group=1),
    Recognizer("PHONE_INTL", _rx(r"(?<![\w+])(\+(?:[1-9]\d{0,2})[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,4})(?!\d)"), Severity.MEDIUM, 0.7, group=1),
    Recognizer("EMPLOYEE_ID", _rx(r"\b((?:EMP|EID|E)[-_]?\d{4,8})\b", 0), Severity.LOW, 0.7, group=1),
    Recognizer("IP_ADDRESS", _rx(r"\b((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))\b"), Severity.LOW, 0.6, group=1),
    Recognizer("ADDRESS", _rx(r"\b(\d{1,5}[,/\s-]+(?:[\w.'-]+\s){0,6}(?:street|st\.?|road|rd\.?|nagar|lane|ln\.?|avenue|ave\.?|colony|layout|cross|main|sector|block|marg|salai)\b[\w\s,.'-]{0,60}?(?:\b\d{6}\b|\b\d{5}\b))"), Severity.MEDIUM, 0.65, group=1),
]

ENTITY_SEVERITY = {r.entity: r.severity for r in RECOGNIZERS} | {
    "PERSON": Severity.LOW, "LOCATION": Severity.LOW, "CONFIDENTIAL_MARKER": Severity.HIGH,
}
# entities that make a payload "sensitive data" for exfiltration checks
HIGH_RISK_ENTITIES = {"AADHAAR", "PAN", "CREDIT_CARD", "IBAN", "BANK_ACCOUNT", "US_SSN", "API_SECRET", "PRIVATE_KEY", "CONFIDENTIAL_MARKER"}


@dataclass
class PIIEntity:
    entity: str
    start: int
    end: int
    score: float
    token: str


def tokenize(entity: str, value: str) -> str:
    key = get_settings().tokenization_secret.encode()
    digest = hmac.new(key, f"{entity}:{value}".encode(), hashlib.sha256).hexdigest()[:8]
    return f"<{entity}_{digest}>"


_presidio = None
_presidio_failed = False


def _get_presidio():
    global _presidio, _presidio_failed
    if _presidio is not None or _presidio_failed:
        return _presidio
    try:
        from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        })
        engine = AnalyzerEngine(nlp_engine=provider.create_engine())
        engine.registry.add_recognizer(PatternRecognizer(supported_entity="IN_AADHAAR", patterns=[Pattern("aadhaar", r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b", 0.6)], context=["aadhaar", "uid"]))
        engine.registry.add_recognizer(PatternRecognizer(supported_entity="IN_PAN", patterns=[Pattern("pan", r"\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b", 0.7)], context=["pan"]))
        _presidio = engine
        log.info("Presidio analyzer loaded")
    except Exception as e:  # pragma: no cover - optional dependency
        log.warning("Presidio unavailable, using regex PII engine only: %s", e)
        _presidio_failed = True
    return _presidio


def detect(text: str) -> list[PIIEntity]:
    found: list[PIIEntity] = []
    for rec in RECOGNIZERS:
        for m in rec.pattern.finditer(text):
            val = m.group(rec.group)
            if rec.validator and not rec.validator(val):
                continue
            s, e = m.start(rec.group), m.end(rec.group)
            found.append(PIIEntity(rec.entity, s, e, rec.score, tokenize(rec.entity, val)))
    for marker in get_settings().confidential_markers:
        for m in re.finditer(re.escape(marker), text, re.I):
            found.append(PIIEntity("CONFIDENTIAL_MARKER", m.start(), m.end(), 0.99, f"<CONFIDENTIAL_{marker.upper()}>"))

    if get_settings().pii_engine == "presidio" and (engine := _get_presidio()):
        mapping = {"IN_AADHAAR": "AADHAAR", "IN_PAN": "PAN", "PHONE_NUMBER": "PHONE_INTL", "EMAIL_ADDRESS": "EMAIL",
                   "LOCATION": "LOCATION", "PERSON": "PERSON", "CREDIT_CARD": "CREDIT_CARD", "US_SSN": "US_SSN", "IBAN_CODE": "IBAN"}
        for r in engine.analyze(text=text, language="en", entities=list(mapping)):
            if r.score < 0.5:
                continue
            ent = mapping[r.entity_type]
            if ent == "AADHAAR" and not _aadhaar_ok(text[r.start:r.end]):
                continue
            found.append(PIIEntity(ent, r.start, r.end, float(r.score), tokenize(ent, text[r.start:r.end])))

    # resolve overlaps: prefer higher severity, then longer span, then score
    found.sort(key=lambda p: (-ENTITY_SEVERITY.get(p.entity, Severity.LOW).weight, -(p.end - p.start), -p.score))
    chosen: list[PIIEntity] = []
    for p in found:
        if all(p.end <= c.start or p.start >= c.end for c in chosen):
            chosen.append(p)
    return sorted(chosen, key=lambda p: p.start)


def mask(text: str, entities: list[PIIEntity], keep: set[str] | None = None) -> str:
    keep = keep or set()
    out, last = [], 0
    for p in entities:
        if p.entity in keep:
            continue
        out.append(text[last:p.start])
        out.append(p.token)
        last = p.end
    out.append(text[last:])
    return "".join(out)


def scan(text: str, *, stage_name: str = STAGE, allowed_entities: set[str] | None = None) -> StageResult:
    """Detect PII. `allowed_entities` = types this principal may transmit unmasked."""
    t0 = time.perf_counter()
    allowed = allowed_entities or set()
    entities = detect(text)
    findings, counts = [], {}
    for p in entities:
        counts[p.entity] = counts.get(p.entity, 0) + 1
    for ent, n in counts.items():
        sev = ENTITY_SEVERITY.get(ent, Severity.LOW)
        findings.append(Finding(
            stage=stage_name, category="pii", rule_id=f"PII_{ent}", severity=sev,
            message=f"{n} × {ent}" + (" (permitted for this role)" if ent in allowed else " (will be masked)"),
            evidence=", ".join(p.token for p in entities if p.entity == ent)[:160],
        ))
    masked = mask(text, entities, keep=allowed)
    to_mask = [p for p in entities if p.entity not in allowed]
    risk = max((ENTITY_SEVERITY.get(p.entity, Severity.LOW).weight * 0.6 for p in to_mask), default=0.0)
    return StageResult(
        name=stage_name, risk=round(risk, 3), findings=findings,
        latency_ms=round((time.perf_counter() - t0) * 1000, 2),
        details={
            "entity_counts": counts,
            "masked_text": masked if to_mask else None,
            "high_risk_entities": sorted({p.entity for p in entities} & HIGH_RISK_ENTITIES),
            "engine": "regex+presidio" if get_settings().pii_engine == "presidio" and _presidio else "regex",
        },
    )
