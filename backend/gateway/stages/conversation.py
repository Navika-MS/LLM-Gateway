"""Multi-turn risk: detect attacks spread across several harmless-looking turns.

We keep a small per-session history of intents and map them onto a data
exfiltration kill chain:

    discover -> select sensitive data -> stage/export -> send externally

Each step on its own can be legitimate. Reaching the last step after earlier
ones in the same session is what we block. Repeated blocked attempts in a
session (probing) also raise risk.

MVP storage is in-process memory with a TTL; swap `SessionStore` for Redis
when running more than one gateway replica.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field

from ..models import Finding, Severity, StageResult

STAGE = "conversation"

KILL_CHAIN = [
    ("discover", {"data_discovery"}),
    ("select", {"sensitive_selection"}),
    ("stage", {"data_staging"}),
    ("exfiltrate", {"external_transfer"}),
]


@dataclass
class Turn:
    ts: float
    intents: set[str]
    blocked: bool
    tainted: bool = False  # an untrusted/quarantined context was seen in this turn


@dataclass
class Session:
    turns: deque = field(default_factory=lambda: deque(maxlen=30))
    tainted: bool = False
    quarantined_ids: set = field(default_factory=set)
    updated: float = field(default_factory=time.time)


class SessionStore:
    def __init__(self, ttl_s: int = 3600):
        self._d: dict[str, Session] = {}
        self._lock = threading.Lock()
        self.ttl = ttl_s

    def get(self, sid: str) -> Session:
        with self._lock:
            now = time.time()
            for k in [k for k, v in self._d.items() if now - v.updated > self.ttl]:
                del self._d[k]
            s = self._d.setdefault(sid, Session())
            s.updated = now
            return s

    def mark_tainted(self, sid: str, chunk_ids: list[str] | None = None) -> None:
        s = self.get(sid)
        s.tainted = True
        s.quarantined_ids |= set(chunk_ids or [])

    def clear(self) -> None:
        with self._lock:
            self._d.clear()


store = SessionStore()


def assess(session_id: str | None, current_intents: set[str]) -> StageResult:
    t0 = time.perf_counter()
    if not session_id:
        return StageResult(name=STAGE, status="skipped", details={"reason": "no session_id"})
    sess = store.get(session_id)
    history = list(sess.turns)
    all_turns = [t.intents for t in history] + [current_intents]

    reached = []
    for step, intents in KILL_CHAIN:
        if any(intents & ti for ti in all_turns):
            reached.append(step)
    findings, risk = [], 0.0
    current_step = next((s for s, i in reversed(KILL_CHAIN) if i & current_intents), None)

    if "exfiltrate" in reached and current_step == "exfiltrate" and len(reached) >= 3:
        risk = 0.95
        findings.append(Finding(stage=STAGE, category="multi_turn", rule_id="MT_EXFIL_CHAIN", severity=Severity.CRITICAL,
                                message=f"exfiltration kill chain completed across turns: {' → '.join(reached)}"))
    elif len(reached) >= 3 and current_step in {"stage", "exfiltrate"}:
        risk = 0.6
        findings.append(Finding(stage=STAGE, category="multi_turn", rule_id="MT_CHAIN_PROGRESS", severity=Severity.MEDIUM,
                                message=f"conversation is progressing along an exfiltration chain: {' → '.join(reached)}"))

    blocked_recent = sum(1 for t in history[-10:] if t.blocked)
    if blocked_recent >= 3:
        risk = max(risk, 0.7)
        findings.append(Finding(stage=STAGE, category="multi_turn", rule_id="MT_PROBING", severity=Severity.HIGH,
                                message=f"{blocked_recent} blocked requests in this session (probing behaviour)"))
    if sess.tainted:
        findings.append(Finding(stage=STAGE, category="multi_turn", rule_id="MT_TAINTED_SESSION", severity=Severity.MEDIUM,
                                message="session previously ingested quarantined/untrusted content"))
        risk = max(risk, 0.3)

    return StageResult(name=STAGE, risk=risk, findings=findings,
                       latency_ms=round((time.perf_counter() - t0) * 1000, 2),
                       details={"turns_in_session": len(history), "kill_chain_reached": reached, "tainted": sess.tainted})


def record(session_id: str | None, intents: set[str], blocked: bool) -> None:
    if session_id:
        store.get(session_id).turns.append(Turn(time.time(), set(intents), blocked))
