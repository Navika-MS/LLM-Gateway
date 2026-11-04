"""Multi-turn risk: detect attacks spread across several harmless-looking turns.

We keep a small per-session history of intents and map them onto a data
exfiltration kill chain:

    discover -> select sensitive data -> stage/export -> send externally

Each step on its own can be legitimate. Reaching the last step after earlier
ones in the same session is what we block. Repeated blocked attempts in a
session (probing) also raise risk.

Sessions belong to the gateway, not to the caller. A session is bound to the
principal that first used it (or opened it via POST /v1/sessions); another
principal presenting the same id is refused. Probing is also counted per user,
so rotating session ids does not reset it.

MVP storage is in-process memory with a TTL; swap `SessionStore` for Redis
when running more than one gateway replica.
"""
from __future__ import annotations

import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field

from ..models import Finding, Severity, StageResult

STAGE = "conversation"
# blocked requests per user within 10 minutes before every further request needs approval
USER_PROBE_LIMIT = 10

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
    owner: str | None = None  # "tenant/user_id" of the principal the session is bound to


class SessionOwnerMismatch(Exception):
    """A principal presented a session id that belongs to someone else."""


class SessionStore:
    def __init__(self, ttl_s: int = 3600):
        self._d: dict[str, Session] = {}
        self._user_blocks: dict[str, deque] = {}
        self._lock = threading.Lock()
        self.ttl = ttl_s

    def _expire(self, now: float) -> None:
        for k in [k for k, v in self._d.items() if now - v.updated > self.ttl]:
            del self._d[k]

    def get(self, sid: str, owner: str | None = None) -> Session:
        """Return the session, creating it if needed. With `owner`, bind it / enforce the binding."""
        with self._lock:
            now = time.time()
            self._expire(now)
            s = self._d.setdefault(sid, Session())
            if owner:
                if s.owner is None:
                    s.owner = owner
                elif s.owner != owner:
                    raise SessionOwnerMismatch(sid)
            s.updated = now
            return s

    def peek(self, sid: str) -> Session | None:
        """Return the session only if the gateway already knows it (never creates one)."""
        with self._lock:
            self._expire(time.time())
            return self._d.get(sid)

    def open(self, owner: str) -> str:
        sid = "gs_" + secrets.token_urlsafe(18)
        self.get(sid, owner)
        return sid

    def mark_tainted(self, sid: str, chunk_ids: list[str] | None = None, owner: str | None = None) -> None:
        s = self.get(sid, owner)
        s.tainted = True
        s.quarantined_ids |= set(chunk_ids or [])

    def note_block(self, user_key: str) -> None:
        with self._lock:
            self._user_blocks.setdefault(user_key, deque(maxlen=50)).append(time.time())

    def recent_user_blocks(self, user_key: str, window_s: int = 600) -> int:
        with self._lock:
            now = time.time()
            return sum(1 for t in self._user_blocks.get(user_key, ()) if now - t <= window_s)

    def clear(self) -> None:
        with self._lock:
            self._d.clear()
            self._user_blocks.clear()


store = SessionStore()


def owner_key(principal) -> str:
    return f"{principal.tenant}/{principal.user_id}"


def assess(session_id: str | None, current_intents: set[str], user_key: str | None = None) -> StageResult:
    t0 = time.perf_counter()
    # probing is tracked per user too, so dropping or rotating the session id does not reset it
    user_blocked = store.recent_user_blocks(user_key) if user_key else 0
    if not session_id:
        if user_blocked >= USER_PROBE_LIMIT:
            return StageResult(name=STAGE, risk=0.5, findings=[Finding(
                stage=STAGE, category="multi_turn", rule_id="MT_USER_PROBING", severity=Severity.MEDIUM,
                message=f"{user_blocked} blocked requests from this user in 10 minutes (probing behaviour)")],
                latency_ms=round((time.perf_counter() - t0) * 1000, 2), details={"user_blocked_10min": user_blocked})
        return StageResult(name=STAGE, status="skipped", details={"reason": "no session_id"})
    try:
        sess = store.get(session_id, user_key)
    except SessionOwnerMismatch:
        return StageResult(name=STAGE, risk=1.0, findings=[Finding(
            stage=STAGE, category="multi_turn", rule_id="MT_SESSION_HIJACK", severity=Severity.CRITICAL,
            message="session id belongs to a different principal")],
            latency_ms=round((time.perf_counter() - t0) * 1000, 2))
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
    elif user_blocked >= USER_PROBE_LIMIT:
        risk = max(risk, 0.5)
        findings.append(Finding(stage=STAGE, category="multi_turn", rule_id="MT_USER_PROBING", severity=Severity.MEDIUM,
                                message=f"{user_blocked} blocked requests from this user in 10 minutes (probing behaviour)"))
    if sess.tainted:
        findings.append(Finding(stage=STAGE, category="multi_turn", rule_id="MT_TAINTED_SESSION", severity=Severity.MEDIUM,
                                message="session previously ingested quarantined/untrusted content"))
        risk = max(risk, 0.3)

    return StageResult(name=STAGE, risk=risk, findings=findings,
                       latency_ms=round((time.perf_counter() - t0) * 1000, 2),
                       details={"turns_in_session": len(history), "kill_chain_reached": reached, "tainted": sess.tainted})


def record(session_id: str | None, intents: set[str], blocked: bool, user_key: str | None = None) -> None:
    if blocked and user_key:
        store.note_block(user_key)
    if session_id:
        try:
            store.get(session_id, user_key).turns.append(Turn(time.time(), set(intents), blocked))
        except SessionOwnerMismatch:
            pass  # already reported by assess()
