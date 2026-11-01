"""Redacted security audit log (SQLite for the MVP).

What is stored: decision, risk, reasons, finding metadata, a SHA-256 of the
original input, and a PII-masked, truncated preview. Raw PII is never written:
everything passes through the PII masker first (see tests/test_audit.py).
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .config import get_settings
from .models import Decision, Finding, Principal
from .stages import pii

_lock = threading.Lock()
_conn: sqlite3.Connection | None = None
_conn_path: str | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY, ts REAL, endpoint TEXT, user_id TEXT, role TEXT, tenant TEXT, session_id TEXT,
  decision TEXT, risk REAL, reasons TEXT, findings TEXT, input_sha256 TEXT, input_preview TEXT, latency_ms REAL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY, ts REAL, request_id TEXT, user_id TEXT, role TEXT, tool TEXT, args_preview TEXT,
  reasons TEXT, status TEXT, decided_by TEXT, decided_ts REAL
);
"""


def conn() -> sqlite3.Connection:
    global _conn, _conn_path
    path = get_settings().audit_db
    if _conn is None or _conn_path != path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        _conn = sqlite3.connect(path, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.executescript(SCHEMA)
        _conn_path = path
    return _conn


def redact(text: str, limit: int = 400) -> str:
    masked = pii.mask(text, pii.detect(text))
    return masked[:limit] + ("…" if len(masked) > limit else "")


def new_id() -> str:
    return uuid.uuid4().hex[:16]


def log_event(*, request_id: str, endpoint: str, principal: Principal, decision: Decision, risk: float,
              reasons: list[str], findings: list[Finding], input_text: str, latency_ms: float,
              session_id: str | None = None) -> None:
    safe_findings = [
        {"stage": f.stage, "category": f.category, "rule_id": f.rule_id, "severity": f.severity.value,
         "message": f.message, "evidence": redact(f.evidence, 160) if f.evidence else None}
        for f in findings
    ]
    with _lock:
        conn().execute(
            "INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (request_id, time.time(), endpoint, principal.user_id, principal.role, principal.tenant, session_id,
             decision.value, risk, json.dumps([redact(r, 300) for r in reasons]), json.dumps(safe_findings),
             hashlib.sha256(input_text.encode()).hexdigest(), redact(input_text), latency_ms),
        )
        conn().commit()


def list_events(limit: int = 100, decision: str | None = None, tenant: str | None = None) -> list[dict[str, Any]]:
    sql, args = "SELECT * FROM events WHERE 1=1", []
    if decision:
        sql += " AND decision = ?"
        args.append(decision)
    if tenant:
        sql += " AND tenant = ?"
        args.append(tenant)
    sql += " ORDER BY ts DESC LIMIT ?"
    args.append(limit)
    rows = []
    for r in conn().execute(sql, args):
        d = dict(r)
        d["reasons"] = json.loads(d["reasons"])
        d["findings"] = json.loads(d["findings"])
        rows.append(d)
    return rows


def stats(tenant: str | None = None) -> dict[str, Any]:
    where, args = ("WHERE tenant = ?", [tenant]) if tenant else ("", [])
    c = conn()
    by_decision = {r[0]: r[1] for r in c.execute(f"SELECT decision, COUNT(*) FROM events {where} GROUP BY decision", args)}
    by_endpoint = {r[0]: r[1] for r in c.execute(f"SELECT endpoint, COUNT(*) FROM events {where} GROUP BY endpoint", args)}
    cats: dict[str, int] = {}
    for (f,) in c.execute(f"SELECT findings FROM events {where} ORDER BY ts DESC LIMIT 2000", args):
        for x in json.loads(f):
            cats[x["category"]] = cats.get(x["category"], 0) + 1
    lat = [r[0] for r in c.execute(f"SELECT latency_ms FROM events {where} ORDER BY ts DESC LIMIT 1000", args)]
    lat.sort()
    p = lambda q: round(lat[min(len(lat) - 1, int(q * len(lat)))], 1) if lat else None  # noqa: E731
    return {"total": sum(by_decision.values()), "by_decision": by_decision, "by_endpoint": by_endpoint,
            "top_categories": dict(sorted(cats.items(), key=lambda kv: -kv[1])[:10]),
            "latency_ms": {"p50": p(0.5), "p95": p(0.95)}}


# ---------------- approvals ----------------

_pending_args: dict[str, dict] = {}  # raw args kept in memory only, never in the DB


def create_approval(*, request_id: str, principal: Principal, tool: str, arguments: dict, reasons: list[str]) -> str:
    aid = "apr_" + new_id()
    _pending_args[aid] = {"tool": tool, "arguments": arguments, "principal": principal.model_dump()}
    with _lock:
        conn().execute("INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                       (aid, time.time(), request_id, principal.user_id, principal.role, tool,
                        redact(json.dumps(arguments), 300), json.dumps(reasons), "pending", None, None))
        conn().commit()
    return aid


def list_approvals(status: str | None = None) -> list[dict]:
    sql, args = "SELECT * FROM approvals", []
    if status:
        sql += " WHERE status = ?"
        args.append(status)
    sql += " ORDER BY ts DESC LIMIT 200"
    out = []
    for r in conn().execute(sql, args):
        d = dict(r)
        d["reasons"] = json.loads(d["reasons"])
        out.append(d)
    return out


def decide_approval(aid: str, approver: Principal, approve: bool) -> dict | None:
    row = conn().execute("SELECT * FROM approvals WHERE id = ?", (aid,)).fetchone()
    if not row or row["status"] != "pending":
        return None
    with _lock:
        conn().execute("UPDATE approvals SET status = ?, decided_by = ?, decided_ts = ? WHERE id = ?",
                       ("approved" if approve else "rejected", approver.user_id, time.time(), aid))
        conn().commit()
    return _pending_args.pop(aid, None)
