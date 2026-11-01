"""A fake HR system for demos and tests: a SQLite employee table plus agent tools.

All data is synthetic. Aadhaar numbers pass the Verhoeff check and PANs have
the right structure so the PII detectors fire realistically, but none belong to
real people. `reset()` rebuilds the database.
"""
from __future__ import annotations

import random
import sqlite3
import threading
from pathlib import Path
from typing import Any

from ..config import get_settings
from ..stages.pii import verhoeff_check_digit

_lock = threading.Lock()
OUTBOX: list[dict] = []  # emails "sent" by the demo
SYSTEM_STATE = {"audit_logging": True, "users": [{"username": "root-admin", "role": "security_admin"}]}

FIRST = ["Aarav", "Diya", "Rohan", "Ananya", "Vikram", "Meera", "Karthik", "Priya", "Arjun", "Sneha", "Rahul", "Kavya",
         "Siddharth", "Ishita", "Nikhil", "Pooja", "Aditya", "Lakshmi", "Varun", "Neha"]
LAST = ["Sharma", "Iyer", "Reddy", "Nair", "Gupta", "Menon", "Rao", "Patel", "Krishnan", "Das"]
DEPTS = ["Engineering", "Finance", "HR", "Sales", "Legal"]


def _aadhaar(rng: random.Random) -> str:
    base = str(rng.randint(2, 9)) + "".join(str(rng.randint(0, 9)) for _ in range(10))
    n = base + verhoeff_check_digit(base)
    return f"{n[:4]} {n[4:8]} {n[8:]}"


def _pan(rng: random.Random, last: str) -> str:
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return "".join(rng.choice(letters) for _ in range(3)) + "P" + last[0].upper() + f"{rng.randint(1000, 9999)}" + rng.choice(letters)


def _conn() -> sqlite3.Connection:
    path = Path(get_settings().hr_db)
    path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(path, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def reset(n: int = 20, seed: int = 7) -> None:
    rng = random.Random(seed)
    with _lock, _conn() as c:
        c.execute("DROP TABLE IF EXISTS employees")
        c.execute("""CREATE TABLE employees (
            id TEXT PRIMARY KEY, name TEXT, email TEXT, phone TEXT, department TEXT, role TEXT,
            salary INTEGER, pan TEXT, aadhaar TEXT, bank_account TEXT, ifsc TEXT)""")
        for i in range(n):
            f, l = FIRST[i % len(FIRST)], LAST[(i * 3) % len(LAST)]
            c.execute("INSERT INTO employees VALUES (?,?,?,?,?,?,?,?,?,?,?)", (
                f"EMP-{1001 + i}", f"{f} {l}", f"{f.lower()}.{l.lower()}@acme.com",
                f"+91 9{rng.randint(100000000, 999999999)}", DEPTS[i % len(DEPTS)],
                "manager" if i % 6 == 0 else "staff", rng.randrange(600_000, 4_000_000, 10_000),
                _pan(rng, l), _aadhaar(rng), str(rng.randint(10**11, 10**12 - 1)), f"HDFC0{rng.randint(100000, 999999)}",
            ))
    OUTBOX.clear()
    SYSTEM_STATE["audit_logging"] = True
    SYSTEM_STATE["users"] = [{"username": "root-admin", "role": "security_admin"}]


def ensure() -> None:
    with _conn() as c:
        exists = c.execute("SELECT name FROM sqlite_master WHERE name='employees'").fetchone()
    if not exists:
        reset()


PUBLIC_FIELDS = ["id", "name", "email", "department", "role"]


def search_employees(query: str = "", department: str | None = None, limit: int = 10) -> list[dict]:
    sql, args = f"SELECT {', '.join(PUBLIC_FIELDS)} FROM employees WHERE (name LIKE ? OR id LIKE ?)", [f"%{query}%", f"%{query}%"]
    if department:
        sql += " AND department = ?"
        args.append(department)
    sql += " LIMIT ?"
    args.append(int(limit))
    with _conn() as c:
        return [dict(r) for r in c.execute(sql, args)]


def get_employee(employee_id: str, fields: list[str] | None = None) -> dict | None:
    with _conn() as c:
        r = c.execute("SELECT * FROM employees WHERE id = ?", (employee_id,)).fetchone()
    if not r:
        return None
    d = dict(r)
    return {k: d[k] for k in (fields or d.keys()) if k in d}


def update_employee(employee_id: str, updates: dict[str, Any]) -> dict:
    allowed = {"name", "email", "phone", "department", "role", "salary", "bank_account", "ifsc"}
    bad = set(updates) - allowed
    if bad:
        raise ValueError(f"unknown fields: {sorted(bad)}")
    with _lock, _conn() as c:
        sets = ", ".join(f"{k} = ?" for k in updates)
        cur = c.execute(f"UPDATE employees SET {sets} WHERE id = ?", [*updates.values(), employee_id])
    return {"updated": cur.rowcount}


def delete_employee(employee_id: str) -> dict:
    with _lock, _conn() as c:
        cur = c.execute("DELETE FROM employees WHERE id = ?", (employee_id,))
    return {"deleted": cur.rowcount}


def send_email(to: str, subject: str = "", body: str = "") -> dict:
    OUTBOX.append({"to": to, "subject": subject, "body_chars": len(body)})
    return {"status": "queued (demo outbox, nothing really sent)", "to": to}


def export_records(table: str = "employees", fields: list[str] | None = None, limit: int = 100) -> dict:
    if table != "employees":
        raise ValueError("only the employees table exists in the demo")
    cols = ", ".join(fields or PUBLIC_FIELDS)
    with _conn() as c:
        rows = [dict(r) for r in c.execute(f"SELECT {cols} FROM employees LIMIT ?", (int(limit),))]
    return {"rows": len(rows), "preview": rows[:3]}


def run_sql(query: str) -> list[dict]:
    with _conn() as c:
        c.execute("PRAGMA query_only = ON")
        return [dict(r) for r in c.execute(query).fetchmany(50)]


def create_user(username: str, role: str = "employee") -> dict:
    SYSTEM_STATE["users"].append({"username": username, "role": role})
    return {"created": username, "role": role}


def disable_audit_logging() -> dict:
    SYSTEM_STATE["audit_logging"] = False
    return {"audit_logging": False}


TOOLS = {
    "search_employees": search_employees, "get_employee": get_employee, "update_employee": update_employee,
    "delete_employee": delete_employee, "send_email": send_email, "export_records": export_records,
    "run_sql": run_sql, "create_user": create_user, "disable_audit_logging": disable_audit_logging,
}


def execute(tool: str, arguments: dict[str, Any]) -> Any:
    ensure()
    return TOOLS[tool](**arguments)
