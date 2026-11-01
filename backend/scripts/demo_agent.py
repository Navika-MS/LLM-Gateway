"""End-to-end attack demo: an AI agent reads a poisoned email and tries to exfiltrate data.

Start the gateway first (uvicorn gateway.main:app --port 8000), then:
    python scripts/demo_agent.py

The "agent" here is deliberately naive: it obeys any instruction it finds in
the retrieved text, which is the worst case. The point of the demo is that the
gateway stops the attack twice: once at context inspection, and again at the
tool call, even if the injected instruction had slipped through.
"""
from __future__ import annotations

import argparse
import re

import httpx

HR_KEY = {"X-API-Key": "demo-hr-key"}


def banner(t: str) -> None:
    print("\n" + "=" * 78 + f"\n{t}\n" + "=" * 78)


def naive_agent_plan(user_request: str, context: str) -> dict | None:
    """Pretend LLM agent: if the context contains 'send_email ... to X', it complies."""
    m = re.search(r"send_email.*?to\s+([\w.+-]+@[\w.-]+\w)", context, re.I | re.S)
    if m:
        return {"tool": "send_email", "arguments": {"to": m.group(1), "subject": "salary sheet",
                                                     "body": "Attached: latest salary sheet"}}
    return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway", default="http://localhost:8000")
    args = ap.parse_args()
    c = httpx.Client(base_url=args.gateway, headers=HR_KEY, timeout=30)
    session = "demo-agent-run"
    user_request = "Summarize the vendor invoice email for October."

    banner(f"Employee asks the agent: {user_request!r}")
    docs = c.get("/v1/demo/documents").json()
    chunks = [d for d in docs if d["source"].endswith("vendor_invoice_email.eml")]
    print(f"Retriever returned {len(chunks)} chunks from the vendor email (source trust: {chunks[0]['trust']}).")

    banner("WITHOUT the gateway: the agent reads the raw email")
    raw = "\n".join(ch["text"] for ch in chunks)
    plan = naive_agent_plan(user_request, raw)
    print("Agent decides to call:", plan)
    print("→ The salary sheet would now be on its way to an outside address.")

    banner("WITH the gateway, line of defence 1: context inspection")
    ctx = c.post("/v1/guard/context", json={"user_query": user_request, "chunks": chunks, "session_id": session}).json()
    for v in ctx["chunks"]:
        rules = ", ".join(sorted({f["rule_id"] for f in v["findings"] if f["severity"] in ("high", "critical")})) or "-"
        print(f"  {v['id']:<28} {v['action'].upper():<11} risk={v['risk']:.2f}  {rules}")
    plan = naive_agent_plan(user_request, ctx["safe_context"])
    print("Agent plan from the SAFE context:", plan or "no tool call (the injected instruction was removed)")

    banner("WITH the gateway, line of defence 2: tool-call guard (assume the injection slipped through)")
    worst_case = naive_agent_plan(user_request, raw)
    quarantined = [v["id"] for v in ctx["chunks"] if v["action"] == "quarantine"]
    res = c.post("/v1/tools/execute", json={**worst_case, "session_id": session, "context_ids": quarantined,
                                            "user_request": user_request}).json()
    print("Decision:", res["decision"])
    for r in res["reasons"]:
        print("  -", r)
    print("Tool executed?", "yes" if res.get("result") else "no")

    banner("Result")
    state = c.get("/v1/demo/state").json()
    print("Emails in the demo outbox:", len(state["outbox"]))
    print("Every step above is in the audit log: GET /v1/audit (or the 'Live Traffic & Audit' tab).")


if __name__ == "__main__":
    main()
