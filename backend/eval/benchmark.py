"""Benchmark the gateway on eval/dataset.jsonl (and optionally public datasets).

    python eval/benchmark.py                      # current env config (ML_MODE etc.)
    python eval/benchmark.py --split test         # held-out split only
    python eval/benchmark.py --hf deepset/prompt-injections   # needs `pip install datasets`
    ML_MODE=deberta python eval/benchmark.py      # with the transformer classifier

Writes eval/report.md and eval/results.json. "Positive" = unsafe sample.
A prompt counts as flagged when the decision is BLOCK or REQUIRE_APPROVAL;
a context chunk counts as flagged when it is sanitized or quarantined.
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
os.environ.setdefault("AUDIT_DB", str(HERE / ".bench_audit.db"))

from gateway.config import get_settings  # noqa: E402
from gateway.models import ContextChunk, ContextRequest, Decision, Principal, PromptRequest  # noqa: E402
from gateway import orchestrator  # noqa: E402

EMPLOYEE = Principal(user_id="bench", role="employee", tenant="bench")
FLAGGED = {Decision.BLOCK, Decision.REQUIRE_APPROVAL}


def predict(row: dict) -> tuple[bool, float]:
    t0 = time.perf_counter()
    if row["kind"] == "context":
        res = orchestrator.guard_context(ContextRequest(user_query=row.get("user_query", "Summarize."), chunks=[
            ContextChunk(id=row["id"], text=row["text"], trust=row.get("trust", "unknown"))]), EMPLOYEE, log=False)
        flagged = res.chunks[0].action != "keep"
    else:
        res = orchestrator.guard_prompt(PromptRequest(text=row["text"]), EMPLOYEE, log=False)
        flagged = res.decision in FLAGGED
    return flagged, (time.perf_counter() - t0) * 1000


def metrics(pairs: list[tuple[bool, bool]]) -> dict:
    tp = sum(1 for y, p in pairs if y and p)
    fp = sum(1 for y, p in pairs if not y and p)
    fn = sum(1 for y, p in pairs if y and not p)
    tn = sum(1 for y, p in pairs if not y and not p)
    prec = tp / (tp + fp) if tp + fp else None
    rec = tp / (tp + fn) if tp + fn else None
    f1 = 2 * prec * rec / (prec + rec) if prec and rec else None
    fpr = fp / (fp + tn) if fp + tn else None
    return {"n": len(pairs), "tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": prec, "recall": rec, "f1": f1,
            "false_positive_rate": fpr, "accuracy": (tp + tn) / len(pairs) if pairs else None}


def load_hf(name: str, limit: int) -> list[dict]:
    from datasets import load_dataset  # optional

    ds = load_dataset(name, split="test" if name == "deepset/prompt-injections" else "train")
    rows = []
    for i, r in enumerate(ds):
        if i >= limit:
            break
        text = r.get("text") or r.get("prompt") or ""
        label = r.get("label", 1)
        rows.append({"id": f"hf-{i}", "kind": "prompt", "text": text, "label": "unsafe" if int(label) == 1 else "safe",
                     "category": name, "source": name, "split": "test"})
    return rows


def fmt(x):
    return "–" if x is None else f"{x:.3f}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", choices=["dev", "test", "all"], default="all")
    ap.add_argument("--hf", action="append", default=[], help="HF dataset id to add (e.g. deepset/prompt-injections)")
    ap.add_argument("--hf-limit", type=int, default=500)
    ap.add_argument("--show-errors", action="store_true")
    args = ap.parse_args()

    rows = [json.loads(l) for l in (HERE / "dataset.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    for name in args.hf:
        rows += load_hf(name, args.hf_limit)
    if args.split != "all":
        rows = [r for r in rows if r["split"] == args.split]

    s = get_settings()
    results, lat = [], []
    for r in rows:
        flagged, ms = predict(r)
        lat.append(ms)
        results.append({**r, "pred_unsafe": flagged, "correct": flagged == (r["label"] == "unsafe"), "latency_ms": round(ms, 2)})

    groups: dict[str, list] = defaultdict(list)
    for r in results:
        y = r["label"] == "unsafe"
        groups["ALL"].append((y, r["pred_unsafe"]))
        groups[f"kind={r['kind']}"].append((y, r["pred_unsafe"]))
        groups[f"split={r['split']}"].append((y, r["pred_unsafe"]))
        groups[f"category={r['category']}"].append((y, r["pred_unsafe"]))
        if r.get("technique"):
            groups[f"technique={r['technique']}"].append((y, r["pred_unsafe"]))
    table = {k: metrics(v) for k, v in sorted(groups.items())}
    lat_sorted = sorted(lat)
    summary = {
        "config": {"ml_mode": s.ml_mode, "intent_mode": s.intent_mode, "pii_engine": s.pii_engine, "split": args.split},
        "latency_ms": {"p50": round(statistics.median(lat), 2), "p95": round(lat_sorted[int(0.95 * (len(lat) - 1))], 2),
                       "max": round(max(lat), 2)},
        "metrics": table,
    }
    (HERE / "results.json").write_text(json.dumps({"summary": summary, "rows": results}, indent=1, ensure_ascii=False))

    lines = [
        "# Benchmark report", "",
        f"Config: `ML_MODE={s.ml_mode}`, `INTENT_MODE={s.intent_mode}`, `PII_ENGINE={s.pii_engine}`, split `{args.split}`, "
        f"{len(results)} samples.", "",
        f"Latency per request: p50 {summary['latency_ms']['p50']} ms, p95 {summary['latency_ms']['p95']} ms.", "",
        "> How to read this: rules were tuned on the `dev` split only, so `split=test` is the honest number. "
        "The dataset was written by the same person who wrote the rules, so real-world accuracy will be lower. "
        "Run `--hf deepset/prompt-injections` (and with `ML_MODE=deberta`) for an independent check.", "",
        "| Group | n | Precision | Recall | F1 | FPR | Accuracy |", "|---|---|---|---|---|---|---|",
    ]
    for k, m in table.items():
        lines.append(f"| {k} | {m['n']} | {fmt(m['precision'])} | {fmt(m['recall'])} | {fmt(m['f1'])} | {fmt(m['false_positive_rate'])} | {fmt(m['accuracy'])} |")
    errors = [r for r in results if not r["correct"]]
    lines += ["", f"## Misclassified ({len(errors)})", ""]
    for r in errors:
        kind = "missed attack" if r["label"] == "unsafe" else "false positive"
        lines.append(f"- **{kind}** `{r['id']}` [{r['category']}] {r['text'][:120]!r}")
    (HERE / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    a = table["ALL"]
    print(f"{len(results)} samples | precision {fmt(a['precision'])} recall {fmt(a['recall'])} F1 {fmt(a['f1'])} "
          f"FPR {fmt(a['false_positive_rate'])} | p50 {summary['latency_ms']['p50']} ms")
    if args.show_errors:
        for r in errors:
            print(("MISS " if r["label"] == "unsafe" else "FP   ") + r["id"], r["split"], repr(r["text"][:140]))
    print(f"report: {HERE / 'report.md'}")


if __name__ == "__main__":
    main()
