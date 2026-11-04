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


def predict(row: dict) -> tuple[bool, float, float | None]:
    """Return (flagged, latency_ms, ml_score). ml_score is the classifier's top P(injection), if it ran."""
    t0 = time.perf_counter()
    ml = None
    if row["kind"] == "context":
        res = orchestrator.guard_context(ContextRequest(user_query=row.get("user_query", "Summarize."), chunks=[
            ContextChunk(id=row["id"], text=row["text"], trust=row.get("trust", "unknown"))]), EMPLOYEE, log=False)
        flagged = res.chunks[0].action != "keep"
    else:
        res = orchestrator.guard_prompt(PromptRequest(text=row["text"]), EMPLOYEE, log=False)
        flagged = res.decision in FLAGGED
        st = next((s for s in res.stages if s.name == "ml_classifier" and s.status == "ok"), None)
        ml = st.risk if st else None
    return flagged, (time.perf_counter() - t0) * 1000, ml


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
                     "category": name, "source": name, "suite": name, "split": "test"})
    return rows


def suite_of(row: dict) -> str:
    """Each dataset is reported on its own. Never pool a public set with the hand-written one."""
    return row.get("suite") or "builtin"


def threshold_sweep(results: list[dict]) -> dict[str, list[dict]]:
    """Classifier-only precision/recall at several thresholds, per suite (prompts only)."""
    out: dict[str, list[dict]] = {}
    by_suite: dict[str, list[dict]] = defaultdict(list)
    for r in results:
        if r.get("ml_score") is not None:
            by_suite[suite_of(r)].append(r)
    for suite, rs in by_suite.items():
        rows = []
        for th in (0.3, 0.5, 0.7, 0.85, 0.95, 0.99):
            m = metrics([(r["label"] == "unsafe", r["ml_score"] >= th) for r in rs])
            rows.append({"threshold": th, **m})
        out[suite] = rows
    return out


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
    predict(rows[0])  # warm-up: model loading must not count as request latency
    for r in rows:
        flagged, ms, ml = predict(r)
        lat.append(ms)
        results.append({**r, "pred_unsafe": flagged, "correct": flagged == (r["label"] == "unsafe"),
                        "latency_ms": round(ms, 2), "ml_score": ml})

    groups: dict[str, list] = defaultdict(list)
    for r in results:
        y = r["label"] == "unsafe"
        su = suite_of(r)
        groups[f"suite={su}"].append((y, r["pred_unsafe"]))
        groups[f"{su} | kind={r['kind']}"].append((y, r["pred_unsafe"]))
        groups[f"{su} | split={r['split']}"].append((y, r["pred_unsafe"]))
        groups[f"{su} | category={r['category']}"].append((y, r["pred_unsafe"]))
        if r.get("technique"):
            groups[f"{su} | technique={r['technique']}"].append((y, r["pred_unsafe"]))
    table = {k: metrics(v) for k, v in sorted(groups.items())}
    suites = {k.split("=", 1)[1]: v for k, v in table.items() if k.startswith("suite=")}
    sweep = threshold_sweep(results)
    lat_sorted = sorted(lat)
    summary = {
        "config": {"ml_mode": s.ml_mode, "intent_mode": s.intent_mode, "pii_engine": s.pii_engine, "split": args.split},
        "latency_ms": {"p50": round(statistics.median(lat), 2), "p95": round(lat_sorted[int(0.95 * (len(lat) - 1))], 2),
                       "max": round(max(lat), 2)},
        "suites": suites,
        "metrics": table,
        "ml_threshold_sweep": sweep,
    }
    (HERE / "results.json").write_text(json.dumps({"summary": summary, "rows": results}, indent=1, ensure_ascii=False))

    lines = [
        "# Benchmark report", "",
        f"Config: `ML_MODE={s.ml_mode}`, `INTENT_MODE={s.intent_mode}`, `PII_ENGINE={s.pii_engine}`, split `{args.split}`, "
        f"{len(results)} samples.", "",
        f"Latency per request: p50 {summary['latency_ms']['p50']} ms, p95 {summary['latency_ms']['p95']} ms.", "",
        "> How to read this: every dataset (suite) is reported separately and never pooled. "
        "`builtin` was written by the same person who wrote the rules (tuned on its `dev` split only), so its numbers "
        "are optimistic. `challenge` is a held-out set of harder attacks that was never used for tuning. "
        "Public sets (`--hf ...`) are the independent check.", "",
        "## Per dataset", "",
        "| Suite | n | Precision | Recall | F1 | FPR | Accuracy |", "|---|---|---|---|---|---|---|",
    ]
    for k, m in suites.items():
        lines.append(f"| **{k}** | {m['n']} | {fmt(m['precision'])} | {fmt(m['recall'])} | {fmt(m['f1'])} | {fmt(m['false_positive_rate'])} | {fmt(m['accuracy'])} |")
    if sweep:
        lines += ["", "## ML classifier alone, by threshold", "",
                  "Prompt samples only; shows the precision/recall trade-off behind `ML_THRESHOLD`.", "",
                  "| Suite | Threshold | Precision | Recall | FPR |", "|---|---|---|---|---|"]
        for su, rs in sweep.items():
            for m in rs:
                lines.append(f"| {su} | {m['threshold']} | {fmt(m['precision'])} | {fmt(m['recall'])} | {fmt(m['false_positive_rate'])} |")
    lines += ["", "## Breakdown", "", "| Group | n | Precision | Recall | F1 | FPR | Accuracy |", "|---|---|---|---|---|---|---|"]
    for k, m in table.items():
        if k.startswith("suite="):
            continue
        lines.append(f"| {k} | {m['n']} | {fmt(m['precision'])} | {fmt(m['recall'])} | {fmt(m['f1'])} | {fmt(m['false_positive_rate'])} | {fmt(m['accuracy'])} |")
    errors = [r for r in results if not r["correct"]]
    lines += ["", f"## Misclassified ({len(errors)})", ""]
    for r in errors:
        kind = "missed attack" if r["label"] == "unsafe" else "false positive"
        lines.append(f"- **{kind}** `{r['id']}` [{suite_of(r)} / {r['category']}] {r['text'][:120]!r}")
    (HERE / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    for su, a in suites.items():
        print(f"{su:<28} n={a['n']:<4} precision {fmt(a['precision'])} recall {fmt(a['recall'])} F1 {fmt(a['f1'])} "
              f"FPR {fmt(a['false_positive_rate'])}")
    print(f"latency p50 {summary['latency_ms']['p50']} ms, p95 {summary['latency_ms']['p95']} ms")
    if args.show_errors:
        for r in errors:
            print(("MISS " if r["label"] == "unsafe" else "FP   ") + r["id"], r["split"], repr(r["text"][:140]))
    print(f"report: {HERE / 'report.md'}")


if __name__ == "__main__":
    main()
