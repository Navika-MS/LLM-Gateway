# Evaluation

Every dataset is reported **separately**. An earlier version pooled the hand-written set with deepset, which hid
how weak the public-set result was.

| Suite | n | What it is | Tuned on it? |
|---|---|---|---|
| `builtin` | 198 | 133 attacks (incl. 48 obfuscated), 50 hard benign prompts, 30 document chunks | yes, `dev` split only |
| `challenge` | 39 | multilingual, ROT13, role-play personas, acrostic extraction, polite indirect injections, benign "you must" policy docs | yes: written from a review of failures, then fixed |
| `holdout` | 26 | new phrasings written **after** the fixes | **never** |
| `--hf deepset/prompt-injections` | 116 | public test split (English + German) | never |

Heuristic mode (`ML_MODE=heuristic`, no model download), from `backend/eval/report.md`:

| Suite | Precision | Recall | FPR |
|---|---|---|---|
| builtin | 1.000 | 0.977 | 0.000 |
| challenge (before fixes) | – | 0.000 | 0.375 |
| challenge (after fixes) | 1.000 | 1.000 | 0.000 |
| **holdout** | 1.000 | **0.333** | 0.000 |

The holdout row is the honest one: rules fixed the classes they were written for and generalise poorly to new
phrasings. That is the reason the gateway does not rely on text filters alone. Tool authorization, gateway-owned
taint tracking and output DLP are designed to hold when a prompt gets through.

With DeBERTa (`ML_MODE=deberta`, 16 GB laptop, CPU only, 2026-11-04; p50 178 ms, p95 346 ms):

| Suite | Precision | Recall | FPR | FPR before the false-alarm fix |
|---|---|---|---|---|
| builtin | 0.985 | 1.000 | **0.031** | 0.062 |
| challenge | 1.000 | 1.000 | **0.000** | 0.188 |
| **holdout** | 1.000 | **0.800** | 0.000 | 0.000 |
| **deepset/prompt-injections** (116) | 1.000 | **0.367** | 0.000 | 0.000 |

What these numbers say:

- **The model is what generalises.** Holdout recall goes from 0.33 (rules only) to 0.80 with DeBERTa.
- **deepset recall is low (0.37).** Most misses are German prompts (the model is English-focused) and role-play
  requests that deepset labels as injections ("I want you to act as a storyteller..."). Some of those labels are
  debatable for an enterprise HR assistant, but the German misses are real: a multilingual model is the fix.
- **The threshold does not help.** In the sweep, the false-positive rate is flat from 0.3 to 0.99: the model is
  >99% confident on its false alarms ("Please ignore the typos", "ignore the previous email thread", internal MFA
  setup steps). So instead of moving the threshold, a model-only verdict is now downgraded when the text matches a
  narrow benign phrasing and no other stage objected, and the model alone can no longer quarantine a trusted
  internal document. That halved builtin false alarms (6.2% to 3.1%) and removed them on challenge (18.8% to 0)
  with no loss of recall anywhere. Both rules were written from those false positives, so treat the improvement as
  optimistic; holdout and deepset, which were not used, are unchanged.

Run from `backend/`:

```bash
pip install datasets
ML_MODE=deberta python eval/benchmark.py --hf deepset/prompt-injections --sweep --concurrency 4
```

`--sweep` adds a classifier-only precision/recall table per threshold (to choose `ML_THRESHOLD` on evidence),
`--concurrency N` measures requests per second. Regenerate the dataset with `python eval/build_dataset.py`.
