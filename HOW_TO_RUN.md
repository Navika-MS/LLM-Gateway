# How to run the LLM Guardrail Gateway (16 GB laptop, no GPU)

Commands are given for **Windows (PowerShell)** and **macOS/Linux**. Pick one path: A (no Docker, recommended to start) or B (Docker).

## 0. Prerequisites

| Tool | Version | Check |
|---|---|---|
| Python | 3.10 to 3.12 (3.13 works for the core) | `python --version` |
| Node.js | 18 or newer | `node --version` |
| Git (optional) | any | `git --version` |
| Docker Desktop (only for path B) | any recent | `docker --version` |
| Ollama (optional) | any | `ollama --version` |

Unzip `llm-guardrail-gateway.zip` into an **empty folder** (not on top of an older copy) and open a terminal in the
`llm-guardrail-gateway` folder it creates. If you see `llm-guardrail-gateway\llm-guardrail-gateway`, use the inner one.
Only ever run one backend at a time: close old terminals from earlier versions first.

---

## Path A: run without Docker

### A1. Backend (terminal 1)

**Windows**
```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1          # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
pip install -r requirements-dev.txt
uvicorn gateway.main:app --reload --port 8000
```

**macOS / Linux**
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn gateway.main:app --reload --port 8000
```

Check it works: open http://localhost:8000/health (should say `"status":"ok"`) and http://localhost:8000/docs (interactive API).

### A2. Dashboard (terminal 2)

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. The top-right dot should be green ("ML: heuristic"). If it says "backend offline", the backend from A1 isn't running.

### A3. Try it

- **Playground** tab: click a preset on the left (e.g. "Direct injection"), then **Run through gateway**.
- Run "Multi-turn 1/4" to "4/4" in order to see the conversation-level block.
- **Secure RAG** tab: "RAG: poisoned Q3 financial PDF".
- **Context** tab: run "mixed chunks" first, then **Tool call** tab: "injected send_email".
- **Policy & Approvals**: switch "Calling as" to *Root (security admin)* to approve requests.
- **Live Traffic & Audit**: every decision, with PII masked.

### A4. Tests, terminal demo, benchmark (terminal 3, venv activated, inside `backend`)

```bash
pytest -q                          # expect: 111 passed
python scripts/demo_agent.py       # needs the backend from A1 running
python eval/benchmark.py           # writes eval/report.md
```

---

## Turning on the real ML stages (optional, one at a time)

Stop the backend (Ctrl+C) first. All commands run in `backend` with the venv active.

### DeBERTa prompt-injection classifier (~1 GB RAM)

Install CPU-only PyTorch **first** (it is deliberately not in `requirements-ml.txt`; the default build is 2 GB+):

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r requirements-ml.txt
python -m spacy download en_core_web_sm      # only needed for Presidio
```

Start the backend with the classifier enabled:

**Windows**
```powershell
$env:ML_MODE="deberta"; uvicorn gateway.main:app --port 8000
```
**macOS / Linux**
```bash
ML_MODE=deberta uvicorn gateway.main:app --port 8000
```

The first request downloads the model (~700 MB) and takes 30 to 60 seconds; after that it's cached. Check http://localhost:8000/health: `ml_loaded` should become `true`. If `ml_error` shows a message, the stage failed and the gateway is failing closed (requests go to approval).

### Presidio NER for PII

Same install as above, then add `PII_ENGINE=presidio` (Windows: `$env:PII_ENGINE="presidio"`).

### Ollama (local LLM, ~2 GB RAM)

1. Install Ollama from https://ollama.com and start it.
2. `ollama pull qwen2.5:1.5b`
3. Start the backend with:
   - Windows: `$env:INTENT_MODE="ollama"; $env:RAG_LLM="ollama"; uvicorn gateway.main:app --port 8000`
   - macOS/Linux: `INTENT_MODE=ollama RAG_LLM=ollama uvicorn gateway.main:app --port 8000`

Expect 1 to 3 seconds per request on CPU. If you stop Ollama, requests get REQUIRE_APPROVAL or BLOCK (fail closed), which is intended.

### Benchmark with DeBERTa

Needs the DeBERTa install above (PyTorch first), then:

**Windows**
```powershell
pip install datasets
$env:PYTHONUTF8="1"; $env:ML_MODE="deberta"
python eval/benchmark.py --hf deepset/prompt-injections --sweep --concurrency 4
```
**macOS / Linux**
```bash
pip install datasets
ML_MODE=deberta python eval/benchmark.py --hf deepset/prompt-injections --sweep --concurrency 4
```

The first line must say `classifier: protectai/deberta-v3-base-prompt-injection-v2`. If the model can't load, the
benchmark stops with an error instead of printing meaningless numbers.

The terminal prints one line per suite (`builtin`, `challenge`, `holdout`, `deepset/prompt-injections`); never
quote a pooled number. `eval/report.md` adds the threshold sweep and every misclassified sample. Put the per-suite
numbers into the README's Evaluation section.

---

## Path B: Docker

Start Docker Desktop, then in the `llm-guardrail-gateway` folder:

```bash
docker compose up --build
```

- Dashboard: http://localhost:8080
- API docs: http://localhost:8000/docs

Variants:

```bash
# with DeBERTa + Presidio (bigger image, ~1.5 GB, first build takes a while)
INSTALL_ML=true ML_MODE=deberta docker compose up --build

# with Ollama in Docker
docker compose --profile llm up --build
docker compose exec ollama ollama pull qwen2.5:1.5b
```

On Windows PowerShell set variables first, e.g. `$env:INSTALL_ML="true"; $env:ML_MODE="deberta"; docker compose up --build`.

Stop with Ctrl+C, or `docker compose down`.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `uvicorn: command not found` | The venv isn't active. Run the activate command again, or use `python -m uvicorn ...` |
| Port 8000 already in use (`WinError 10048`) | An old backend is still running. Close its terminal, or on Windows: `netstat -ano \| findstr :8000`, then `taskkill /PID <number> /F` |
| UI shows `Unexpected token ... is not valid JSON` | You are running an old build, or the backend is down. Use the latest zip; it shows the real error instead |
| Every prompt suddenly needs approval after testing many attacks | Per-user probing protection (10 blocked requests in 10 minutes). As admin: `POST /v1/demo/reset`, or restart the backend |
| Dashboard says "backend offline" | Start the backend first; check http://localhost:8000/health |
| PowerShell won't activate the venv | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| torch install is huge (2 GB+) | You missed `--index-url https://download.pytorch.org/whl/cpu`; uninstall and reinstall with it |
| `No module named 'torch'` / benchmark says the classifier did not load | Run `pip install torch --index-url https://download.pytorch.org/whl/cpu` inside the venv |
| Every request says REQUIRE_APPROVAL with "fail-closed" | A configured stage (DeBERTa or Ollama) failed. Check `/health` for `ml_error`, or that Ollama is running |
| Want a clean demo state | As admin: `POST /v1/demo/reset`, or delete `backend/data/*.db` and restart |

**RAM tip:** the core alone uses about 100 MB. Turn on DeBERTa, then Ollama, one at a time and watch Task Manager / Activity Monitor. All of it together is around 4 to 5 GB.
