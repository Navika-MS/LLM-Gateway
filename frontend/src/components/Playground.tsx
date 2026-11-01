import { useEffect, useMemo, useState } from "react";
import { api, ENDPOINTS, IDENTITIES } from "../api";
import type { ContextResponse, GuardResponse, Mode, RagResponse, Scenario } from "../api";
import { ContextResult, DecisionBadge, GuardResult, RagResult } from "./Results";

const MODES: { id: Mode; label: string; hint: string }[] = [
  { id: "prompt", label: "Prompt", hint: "Inspect a user prompt before it reaches the LLM." },
  { id: "rag", label: "Secure RAG", hint: "Full pipeline: prompt → retrieval → context inspection → LLM → output DLP." },
  { id: "context", label: "Context", hint: "Inspect retrieved chunks for indirect prompt injection." },
  { id: "tool", label: "Tool call", hint: "Authorize an agent's tool call against the fake HR system." },
  { id: "output", label: "Output", hint: "Check a model response for PII leaks and exfiltration." },
];

const DEFAULTS: Record<Mode, Record<string, unknown>> = {
  prompt: { text: "", session_id: "" },
  rag: { query: "", session_id: "" },
  context: { user_query: "Summarize the latest financial report.", chunks: [{ id: "c1", text: "", source: "manual", trust: "unknown" }] },
  tool: { tool: "search_employees", arguments: { query: "Priya" }, user_request: "Find Priya's email" },
  output: { text: "" },
};

type AnyResult = GuardResponse | ContextResponse | RagResponse;

export default function Playground({ apiKey, setApiKey }: { apiKey: string; setApiKey: (k: string) => void }) {
  const [mode, setMode] = useState<Mode>("prompt");
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [active, setActive] = useState<Scenario | null>(null);
  const [text, setText] = useState("");
  const [session, setSession] = useState("");
  const [json, setJson] = useState(JSON.stringify(DEFAULTS.tool, null, 2));
  const [result, setResult] = useState<{ mode: Mode; data: AnyResult } | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api<Scenario[]>("/v1/demo/scenarios", apiKey).then(setScenarios).catch((e) => setError(String(e)));
  }, [apiKey]);

  const visible = useMemo(() => scenarios.filter((s) => s.mode === mode), [scenarios, mode]);

  function load(s: Scenario) {
    setActive(s);
    setResult(null);
    setError("");
    if (s.key) setApiKey(s.key);
    if (s.mode === "prompt" || s.mode === "output") {
      setText(String(s.body.text ?? ""));
      setSession(String(s.body.session_id ?? ""));
    } else if (s.mode === "rag") {
      setText(String(s.body.query ?? ""));
      setSession(String(s.body.session_id ?? ""));
    } else {
      setJson(JSON.stringify(s.body, null, 2));
    }
  }

  function switchMode(m: Mode) {
    setMode(m);
    setActive(null);
    setResult(null);
    setError("");
    setText("");
    setSession("");
    if (m === "tool" || m === "context") setJson(JSON.stringify(DEFAULTS[m], null, 2));
  }

  async function run() {
    setBusy(true);
    setError("");
    try {
      let body: Record<string, unknown>;
      if (mode === "prompt") body = { text, ...(session ? { session_id: session } : {}) };
      else if (mode === "output") body = { text };
      else if (mode === "rag") body = { query: text, ...(session ? { session_id: session } : {}) };
      else body = JSON.parse(json);
      const data = await api<AnyResult>(ENDPOINTS[mode], apiKey, body);
      setResult({ mode, data });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const hint = MODES.find((m) => m.id === mode)!.hint;
  const decision = result ? (result.data as { decision: GuardResponse["decision"] }).decision : null;

  return (
    <div className="playground">
      <aside className="scenarios">
        <div className="label">Attack & benign presets</div>
        {visible.map((s) => (
          <button key={s.id} className={`scenario ${active?.id === s.id ? "active" : ""}`} onClick={() => load(s)}>
            <span>{s.title}</span>
            <DecisionBadge d={s.expect} small />
          </button>
        ))}
        {!visible.length && <p className="muted small">Start the backend to load presets.</p>}
      </aside>

      <section className="editor">
        <div className="tabs">
          {MODES.map((m) => (
            <button key={m.id} className={`tab ${mode === m.id ? "active" : ""}`} onClick={() => switchMode(m.id)}>
              {m.label}
            </button>
          ))}
        </div>
        <p className="muted small">{hint}</p>

        <div className="row">
          <label className="field grow">
            <span className="label">Calling as</span>
            <select value={apiKey} onChange={(e) => setApiKey(e.target.value)}>
              {IDENTITIES.map((i) => (
                <option key={i.key} value={i.key}>
                  {i.label}
                </option>
              ))}
            </select>
          </label>
          {(mode === "prompt" || mode === "rag") && (
            <label className="field grow">
              <span className="label">Session id (multi-turn)</span>
              <input value={session} placeholder="optional" onChange={(e) => setSession(e.target.value)} />
            </label>
          )}
        </div>

        {mode === "tool" || mode === "context" ? (
          <textarea className="code" rows={16} value={json} onChange={(e) => setJson(e.target.value)} spellCheck={false} />
        ) : (
          <textarea
            rows={mode === "output" ? 7 : 5}
            value={text}
            placeholder={mode === "rag" ? "Ask the HR/finance assistant…" : mode === "output" ? "Paste a model response…" : "Type a prompt…"}
            onChange={(e) => setText(e.target.value)}
          />
        )}
        <div className="row">
          <button className="primary" onClick={run} disabled={busy}>
            {busy ? "Inspecting…" : "Run through gateway"}
          </button>
          {active && decision && (
            <span className={`small ${decision === active.expect ? "ok" : "error"}`}>
              {decision === active.expect ? "✓ matches expected" : `✗ expected ${active.expect}`}
            </span>
          )}
        </div>
        {error && <p className="error">{error}</p>}
      </section>

      <section className="output">
        {!result && <div className="empty muted">Pick a preset or type your own input, then run it to see every security stage.</div>}
        {result?.mode === "rag" && <RagResult r={result.data as RagResponse} />}
        {result?.mode === "context" && <ContextResult r={result.data as ContextResponse} />}
        {result && ["prompt", "tool", "output"].includes(result.mode) && <GuardResult r={result.data as GuardResponse} />}
      </section>
    </div>
  );
}
