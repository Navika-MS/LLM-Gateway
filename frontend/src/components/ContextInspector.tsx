import { useEffect, useState } from "react";
import { api } from "../api";
import type { ContextResponse } from "../api";
import { ContextResult } from "./Results";

interface Chunk {
  id: string;
  text: string;
  source: string;
  source_type: string;
  trust: string;
}

export default function ContextInspector({ apiKey }: { apiKey: string }) {
  const [docs, setDocs] = useState<Chunk[]>([]);
  const [selected, setSelected] = useState<Chunk[]>([]);
  const [query, setQuery] = useState("Summarize the latest financial report.");
  const [custom, setCustom] = useState("");
  const [trust, setTrust] = useState("external");
  const [result, setResult] = useState<ContextResponse | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api<Chunk[]>("/v1/demo/documents", apiKey).then(setDocs).catch((e) => setError(String(e)));
  }, [apiKey]);

  const toggle = (c: Chunk) =>
    setSelected((s) => (s.some((x) => x.id === c.id) ? s.filter((x) => x.id !== c.id) : [...s, c]));

  function addCustom() {
    if (!custom.trim()) return;
    setSelected((s) => [...s, { id: `custom-${s.length + 1}`, text: custom, source: "pasted", source_type: "other", trust }]);
    setCustom("");
  }

  async function inspect() {
    setError("");
    try {
      setResult(await api<ContextResponse>("/v1/guard/context", apiKey, { user_query: query, chunks: selected }));
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="page two-col">
      <div>
        <p className="muted small">
          Pick retrieved chunks from the demo corpus (some are poisoned) or paste your own, then inspect them as the RAG
          pipeline would before they reach the LLM.
        </p>
        <label className="field">
          <span className="label">User question</span>
          <input value={query} onChange={(e) => setQuery(e.target.value)} />
        </label>
        <div className="label">Demo corpus</div>
        <div className="doclist">
          {docs.map((d) => (
            <label key={d.id} className={`doc ${selected.some((x) => x.id === d.id) ? "on" : ""}`}>
              <input type="checkbox" checked={selected.some((x) => x.id === d.id)} onChange={() => toggle(d)} />
              <span>
                <code>{d.id}</code> <span className={`trust trust-${d.trust}`}>{d.trust}</span>
                <span className="doc-text">{d.text.slice(0, 140)}</span>
              </span>
            </label>
          ))}
        </div>
        <label className="field">
          <span className="label">Paste a chunk</span>
          <textarea rows={3} value={custom} onChange={(e) => setCustom(e.target.value)} />
        </label>
        <div className="row">
          <select value={trust} onChange={(e) => setTrust(e.target.value)}>
            <option value="trusted">trusted</option>
            <option value="internal">internal</option>
            <option value="external">external</option>
            <option value="unknown">unknown</option>
          </select>
          <button onClick={addCustom}>Add chunk</button>
          <button className="primary" onClick={inspect} disabled={!selected.length}>
            Inspect {selected.length} chunk{selected.length === 1 ? "" : "s"}
          </button>
        </div>
        {error && <p className="error">{error}</p>}
      </div>
      <div>{result ? <ContextResult r={result} /> : <div className="empty muted">Results appear here.</div>}</div>
    </div>
  );
}
