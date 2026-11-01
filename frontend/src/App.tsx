import { useEffect, useState } from "react";
import { API_BASE } from "./api";
import AuditLog from "./components/AuditLog";
import ContextInspector from "./components/ContextInspector";
import Playground from "./components/Playground";
import PolicyView from "./components/PolicyView";

type Page = "playground" | "context" | "audit" | "policy";
const PAGES: { id: Page; label: string }[] = [
  { id: "playground", label: "Playground" },
  { id: "context", label: "Context Inspector" },
  { id: "audit", label: "Live Traffic & Audit" },
  { id: "policy", label: "Policy & Approvals" },
];

interface Health {
  status: string;
  stages: Record<string, string | boolean | null>;
}

export default function App() {
  const [page, setPage] = useState<Page>("playground");
  const [apiKey, setApiKey] = useState("demo-employee-key");
  const [health, setHealth] = useState<Health | null>(null);
  const [down, setDown] = useState(false);

  useEffect(() => {
    const check = () =>
      fetch(API_BASE + "/health")
        .then((r) => r.json())
        .then((h) => {
          setHealth(h);
          setDown(false);
        })
        .catch(() => setDown(true));
    check();
    const t = setInterval(check, 10000);
    return () => clearInterval(t);
  }, []);

  return (
    <div className="app">
      <header>
        <div className="brand">
          <span className="logo">⛨</span>
          <div>
            <div className="title">LLM Guardrail Gateway</div>
            <div className="muted small">Zero-trust security layer for RAG, agents and copilots</div>
          </div>
        </div>
        <nav>
          {PAGES.map((p) => (
            <button key={p.id} className={`nav ${page === p.id ? "active" : ""}`} onClick={() => setPage(p.id)}>
              {p.label}
            </button>
          ))}
        </nav>
        <div className="health small">
          {down ? (
            <span className="error">● backend offline</span>
          ) : health ? (
            <span title={JSON.stringify(health.stages)}>
              <span className="ok">●</span> ML: {String(health.stages.ml_mode)} · intent: {String(health.stages.intent_mode)}
            </span>
          ) : (
            "…"
          )}
        </div>
      </header>
      <main>
        {page === "playground" && <Playground apiKey={apiKey} setApiKey={setApiKey} />}
        {page === "context" && <ContextInspector apiKey={apiKey} />}
        {page === "audit" && <AuditLog apiKey={apiKey === "demo-employee-key" ? "demo-admin-key" : apiKey} />}
        {page === "policy" && <PolicyView apiKey={apiKey} />}
      </main>
    </div>
  );
}
