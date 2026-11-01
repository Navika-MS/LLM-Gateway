import { useState } from "react";
import type { ChunkVerdict, ContextResponse, Decision, Finding, GuardResponse, RagResponse, StageResult } from "../api";

const DECISION_TEXT: Record<Decision, string> = {
  ALLOW: "Allowed",
  SANITIZE: "Allowed after sanitizing",
  REQUIRE_APPROVAL: "Needs human approval",
  BLOCK: "Blocked",
};

export function DecisionBadge({ d, small }: { d: Decision; small?: boolean }) {
  return <span className={`badge badge-${d} ${small ? "badge-sm" : ""}`}>{small ? d.replace("_", " ") : DECISION_TEXT[d]}</span>;
}

export function RiskBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const level = value >= 0.8 ? "high" : value >= 0.5 ? "med" : value > 0 ? "low" : "none";
  return (
    <div className="riskbar" title={`risk ${value.toFixed(2)}`}>
      <div className={`riskbar-fill risk-${level}`} style={{ width: `${Math.max(pct, 2)}%` }} />
    </div>
  );
}

export function FindingList({ findings }: { findings: Finding[] }) {
  if (!findings.length) return <p className="muted small">No findings.</p>;
  return (
    <ul className="findings">
      {findings.map((f, i) => (
        <li key={i}>
          <span className={`sev sev-${f.severity}`}>{f.severity}</span>
          <code>{f.rule_id}</code> <span>{f.message}</span>
          {f.evidence && <div className="evidence">“{f.evidence}”</div>}
        </li>
      ))}
    </ul>
  );
}

const STAGE_LABELS: Record<string, string> = {
  auth: "1 · Authentication & authorization",
  normalization: "2 · Input normalization",
  signatures: "3 · Deterministic signatures",
  pii: "4 · PII detection",
  ml_classifier: "5 · ML injection classifier",
  intent: "6 · Semantic intent",
  conversation: "7 · Multi-turn risk",
  output_dlp: "Output DLP",
  tool_registry: "Tool registry",
  tool_authz: "Tool authorization",
  tool_arguments: "Argument validation",
  tool_taint: "Context taint",
  tool_alignment: "Intent alignment",
};

export function StageCard({ s }: { s: StageResult }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`stage stage-${s.status}`}>
      <div className="stage-head" onClick={() => setOpen(!open)}>
        <span className="stage-name">{STAGE_LABELS[s.name] ?? s.name}</span>
        <span className={`status status-${s.status}`}>{s.status}</span>
        <RiskBar value={s.risk} />
        <span className="muted small mono">{s.latency_ms.toFixed(1)} ms</span>
        <span className="chev">{open ? "▾" : "▸"}</span>
      </div>
      {s.error && <p className="error small">{s.error}</p>}
      {s.findings.length > 0 && <FindingList findings={s.findings} />}
      {open && <pre className="details">{JSON.stringify(s.details, null, 2)}</pre>}
    </div>
  );
}

function Summary({ decision, risk, reasons, latency }: { decision: Decision; risk: number; reasons: string[]; latency: number }) {
  return (
    <div className={`summary summary-${decision}`}>
      <div className="summary-top">
        <DecisionBadge d={decision} />
        <span className="muted small mono">risk {risk.toFixed(2)} · {latency.toFixed(1)} ms</span>
      </div>
      <ul className="reasons">
        {reasons.map((r, i) => (
          <li key={i}>{r}</li>
        ))}
      </ul>
    </div>
  );
}

export function GuardResult({ r, title }: { r: GuardResponse; title?: string }) {
  return (
    <div className="result">
      {title && <h3>{title}</h3>}
      <Summary decision={r.decision} risk={r.risk_score} reasons={r.reasons} latency={r.latency_ms} />
      {r.approval_id && <p className="note">Approval request <code>{r.approval_id}</code> created. A security admin can approve it on the Policy tab.</p>}
      {r.sanitized_text && r.decision === "SANITIZE" && (
        <div className="block">
          <div className="label">Text forwarded to the LLM</div>
          <pre className="sanitized">{r.sanitized_text}</pre>
        </div>
      )}
      {r.result !== undefined && r.result !== null && (
        <div className="block">
          <div className="label">Tool result (demo HR system)</div>
          <pre className="sanitized">{JSON.stringify(r.result, null, 2)}</pre>
        </div>
      )}
      <div className="stages">
        {r.stages.map((s) => (
          <StageCard key={s.name} s={s} />
        ))}
      </div>
    </div>
  );
}

export function ChunkCard({ c }: { c: ChunkVerdict }) {
  return (
    <div className={`chunk chunk-${c.action}`}>
      <div className="chunk-head">
        <span className={`action action-${c.action}`}>{c.action}</span>
        <code>{c.id}</code>
        <span className="muted small">{c.source}</span>
        <span className={`trust trust-${c.trust}`}>{c.trust}</span>
        <RiskBar value={c.risk} />
      </div>
      {c.action !== "quarantine" && c.sanitized_text && <p className="chunk-text">{c.sanitized_text}</p>}
      {c.action === "quarantine" && <p className="muted small">Removed from the LLM context.</p>}
      <FindingList findings={c.findings} />
    </div>
  );
}

export function ContextResult({ r }: { r: ContextResponse }) {
  return (
    <div className="result">
      <Summary decision={r.decision} risk={r.risk_score} reasons={r.reasons} latency={r.latency_ms} />
      {r.chunks.map((c) => (
        <ChunkCard key={c.id} c={c} />
      ))}
      {r.safe_context && (
        <details className="block">
          <summary className="label">Safe context passed to the LLM (spotlighted)</summary>
          <pre className="sanitized">{r.safe_context}</pre>
        </details>
      )}
    </div>
  );
}

export function RagResult({ r }: { r: RagResponse }) {
  return (
    <div className="result">
      <Summary decision={r.decision} risk={r.prompt_check.risk_score} reasons={r.reasons} latency={r.latency_ms} />
      <div className="block">
        <div className="label">Answer returned to the user</div>
        <pre className="sanitized">{r.answer ?? "(no answer: request stopped by the gateway)"}</pre>
      </div>
      <GuardResult r={r.prompt_check} title="Step 1 · User prompt" />
      {r.context_check && (
        <>
          <h3>Step 2 · Retrieved context</h3>
          <ContextResult r={r.context_check} />
        </>
      )}
      {r.output_check && <GuardResult r={r.output_check} title="Step 3 · Model output" />}
    </div>
  );
}
