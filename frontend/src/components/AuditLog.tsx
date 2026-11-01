import { Fragment, useEffect, useState } from "react";
import { api } from "../api";
import type { Decision, Finding } from "../api";
import { DecisionBadge, FindingList } from "./Results";

interface Event {
  id: string;
  ts: number;
  endpoint: string;
  user_id: string;
  role: string;
  session_id: string | null;
  decision: Decision;
  risk: number;
  reasons: string[];
  findings: Finding[];
  input_preview: string;
  latency_ms: number;
}

interface Stats {
  total: number;
  by_decision: Record<string, number>;
  top_categories: Record<string, number>;
  latency_ms: { p50: number | null; p95: number | null };
}

export default function AuditLog({ apiKey }: { apiKey: string }) {
  const [events, setEvents] = useState<Event[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [filter, setFilter] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const [live, setLive] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let stop = false;
    const load = () =>
      Promise.all([
        api<Event[]>(`/v1/audit?limit=200${filter ? `&decision=${filter}` : ""}`, apiKey),
        api<Stats>("/v1/stats", apiKey),
      ])
        .then(([e, s]) => {
          if (!stop) {
            setEvents(e);
            setStats(s);
            setError("");
          }
        })
        .catch((e) => setError(String(e)));
    load();
    const t = live ? setInterval(load, 3000) : undefined;
    return () => {
      stop = true;
      if (t) clearInterval(t);
    };
  }, [apiKey, filter, live]);

  return (
    <div className="page">
      <div className="cards">
        <div className="card">
          <div className="label">Requests</div>
          <div className="big">{stats?.total ?? "–"}</div>
        </div>
        {(["ALLOW", "SANITIZE", "REQUIRE_APPROVAL", "BLOCK"] as Decision[]).map((d) => (
          <div className="card" key={d}>
            <DecisionBadge d={d} small />
            <div className="big">{stats?.by_decision[d] ?? 0}</div>
          </div>
        ))}
        <div className="card">
          <div className="label">Latency p50 / p95</div>
          <div className="big mono">
            {stats?.latency_ms.p50 ?? "–"} / {stats?.latency_ms.p95 ?? "–"} <span className="small muted">ms</span>
          </div>
        </div>
      </div>
      {stats && Object.keys(stats.top_categories).length > 0 && (
        <p className="small muted">
          Top threat categories:{" "}
          {Object.entries(stats.top_categories)
            .map(([k, v]) => `${k} (${v})`)
            .join(" · ")}
        </p>
      )}

      <div className="row">
        <label className="field">
          <span className="label">Decision</span>
          <select value={filter} onChange={(e) => setFilter(e.target.value)}>
            <option value="">All</option>
            <option>ALLOW</option>
            <option>SANITIZE</option>
            <option>REQUIRE_APPROVAL</option>
            <option>BLOCK</option>
          </select>
        </label>
        <label className="check">
          <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} /> Live (3s)
        </label>
        <span className="small muted">Inputs are stored PII-masked with a SHA-256 hash. Raw values are never written.</span>
      </div>
      {error && <p className="error">{error}</p>}

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Endpoint</th>
              <th>User</th>
              <th>Decision</th>
              <th>Risk</th>
              <th>Input (redacted)</th>
              <th>ms</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <Fragment key={e.id}>
                <tr className="clickable" onClick={() => setOpen(open === e.id ? null : e.id)}>
                  <td className="mono small">{new Date(e.ts * 1000).toLocaleTimeString()}</td>
                  <td className="mono small">{e.endpoint}</td>
                  <td className="small">
                    {e.user_id} <span className="muted">({e.role})</span>
                  </td>
                  <td>
                    <DecisionBadge d={e.decision} small />
                  </td>
                  <td className="mono small">{e.risk.toFixed(2)}</td>
                  <td className="small ellipsis">{e.input_preview}</td>
                  <td className="mono small">{e.latency_ms.toFixed(1)}</td>
                </tr>
                {open === e.id && (
                  <tr>
                    <td colSpan={7} className="expanded">
                      <ul className="reasons">
                        {e.reasons.map((r, i) => (
                          <li key={i}>{r}</li>
                        ))}
                      </ul>
                      <FindingList findings={e.findings} />
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
        {!events.length && <p className="muted small">No events yet. Run something in the Playground.</p>}
      </div>
    </div>
  );
}
