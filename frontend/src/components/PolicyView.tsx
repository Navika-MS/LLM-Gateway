import { useEffect, useState } from "react";
import { api } from "../api";

interface Role {
  description: string;
  permissions: string[];
  pii_allowed: string[];
  workflows: string[];
  can_approve?: boolean;
}
interface Tool {
  action: string;
  risk: string;
  permission?: string;
  requires_approval?: boolean;
  deny_always?: boolean;
  [k: string]: unknown;
}
interface Policy {
  thresholds: Record<string, number>;
  always_block_categories: string[];
  operations: Record<string, { default: string; with_workflow: string }>;
  roles: Record<string, Role>;
  tools: Record<string, Tool>;
}
interface Approval {
  id: string;
  ts: number;
  user_id: string;
  role: string;
  tool: string;
  args_preview: string;
  reasons: string[];
  status: string;
  decided_by: string | null;
}

export default function PolicyView({ apiKey }: { apiKey: string }) {
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [approvals, setApprovals] = useState<Approval[] | null>(null);
  const [msg, setMsg] = useState("");

  const loadApprovals = () =>
    api<Approval[]>("/v1/approvals", apiKey)
      .then(setApprovals)
      .catch(() => setApprovals(null));

  useEffect(() => {
    api<Policy>("/v1/policy", apiKey).then(setPolicy).catch((e) => setMsg(String(e)));
    loadApprovals();
  }, [apiKey]); // eslint-disable-line react-hooks/exhaustive-deps

  async function decide(id: string, action: "approve" | "reject") {
    try {
      const r = await api<Record<string, unknown>>(`/v1/approvals/${id}/${action}`, apiKey, {});
      setMsg(JSON.stringify(r));
      loadApprovals();
    } catch (e) {
      setMsg(String(e));
    }
  }

  if (!policy) return <div className="page muted">{msg || "Loading policy…"}</div>;
  return (
    <div className="page">
      <h2>Approval queue</h2>
      {approvals === null ? (
        <p className="muted small">Switch to the security admin identity to see and decide approvals.</p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Requested by</th>
                <th>Tool</th>
                <th>Arguments (redacted)</th>
                <th>Why</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {approvals.map((a) => (
                <tr key={a.id}>
                  <td className="small">
                    {a.user_id} <span className="muted">({a.role})</span>
                  </td>
                  <td>
                    <code>{a.tool}</code>
                  </td>
                  <td className="small mono ellipsis">{a.args_preview}</td>
                  <td className="small">{a.reasons.join("; ")}</td>
                  <td className="small">{a.status}{a.decided_by ? ` by ${a.decided_by}` : ""}</td>
                  <td className="nowrap">
                    {a.status === "pending" && (
                      <>
                        <button onClick={() => decide(a.id, "approve")}>Approve</button>{" "}
                        <button onClick={() => decide(a.id, "reject")}>Reject</button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!approvals.length && <p className="muted small">No approval requests yet.</p>}
        </div>
      )}
      {msg && <pre className="details">{msg}</pre>}

      <h2>Roles</h2>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Role</th>
              <th>Permissions</th>
              <th>PII it may see</th>
              <th>Authorized workflows</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(policy.roles).map(([name, r]) => (
              <tr key={name}>
                <td>
                  <b>{name}</b>
                  <div className="muted small">{r.description}</div>
                </td>
                <td className="small mono">{r.permissions.join(", ")}</td>
                <td className="small mono">{r.pii_allowed.join(", ")}</td>
                <td className="small mono">{r.workflows.join(", ") || "none"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2>Agent tools</h2>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Tool</th>
              <th>Action</th>
              <th>Risk</th>
              <th>Permission</th>
              <th>Rule</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(policy.tools).map(([name, t]) => (
              <tr key={name}>
                <td>
                  <code>{name}</code>
                </td>
                <td className="small">{t.action}</td>
                <td>
                  <span className={`sev sev-${t.risk === "critical" ? "critical" : t.risk === "high" ? "high" : "low"}`}>{t.risk}</span>
                </td>
                <td className="small mono">{t.permission ?? "–"}</td>
                <td className="small">{t.deny_always ? "never allowed" : t.requires_approval ? "always needs approval" : "policy checks"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2>Prompt-level operations</h2>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Category</th>
              <th>Default</th>
              <th>With authorized workflow</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(policy.operations).map(([k, v]) => (
              <tr key={k}>
                <td className="mono small">{k}</td>
                <td className="small">{v.default}</td>
                <td className="small">{v.with_workflow}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="small muted">
        Thresholds: {Object.entries(policy.thresholds).map(([k, v]) => `${k}=${v}`).join(" · ")}. Always blocked:{" "}
        {policy.always_block_categories.join(", ")}.
      </p>
    </div>
  );
}
