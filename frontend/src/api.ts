export const API_BASE = import.meta.env.VITE_API_URL ?? "/api";

export type Decision = "ALLOW" | "SANITIZE" | "REQUIRE_APPROVAL" | "BLOCK";
export type Severity = "low" | "medium" | "high" | "critical";

export interface Finding {
  stage: string;
  category: string;
  rule_id: string;
  severity: Severity;
  message: string;
  evidence?: string | null;
  view?: string | null;
}

export interface StageResult {
  name: string;
  status: "ok" | "skipped" | "error";
  risk: number;
  findings: Finding[];
  latency_ms: number;
  details: Record<string, unknown>;
  error?: string | null;
}

export interface GuardResponse {
  request_id: string;
  decision: Decision;
  risk_score: number;
  reasons: string[];
  sanitized_text?: string | null;
  stages: StageResult[];
  latency_ms: number;
  approval_id?: string | null;
  result?: unknown;
}

export interface ChunkVerdict {
  id: string;
  source: string;
  trust: string;
  action: "keep" | "sanitize" | "quarantine";
  risk: number;
  findings: Finding[];
  sanitized_text?: string | null;
}

export interface ContextResponse {
  request_id: string;
  decision: Decision;
  risk_score: number;
  reasons: string[];
  chunks: ChunkVerdict[];
  safe_context: string;
  latency_ms: number;
}

export interface RagResponse {
  request_id: string;
  decision: Decision;
  answer?: string | null;
  reasons: string[];
  prompt_check: GuardResponse;
  context_check?: ContextResponse | null;
  output_check?: GuardResponse | null;
  latency_ms: number;
}

export type Mode = "prompt" | "rag" | "context" | "tool" | "output";

export interface Scenario {
  id: string;
  mode: Mode;
  title: string;
  expect: Decision;
  key?: string;
  body: Record<string, unknown>;
}

export const IDENTITIES = [
  { key: "demo-employee-key", label: "Alice (employee)" },
  { key: "demo-hr-key", label: "Harini (HR manager)" },
  { key: "demo-admin-key", label: "Root (security admin)" },
];

export const ENDPOINTS: Record<Mode, string> = {
  prompt: "/v1/guard/prompt",
  rag: "/v1/rag/query",
  context: "/v1/guard/context",
  tool: "/v1/tools/execute",
  output: "/v1/guard/output",
};

export async function api<T>(path: string, apiKey: string, body?: unknown): Promise<T> {
  const res = await fetch(API_BASE + path, {
    method: body === undefined ? "GET" : "POST",
    headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    // not JSON: usually the backend is down (dev proxy error) or crashed before answering
    throw new Error(`HTTP ${res.status} from ${path}: ${text.slice(0, 200) || "no response body"}` +
      (res.status >= 500 ? " (is the backend running? check its terminal for a traceback)" : ""));
  }
  if (!res.ok) throw new Error(data?.detail ? JSON.stringify(data.detail) : `HTTP ${res.status} from ${path}`);
  return data as T;
}
