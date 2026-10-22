import { DEFAULT_MAX_RESPONSE_BYTES, type HotwashConfig } from "./config.js";
import type {
  ExecutionDetail,
  ExecutionStep,
  ExecutionSummary,
  PlaybookDetail,
  PlaybookSummary,
  SuggestionAcceptResponse,
  SuggestionDetail,
  SuggestionState,
  SuggestionSummary,
  TimelineEvent,
} from "./types.js";

const MAX_REDIRECTS = 3;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const MAX_ERROR_DETAIL_CHARS = 500;

export class ResponseTooLargeError extends Error {
  constructor(limit: number) {
    super(`Hotwash API response exceeded the ${limit} byte limit`);
  }
}

// Read a response body through a strict byte ceiling so an oversized or
// unending body is cut off before it is buffered whole or parsed.
async function readBodyLimited(response: Response, limit: number): Promise<string> {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > limit) {
    await response.body?.cancel().catch(() => undefined);
    throw new ResponseTooLargeError(limit);
  }
  if (!response.body) return "";
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let total = 0;
  let text = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel().catch(() => undefined);
      throw new ResponseTooLargeError(limit);
    }
    text += decoder.decode(value, { stream: true });
  }
  return text + decoder.decode();
}

function describeDetail(detail: unknown): string {
  const text = typeof detail === "string" ? detail : JSON.stringify(detail);
  return text.length > MAX_ERROR_DETAIL_CHARS ? `${text.slice(0, MAX_ERROR_DETAIL_CHARS)}...` : text;
}

export class HotwashClient {
  private readonly baseUrl: string;
  private readonly origin: string;
  private readonly apiKey?: string;
  private readonly timeout: number;
  private readonly maxResponseBytes: number;

  constructor(config: HotwashConfig) {
    this.baseUrl = config.url;
    this.origin = new URL(config.url).origin;
    this.apiKey = config.apiKey;
    this.timeout = config.timeout;
    this.maxResponseBytes = config.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  }

  private headers(extra: Record<string, string> = {}): Record<string, string> {
    const base: Record<string, string> = { Accept: "application/json", ...extra };
    if (this.apiKey) base["X-API-Key"] = this.apiKey;
    return base;
  }

  // Redirects are followed by hand, only within the configured origin and for a
  // few hops, so the API key header is only ever sent to the configured backend.
  private async fetchSameOrigin(first: string, init: RequestInit): Promise<Response> {
    let target = first;
    let current = init;
    for (let hop = 0; ; hop += 1) {
      const response = await fetch(target, { ...current, redirect: "manual" });
      if (!REDIRECT_STATUSES.has(response.status)) return response;
      await response.body?.cancel().catch(() => undefined);
      const location = response.headers.get("location");
      if (!location || hop >= MAX_REDIRECTS) {
        throw new Error(`Hotwash API ${response.status}: redirect not followed`);
      }
      const next = new URL(location, target);
      if (next.origin !== this.origin) {
        throw new Error(`Hotwash API ${response.status}: refusing redirect to a different origin`);
      }
      const method = (current.method ?? "GET").toUpperCase();
      if (response.status === 303 || ((response.status === 301 || response.status === 302) && method === "POST")) {
        const { body: _body, ...rest } = current;
        current = { ...rest, method: "GET" };
      }
      target = next.toString();
    }
  }

  private async request<T>(path: string, init: RequestInit = {}, parseJson = true): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    try {
      const response = await this.fetchSameOrigin(`${this.baseUrl}${path}`, {
        ...init,
        headers: { ...this.headers(init.body && !(init.body instanceof FormData) ? { "Content-Type": "application/json" } : {}), ...(init.headers as Record<string, string> | undefined) },
        signal: controller.signal,
      });
      const text = await readBodyLimited(response, this.maxResponseBytes);
      if (!response.ok) {
        let detail: unknown = response.statusText || `HTTP ${response.status}`;
        try {
          const data = text ? JSON.parse(text) : null;
          if (data?.detail) detail = data.detail;
          else if (data?.error) detail = data.error;
        } catch {
          // body wasn't JSON; keep statusText
        }
        throw new Error(`Hotwash API ${response.status}: ${describeDetail(detail)}`);
      }
      if (!parseJson || !text) return undefined as T;
      return JSON.parse(text) as T;
    } finally {
      clearTimeout(timer);
    }
  }

  listPlaybooks(filters: { category?: string; tag?: string; search?: string } = {}): Promise<PlaybookSummary[]> {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(filters)) {
      if (value) params.set(key, String(value));
    }
    const qs = params.toString();
    return this.request<PlaybookSummary[]>(`/api/playbooks${qs ? `?${qs}` : ""}`);
  }

  getPlaybook(id: number): Promise<PlaybookDetail> {
    return this.request<PlaybookDetail>(`/api/playbooks/${id}`);
  }

  startRun(payload: {
    playbook_id: number;
    incident_title: string;
    incident_id?: string;
    started_by?: string;
    context?: Record<string, unknown>;
  }): Promise<ExecutionSummary> {
    return this.request<ExecutionSummary>(`/api/executions`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  getRun(executionId: number): Promise<ExecutionDetail> {
    return this.request<ExecutionDetail>(`/api/executions/${executionId}`);
  }

  listRuns(filters: { status?: string; playbook_id?: number; limit?: number } = {}): Promise<ExecutionSummary[]> {
    const params = new URLSearchParams();
    if (filters.status) params.set("status", filters.status);
    if (filters.playbook_id !== undefined) params.set("playbook_id", String(filters.playbook_id));
    if (filters.limit !== undefined) params.set("limit", String(filters.limit));
    const qs = params.toString();
    return this.request<ExecutionSummary[]>(`/api/executions${qs ? `?${qs}` : ""}`);
  }

  advanceStep(
    executionId: number,
    nodeId: string,
    payload: { status?: string; assignee?: string; notes?: string; decision_taken?: string },
  ): Promise<ExecutionDetail> {
    return this.request<ExecutionDetail>(`/api/executions/${executionId}/steps/${encodeURIComponent(nodeId)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
  }

  patchExecution(executionId: number, payload: { status?: string; notes?: string; confirm?: boolean }): Promise<ExecutionSummary> {
    return this.request<ExecutionSummary>(`/api/executions/${executionId}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
  }

  attachArtifact(executionId: number, nodeId: string, filename: string, content: Uint8Array, provenance: { source_tool?: string; source_ref?: string; observed_at?: string } = {}): Promise<ExecutionStep> {
    const form = new FormData();
    const blob = new Blob([content]);
    form.append("file", blob, filename);
    for (const [key, value] of Object.entries(provenance)) {
      if (value !== undefined) form.append(key, value);
    }
    return this.request<ExecutionStep>(
      `/api/executions/${executionId}/steps/${encodeURIComponent(nodeId)}/evidence`,
      { method: "POST", body: form },
    );
  }

  getTimeline(executionId: number): Promise<TimelineEvent[]> {
    return this.request<TimelineEvent[]>(`/api/executions/${executionId}/timeline`);
  }

  listSuggestions(filters: { state?: SuggestionState; mapping_id?: number; limit?: number } = {}): Promise<SuggestionSummary[]> {
    const params = new URLSearchParams();
    if (filters.state) params.set("state", filters.state);
    if (filters.mapping_id !== undefined) params.set("mapping_id", String(filters.mapping_id));
    if (filters.limit !== undefined) params.set("limit", String(filters.limit));
    const qs = params.toString();
    return this.request<SuggestionSummary[]>(`/api/ingest/suggestions${qs ? `?${qs}` : ""}`);
  }

  getSuggestion(suggestionId: number): Promise<SuggestionDetail> {
    return this.request<SuggestionDetail>(`/api/ingest/suggestions/${suggestionId}`);
  }

  acceptSuggestion(suggestionId: number): Promise<SuggestionAcceptResponse> {
    return this.request<SuggestionAcceptResponse>(
      `/api/ingest/suggestions/${suggestionId}/accept?confirm=true`,
      { method: "POST" },
    );
  }

  dismissSuggestion(suggestionId: number, reason?: string): Promise<SuggestionSummary> {
    const init: RequestInit = { method: "POST" };
    if (reason && reason.length > 0) {
      init.body = JSON.stringify({ reason });
    }
    return this.request<SuggestionSummary>(
      `/api/ingest/suggestions/${suggestionId}/dismiss?confirm=true`,
      init,
    );
  }
}
