import type { HotwashConfig } from "./config.js";
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

export class HotwashClient {
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly timeout: number;

  constructor(config: HotwashConfig) {
    this.baseUrl = config.url;
    this.apiKey = config.apiKey;
    this.timeout = config.timeout;
  }

  private headers(extra: Record<string, string> = {}): Record<string, string> {
    const base: Record<string, string> = { Accept: "application/json", ...extra };
    if (this.apiKey) base["X-API-Key"] = this.apiKey;
    return base;
  }

  private async request<T>(path: string, init: RequestInit = {}, parseJson = true): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        ...init,
        headers: { ...this.headers(init.body && !(init.body instanceof FormData) ? { "Content-Type": "application/json" } : {}), ...(init.headers as Record<string, string> | undefined) },
        signal: controller.signal,
      });
      const text = await response.text();
      if (!response.ok) {
        let detail = response.statusText || `HTTP ${response.status}`;
        try {
          const data = text ? JSON.parse(text) : null;
          if (data?.detail) detail = data.detail;
          else if (data?.error) detail = data.error;
        } catch {
          // body wasn't JSON; keep statusText
        }
        throw new Error(`Hotwash API ${response.status}: ${detail}`);
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

  patchExecution(executionId: number, payload: { status?: string; notes?: string }): Promise<ExecutionSummary> {
    return this.request<ExecutionSummary>(`/api/executions/${executionId}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
  }

  attachArtifact(executionId: number, nodeId: string, filename: string, content: Uint8Array): Promise<ExecutionStep> {
    const form = new FormData();
    const blob = new Blob([content]);
    form.append("file", blob, filename);
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
      `/api/ingest/suggestions/${suggestionId}/accept`,
      { method: "POST" },
    );
  }

  dismissSuggestion(suggestionId: number, reason?: string): Promise<SuggestionSummary> {
    const init: RequestInit = { method: "POST" };
    if (reason && reason.length > 0) {
      init.body = JSON.stringify({ reason });
    }
    return this.request<SuggestionSummary>(
      `/api/ingest/suggestions/${suggestionId}/dismiss`,
      init,
    );
  }
}
