export interface PlaybookSummary {
  id: number;
  title: string;
  description?: string | null;
  category?: string | null;
  tags?: { id: number; name: string }[];
  node_count?: number;
  created_at?: string;
  updated_at?: string;
}

export interface PlaybookDetail extends PlaybookSummary {
  content_markdown?: string | null;
  graph_json?: {
    nodes: { id: string; label: string; type: string; metadata?: Record<string, unknown> }[];
    edges: { id: string; source: string; target: string; label?: string | null }[];
  } | null;
  versions_count?: number;
  share_token?: string | null;
}

export interface ExecutionSummary {
  id: number;
  playbook_id: number;
  playbook_title?: string | null;
  incident_title: string;
  incident_id?: string | null;
  status: "active" | "paused" | "completed" | "abandoned" | string;
  started_by?: string | null;
  started_at: string;
  completed_at?: string | null;
  steps_total: number;
  steps_completed: number;
}

export interface ExecutionEvidence {
  filename: string;
  size: number;
  uploaded_at: string;
  sha256?: string | null;
  source_tool?: string | null;
  source_ref?: string | null;
  observed_at?: string | null;
}

export interface ExecutionStep {
  node_id: string;
  node_type: string;
  node_label: string;
  phase?: string | null;
  status: string;
  assignee?: string | null;
  notes: string[];
  evidence: ExecutionEvidence[];
  decision_taken?: string | null;
  decision_options?: string[] | null;
  started_at?: string | null;
  completed_at?: string | null;
}

export interface ExecutionDetail {
  execution: ExecutionSummary;
  steps: ExecutionStep[];
  playbook_title?: string | null;
}

export interface TimelineEvent {
  timestamp: string;
  event_type: string;
  actor?: string | null;
  description: string;
}

export type SuggestionState = "pending" | "accepted" | "dismissed";

export interface SuggestionSummary {
  id: number;
  mapping_id: number;
  playbook_id: number;
  state: SuggestionState | string;
  fingerprint: string;
  rule_id?: string | null;
  agent_id?: string | null;
  agent_name?: string | null;
  description?: string | null;
  accepted_execution_id?: number | null;
  created_at: string;
  resolved_at?: string | null;
}

export interface MappingSummary {
  id: number;
  name: string;
  playbook_id: number;
  mode: string;
  rule_id_pattern?: string | null;
  rule_groups_pattern?: string | null;
  agent_name_pattern?: string | null;
  cooldown_seconds: number;
  has_hmac_secret: boolean;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface SuggestionDetail extends SuggestionSummary {
  alert_payload: Record<string, unknown>;
  mapping: MappingSummary;
  playbook_title?: string | null;
}

export interface SuggestionAcceptResponse {
  execution: ExecutionSummary;
  already_accepted: boolean;
}

export interface ReadMetadata {
  observed_at: string;
  coverage: "unverified" | "incomplete";
  gaps: string[];
}

export interface ReadPage<T> extends ReadMetadata {
  items: T[];
  returned: number;
  scanned: number;
  offset: number;
  limit: number;
  has_more: boolean;
  overflow: boolean;
  case_id?: string;
}

export interface CaseEvidence {
  id: string;
  status: string | null;
  stage?: string | null;
  title?: string | null;
  number?: number;
  tags?: (string | null)[];
  dates: Record<string, number>;
}

export interface ObservableEvidence {
  id: string;
  data_type: "hash" | "filename";
  data: string;
  tlp: number | null;
  dates: Record<string, number>;
}

export interface CommentEvidence {
  id: string;
  external: false;
  message: string | null;
  dates: Record<string, number>;
}

export interface AnalyzerJobEvidence {
  id: string;
  status: string | null;
  analyzerId?: string | null;
  analyzerName?: string | null;
  analyzerDefinition?: string | null;
  dates: Record<string, number>;
  report: {
    verdict: "unknown";
    taxonomies?: { namespace: string | null; predicate: string | null; value: string | null; level: string | null }[];
    circl_trust?: number;
    misp_event_uuids?: string[];
    misp_event_count?: number | null;
    misp_returned_event_count?: number;
  };
}

export interface RunReport {
  execution: ExecutionSummary;
  playbook_title?: string | null;
  metrics: {
    total_duration?: string | null;
    steps_completed?: number;
    steps_total?: number;
    mean_step_time?: string | null;
    bottleneck_step?: string | null;
    bottleneck_time?: string | null;
  };
  timeline: TimelineEvent[];
  steps: (Omit<ExecutionStep, "evidence"> & {
    duration?: string | null;
    // _build_report preserves these recorded attachment fields. They are parsed
    // only by the new report read, never trusted as run-to-case identity.
    evidence: (ExecutionEvidence & { connector?: unknown; action?: unknown; result?: unknown })[];
  })[];
}
