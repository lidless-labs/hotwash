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
