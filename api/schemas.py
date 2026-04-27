"""
Pydantic schemas for Hotwash CRUD API.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class TagOut(BaseModel):
    """Tag output schema."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str


class PlaybookCreate(BaseModel):
    """Playbook create input schema."""

    title: str = Field(..., min_length=1)
    description: Optional[str] = None
    category: Optional[str] = None
    content_markdown: str = Field(..., min_length=1)
    tags: Optional[List[str]] = None


class PlaybookUpdate(BaseModel):
    """Playbook update input schema."""

    title: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    content_markdown: Optional[str] = None
    tags: Optional[List[str]] = None


class PlaybookSummary(BaseModel):
    """Playbook summary output schema (list view)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    description: Optional[str] = None
    category: Optional[str] = None
    tags: List[TagOut]
    node_count: int
    created_at: datetime
    updated_at: datetime


class PlaybookDetail(BaseModel):
    """Playbook detail output schema (single view)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    description: Optional[str] = None
    category: Optional[str] = None
    content_markdown: Optional[str] = None
    graph_json: Optional[Dict[str, Any]] = None
    tags: List[TagOut]
    node_count: int
    created_at: datetime
    updated_at: datetime
    versions_count: int
    share_token: Optional[str] = None


class PlaybookVersionOut(BaseModel):
    """Playbook version output schema."""

    model_config = ConfigDict(from_attributes=True)

    version_number: int
    content_markdown: Optional[str] = None
    graph_json: Optional[Dict[str, Any]] = None
    change_summary: Optional[str] = None
    created_at: datetime


class ExportMetadata(BaseModel):
    exported_at: datetime
    format_version: str = "1.0"
    generator: str = "Hotwash"


class PlaybookExport(BaseModel):
    id: int
    title: str
    description: Optional[str] = None
    category: Optional[str] = None
    content_markdown: Optional[str] = None
    graph_json: Optional[Dict[str, Any]] = None
    tags: List[TagOut] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
    share_token: Optional[str] = None
    export_metadata: ExportMetadata


class PlaybookImport(BaseModel):
    title: str = Field(..., min_length=1)
    description: Optional[str] = None
    category: str = Field(..., min_length=1)
    content_markdown: Optional[str] = None
    graph_json: Optional[Dict[str, Any]] = None
    tags: List[str] = Field(default_factory=list)


class BulkImportResult(BaseModel):
    filename: str
    status: str
    playbook_id: Optional[int] = None
    error: Optional[str] = None


class ShareResponse(BaseModel):
    share_url: str
    token: str


class SharedPlaybookResponse(PlaybookDetail):
    shared: bool = True


# Backwards-compatible naming expected by some clients/docs.
class PlaybookResponse(PlaybookDetail):
    pass


# --- Execution schemas ---

class ExecutionEvidence(BaseModel):
    filename: str
    size: int
    uploaded_at: datetime


class ExecutionStep(BaseModel):
    node_id: str
    node_type: str
    node_label: str
    phase: Optional[str] = None
    status: str = "not_started"
    assignee: Optional[str] = None
    notes: List[str] = Field(default_factory=list)
    evidence: List[ExecutionEvidence] = Field(default_factory=list)
    decision_taken: Optional[str] = None
    decision_options: Optional[List[str]] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class ExecutionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    playbook_id: int
    incident_title: str = Field(..., min_length=1)
    incident_id: Optional[str] = None
    started_by: Optional[str] = None
    context: Optional[Dict[str, Any]] = None


class ExecutionUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Optional[str] = None
    notes: Optional[str] = None


class ExecutionStepUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Optional[str] = None
    assignee: Optional[str] = None
    notes: Optional[str] = None
    decision_taken: Optional[str] = None


class ExecutionSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    playbook_id: int
    playbook_title: Optional[str] = None
    incident_title: str
    incident_id: Optional[str] = None
    status: str
    started_by: Optional[str] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    steps_total: int = 0
    steps_completed: int = 0


class ExecutionDetail(BaseModel):
    execution: ExecutionSummary
    steps: List[ExecutionStep]
    playbook_title: Optional[str] = None


class TimelineEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    timestamp: datetime
    event_type: str
    actor: Optional[str] = None
    description: str


# --- Integration schemas ---

class IntegrationOut(BaseModel):
    """Integration output schema (no secrets)."""
    model_config = ConfigDict(from_attributes=True)

    tool_name: str
    display_name: str
    base_url: str
    enabled: bool
    verify_ssl: bool
    mock_mode: bool
    last_checked: Optional[datetime] = None
    last_status: str
    has_api_key: bool
    has_credentials: bool


class IntegrationUpdate(BaseModel):
    """Integration update input schema."""
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    enabled: Optional[bool] = None
    verify_ssl: Optional[bool] = None
    mock_mode: Optional[bool] = None
