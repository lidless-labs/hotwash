"""
Pydantic schemas for Hotwash CRUD API.
"""

from datetime import datetime
from typing import Annotated, Any, Dict, List, Optional

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainSerializer,
    StringConstraints,
)

# Playbook write bounds. These mirror the MCP tool schemas in
# mcp/src/tools/playbooks.ts so an API key holder cannot exceed what the
# bounded agent tools allow. Tag.name is String(100), so a longer tag would
# otherwise fail at the database layer instead of the request.
PLAYBOOK_TITLE_MAX = 200
PLAYBOOK_DESCRIPTION_MAX = 8000
PLAYBOOK_CATEGORY_MAX = 100
PLAYBOOK_CONTENT_MAX = 100000
PLAYBOOK_TAG_MAX_ITEMS = 18


def _reject_blank(value: str) -> str:
    """A single space passes min_length=1 but would be stripped to nothing."""
    if not value.strip():
        raise ValueError("must not be blank")
    return value


def _tag_name(value: Any) -> Any:
    """Accept the ``{id, name}`` tag shape from an exported playbook."""
    if isinstance(value, dict):
        name = value.get("name")
        if not isinstance(name, str):
            raise ValueError("tag objects must carry a string name")
        return name
    return value


PlaybookTitle = Annotated[
    str,
    StringConstraints(min_length=1, max_length=PLAYBOOK_TITLE_MAX),
    AfterValidator(_reject_blank),
]
# Import requires a category; create and update accept any string (including "")
# because the web UI sends its selected category verbatim.
PlaybookCategory = Annotated[
    str,
    StringConstraints(min_length=1, max_length=PLAYBOOK_CATEGORY_MAX),
]
PlaybookContent = Annotated[
    str,
    StringConstraints(min_length=1, max_length=PLAYBOOK_CONTENT_MAX),
    AfterValidator(_reject_blank),
]
PlaybookTagName = Annotated[
    str,
    StringConstraints(min_length=1, max_length=100),
    AfterValidator(_reject_blank),
]
# Import accepts the tag objects an export writes, then bounds them like a tag.
ImportTagName = Annotated[
    str,
    BeforeValidator(_tag_name),
    StringConstraints(min_length=1, max_length=100),
    AfterValidator(_reject_blank),
]
# Serialized with six fractional digits so a read round-trips exactly into the
# expected_updated_at precondition instead of losing sub-second precision.
MicrosecondTimestamp = Annotated[
    datetime,
    PlainSerializer(
        lambda value: value.isoformat(timespec="microseconds"),
        return_type=str,
        when_used="json",
    ),
]


class TagOut(BaseModel):
    """Tag output schema."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str


class PlaybookCreate(BaseModel):
    """Playbook create input schema."""

    model_config = ConfigDict(extra="forbid")

    title: PlaybookTitle
    description: Optional[str] = Field(default=None, max_length=PLAYBOOK_DESCRIPTION_MAX)
    category: Optional[str] = Field(default=None, max_length=PLAYBOOK_CATEGORY_MAX)
    content_markdown: PlaybookContent
    tags: Optional[List[PlaybookTagName]] = Field(default=None, max_length=PLAYBOOK_TAG_MAX_ITEMS)


class PlaybookUpdate(BaseModel):
    """Playbook update input schema.

    ``expected_updated_at`` is an optional optimistic-concurrency precondition:
    send the ``updated_at`` value from the read that produced this payload and
    the write is rejected with 409 if the playbook changed in between. Callers
    that omit it (the web UI) still get ``updated_at`` bumped; the check runs
    against the value read in the same request.
    """

    model_config = ConfigDict(extra="forbid")

    title: Optional[PlaybookTitle] = None
    description: Optional[str] = Field(default=None, max_length=PLAYBOOK_DESCRIPTION_MAX)
    category: Optional[str] = Field(default=None, max_length=PLAYBOOK_CATEGORY_MAX)
    content_markdown: Optional[PlaybookContent] = None
    tags: Optional[List[PlaybookTagName]] = Field(default=None, max_length=PLAYBOOK_TAG_MAX_ITEMS)
    expected_updated_at: Optional[datetime] = None


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
    updated_at: MicrosecondTimestamp


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
    updated_at: MicrosecondTimestamp
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
    updated_at: MicrosecondTimestamp
    share_token: Optional[str] = None
    export_metadata: ExportMetadata


class PlaybookImport(BaseModel):
    """Playbook import input schema.

    Applies the same bounds as ``PlaybookCreate`` so ``POST /playbooks/import``
    cannot be used to write a row the bounded agent tools would refuse. The
    export-only fields are accepted and ignored so a playbook exported by
    Hotwash can be re-imported; ``share_token`` is deliberately not restored.
    """

    model_config = ConfigDict(extra="forbid")

    title: PlaybookTitle
    description: Optional[str] = Field(default=None, max_length=PLAYBOOK_DESCRIPTION_MAX)
    # Optional: an export of a playbook saved without a category carries null.
    category: Optional[PlaybookCategory] = None
    content_markdown: PlaybookContent
    graph_json: Optional[Dict[str, Any]] = None
    tags: List[ImportTagName] = Field(default_factory=list, max_length=PLAYBOOK_TAG_MAX_ITEMS)
    # Present in an exported playbook; ignored on import.
    id: Optional[int] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    share_token: Optional[str] = None
    export_metadata: Optional[Dict[str, Any]] = None


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
    content_type: Optional[str] = None
    connector: Optional[str] = None
    action: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    sha256: Optional[str] = None
    source_tool: Optional[str] = None
    source_ref: Optional[str] = None
    observed_at: Optional[str] = None


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
    # Required when status is "abandoned"; ignored otherwise.
    confirm: Optional[bool] = None


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


# --- Wazuh ingest schemas ---


class WazuhRuleIn(BaseModel):
    """Subset of Wazuh rule fields we read; pass-through for the rest."""

    model_config = ConfigDict(extra="allow")

    id: Optional[str] = None
    level: Optional[int] = None
    description: Optional[str] = None
    groups: List[str] = Field(default_factory=list)


class WazuhAgentIn(BaseModel):
    """Subset of Wazuh agent fields we read; pass-through for the rest."""

    model_config = ConfigDict(extra="allow")

    id: Optional[str] = None
    name: Optional[str] = None
    ip: Optional[str] = None


class WazuhAlertIngest(BaseModel):
    """Inbound Wazuh alert payload.

    extra="allow" intentionally: Wazuh decoders vary widely and rejecting
    unknown fields would drop legitimate alerts. The full body is preserved
    into Execution.context_json regardless of which fields we model here.
    """

    model_config = ConfigDict(extra="allow")

    rule: Optional[WazuhRuleIn] = None
    agent: Optional[WazuhAgentIn] = None
    timestamp: Optional[str] = None
    full_log: Optional[str] = None
    data: Optional[Dict[str, Any]] = None


class MappingCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1)
    playbook_id: int
    mode: str = Field(default="suggest")
    rule_id_pattern: Optional[str] = None
    rule_groups_pattern: Optional[str] = None
    agent_name_pattern: Optional[str] = None
    cooldown_seconds: int = Field(default=300, ge=0)
    hmac_secret: str = Field(..., min_length=8)
    enabled: bool = True


class MappingUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = None
    playbook_id: Optional[int] = None
    mode: Optional[str] = None
    rule_id_pattern: Optional[str] = None
    rule_groups_pattern: Optional[str] = None
    agent_name_pattern: Optional[str] = None
    cooldown_seconds: Optional[int] = Field(default=None, ge=0)
    hmac_secret: Optional[str] = Field(default=None, min_length=8)
    enabled: Optional[bool] = None


class MappingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    playbook_id: int
    mode: str
    rule_id_pattern: Optional[str] = None
    rule_groups_pattern: Optional[str] = None
    agent_name_pattern: Optional[str] = None
    cooldown_seconds: int
    has_hmac_secret: bool
    enabled: bool
    created_at: datetime
    updated_at: datetime


class IngestResponse(BaseModel):
    status: str
    reason: Optional[str] = None
    mapping_id: Optional[int] = None
    fingerprint: Optional[str] = None
    execution_id: Optional[int] = None
    suggestion_id: Optional[int] = None


class SuggestionOut(BaseModel):
    """List-row shape for an ingest suggestion. Excludes the full alert payload."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    mapping_id: int
    playbook_id: int
    state: str
    fingerprint: str
    rule_id: Optional[str] = None
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    description: Optional[str] = None
    accepted_execution_id: Optional[int] = None
    created_at: datetime
    resolved_at: Optional[datetime] = None


class SuggestionDetail(BaseModel):
    """Detail view: includes the parsed alert payload, mapping, and resolved playbook title."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    mapping_id: int
    playbook_id: int
    state: str
    fingerprint: str
    rule_id: Optional[str] = None
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    description: Optional[str] = None
    accepted_execution_id: Optional[int] = None
    created_at: datetime
    resolved_at: Optional[datetime] = None
    alert_payload: Dict[str, Any] = Field(default_factory=dict)
    mapping: MappingOut
    playbook_title: Optional[str] = None


class SuggestionDismiss(BaseModel):
    """Optional dismissal reason. Not persisted to the database.

    The IngestSuppressionLog row written on dismiss uses a fixed-vocabulary
    reason column (always "suggestion_dismissed"). This free-form text is
    accepted purely so a future audit-log surface can record analyst intent;
    today only the fact that a reason was provided is logged at INFO level.
    """

    model_config = ConfigDict(extra="forbid")

    reason: Optional[str] = Field(default=None, max_length=500)


class SuggestionAcceptResponse(BaseModel):
    """Returned by POST /ingest/suggestions/{id}/accept.

    Wraps the resulting Execution summary along with an idempotency flag so
    callers can tell whether this call created the execution or returned an
    existing one.
    """

    execution: ExecutionSummary
    already_accepted: bool = False


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
