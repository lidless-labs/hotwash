"""
Pydantic schemas for Playbook Forge CRUD API.
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
    generator: str = "Playbook Forge"


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
    tags: Optional[List[str]] = None


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
