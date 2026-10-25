"""Pydantic request schemas for integration action endpoints."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class CreateCaseRequest(_Strict):
    title: str = Field(..., min_length=1, max_length=512)
    description: str = Field(..., min_length=1)
    severity: int = Field(default=2, ge=1, le=4)
    tlp: int = Field(default=2, ge=0, le=3)
    pap: int = Field(default=2, ge=0, le=3)
    tags: list[str] = Field(default_factory=list)


class CreateAlertRequest(_Strict):
    type: str = Field(..., min_length=1, max_length=128)
    source: str = Field(..., min_length=1, max_length=128)
    source_ref: str = Field(..., min_length=1, max_length=256)
    title: str = Field(..., min_length=1, max_length=512)
    description: str = Field(..., min_length=1)
    severity: int = Field(default=2, ge=1, le=4)
    tlp: int = Field(default=2, ge=0, le=3)
    pap: int = Field(default=2, ge=0, le=3)
    observables: list[dict[str, Any]] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class AddObservableRequest(_Strict):
    case_id: str = Field(..., pattern=r"^~[A-Za-z0-9]+$", max_length=128)
    data_type: str = Field(..., min_length=1, max_length=64)
    data: str = Field(..., min_length=1)
    message: str | None = None
    tlp: int = Field(default=2, ge=0, le=3)
    ioc: bool = False
    sighted: bool = False
    tags: list[str] = Field(default_factory=list)


class RunAnalyzerRequest(_Strict):
    """Launch a Cortex analyzer on an existing TheHive observable.

    All three ids are sent in the JSON body, not the URL path, but they are
    still validated strictly so a caller cannot smuggle path segments,
    whitespace, or query strings into a value that reaches the upstream API.
    """

    artifact_id: str = Field(..., pattern=r"^~[A-Za-z0-9]+$", max_length=128)
    analyzer_id: str = Field(..., pattern=r"^[A-Za-z0-9_-]+$", max_length=128)
    cortex_id: str = Field(default="cortex0", pattern=r"^[A-Za-z0-9_-]+$", max_length=64)


# Read IDs deliberately do not inherit whitespace stripping from write schemas.
TheHiveReadId = Annotated[str, Field(pattern=r"^~[A-Za-z0-9]+$", max_length=128)]


class TheHiveReadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ListCasesRequest(TheHiveReadRequest):
    offset: int = Field(default=0, ge=0, le=10000)
    limit: int = Field(default=50, ge=1, le=100)


class GetCaseRequest(TheHiveReadRequest):
    case_id: TheHiveReadId


class ListCaseEvidenceRequest(ListCasesRequest):
    case_id: TheHiveReadId


class GetAnalyzerJobRequest(TheHiveReadRequest):
    job_id: TheHiveReadId


THEHIVE_READ_ACTIONS = frozenset({
    "list_cases", "get_case", "list_case_observables", "list_case_comments", "get_analyzer_job",
})
