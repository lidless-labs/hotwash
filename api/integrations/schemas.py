"""Pydantic request schemas for integration action endpoints."""

from __future__ import annotations

import unicodedata
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


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


# A candidate association is deliberately separate from authenticated provenance.
FindingId = Annotated[str, Field(strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$", max_length=128)]
FindingRunId = Annotated[int, Field(strict=True, gt=0, le=9223372036854775807)]


class FindingCandidate(TheHiveReadRequest):
    source: Literal["wazuh"]
    source_instance_ref: FindingId
    asset_id: FindingId
    rule_id: FindingId
    sha256: str = Field(strict=True, pattern=r"^[A-Fa-f0-9]{64}$", min_length=64, max_length=64)

    @field_validator("sha256")
    @classmethod
    def lowercase_hash(cls, value: str) -> str:
        return value.lower()


class FindingCheckRequest(FindingCandidate):
    run_id: FindingRunId | None = None


FindingGap = Literal[
    "source_binding_unverified", "visibility_unverified", "query_contract_unverified",
    "cases_capped", "case_record_invalid", "case_identity_unmapped", "case_identity_invalid",
    "case_identity_conflict", "case_lifecycle_unknown", "case_lifecycle_conflict",
    "runs_capped", "run_context_invalid", "run_context_oversized", "run_identity_unmapped",
    "run_case_link_missing", "run_case_link_unresolved", "run_case_link_conflict", "run_attempt_state_unverified",
]


class FindingCaseMatch(TheHiveReadRequest):
    case_id: TheHiveReadId
    lifecycle: Literal["open", "closed", "unknown"]
    identity_basis: Literal["fingerprint_tag_v1"] = "fingerprint_tag_v1"


class FindingRunMatch(TheHiveReadRequest):
    run_id: FindingRunId
    case_id: TheHiveReadId | None
    identity_basis: Literal["untrusted_context_v1"] = "untrusted_context_v1"
    attempt_state: None = None


class FindingCoverage(TheHiveReadRequest):
    cases: Literal["complete", "incomplete", "unverified"]
    runs: Literal["complete", "incomplete", "unverified"]
    visibility: Literal["unverified"] = "unverified"
    observed_at: datetime
    contract_version: Literal[1] = 1


class FindingCheckResponse(TheHiveReadRequest):
    schema_version: Literal[1] = 1
    fingerprint: str = Field(pattern=r"^v1:[a-f0-9]{64}$")
    candidate: FindingCandidate
    identity_binding: Literal["unverified"] = "unverified"
    case_matches: list[FindingCaseMatch] = Field(max_length=100)
    run_matches: list[FindingRunMatch] = Field(max_length=100)
    coverage: FindingCoverage
    disposition: Literal["no_match_visible", "one_open_candidate", "closed_only", "ambiguous", "blocked"]
    gaps: list[FindingGap] = Field(max_length=18)


ROOTCHECK_GROUP = "/dev/.lxc/proc"


def validate_rootcheck_path(value: str) -> str:
    """Validate a literal descendant, without normalizing its identity."""
    if (len(value) > 2000 or not value.startswith(ROOTCHECK_GROUP + "/")
            or any(unicodedata.category(c).startswith("C") or c in "\\'" for c in value)
            or any(part in {"", ".", ".."} for part in value[len(ROOTCHECK_GROUP) + 1:].split("/"))):
        raise ValueError("Invalid literal rootcheck path")
    return value


class RootcheckCandidate(TheHiveReadRequest):
    source: Literal["wazuh"]
    source_instance_ref: FindingId
    agent_registration_ref: FindingId
    agent_id: str = Field(strict=True, pattern=r"^[0-9]{1,128}$", max_length=128)
    signature: Literal["hidden-file-on-dev-v1"]
    scope: Literal["group", "path"]
    subject: str = Field(strict=True, max_length=2000)

    @field_validator("subject")
    @classmethod
    def literal_subject(cls, value: str, info) -> str:
        if info.data.get("scope") == "group":
            if value != ROOTCHECK_GROUP:
                raise ValueError("Invalid rootcheck group")
            return value
        return validate_rootcheck_path(value)


class RootcheckCheckRequest(RootcheckCandidate):
    run_id: FindingRunId | None = None


class RootcheckCaseMatch(FindingCaseMatch):
    identity_basis: Literal["candidate_tag_v2"] = "candidate_tag_v2"


class RootcheckRunMatch(FindingRunMatch):
    identity_basis: Literal["untrusted_context_v2"] = "untrusted_context_v2"


class RootcheckCoverage(FindingCoverage):
    contract_version: Literal[2] = 2


class RootcheckCheckResponse(TheHiveReadRequest):
    schema_version: Literal[2] = 2
    candidate_key: str = Field(pattern=r"^v2:[a-f0-9]{64}$")
    candidate: RootcheckCandidate
    identity_binding: Literal["unverified"] = "unverified"
    case_matches: list[RootcheckCaseMatch] = Field(max_length=100)
    run_matches: list[RootcheckRunMatch] = Field(max_length=100)
    coverage: RootcheckCoverage
    disposition: Literal["no_match_visible", "one_open_candidate", "closed_only", "ambiguous", "blocked"]
    gaps: list[FindingGap] = Field(max_length=18)


class _ReceiptStrict(TheHiveReadRequest):
    model_config = ConfigDict(extra="forbid", strict=True)


class _RootcheckReceiptRequest(_ReceiptStrict):
    agent_id: str = Field(pattern=r"^[0-9]{1,128}$", max_length=128)
    status: str = Field(min_length=1, max_length=128)
    limit: int = Field(ge=1, le=100)


class _RootcheckReceiptPagination(_ReceiptStrict):
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)
    has_more: bool


class RootcheckReceiptRow(_ReceiptStrict):
    receipt_index: int = Field(ge=0, le=99)
    source_record_id: None = None
    status: str = Field(min_length=1, max_length=128)
    path: str = Field(max_length=2000)
    date_first: str = Field(min_length=1, max_length=128)
    date_last: str = Field(min_length=1, max_length=128)


class _RootcheckReceiptInputRow(_ReceiptStrict):
    receipt_index: int = Field(ge=0, le=99)
    source_record_id: None
    status: str = Field(min_length=1, max_length=128)
    source_signature_log: str
    proc_paths: list[str] = Field(max_length=100)
    date_first: str = Field(min_length=1, max_length=128)
    date_last: str = Field(min_length=1, max_length=128)


class _RootcheckReceiptInput(_ReceiptStrict):
    mode: Literal["historical_cached_receipt_recovery"]
    recovered_at: str = Field(min_length=1, max_length=128)
    source_session: str = Field(min_length=1, max_length=256)
    cache_offset: int = Field(ge=0)
    tool_name: str = Field(min_length=1, max_length=256)
    tool_call_id: str = Field(min_length=1, max_length=256)
    request: _RootcheckReceiptRequest
    request_observed_at: str = Field(min_length=1, max_length=128)
    result_observed_at: str = Field(min_length=1, max_length=128)
    result_is_error: bool
    total: int = Field(ge=0)
    returned: int = Field(ge=0)
    proc_path_records: int = Field(ge=0)
    other_records: int = Field(ge=0)
    pagination: _RootcheckReceiptPagination
    output_metadata: dict[str, str]
    source_payload_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    records: list[_RootcheckReceiptInputRow] = Field(max_length=100)
    exact_proc_paths: list[str] = Field(max_length=100)
    limits: list[str]
    new_soc_calls: Literal[0]


class RootcheckReceiptProjection(TheHiveReadRequest):
    schema_version: Literal[2] = 2
    disposition: Literal["projected", "receipt_invalid", "receipt_capped", "receipt_inconsistent"]
    provenance: Literal["historical_cached_receipt_recovery"] = "historical_cached_receipt_recovery"
    source_binding: Literal["unverified"] = "unverified"
    gaps: tuple[Literal["source_binding_unverified"], Literal["visibility_unverified"],
                Literal["query_contract_unverified"]] = (
                    "source_binding_unverified", "visibility_unverified", "query_contract_unverified",
                )
    source_session: str | None = None
    cache_offset: int | None = None
    tool_name: str | None = None
    tool_call_id: str | None = None
    request: _RootcheckReceiptRequest | None = None
    request_observed_at: str | None = None
    result_observed_at: str | None = None
    recovered_at: str | None = None
    result_is_error: bool | None = None
    total: int | None = None
    returned: int | None = None
    pagination: _RootcheckReceiptPagination | None = None
    source_payload_sha256: str | None = None
    rows: list[RootcheckReceiptRow] = Field(default_factory=list, max_length=100)
    exact_proc_paths: list[str] = Field(default_factory=list, max_length=100)
    other_records: int = Field(default=0, ge=0, le=100)
    other_receipt_indexes: list[int] = Field(default_factory=list, max_length=100)
