"""Connector contract and registry for live integration actions."""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Annotated, Any, Protocol, Type
from uuid import UUID

import requests
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

logger = logging.getLogger(__name__)


def _allowed_active_response_commands() -> set[str]:
    """Configured allow-list of permitted Wazuh active-response commands.

    Reads ``HOTWASH_WAZUH_AR_COMMANDS`` (comma-separated). An unset or empty
    value yields an empty set, which permits nothing: active response stays
    disabled until an operator names the commands that may be dispatched.
    """
    raw = os.environ.get("HOTWASH_WAZUH_AR_COMMANDS", "").strip()
    return {token.strip() for token in raw.split(",") if token.strip()}


def _enforce_active_response_allowlist(command: str) -> None:
    allowed = _allowed_active_response_commands()
    if not allowed:
        raise HTTPException(
            status_code=403,
            detail=(
                "Wazuh active response is disabled; set HOTWASH_WAZUH_AR_COMMANDS "
                "to the commands that may be dispatched"
            ),
        )
    if command not in allowed:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Active-response command '{command}' is not permitted; "
                "add it to HOTWASH_WAZUH_AR_COMMANDS to allow it"
            ),
        )


def _decrypt_or_fail(encrypted: str | None, label: str) -> str | None:
    """Decrypt a stored secret, distinguishing "none stored" from "cannot decrypt".

    ``decrypt_secret`` returns None for both an absent secret and a corrupt or
    wrong-key ciphertext, so callers that treat None as "no auth" would send a
    request unauthenticated when a stored key simply failed to decrypt. Return
    None only when nothing was stored; raise when a stored secret can't be
    decrypted.
    """
    if not encrypted:
        return None
    plain = decrypt_secret(encrypted)
    if plain is None:
        raise HTTPException(status_code=500, detail=f"Stored {label} could not be decrypted")
    return plain

from api.crypto import decrypt_secret
from api.integrations.clients.bounded import UpstreamResponseTooLarge, read_bounded
from api.integrations.clients.thehive import TheHiveClient, TheHiveError
from api.integrations.clients.wazuh import WazuhClient, WazuhError
from api.integrations.schemas import (
    AddObservableRequest,
    CreateAlertRequest,
    CreateCaseRequest,
    RunAnalyzerRequest,
    GetCaseRequest,
    GetAnalyzerJobRequest,
    ListCasesRequest,
    ListCaseEvidenceRequest,
    THEHIVE_READ_ACTIONS,
)
from api.security import apply_host_pinning, resolve_and_pin_integration_url


class Connector(Protocol):
    """Contract for integrations that expose executable SOAR actions."""

    tool_name: str

    def actions(self) -> dict[str, Type[BaseModel]]:
        """Return action name to request schema mappings."""

    def execute(self, action_name: str, validated_payload: BaseModel, integration_row: Any) -> dict[str, Any]:
        """Execute an action using an already validated request model."""

    def test_connection(self, integration_row: Any) -> dict[str, Any]:
        """Probe the configured integration and return a status payload."""


class TheHiveConnector:
    tool_name = "thehive"

    def actions(self) -> dict[str, Type[BaseModel]]:
        return {
            "create_case": CreateCaseRequest,
            "create_alert": CreateAlertRequest,
            "add_observable": AddObservableRequest,
            "run_analyzer": RunAnalyzerRequest,
            "list_cases": ListCasesRequest,
            "get_case": GetCaseRequest,
            "list_case_observables": ListCaseEvidenceRequest,
            "list_case_comments": ListCaseEvidenceRequest,
            "get_analyzer_job": GetAnalyzerJobRequest,
        }

    def _client(self, integration_row: Any) -> TheHiveClient:
        if not integration_row.base_url:
            raise HTTPException(status_code=400, detail="No base_url configured")
        api_key_plain = decrypt_secret(integration_row.api_key)
        if not api_key_plain:
            raise HTTPException(status_code=400, detail="No API key configured")
        pinned = resolve_and_pin_integration_url(integration_row.base_url)
        return TheHiveClient(
            base_url=integration_row.base_url,
            api_key=api_key_plain,
            verify_ssl=integration_row.verify_ssl,
            pinned=pinned,
        )

    def execute(self, action_name: str, validated_payload: BaseModel, integration_row: Any) -> dict[str, Any]:
        if action_name in THEHIVE_READ_ACTIONS:
            # Also protect callers outside the HTTP dispatcher. Reads never use
            # mock results or attach evidence to an execution.
            if not integration_row.enabled or integration_row.mock_mode:
                raise HTTPException(status_code=400, detail="TheHive reads require an enabled live integration")
            return self._read(action_name, validated_payload, self._client(integration_row))
        client = self._client(integration_row)
        if action_name == "create_case":
            payload = _as(CreateCaseRequest, validated_payload)
            result = client.create_case(
                title=payload.title,
                description=payload.description,
                severity=payload.severity,
                tlp=payload.tlp,
                pap=payload.pap,
                tags=payload.tags,
            )
            case_id = result.get("_id")
            number = result.get("number")
            case_url = (
                f"{integration_row.base_url.rstrip('/')}/cases/{number}/details" if number else None
            )
            return {"case_id": case_id, "number": number, "url": case_url, "raw": result}

        if action_name == "create_alert":
            payload = _as(CreateAlertRequest, validated_payload)
            result = client.create_alert(
                type=payload.type,
                source=payload.source,
                source_ref=payload.source_ref,
                title=payload.title,
                description=payload.description,
                severity=payload.severity,
                tlp=payload.tlp,
                pap=payload.pap,
                observables=payload.observables,
                tags=payload.tags,
            )
            return {"alert_id": result.get("_id"), "raw": result}

        if action_name == "add_observable":
            payload = _as(AddObservableRequest, validated_payload)
            result = client.add_observable(
                case_id=payload.case_id,
                data_type=payload.data_type,
                data=payload.data,
                message=payload.message,
                tlp=payload.tlp,
                ioc=payload.ioc,
                sighted=payload.sighted,
                tags=payload.tags,
            )
            return {"observable_id": result.get("_id"), "raw": result}

        if action_name == "run_analyzer":
            payload = _as(RunAnalyzerRequest, validated_payload)
            result = client.run_analyzer(
                artifact_id=payload.artifact_id,
                analyzer_id=payload.analyzer_id,
                cortex_id=payload.cortex_id,
            )
            return {"job_id": result.get("_id"), "status": result.get("status"), "raw": result}

        raise HTTPException(status_code=404, detail=f"Unknown action: {action_name}")

    def _read(self, action: str, payload: BaseModel, client: TheHiveClient) -> dict[str, Any]:
        gaps: list[str] = []
        result: dict[str, Any] = {
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "coverage": "unverified", "gaps": gaps,
        }
        if action == "get_case":
            request = _as(GetCaseRequest, payload)
            raw = client.get_case(case_id=request.case_id)
            result["case"] = _read_case(raw, gaps)
            if result["case"]["id"] != request.case_id:
                raise TheHiveError("Invalid read identity")
            gaps.extend(["identity_unbound", "visibility_unverified", "link_unavailable"])
        elif action == "get_analyzer_job":
            request = _as(GetAnalyzerJobRequest, payload)
            raw = client.get_analyzer_job(job_id=request.job_id)
            result["job"] = _read_job(raw, gaps)
            if result["job"]["id"] != request.job_id:
                raise TheHiveError("Invalid read identity")
            gaps.extend(["job_association_unverified", "link_unavailable"])
        else:
            request = _as(ListCasesRequest, payload)
            if action == "list_cases":
                raw = client.list_cases(offset=request.offset, limit=request.limit)
                project = _read_case
            else:
                request = _as(ListCaseEvidenceRequest, payload)
                result["case_id"] = request.case_id
                if action == "list_case_observables":
                    raw = client.list_case_observables(**request.model_dump())
                    project = _read_observable
                else:
                    raw = client.list_case_comments(**request.model_dump())
                    project = _read_comment
            if not isinstance(raw, list) or len(raw) > request.limit + 1:
                raise TheHiveError("Invalid read page")
            ids = [_read_id(row) for row in raw]
            if len(set(ids)) != len(ids):
                raise TheHiveError("Duplicate read identities")
            items = []
            for row in raw[:request.limit]:
                item = project(row, gaps)
                if item is not None:
                    items.append(item)
            more = len(raw) > request.limit
            result.update(items=items, returned=len(items), scanned=min(len(raw), request.limit),
                          offset=request.offset, limit=request.limit, has_more=more, overflow=more)
            gaps.extend(["query_contract_unverified", "visibility_unverified", "identity_unbound"])
            if more:
                gaps.append("overflow")
        result["gaps"] = sorted(set(gaps))
        return result

    def test_connection(self, integration_row: Any) -> dict[str, Any]:
        return self._client(integration_row).status()


def _read_id(raw: Any) -> str:
    if not isinstance(raw, dict):
        raise TheHiveError("Invalid read object")
    value = raw.get("_id")
    if not isinstance(value, str) or len(value) > 128 or not re.fullmatch(r"~[A-Za-z0-9]+", value):
        raise TheHiveError("Invalid read identity")
    if "id" in raw and raw["id"] != value:
        raise TheHiveError("Conflicting read identities")
    return value


def _read_text(value: Any, gaps: list[str], *, maximum: int = 128) -> str | None:
    if not isinstance(value, str):
        gaps.append("missing_or_invalid_field")
        return None
    if len(value) > maximum:
        gaps.append("source_text_truncated")
        return value[:maximum]
    return value


def _read_dates(raw: dict[str, Any], gaps: list[str]) -> dict[str, int]:
    dates = {}
    for key in ("_createdAt", "_updatedAt", "createdAt", "updatedAt", "startDate", "endDate"):
        if key in raw:
            value = raw[key]
            if type(value) is int and 0 <= value <= 9007199254740991:
                dates[key] = value
            else:
                gaps.append("invalid_date")
    return dates


def _read_case(raw: Any, gaps: list[str]) -> dict[str, Any]:
    result = {"id": _read_id(raw), "status": _read_text(raw.get("status"), gaps),
              "dates": _read_dates(raw, gaps)}
    for key in ("stage", "title"):
        if key in raw:
            result[key] = _read_text(raw[key], gaps, maximum=512)
    if type(raw.get("number")) is int and 0 < raw["number"] <= 9007199254740991:
        result["number"] = raw["number"]
    tags = raw.get("tags", [])
    if isinstance(tags, list):
        result["tags"] = [_read_text(tag, gaps) for tag in tags[:32]]
        if len(tags) > 32:
            gaps.append("tags_truncated")
    else:
        gaps.append("invalid_tags")
    return result


def _read_observable(raw: Any, gaps: list[str]) -> dict[str, Any] | None:
    identifier = _read_id(raw)
    data_type, data = raw.get("dataType"), raw.get("data")
    if data_type == "hash" and isinstance(data, str) and len(data) in (32, 40, 64, 128) and re.fullmatch(r"[a-fA-F0-9]+", data):
        data = data.lower()
    elif data_type == "filename" and isinstance(data, str) and 0 < len(data) <= 2000 and not re.search(r"[\x00-\x1f\x7f]", data):
        pass  # A path is data only. It is never resolved, opened or fetched.
    else:
        gaps.append("unsupported_observable")
        return None
    tlp = raw.get("tlp")
    if type(tlp) is not int or not 0 <= tlp <= 3:
        gaps.append("invalid_tlp")
        tlp = None
    return {"id": identifier, "data_type": data_type, "data": data, "tlp": tlp,
            "dates": _read_dates(raw, gaps)}


def _read_comment(raw: Any, gaps: list[str]) -> dict[str, Any] | None:
    identifier = _read_id(raw)
    if raw.get("external") is not False:
        gaps.append("non_internal_comment_omitted")
        return None
    return {"id": identifier, "external": False,
            "message": _read_text(raw.get("message"), gaps, maximum=2000),
            "dates": _read_dates(raw, gaps)}


def _read_job(raw: Any, gaps: list[str]) -> dict[str, Any]:
    result = {"id": _read_id(raw), "status": _read_text(raw.get("status"), gaps),
              "dates": _read_dates(raw, gaps)}
    for key in ("analyzerId", "analyzerName", "analyzerDefinition"):
        if key in raw:
            result[key] = _read_text(raw[key], gaps)
    evidence: dict[str, Any] = {"verdict": "unknown"}
    result["report"] = evidence
    # Definition is the exact approved name/version, never a guessed worker id.
    definition = raw.get("analyzerDefinition")
    if definition not in ("CIRCLHashlookup_1_1", "MISP_2_1"):
        gaps.append("unsupported_analyzer_report")
        return result
    report = raw.get("report")
    if not isinstance(report, dict):
        gaps.append("report_missing")
        return result
    summary = report.get("summary")
    taxonomies = summary.get("taxonomies") if isinstance(summary, dict) else None
    if isinstance(taxonomies, list):
        evidence["taxonomies"] = []
        for taxonomy in taxonomies[:20]:
            if not isinstance(taxonomy, dict):
                gaps.append("invalid_taxonomy")
                continue
            evidence["taxonomies"].append({key: _read_text(taxonomy.get(key), gaps, maximum=256)
                                          for key in ("namespace", "predicate", "value", "level")})
        if len(taxonomies) > 20:
            gaps.append("taxonomies_truncated")
    else:
        gaps.append("taxonomies_missing")
    full = report.get("full")
    if not isinstance(full, dict):
        gaps.append("unsupported_report_shape")
        return result
    if definition == "CIRCLHashlookup_1_1":
        trust = full.get("hashlookup:trust")
        if type(trust) is int and 0 <= trust <= 100:
            evidence["circl_trust"] = trust
        else:
            gaps.append("circl_trust_missing_or_invalid")
    else:
        results = full.get("results")
        if not isinstance(results, list):
            gaps.append("unsupported_report_shape")
            return result
        events: set[str] = set()
        complete = True
        if len(results) > 20:
            gaps.append("misp_results_truncated")
            complete = False
        for source in results[:20]:
            rows = source.get("result") if isinstance(source, dict) else None
            if not isinstance(rows, list):
                gaps.append("unsupported_misp_result")
                complete = False
                continue
            if len(rows) > 100:
                gaps.append("misp_events_truncated")
                complete = False
            for row in rows[:100]:
                try:
                    value = row.get("uuid") if isinstance(row, dict) else None
                    if not isinstance(value, str) or len(value) != 36:
                        raise ValueError()
                    events.add(str(UUID(value)))
                except ValueError:
                    gaps.append("invalid_misp_event")
                    complete = False
        evidence["misp_event_uuids"] = sorted(events)[:100]
        if len(events) > 100:
            gaps.append("misp_events_truncated")
            complete = False
        evidence["misp_event_count"] = len(events) if complete else None
        evidence["misp_returned_event_count"] = len(evidence["misp_event_uuids"])
        if not events:
            gaps.append("lookup_miss_not_clean")
    if raw.get("status") != "Success":
        gaps.append("job_not_successful")
    gaps.append("upstream_claims_not_verdict")
    return result


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class WazuhGetAgentsRequest(_Strict):
    status: str | None = Field(default=None, max_length=64)
    search: str | None = Field(default=None, max_length=256)
    limit: int | None = Field(default=None, ge=1)
    select: str | None = Field(default=None, max_length=512)


class WazuhGetAgentRequest(_Strict):
    agent_id: str = Field(pattern=r"^\d+$", max_length=32)


WazuhAgentId = Annotated[str, Field(pattern=r"^[0-9]+$", max_length=32)]
WazuhActiveResponseArgument = Annotated[str, Field(max_length=1024)]
MAX_WAZUH_ACTIVE_RESPONSE_ALERT_BYTES = 64 * 1024


class WazuhRunActiveResponseRequest(_Strict):
    command: str = Field(min_length=1, max_length=256)
    agent_ids: list[WazuhAgentId] = Field(min_length=1, max_length=100)
    arguments: list[WazuhActiveResponseArgument] = Field(default_factory=list, max_length=32)
    alert: dict[str, Any] = Field(default_factory=dict)
    # Endpoint-affecting: the caller must opt in explicitly on every request.
    confirm: StrictBool
    # Validate the request and report what would run without contacting Wazuh.
    dry_run: bool = False

    @field_validator("confirm")
    @classmethod
    def _require_confirm(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("confirm must be true to run an active response")
        return value

    @field_validator("alert")
    @classmethod
    def _validate_alert_size(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("alert must be JSON serializable") from exc
        if len(encoded) > MAX_WAZUH_ACTIVE_RESPONSE_ALERT_BYTES:
            raise ValueError("alert must not exceed 65536 encoded bytes")
        return value


class HttpWebhookPostJsonRequest(_Strict):
    path: str | None = Field(default=None, max_length=2048)
    body: Any = Field(default_factory=dict)


class HttpWebhookConnector:
    tool_name = "http_webhook"

    def actions(self) -> dict[str, Type[BaseModel]]:
        return {"post_json": HttpWebhookPostJsonRequest}

    def execute(self, action_name: str, validated_payload: BaseModel, integration_row: Any) -> dict[str, Any]:
        if action_name != "post_json":
            raise HTTPException(status_code=404, detail=f"Unknown action: {action_name}")
        if not integration_row.base_url:
            raise HTTPException(status_code=400, detail="No base_url configured")

        payload = _as(HttpWebhookPostJsonRequest, validated_payload)
        target_url = _join_url_path(integration_row.base_url, payload.path)
        pinned = resolve_and_pin_integration_url(target_url)

        session = requests.Session()
        session.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
        api_key_plain = _decrypt_or_fail(integration_row.api_key, "webhook credential")
        if api_key_plain:
            session.headers["Authorization"] = f"Bearer {api_key_plain}"
        apply_host_pinning(session, pinned)

        try:
            response = session.post(
                pinned.url,
                json=payload.body,
                timeout=10.0,
                verify=integration_row.verify_ssl,
                allow_redirects=False,
                stream=True,
            )
            read_bounded(response)
        except UpstreamResponseTooLarge as exc:
            raise HTTPException(
                status_code=502,
                detail={"message": "HTTP webhook response exceeded the size limit"},
            ) from exc
        except requests.RequestException as exc:
            raise HTTPException(
                status_code=502,
                detail={"message": f"HTTP webhook request failed: {exc}"},
            ) from exc

        return {"status_code": response.status_code, "body": _response_body(response)}

    def test_connection(self, integration_row: Any) -> dict[str, Any]:
        if not integration_row.base_url:
            raise HTTPException(status_code=400, detail="No base_url configured")
        pinned = resolve_and_pin_integration_url(integration_row.base_url)
        session = requests.Session()
        api_key_plain = _decrypt_or_fail(integration_row.api_key, "webhook credential")
        if api_key_plain:
            session.headers["Authorization"] = f"Bearer {api_key_plain}"
        apply_host_pinning(session, pinned)
        try:
            response = session.get(
                pinned.url,
                timeout=5,
                verify=integration_row.verify_ssl,
                allow_redirects=False,
                stream=True,
            )
            # Only the status code is used; drop the body without buffering it.
            response.close()
        except requests.RequestException as exc:
            return {"status": "disconnected", "error": str(exc)}
        return {
            "status": "connected" if response.status_code in (200, 401, 403, 404, 405) else "error",
            "status_code": response.status_code,
        }


def preflight_active_response(
    validated_payload: BaseModel, *, enforce_policy: bool = True
) -> dict[str, Any] | None:
    """Apply the active-response policy; return the dry-run report when requested.

    Raises 403/422 for a disabled or disallowed command when ``enforce_policy``
    is set. Wazuh has no dry-run mode for active response, so a dry run stops
    before any upstream call and reports the request that would be sent. The
    mock-mode dispatcher passes ``enforce_policy=False``: mock mode never reaches
    a manager, so it needs no allow-list, but a dry run still reports the request.
    """
    payload = _as(WazuhRunActiveResponseRequest, validated_payload)
    if enforce_policy:
        _enforce_active_response_allowlist(payload.command)
    if not payload.dry_run:
        return None
    return {
        "dry_run": True,
        "would_run": {
            "command": payload.command,
            "agent_ids": payload.agent_ids,
            "arguments": payload.arguments,
            "alert": payload.alert,
        },
    }


class WazuhConnector:
    tool_name = "wazuh"

    def actions(self) -> dict[str, Type[BaseModel]]:
        return {
            "get_agents": WazuhGetAgentsRequest,
            "get_agent": WazuhGetAgentRequest,
            "run_active_response": WazuhRunActiveResponseRequest,
        }

    def _client(self, integration_row: Any) -> WazuhClient:
        if not integration_row.base_url:
            raise HTTPException(status_code=400, detail="No base_url configured")
        if not integration_row.username:
            raise HTTPException(status_code=400, detail="No username configured")
        password_plain = decrypt_secret(integration_row.password)
        if not password_plain:
            raise HTTPException(status_code=400, detail="No password configured")
        pinned = resolve_and_pin_integration_url(integration_row.base_url)
        return WazuhClient(
            base_url=integration_row.base_url,
            username=integration_row.username,
            password=password_plain,
            verify_ssl=integration_row.verify_ssl,
            pinned=pinned,
        )

    def execute(self, action_name: str, validated_payload: BaseModel, integration_row: Any) -> dict[str, Any]:
        if action_name == "run_active_response":
            return self._run_active_response(validated_payload, integration_row)

        client = self._client(integration_row)
        if action_name == "get_agents":
            payload = _as(WazuhGetAgentsRequest, validated_payload)
            result = client.list_agents(
                status=payload.status,
                search=payload.search,
                limit=payload.limit,
                select=payload.select,
            )
            return _wazuh_collection_result("agents", result)

        if action_name == "get_agent":
            payload = _as(WazuhGetAgentRequest, validated_payload)
            result = client.get_agent(payload.agent_id)
            items = _wazuh_affected_items(result)
            return {"agent": items[0] if items else None, "raw": result}

        raise HTTPException(status_code=404, detail=f"Unknown action: {action_name}")

    def _run_active_response(self, validated_payload: BaseModel, integration_row: Any) -> dict[str, Any]:
        dry_run = preflight_active_response(validated_payload)
        if dry_run is not None:
            return dry_run
        payload = _as(WazuhRunActiveResponseRequest, validated_payload)
        client = self._client(integration_row)
        result = client.run_active_response(
            command=payload.command,
            agent_ids=payload.agent_ids,
            arguments=payload.arguments,
            alert=payload.alert,
        )
        return _wazuh_collection_result("affected_agents", result)

    def test_connection(self, integration_row: Any) -> dict[str, Any]:
        info = self._client(integration_row).api_info()
        if not isinstance(info, dict):
            raise WazuhError(
                "Wazuh API info response must be a JSON object",
                details={"response_type": type(info).__name__},
            )
        # Wazuh 4.x wraps the payload in a "data" envelope.
        meta = info.get("data") if isinstance(info.get("data"), dict) else info
        return {
            "status": "connected",
            "title": meta.get("title"),
            "api_version": meta.get("api_version"),
            "raw": info,
        }


def _as(schema: Type[BaseModel], payload: BaseModel) -> Any:
    if isinstance(payload, schema):
        return payload
    return schema.model_validate(payload)


def _join_url_path(base_url: str, path: str | None) -> str:
    if not path:
        return base_url
    stripped = path.strip()
    if stripped.startswith(("http://", "https://", "//")):
        raise HTTPException(status_code=422, detail="Webhook path must be relative")
    # Reject parent-directory traversal and ambiguous encoded separators so a
    # downstream decoder cannot turn a safe-looking relative path into `..`.
    lowered = stripped.lower()
    encoded_traversal_tokens = ("%2e", "%2f", "%5c", "%25")
    if (
        ".." in stripped.split("/")
        or "\\" in stripped
        or any(token in lowered for token in encoded_traversal_tokens)
    ):
        raise HTTPException(status_code=422, detail="Webhook path must not contain traversal segments")
    return f"{base_url.rstrip('/')}/{stripped.lstrip('/')}"


def _response_body(response: requests.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return response.text[:4096]


def _wazuh_affected_items(result: dict[str, Any]) -> list[Any]:
    data = result.get("data") if isinstance(result, dict) else None
    if not isinstance(data, dict):
        return []
    items = data.get("affected_items")
    return items if isinstance(items, list) else []


def _wazuh_total(result: dict[str, Any]) -> int:
    data = result.get("data") if isinstance(result, dict) else None
    if not isinstance(data, dict):
        return 0
    total = data.get("total_affected_items")
    return total if isinstance(total, int) else len(_wazuh_affected_items(result))


def _wazuh_failed_items(result: dict[str, Any]) -> list[Any]:
    data = result.get("data") if isinstance(result, dict) else None
    if not isinstance(data, dict):
        return []
    items = data.get("failed_items")
    return items if isinstance(items, list) else []


def _wazuh_total_failed(result: dict[str, Any]) -> int:
    data = result.get("data") if isinstance(result, dict) else None
    if not isinstance(data, dict):
        return 0
    total = data.get("total_failed_items")
    return total if isinstance(total, int) else len(_wazuh_failed_items(result))


def _wazuh_collection_result(key: str, result: dict[str, Any]) -> dict[str, Any]:
    # Wazuh returns HTTP 200 for active-response even when it failed on some
    # agents, reporting them under failed_items. Surface that so a failed
    # response is not stored as a successful action (silent partial failure).
    out: dict[str, Any] = {
        key: _wazuh_affected_items(result),
        "total": _wazuh_total(result),
        "raw": result,
    }
    failed = _wazuh_failed_items(result)
    total_failed = _wazuh_total_failed(result)
    if failed or total_failed:
        out["failed"] = failed
        out["total_failed"] = total_failed
    return out


_REGISTRY: dict[str, Connector] = {
    "thehive": TheHiveConnector(),
    "http_webhook": HttpWebhookConnector(),
    "wazuh": WazuhConnector(),
}


def get_connector(tool_name: str) -> Connector | None:
    return _REGISTRY.get(tool_name)


def registered_tool_names() -> list[str]:
    return sorted(_REGISTRY)
