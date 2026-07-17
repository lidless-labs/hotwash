"""Connector contract and registry for live integration actions."""

from __future__ import annotations

import json
from typing import Annotated, Any, Protocol, Type

import requests
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from api.crypto import decrypt_secret
from api.integrations.clients.thehive import TheHiveClient
from api.integrations.clients.wazuh import WazuhClient, WazuhError
from api.integrations.schemas import (
    AddObservableRequest,
    CreateAlertRequest,
    CreateCaseRequest,
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

        raise HTTPException(status_code=404, detail=f"Unknown action: {action_name}")

    def test_connection(self, integration_row: Any) -> dict[str, Any]:
        return self._client(integration_row).status()


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
        api_key_plain = decrypt_secret(integration_row.api_key)
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
            )
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
        api_key_plain = decrypt_secret(integration_row.api_key)
        if api_key_plain:
            session.headers["Authorization"] = f"Bearer {api_key_plain}"
        apply_host_pinning(session, pinned)
        try:
            response = session.get(
                pinned.url,
                timeout=5,
                verify=integration_row.verify_ssl,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            return {"status": "disconnected", "error": str(exc)}
        return {
            "status": "connected" if response.status_code in (200, 401, 403, 404, 405) else "error",
            "status_code": response.status_code,
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

        if action_name == "run_active_response":
            payload = _as(WazuhRunActiveResponseRequest, validated_payload)
            result = client.run_active_response(
                command=payload.command,
                agent_ids=payload.agent_ids,
                arguments=payload.arguments,
                alert=payload.alert,
            )
            return _wazuh_collection_result("affected_agents", result)

        raise HTTPException(status_code=404, detail=f"Unknown action: {action_name}")

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


def _wazuh_collection_result(key: str, result: dict[str, Any]) -> dict[str, Any]:
    return {
        key: _wazuh_affected_items(result),
        "total": _wazuh_total(result),
        "raw": result,
    }


_REGISTRY: dict[str, Connector] = {
    "thehive": TheHiveConnector(),
    "http_webhook": HttpWebhookConnector(),
    "wazuh": WazuhConnector(),
}


def get_connector(tool_name: str) -> Connector | None:
    return _REGISTRY.get(tool_name)


def registered_tool_names() -> list[str]:
    return sorted(_REGISTRY)
