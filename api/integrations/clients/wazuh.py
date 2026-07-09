"""Wazuh 4.x manager API HTTP client."""

from __future__ import annotations

from typing import Any

import requests

from api.security import PinnedURL, apply_host_pinning


class WazuhError(Exception):
    """Raised when Wazuh returns an error or the request fails."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.details = details or {}


class WazuhClient:
    """Minimal client for the Wazuh 4.x manager API."""

    def __init__(
        self,
        *,
        base_url: str,
        username: str,
        password: str,
        verify_ssl: bool = True,
        timeout: float = 10.0,
        pinned: PinnedURL | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self._password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._jwt: str | None = None
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )
        self._request_base = self.base_url
        if pinned is not None:
            self._request_base = pinned.url.rstrip("/")
            apply_host_pinning(self._session, pinned)

    def _sanitize_value(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                self._sanitize_value(key): self._sanitize_value(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self._sanitize_value(item) for item in value]
        if isinstance(value, str):
            sanitized = value
            for secret in (self._password, self._jwt):
                if secret:
                    sanitized = sanitized.replace(secret, "[redacted]")
            return sanitized
        return value

    def _error_from_response(self, response: requests.Response, fallback: str) -> WazuhError:
        try:
            body = response.json()
        except ValueError:
            body = {"text": response.text[:500]}
        details = self._sanitize_value(body)
        message = fallback
        if isinstance(details, dict):
            title = details.get("title") or details.get("error")
            detail = details.get("detail") or details.get("message")
            parts = [str(item) for item in (title, detail) if item]
            if parts:
                message = ": ".join(parts)
        return WazuhError(
            self._sanitize_value(message),
            status_code=response.status_code,
            details=details if isinstance(details, dict) else {"body": details},
        )

    def _authenticate(self) -> str:
        url = f"{self._request_base}/security/user/authenticate"
        try:
            response = self._session.request(
                "POST",
                url,
                params={"raw": "true"},
                auth=(self.username, self._password),
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise WazuhError(
                f"Wazuh authentication request failed: {self._sanitize_value(str(exc))}",
                status_code=None,
                details={"upstream": "connection_error"},
            ) from exc

        if not response.ok:
            raise self._error_from_response(response, "Wazuh authentication failed")

        token = response.text.strip().strip('"')
        if not token:
            raise WazuhError(
                "Wazuh authentication returned an empty token",
                status_code=response.status_code,
                details={},
            )
        self._jwt = token
        return token

    def _authenticated_request(
        self,
        method: str,
        path: str,
        *,
        json: Any | None = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        if not self._jwt:
            self._authenticate()
        try:
            return self._request(method, path, json=json, params=params)
        except WazuhError as exc:
            if exc.status_code != 401:
                raise
        self._jwt = None
        self._authenticate()
        return self._request(method, path, json=json, params=params)

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any | None = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        url = f"{self._request_base}{path}"
        headers = {"Authorization": f"Bearer {self._jwt}"}
        try:
            response = self._session.request(
                method,
                url,
                json=json,
                params=params,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise WazuhError(
                f"Wazuh request failed: {self._sanitize_value(str(exc))}",
                status_code=None,
                details={"upstream": "connection_error"},
            ) from exc

        if not response.ok:
            raise self._error_from_response(response, f"Wazuh returned {response.status_code}")

        try:
            return response.json()
        except ValueError as exc:
            raise WazuhError(
                "Wazuh returned non-JSON response",
                status_code=response.status_code,
                details={"text": self._sanitize_value(response.text[:500])},
            ) from exc

    def api_info(self) -> dict[str, Any]:
        return self._authenticated_request("GET", "/")

    def list_agents(
        self,
        *,
        status: str | None = None,
        search: str | None = None,
        limit: int | None = None,
        select: str | None = None,
    ) -> dict[str, Any]:
        params = {
            key: value
            for key, value in {
                "status": status,
                "search": search,
                "limit": limit,
                "select": select,
            }.items()
            if value is not None
        }
        return self._authenticated_request("GET", "/agents", params=params)

    def get_agent(self, agent_id: str) -> dict[str, Any]:
        return self._authenticated_request("GET", "/agents", params={"agents_list": agent_id})

    def run_active_response(
        self,
        *,
        command: str,
        agent_ids: list[str],
        arguments: list[str] | None = None,
        alert: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = {
            "command": command,
            "arguments": arguments or [],
            "alert": alert or {},
        }
        return self._authenticated_request(
            "PUT",
            "/active-response",
            params={"agents_list": ",".join(agent_ids)},
            json=payload,
        )
