"""TheHive 5.x HTTP client.

Tested against TheHive 5.4. Uses /api/v1 endpoints with Bearer auth.
"""

from __future__ import annotations

import logging
from typing import Any

import requests

logger = logging.getLogger(__name__)


class TheHiveError(Exception):
    """Raised when TheHive returns an error or the request fails."""

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


class TheHiveClient:
    """Minimal client for TheHive 5.x /api/v1 endpoints."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        verify_ssl: bool = True,
        timeout: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any | None = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        url = f"{self.base_url}{path}"
        try:
            resp = self._session.request(
                method,
                url,
                json=json,
                params=params,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
        except requests.RequestException as exc:
            raise TheHiveError(
                f"TheHive request failed: {exc}",
                status_code=None,
                details={"upstream": "connection_error"},
            ) from exc

        if resp.status_code == 401:
            try:
                body = resp.json()
            except ValueError:
                body = {}
            raise TheHiveError(
                "Invalid API key for TheHive",
                status_code=401,
                details=body,
            )

        if not resp.ok:
            try:
                body = resp.json()
            except ValueError:
                body = {"text": resp.text[:500]}
            raise TheHiveError(
                f"TheHive returned {resp.status_code}",
                status_code=resp.status_code,
                details=body,
            )

        try:
            return resp.json()
        except ValueError as exc:
            raise TheHiveError(
                "TheHive returned non-JSON response",
                status_code=resp.status_code,
                details={"text": resp.text[:500]},
            ) from exc

    def status(self) -> dict[str, Any]:
        """Return {status, version, user, stats}.

        Calls /api/v1/user/current (requires auth) and /api/v1/status (public on TheHive 5).
        Raises TheHiveError on auth failure or connection issues.
        """
        user = self._request("GET", "/api/v1/user/current")
        try:
            status_info = self._request("GET", "/api/v1/status")
        except TheHiveError:
            status_info = {}

        version = "unknown"
        versions = status_info.get("versions") if isinstance(status_info, dict) else None
        if isinstance(versions, dict):
            version = versions.get("TheHive") or versions.get("thehive") or "unknown"

        return {
            "status": "connected",
            "version": version,
            "user": user.get("login") or user.get("name") or "unknown",
            "stats": {},
        }

    def create_case(
        self,
        *,
        title: str,
        description: str,
        severity: int = 2,
        tlp: int = 2,
        pap: int = 2,
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "title": title,
            "description": description,
            "severity": severity,
            "tlp": tlp,
            "pap": pap,
        }
        if tags:
            payload["tags"] = tags
        return self._request("POST", "/api/v1/case", json=payload)

    def create_alert(
        self,
        *,
        type: str,
        source: str,
        source_ref: str,
        title: str,
        description: str,
        severity: int = 2,
        tlp: int = 2,
        pap: int = 2,
        observables: list[dict[str, Any]] | None = None,
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "type": type,
            "source": source,
            "sourceRef": source_ref,
            "title": title,
            "description": description,
            "severity": severity,
            "tlp": tlp,
            "pap": pap,
        }
        if observables:
            payload["observables"] = observables
        if tags:
            payload["tags"] = tags
        return self._request("POST", "/api/v1/alert", json=payload)

    def add_observable(
        self,
        *,
        case_id: str,
        data_type: str,
        data: str,
        message: str | None = None,
        tlp: int = 2,
        ioc: bool = False,
        sighted: bool = False,
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "dataType": data_type,
            "data": data,
            "tlp": tlp,
            "ioc": ioc,
            "sighted": sighted,
        }
        if message is not None:
            payload["message"] = message
        if tags:
            payload["tags"] = tags
        return self._request("POST", f"/api/v1/case/{case_id}/observable", json=payload)
