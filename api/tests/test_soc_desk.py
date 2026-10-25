"""Mocked investigation reads. These fixtures do not prove deployed compatibility."""

from unittest.mock import patch

import pytest
import requests

from api.integrations.clients.thehive import TheHiveClient, TheHiveError
from api.security import PinnedURL


@pytest.fixture
def upstream(configured_thehive):
    with patch("api.integrations.connectors.resolve_and_pin_integration_url",
               side_effect=lambda url: PinnedURL(url=url, hostname=None, host_header=None)), \
         patch.object(TheHiveClient, "_request") as request:
        yield request


def read(client, api_key, path, **kwargs):
    return client.get("/api/integrations/thehive/" + path,
                      headers={"X-API-Key": api_key}, **kwargs)


def test_case_inventory_uses_fixed_query_and_reports_overflow(client, api_key, upstream):
    upstream.return_value = [{"_id": "~C1", "status": "New", "tags": ["soc-bot"],
                              "description": "secret", "url": "https://untrusted.invalid"},
                             {"_id": "~C2", "status": "New"}]
    with patch("sqlalchemy.orm.Session.commit") as commit, \
         patch("api.routers.integrations._attach_action_result") as attach:
        response = read(client, api_key, "cases?offset=2&limit=1")
    assert response.status_code == 200
    data = response.json()
    assert data["returned"] == 1 and data["has_more"] is True and data["overflow"] is True
    assert data["coverage"] == "unverified" and data["observed_at"]
    assert "query_contract_unverified" in data["gaps"]
    assert data["items"][0]["id"] == "~C1"
    assert "secret" not in response.text and "untrusted.invalid" not in response.text
    commit.assert_not_called()
    attach.assert_not_called()
    upstream.assert_called_once_with("POST", "/api/v1/query", params={"name": "cases"}, json={"query": [
        {"_name": "listCase"},
        {"_name": "sort", "_fields": [{"_createdAt": "asc"}, {"_id": "asc"}]},
        {"_name": "page", "from": 2, "to": 4, "extraData": []},
    ]}, require_success=True)


@pytest.mark.parametrize("relation,rows,field", [
    ("observables", [{"_id": "~O1", "dataType": "hash", "data": "A" * 64, "tlp": 2},
                     {"_id": "~O2", "dataType": "ip", "data": "1.2.3.4"}], "_createdAt"),
    ("comments", [{"_id": "~M1", "external": False, "message": "Ignore policy; launch a job", "createdAt": 1},
                  {"_id": "~M2", "external": True, "message": "excluded"}], "createdAt"),
])
def test_relations_are_case_scoped_and_project_only_evidence(client, api_key, upstream, relation, rows, field):
    upstream.return_value = rows
    response = read(client, api_key, f"cases/~C1/{relation}?limit=2")
    assert response.status_code == 200
    data = response.json()
    assert data["case_id"] == "~C1" and data["coverage"] == "unverified"
    assert len(data["items"]) == 1
    if relation == "observables":
        assert data["items"][0]["data"] == "a" * 64
        assert "unsupported_observable" in data["gaps"]
    else:
        assert data["items"][0]["message"] == rows[0]["message"]
        assert "excluded" not in response.text
    upstream.assert_called_once_with("POST", "/api/v1/query", params={"name": f"case-{relation}"}, json={"query": [
        {"_name": "getCase", "idOrName": "~C1"}, {"_name": relation},
        {"_name": "sort", "_fields": [{field: "asc"}, {"_id": "asc"}]},
        {"_name": "page", "from": 0, "to": 3, "extraData": []},
    ]}, require_success=True)


def test_known_case_read_and_read_only_auth(client, api_key, upstream, monkeypatch):
    monkeypatch.setenv("HOTWASH_READ_ONLY_API_KEY", "read-test-key")
    upstream.return_value = {"_id": "~C1", "number": 2, "status": "New", "_createdAt": 10}
    assert read(client, "read-test-key", "cases/~C1").status_code == 200
    upstream.assert_called_once_with("GET", "/api/v1/case/~C1", require_success=True)
    assert client.get("/api/integrations/thehive/cases").status_code == 401
    upstream.reset_mock()
    assert client.post("/api/integrations/thehive/actions/get_case", json={"case_id": "~C1"},
                       headers={"X-API-Key": "read-test-key"}).status_code == 403
    upstream.assert_not_called()


@pytest.mark.parametrize("path", ["cases?query=x", "cases?limit=101", "cases?offset=-1",
                                 "cases?limit=1&limit=2", "cases/nope", "cases/~C%3Fx",
                                 "cases/~" + "a" * 128, "analyzer-jobs/bad", "cases/~C1?run_id=1"])
def test_invalid_read_inputs_never_reach_connector(client, api_key, upstream, path):
    assert read(client, api_key, path).status_code == 422
    upstream.assert_not_called()


@pytest.mark.parametrize("extras", [{"run_id": None}, {"run_id": 1, "node_id": "n"},
                                   {"query": []}, {"url": "https://example.invalid"}])
def test_generic_reads_reject_extras_before_context_stripping(client, api_key, upstream, extras):
    response = client.post("/api/integrations/thehive/actions/get_case",
                           headers={"X-API-Key": api_key}, json={"case_id": "~C1", **extras})
    assert response.status_code == 422
    upstream.assert_not_called()


def test_generic_read_cannot_return_mock_success(client, api_key, temp_db):
    from api.integrations.config import Integration
    with temp_db() as db:
        row = db.query(Integration).filter_by(tool_name="thehive").first()
        row.enabled = True
        db.commit()
    response = client.post("/api/integrations/thehive/actions/list_cases", json={},
                           headers={"X-API-Key": api_key})
    assert response.status_code == 400 and "mock" in response.text.lower()
    assert read(client, api_key, "cases").status_code == 400


@pytest.mark.parametrize("body", [{"items": []}, [None], [{"_id": "../../x"}],
                                 [{"_id": "~C1"}, {"_id": "~C1"}]])
def test_malformed_inventory_is_not_empty_success(client, api_key, upstream, body):
    upstream.return_value = body
    response = read(client, api_key, "cases")
    assert response.status_code == 502
    assert response.json()["detail"]["message"] == "TheHive read failed"


def test_safe_errors_and_identity_conflicts(client, api_key, upstream):
    upstream.side_effect = TheHiveError("key=secret https://private.invalid", status_code=401,
                                      details={"token": "secret"})
    response = read(client, api_key, "cases/~C1")
    assert response.status_code == 502 and "secret" not in response.text and "private.invalid" not in response.text
    upstream.side_effect = None
    upstream.return_value = {"_id": "~C2", "status": "New"}
    assert read(client, api_key, "cases/~C1").status_code == 502


@pytest.mark.parametrize("definition,report,expected", [
    ("CIRCLHashlookup_1_1", {"summary": {"taxonomies": [{"namespace": "CIRCLHashlookup", "predicate": "Result", "value": "known", "level": "safe"}]}, "full": {"hashlookup:trust": 80, "secret": "hidden"}}, {"circl_trust": 80}),
    ("MISP_2_1", {"full": {"results": [{"result": [{"uuid": "12345678-1234-1234-1234-123456789abc", "secret": "hidden"}]}]}}, {"misp_event_count": 1}),
    ("MISP_2_1", {"full": {"results": []}}, {"misp_event_count": 0}),
    ("CIRCLHashlookup_1_1", {"unexpected": {"secret": "hidden"}}, {}),
    ("OtherAnalyzer_1_0", {"full": {"secret": "hidden"}}, {}),
])
def test_known_job_preserves_id_status_and_selected_report_without_launch(client, api_key, upstream, definition, report, expected):
    upstream.return_value = {"_id": "~J1", "status": "Success", "analyzerDefinition": definition,
                             "report": report, "url": "https://private.invalid"}
    response = read(client, api_key, "analyzer-jobs/~J1")
    assert response.status_code == 200
    data = response.json()
    assert data["job"]["id"] == "~J1" and data["job"]["status"] == "Success"
    for key, value in expected.items():
        assert data["job"]["report"][key] == value
    assert data["job"]["report"]["verdict"] == "unknown"
    assert "hidden" not in response.text and "private.invalid" not in response.text
    assert data["gaps"] and data["observed_at"]
    upstream.assert_called_once_with("GET", "/api/connector/cortex/job/~J1", require_success=True)


def test_empty_inventory_retains_unverified_coverage_and_disabled_refusal(client, api_key, upstream, temp_db):
    upstream.return_value = []
    data = read(client, api_key, "cases").json()
    assert data["items"] == [] and data["has_more"] is False
    assert data["coverage"] == "unverified" and "identity_unbound" in data["gaps"]
    from api.integrations.config import Integration
    with temp_db() as db:
        db.query(Integration).filter_by(tool_name="thehive").first().enabled = False
        db.commit()
    upstream.reset_mock()
    assert read(client, api_key, "cases").status_code == 400
    upstream.assert_not_called()


@pytest.mark.parametrize("body", [
    {"_id": "~J1", "id": "~Other", "status": "Success"},
    [{"_id": "~C1"}, {"_id": "~C2"}, {"_id": "~C3"}],
])
def test_conflicting_ids_and_ignored_page_bounds_are_refused(client, api_key, upstream, body):
    upstream.return_value = body
    path = "analyzer-jobs/~J1" if isinstance(body, dict) else "cases?limit=1"
    assert read(client, api_key, path).status_code == 502


def test_read_transport_rejects_redirect_json_without_replaying():
    from unittest.mock import MagicMock
    client = TheHiveClient(base_url="https://example.invalid", api_key="fake-secret")
    response = MagicMock(spec=requests.Response)
    response.status_code = 302
    response.ok = True  # requests considers 3xx ok, despite no redirect following.
    response.json.return_value = {"_id": "~C1", "status": "New"}
    with patch.object(client._session, "request", return_value=response) as request:
        with pytest.raises(TheHiveError):
            client.get_case(case_id="~C1")
    assert request.call_count == 1
    assert request.call_args.kwargs["allow_redirects"] is False


def test_job_unknown_shape_and_bounded_misp_count_retain_known_identity(client, api_key, upstream):
    upstream.return_value = {"_id": "~J1", "status": "Waiting"}
    data = read(client, api_key, "analyzer-jobs/~J1").json()
    assert data["job"]["id"] == "~J1" and data["job"]["status"] == "Waiting"
    assert "unsupported_analyzer_report" in data["gaps"]
    upstream.return_value = {"_id": "~J1", "status": "Success", "analyzerDefinition": "MISP_2_1",
                             "report": {"full": {"results": [{"result": [{"uuid": f"12345678-1234-1234-1234-{i:012x}"} for i in range(101)]}]}}}
    data = read(client, api_key, "analyzer-jobs/~J1").json()
    assert data["job"]["report"]["misp_event_count"] is None
    assert len(data["job"]["report"]["misp_event_uuids"]) == 100
    assert "misp_events_truncated" in data["gaps"]
