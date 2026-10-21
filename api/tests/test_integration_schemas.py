"""Tests for integration action request schemas."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from api.integrations.schemas import (
    AddObservableRequest,
    CreateAlertRequest,
    CreateCaseRequest,
    RunAnalyzerRequest,
)


def test_create_case_minimal():
    req = CreateCaseRequest(title="t", description="d")
    assert req.severity == 2
    assert req.tlp == 2
    assert req.pap == 2
    assert req.tags == []


def test_create_case_rejects_extra_fields():
    with pytest.raises(ValidationError):
        CreateCaseRequest(title="t", description="d", evil="x")


def test_create_case_severity_bounds():
    with pytest.raises(ValidationError):
        CreateCaseRequest(title="t", description="d", severity=5)
    with pytest.raises(ValidationError):
        CreateCaseRequest(title="t", description="d", severity=0)


def test_create_case_title_required():
    with pytest.raises(ValidationError):
        CreateCaseRequest(description="d")
    with pytest.raises(ValidationError):
        CreateCaseRequest(title="", description="d")


def test_create_alert_requires_source_ref():
    with pytest.raises(ValidationError):
        CreateAlertRequest(type="t", source="s", title="x", description="y")
    req = CreateAlertRequest(
        type="t", source="s", source_ref="r", title="x", description="y"
    )
    assert req.source_ref == "r"
    assert req.observables == []


def test_create_alert_observable_shape():
    req = CreateAlertRequest(
        type="t",
        source="s",
        source_ref="r",
        title="x",
        description="y",
        observables=[{"dataType": "ip", "data": "1.2.3.4"}],
    )
    assert req.observables == [{"dataType": "ip", "data": "1.2.3.4"}]


def test_add_observable_minimal():
    req = AddObservableRequest(case_id="~1", data_type="ip", data="1.2.3.4")
    assert req.tlp == 2
    assert req.ioc is False


def test_add_observable_rejects_empty_data():
    with pytest.raises(ValidationError):
        AddObservableRequest(case_id="~1", data_type="ip", data="")


def test_add_observable_rejects_path_injection_in_case_id():
    """case_id must match TheHive's ID format (~ followed by alphanumerics).

    Without strict validation, a caller could inject path segments or query
    strings to redirect the request under Hotwash's credentials.
    """
    bad_ids = [
        "~123/observable/other",
        "../etc/passwd",
        "~123?delete=true",
        "~123#fragment",
        "~123 with space",
        "no-tilde",
    ]
    for bad in bad_ids:
        with pytest.raises(ValidationError):
            AddObservableRequest(case_id=bad, data_type="ip", data="1.2.3.4")


def test_add_observable_accepts_real_thehive_ids():
    """Sample IDs observed against TheHive 5.4: ~123, ~8288, ~40964216."""
    for ok in ["~123", "~8288", "~40964216", "~A1"]:
        req = AddObservableRequest(case_id=ok, data_type="ip", data="1.2.3.4")
        assert req.case_id == ok


def test_run_analyzer_defaults_cortex_id():
    req = RunAnalyzerRequest(artifact_id="~12304", analyzer_id="0123456789abcdef0123456789abcdef")
    assert req.cortex_id == "cortex0"


def test_run_analyzer_accepts_real_ids():
    req = RunAnalyzerRequest(
        artifact_id="~12304",
        analyzer_id="CIRCLHashlookup_1_1",
        cortex_id="cortex-lab_1",
    )
    assert req.artifact_id == "~12304"
    assert req.cortex_id == "cortex-lab_1"


def test_run_analyzer_rejects_unsafe_ids():
    bad_values = [
        "~123/job",
        "../etc/passwd",
        "~123?x=1",
        "~123#frag",
        "~123 with space",
        "no-tilde",
        "",
    ]
    for bad in bad_values:
        with pytest.raises(ValidationError):
            RunAnalyzerRequest(artifact_id=bad, analyzer_id="abc123")
    for bad in ["a/b", "a b", "a?b", "a\\nb", "..", "", "a%2fb"]:
        with pytest.raises(ValidationError):
            RunAnalyzerRequest(artifact_id="~1", analyzer_id=bad)
        with pytest.raises(ValidationError):
            RunAnalyzerRequest(artifact_id="~1", analyzer_id="abc", cortex_id=bad)


def test_run_analyzer_rejects_extra_fields():
    with pytest.raises(ValidationError):
        RunAnalyzerRequest(artifact_id="~1", analyzer_id="abc", url="http://evil")
