"""Security and report coverage for execution routes."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from starlette.websockets import WebSocketDisconnect


def _create_execution(temp_db, *, node_id: str = "node_1") -> int:
    from api.orm_models import Execution, ExecutionEvent, Playbook
    from api.services.executions import serialize_steps

    now = datetime.now(timezone.utc)
    graph = {
        "nodes": [
            {"id": node_id, "label": "Collect evidence", "type": "step"},
        ],
        "edges": [],
    }
    steps = [
        {
            "node_id": node_id,
            "node_type": "step",
            "node_label": "Collect evidence",
            "phase": None,
            "status": "completed",
            "assignee": "analyst",
            "notes": ["Initial note"],
            "evidence": [],
            "decision_taken": None,
            "decision_options": None,
            "started_at": (now - timedelta(minutes=5)).isoformat(),
            "completed_at": now.isoformat(),
        }
    ]

    with temp_db() as session:
        playbook = Playbook(
            title="IR Playbook",
            description=None,
            category="Incident Response",
            content_markdown="# IR Playbook",
            graph_json=json.dumps(graph),
        )
        session.add(playbook)
        session.flush()
        execution = Execution(
            playbook_id=playbook.id,
            incident_title="Suspicious host",
            incident_id="INC-1",
            started_by="analyst",
            status="completed",
            started_at=now - timedelta(minutes=10),
            completed_at=now,
            steps_json=serialize_steps(steps),
        )
        session.add(execution)
        session.flush()
        session.add(
            ExecutionEvent(
                execution_id=execution.id,
                event_type="execution_completed",
                actor="analyst",
                description="Execution completed",
            )
        )
        execution_id = execution.id
        session.commit()
    return execution_id


def test_execution_websocket_requires_valid_api_key(client, temp_db, api_key):
    execution_id = _create_execution(temp_db)

    with client.websocket_connect(
        f"/api/executions/{execution_id}/live?api_key={api_key}"
    ) as websocket:
        websocket.send_text("ping")

    with pytest.raises(WebSocketDisconnect) as missing:
        with client.websocket_connect(f"/api/executions/{execution_id}/live"):
            pass
    assert missing.value.code == 4401

    with pytest.raises(WebSocketDisconnect) as invalid:
        with client.websocket_connect(
            f"/api/executions/{execution_id}/live?api_key=wrong"
        ):
            pass
    assert invalid.value.code == 4401


def test_evidence_upload_rejects_unsafe_filename_and_deduplicates(
    client,
    temp_db,
    api_key,
    monkeypatch,
    tmp_path,
):
    from api.routers import executions

    monkeypatch.setattr(executions, "EVIDENCE_ROOT", tmp_path / "evidence")
    execution_id = _create_execution(temp_db)
    url = f"/api/executions/{execution_id}/steps/node_1/evidence"
    headers = {"X-API-Key": api_key}

    first = client.post(
        url,
        headers=headers,
        files={"file": ("evidence.txt", b"one", "text/plain")},
    )
    assert first.status_code == 200
    assert first.json()["evidence"][-1]["filename"] == "evidence.txt"

    second = client.post(
        url,
        headers=headers,
        files={"file": ("evidence.txt", b"two", "text/plain")},
    )
    assert second.status_code == 200
    assert second.json()["evidence"][-1]["filename"] == "evidence-1.txt"

    unsafe = client.post(
        url,
        headers=headers,
        files={"file": ("../evil.txt", b"bad", "text/plain")},
    )
    assert unsafe.status_code == 400


def test_evidence_upload_rejects_unsafe_node_id(
    client,
    temp_db,
    api_key,
    monkeypatch,
    tmp_path,
):
    from api.routers import executions

    monkeypatch.setattr(executions, "EVIDENCE_ROOT", tmp_path / "evidence")
    execution_id = _create_execution(temp_db, node_id="bad node")
    resp = client.post(
        f"/api/executions/{execution_id}/steps/bad%20node/evidence",
        headers={"X-API-Key": api_key},
        files={"file": ("evidence.txt", b"body", "text/plain")},
    )
    assert resp.status_code == 400


def test_execution_report_json_and_markdown(client, temp_db, api_key):
    execution_id = _create_execution(temp_db)
    headers = {"X-API-Key": api_key}

    report = client.get(f"/api/executions/{execution_id}/report", headers=headers)
    assert report.status_code == 200
    body = report.json()
    assert body["execution"]["incident_title"] == "Suspicious host"
    assert body["playbook_title"] == "IR Playbook"
    assert body["metrics"]["steps_completed"] == 1
    assert body["timeline"][0]["description"] == "Execution completed"

    markdown = client.get(
        f"/api/executions/{execution_id}/report/markdown",
        headers=headers,
    )
    assert markdown.status_code == 200
    assert "# After-Action Report" in markdown.text
    assert "Suspicious host" in markdown.text


def test_step_status_change_blocked_on_terminal_execution(client, temp_db, api_key):
    # H1: a completed/abandoned run's completion state is frozen.
    execution_id = _create_execution(temp_db)  # status="completed"
    resp = client.patch(
        f"/api/executions/{execution_id}/steps/node_1",
        headers={"X-API-Key": api_key},
        json={"status": "in_progress"},
    )
    assert resp.status_code == 409


def test_step_decision_change_blocked_on_terminal_execution(client, temp_db, api_key):
    execution_id = _create_execution(temp_db)
    resp = client.patch(
        f"/api/executions/{execution_id}/steps/node_1",
        headers={"X-API-Key": api_key},
        json={"decision_taken": "escalate"},
    )
    assert resp.status_code == 409


def test_step_note_still_allowed_on_terminal_execution(client, temp_db, api_key):
    # Annotations (notes/assignee/evidence) stay allowed for after-action review.
    execution_id = _create_execution(temp_db)
    resp = client.patch(
        f"/api/executions/{execution_id}/steps/node_1",
        headers={"X-API-Key": api_key},
        json={"notes": "after-action note"},
    )
    assert resp.status_code == 200
    assert "after-action note" in resp.json()["steps"][0]["notes"]
