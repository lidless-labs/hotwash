"""ActiveGraph-inspired run_events: reducer oracle + fork/diff.

Drives the real HTTP flow so the structured event stream is exercised exactly
as production writes it, then checks that replaying the log reproduces
steps_json, that a fork diverges only after its cut point, and that diff reports
the divergence. See docs/design/activegraph-inspiration.md.
"""

from __future__ import annotations

import json

from datetime import datetime, timezone


def _seed_playbook(temp_db) -> int:
    from api.orm_models import Playbook

    graph = {
        "nodes": [
            {"id": "n1", "label": "Triage", "type": "step"},
            {"id": "n2", "label": "Contain", "type": "step"},
            {"id": "n3", "label": "Eradicate", "type": "step"},
        ],
        "edges": [],
    }
    with temp_db() as session:
        pb = Playbook(
            title="IR",
            category="Incident Response",
            content_markdown="# IR",
            graph_json=json.dumps(graph),
        )
        session.add(pb)
        session.flush()
        pb_id = pb.id
        session.commit()
    return pb_id


def _create_execution(client, headers, playbook_id) -> int:
    resp = client.post(
        "/api/executions",
        headers=headers,
        json={"playbook_id": playbook_id, "incident_title": "Host compromise"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _advance(client, headers, execution_id, node_id, **fields):
    resp = client.patch(
        f"/api/executions/{execution_id}/steps/{node_id}",
        headers=headers,
        json=fields,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_replay_matches_persisted_after_updates(client, temp_db, api_key):
    headers = {"X-API-Key": api_key}
    pb = _seed_playbook(temp_db)
    ex = _create_execution(client, headers, pb)

    _advance(client, headers, ex, "n1", status="in_progress")
    _advance(client, headers, ex, "n1", status="completed", notes="triaged", assignee="ana")
    _advance(client, headers, ex, "n2", status="in_progress", decision_taken="isolate")

    replay = client.get(f"/api/executions/{ex}/replay", headers=headers).json()
    assert replay["matches_persisted"] is True
    assert replay["event_count"] >= 4  # run_started + the step events

    # The projected state reflects the mutations.
    by_node = {s["node_id"]: s for s in replay["steps"]}
    assert by_node["n1"]["status"] == "completed"
    assert by_node["n1"]["notes"] == ["triaged"]
    assert by_node["n1"]["assignee"] == "ana"
    assert by_node["n2"]["status"] == "in_progress"
    assert by_node["n2"]["decision_taken"] == "isolate"
    assert by_node["n3"]["status"] == "not_started"


def test_fork_diverges_only_after_the_cut(client, temp_db, api_key):
    headers = {"X-API-Key": api_key}
    pb = _seed_playbook(temp_db)
    ex = _create_execution(client, headers, pb)

    _advance(client, headers, ex, "n1", status="completed")

    # Fork at the latest event, then diverge parent and fork differently.
    fork_id = client.post(f"/api/executions/{ex}/fork", headers=headers).json()["id"]

    _advance(client, headers, ex, "n2", status="completed")  # parent only
    _advance(client, headers, fork_id, "n2", status="skipped")  # fork only

    # Both forks still agree the reducer reproduces their own state.
    assert client.get(f"/api/executions/{fork_id}/replay", headers=headers).json()["matches_persisted"] is True

    diff = client.get(f"/api/executions/{ex}/diff/{fork_id}", headers=headers).json()
    assert diff["identical"] is False
    changed = {d["node_id"]: d for d in diff["differences"]}
    # n1 was shared before the cut -> identical; n2 diverged -> differs.
    assert "n1" not in changed
    assert changed["n2"]["issue"] == "differs"
    assert changed["n2"]["fields"]["status"] == {"a": "completed", "b": "skipped"}


def test_diff_of_identical_runs_is_clean(client, temp_db, api_key):
    headers = {"X-API-Key": api_key}
    pb = _seed_playbook(temp_db)
    ex = _create_execution(client, headers, pb)
    _advance(client, headers, ex, "n1", status="completed")

    # A fork with no further changes is structurally identical to its parent.
    fork_id = client.post(f"/api/executions/{ex}/fork", headers=headers).json()["id"]
    diff = client.get(f"/api/executions/{ex}/diff/{fork_id}", headers=headers).json()
    assert diff["identical"] is True
    assert diff["differences"] == []
