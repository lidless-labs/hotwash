"""Playbook write hardening: schema bounds and optimistic concurrency (#46, #47).

The bounds mirror the MCP playbook tool schemas so an API key holder cannot
write a row the bounded agent tools would refuse, and cannot exceed the
Tag.name column length. The precondition lets a read-then-write caller (the MCP
update tool) refuse to overwrite a playbook that changed between its read and
its write.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

CONTENT = "# Triage\n\n## Review\n\nCheck the alert.\n"


def _headers(api_key):
    return {"X-API-Key": api_key}


def _create(client, api_key, **overrides):
    body = {"title": "Triage", "content_markdown": CONTENT}
    body.update(overrides)
    return client.post("/api/playbooks", headers=_headers(api_key), json=body)


# --- #47: schema bounds ----------------------------------------------------


@pytest.mark.parametrize(
    "field,value",
    [
        ("title", "x" * 201),
        ("description", "x" * 8001),
        ("category", "x" * 101),
        ("content_markdown", "x" * 100001),
        ("tags", ["x" * 101]),
        ("tags", [str(index) for index in range(19)]),
        ("tags", [""]),
    ],
)
def test_create_rejects_out_of_bounds_fields(client, temp_db, api_key, field, value):
    resp = _create(client, api_key, **{field: value})
    assert resp.status_code == 422


@pytest.mark.parametrize(
    "field,value",
    [
        ("title", "x" * 201),
        ("description", "x" * 8001),
        ("category", "x" * 101),
        ("content_markdown", "x" * 100001),
        ("tags", ["x" * 101]),
        ("tags", [str(index) for index in range(19)]),
    ],
)
def test_update_rejects_out_of_bounds_fields(client, temp_db, api_key, field, value):
    playbook_id = _create(client, api_key).json()["id"]
    resp = client.put(f"/api/playbooks/{playbook_id}", headers=_headers(api_key), json={field: value})
    assert resp.status_code == 422


def test_create_and_update_reject_unknown_fields(client, temp_db, api_key):
    resp = _create(client, api_key, graph_json={"nodes": [], "edges": []})
    assert resp.status_code == 422

    playbook_id = _create(client, api_key).json()["id"]
    resp = client.put(
        f"/api/playbooks/{playbook_id}",
        headers=_headers(api_key),
        json={"title": "Renamed", "is_deleted": True},
    )
    assert resp.status_code == 422


def test_boundary_sizes_are_accepted(client, temp_db, api_key):
    content = ("## Step\n\nDo the thing.\n" * 7200)[:100000]
    resp = _create(
        client,
        api_key,
        title="t" * 200,
        description="d" * 8000,
        category="c" * 100,
        content_markdown=content,
        tags=[str(index).ljust(100, "t") for index in range(18)],
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert len(body["title"]) == 200
    assert len(body["tags"]) == 18


# --- #46: optimistic concurrency ------------------------------------------


def test_update_without_a_precondition_stays_last_write_wins(client, temp_db, api_key):
    playbook_id = _create(client, api_key).json()["id"]
    resp = client.put(f"/api/playbooks/{playbook_id}", headers=_headers(api_key), json={"title": "Renamed"})
    assert resp.status_code == 200
    assert resp.json()["title"] == "Renamed"


def test_update_accepts_the_updated_at_it_read(client, temp_db, api_key):
    playbook_id = _create(client, api_key).json()["id"]
    read = client.get(f"/api/playbooks/{playbook_id}", headers=_headers(api_key)).json()
    resp = client.put(
        f"/api/playbooks/{playbook_id}",
        headers=_headers(api_key),
        json={"title": "Renamed", "expected_updated_at": read["updated_at"]},
    )
    assert resp.status_code == 200
    assert resp.json()["title"] == "Renamed"


def test_stale_precondition_is_rejected_with_409(client, temp_db, api_key):
    playbook_id = _create(client, api_key).json()["id"]
    resp = client.put(
        f"/api/playbooks/{playbook_id}",
        headers=_headers(api_key),
        json={"title": "Renamed", "expected_updated_at": "2020-01-01T00:00:00"},
    )
    assert resp.status_code == 409
    assert "re-read" in resp.json()["detail"]

    # The rejected write must not have landed.
    read = client.get(f"/api/playbooks/{playbook_id}", headers=_headers(api_key)).json()
    assert read["title"] == "Triage"


def test_a_retag_between_read_and_write_is_rejected(client, temp_db, api_key):
    from api.orm_models import Playbook
    from api.services.tags import get_or_create_tag

    playbook_id = _create(client, api_key, tags=["draft"]).json()["id"]
    read = client.get(f"/api/playbooks/{playbook_id}", headers=_headers(api_key)).json()

    # A human retags the playbook after the agent's ownership read.
    with temp_db() as session:
        playbook = session.get(Playbook, playbook_id)
        playbook.tags = [get_or_create_tag(session, "reviewed-by-human")]
        # SQLite CURRENT_TIMESTAMP has one-second resolution, so advance the
        # stored version to make the retag observable as a distinct write.
        playbook.updated_at = playbook.updated_at + timedelta(seconds=2)
        session.commit()

    resp = client.put(
        f"/api/playbooks/{playbook_id}",
        headers=_headers(api_key),
        json={"title": "Renamed", "expected_updated_at": read["updated_at"]},
    )
    assert resp.status_code == 409
    read_after = client.get(f"/api/playbooks/{playbook_id}", headers=_headers(api_key)).json()
    assert read_after["title"] == "Triage"
    assert [tag["name"] for tag in read_after["tags"]] == ["reviewed-by-human"]


@pytest.mark.parametrize("value", ["not-a-timestamp", "2026-13-45T00:00:00"])
def test_malformed_precondition_is_rejected(client, temp_db, api_key, value):
    playbook_id = _create(client, api_key).json()["id"]
    resp = client.put(
        f"/api/playbooks/{playbook_id}",
        headers=_headers(api_key),
        json={"title": "Renamed", "expected_updated_at": value},
    )
    assert resp.status_code == 422


def test_precondition_on_a_missing_playbook_is_404(client, temp_db, api_key):
    resp = client.put(
        "/api/playbooks/9999",
        headers=_headers(api_key),
        json={"title": "Renamed", "expected_updated_at": "2026-01-01T00:00:00"},
    )
    assert resp.status_code == 404
