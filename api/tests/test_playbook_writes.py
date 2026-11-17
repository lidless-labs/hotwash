"""Playbook write hardening: schema bounds and optimistic concurrency (#46, #47).

The bounds mirror the MCP playbook tool schemas so an API key holder cannot
write a row the bounded agent tools would refuse, and cannot exceed the
Tag.name column length. The precondition lets a read-then-write caller (the MCP
update tool) refuse to overwrite a playbook that changed between its read and
its write.
"""

from __future__ import annotations

from datetime import datetime

import pytest

CONTENT = "# Triage\n\n## Review\n\nCheck the alert.\n"


def _headers(api_key):
    return {"X-API-Key": api_key}


def _create(client, api_key, **overrides):
    body = {"title": "Triage", "content_markdown": CONTENT}
    body.update(overrides)
    return client.post("/api/playbooks", headers=_headers(api_key), json=body)


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _microseconds(value: str) -> int:
    return len(value.partition(".")[2])


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


@pytest.mark.parametrize(
    "field,value",
    [("title", " "), ("title", "\t\n"), ("content_markdown", "   "), ("tags", [" "]), ("tags", ["ok", "\t"])],
)
def test_create_rejects_blank_text(client, temp_db, api_key, field, value):
    assert _create(client, api_key, **{field: value}).status_code == 422


@pytest.mark.parametrize(
    "field,value",
    [("title", " "), ("content_markdown", "\n"), ("tags", [" "]), ("tags", ["ok", " "])],
)
def test_update_rejects_blank_text(client, temp_db, api_key, field, value):
    playbook_id = _create(client, api_key).json()["id"]
    resp = client.put(f"/api/playbooks/{playbook_id}", headers=_headers(api_key), json={field: value})
    assert resp.status_code == 422


def test_a_blank_tag_cannot_clear_existing_tags(client, temp_db, api_key):
    playbook_id = _create(client, api_key, tags=["soc-bot", "draft"]).json()["id"]
    resp = client.put(
        f"/api/playbooks/{playbook_id}",
        headers=_headers(api_key),
        json={"tags": [" "]},
    )
    assert resp.status_code == 422
    # The rejected write must not have dropped the agent's ownership tags.
    read = client.get(f"/api/playbooks/{playbook_id}", headers=_headers(api_key)).json()
    assert [tag["name"] for tag in read["tags"]] == ["soc-bot", "draft"]


# --- #47 through the import routes ---------------------------------------

IMPORT_BASE = {"title": "Imported", "category": "Imported", "content_markdown": CONTENT}


@pytest.mark.parametrize(
    "field,value",
    [
        ("title", "x" * 201),
        ("title", "   "),
        ("description", "x" * 8001),
        ("category", "x" * 101),
        ("content_markdown", "x" * 100001),
        ("content_markdown", "   "),
        ("tags", ["x" * 101]),
        ("tags", [str(index) for index in range(19)]),
        ("tags", [" "]),
    ],
)
def test_import_rejects_out_of_bounds_fields(client, temp_db, api_key, field, value):
    resp = client.post(
        "/api/playbooks/import",
        headers=_headers(api_key),
        json={**IMPORT_BASE, field: value},
    )
    assert resp.status_code == 422


def test_import_rejects_unknown_fields(client, temp_db, api_key):
    resp = client.post(
        "/api/playbooks/import",
        headers=_headers(api_key),
        json={**IMPORT_BASE, "is_deleted": True},
    )
    assert resp.status_code == 422
    assert client.get("/api/playbooks", headers=_headers(api_key)).json() == []


def test_import_accepts_an_exported_playbook(client, temp_db, api_key):
    playbook_id = _create(client, api_key, tags=["soc-bot"]).json()["id"]
    exported = client.get(
        f"/api/playbooks/{playbook_id}/export?format=json", headers=_headers(api_key)
    ).json()

    resp = client.post("/api/playbooks/import", headers=_headers(api_key), json=exported)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["id"] != playbook_id
    assert body["title"] == "Triage"
    assert [tag["name"] for tag in body["tags"]] == ["soc-bot"]


def test_bulk_import_rejects_a_file_over_the_content_bound(client, temp_db, api_key):
    resp = client.post(
        "/api/playbooks/import/bulk",
        headers=_headers(api_key),
        files=[("files", ("big.md", "# Big\n" + "x" * 100000, "text/markdown"))],
    )
    assert resp.status_code == 400
    assert "100000" in resp.json()["detail"]


def test_bulk_import_truncates_a_long_heading_title(client, temp_db, api_key):
    resp = client.post(
        "/api/playbooks/import/bulk",
        headers=_headers(api_key),
        files=[("files", ("long.md", "# " + "T" * 250 + "\n", "text/markdown"))],
    )
    assert resp.status_code == 200, resp.text
    created_id = resp.json()[0]["playbook_id"]
    read = client.get(f"/api/playbooks/{created_id}", headers=_headers(api_key)).json()
    assert len(read["title"]) == 200


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
    playbook_id = _create(client, api_key, tags=["draft", "soc-bot"]).json()["id"]
    read = client.get(f"/api/playbooks/{playbook_id}", headers=_headers(api_key)).json()

    # A human retags through the API after the agent's ownership read. Both
    # writes land in the same second, which is exactly the #46 race.
    retag = client.put(
        f"/api/playbooks/{playbook_id}",
        headers=_headers(api_key),
        json={"tags": ["reviewed-by-human", "soc-bot"]},
    )
    assert retag.status_code == 200

    resp = client.put(
        f"/api/playbooks/{playbook_id}",
        headers=_headers(api_key),
        json={"title": "Renamed", "expected_updated_at": read["updated_at"]},
    )
    assert resp.status_code == 409
    read_after = client.get(f"/api/playbooks/{playbook_id}", headers=_headers(api_key)).json()
    assert read_after["title"] == "Triage"
    assert {tag["name"] for tag in read_after["tags"]} == {"reviewed-by-human", "soc-bot"}


def test_a_tags_only_update_bumps_updated_at(client, temp_db, api_key):
    playbook_id = _create(client, api_key, tags=["draft"]).json()["id"]
    read = client.get(f"/api/playbooks/{playbook_id}", headers=_headers(api_key)).json()

    resp = client.put(
        f"/api/playbooks/{playbook_id}",
        headers=_headers(api_key),
        json={"tags": ["draft", "soc-bot"]},
    )
    assert resp.status_code == 200
    # SQLAlchemy's onupdate would not fire here: no playbooks column changed.
    assert _parse(resp.json()["updated_at"]) > _parse(read["updated_at"])
    assert _microseconds(resp.json()["updated_at"]) == 6


def test_each_accepted_write_strictly_advances_updated_at(client, temp_db, api_key):
    playbook_id = _create(client, api_key).json()["id"]
    stamps = []
    for title in ["One", "Two", "Three", "Four", "Five"]:
        resp = client.put(f"/api/playbooks/{playbook_id}", headers=_headers(api_key), json={"title": title})
        assert resp.status_code == 200
        stamps.append(_parse(resp.json()["updated_at"]))
    # Strictly increasing even when several writes land in the same second.
    assert stamps == sorted(stamps)
    assert len(set(stamps)) == len(stamps)


def test_two_writes_with_the_same_precondition_cannot_both_pass(client, temp_db, api_key):
    playbook_id = _create(client, api_key).json()["id"]
    read = client.get(f"/api/playbooks/{playbook_id}", headers=_headers(api_key)).json()
    body = {"title": "Renamed", "expected_updated_at": read["updated_at"]}

    first = client.put(f"/api/playbooks/{playbook_id}", headers=_headers(api_key), json=body)
    second = client.put(f"/api/playbooks/{playbook_id}", headers=_headers(api_key), json=body)
    assert first.status_code == 200
    assert second.status_code == 409


def test_precondition_accepts_a_timezone_aware_value(client, temp_db, api_key):
    playbook_id = _create(client, api_key).json()["id"]
    read = client.get(f"/api/playbooks/{playbook_id}", headers=_headers(api_key)).json()
    aware = f"{read['updated_at']}+00:00"

    resp = client.put(
        f"/api/playbooks/{playbook_id}",
        headers=_headers(api_key),
        json={"title": "Renamed", "expected_updated_at": aware},
    )
    assert resp.status_code == 200


def test_precondition_normalizes_an_offset_instead_of_ignoring_it(client, temp_db, api_key):
    playbook_id = _create(client, api_key).json()["id"]
    read = client.get(f"/api/playbooks/{playbook_id}", headers=_headers(api_key)).json()
    # The same wall clock one hour east is a different instant, so it must not match.
    resp = client.put(
        f"/api/playbooks/{playbook_id}",
        headers=_headers(api_key),
        json={"title": "Renamed", "expected_updated_at": f"{read['updated_at']}+01:00"},
    )
    assert resp.status_code == 409


def test_a_whole_second_timestamp_still_satisfies_its_own_precondition(client, temp_db, api_key):
    playbook_id = _create(client, api_key).json()["id"]
    # The share route is still on SQLAlchemy's onupdate, so it stores the
    # whole-second CURRENT_TIMESTAMP that older rows also carry. The read must
    # round-trip into the precondition even though the text lost its fraction.
    shared = client.post(f"/api/playbooks/{playbook_id}/share", headers=_headers(api_key))
    assert shared.status_code == 200

    read = client.get(f"/api/playbooks/{playbook_id}", headers=_headers(api_key)).json()
    assert read["updated_at"].endswith(".000000")
    resp = client.put(
        f"/api/playbooks/{playbook_id}",
        headers=_headers(api_key),
        json={"title": "Renamed", "expected_updated_at": read["updated_at"]},
    )
    assert resp.status_code == 200
    assert _parse(resp.json()["updated_at"]) > _parse(read["updated_at"])


def test_create_and_duplicate_carry_microsecond_timestamps(client, temp_db, api_key):
    created = _create(client, api_key, title="t" * 200).json()
    assert _microseconds(created["updated_at"]) == 6
    assert created["updated_at"] == created["created_at"]

    duplicate = client.post(
        f"/api/playbooks/{created['id']}/duplicate", headers=_headers(api_key)
    ).json()
    assert _microseconds(duplicate["updated_at"]) == 6
    assert _parse(duplicate["updated_at"]) > _parse(created["updated_at"])
    # " (Copy)" must not push the title past the 200-character write bound.
    assert len(duplicate["title"]) == 200
    assert duplicate["title"].endswith(" (Copy)")


def test_duplicate_keeps_a_short_title_intact(client, temp_db, api_key):
    playbook_id = _create(client, api_key, title="Triage").json()["id"]
    duplicate = client.post(
        f"/api/playbooks/{playbook_id}/duplicate", headers=_headers(api_key)
    ).json()
    assert duplicate["title"] == "Triage (Copy)"


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
