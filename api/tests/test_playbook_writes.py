"""Playbook write hardening: schema bounds and optimistic concurrency (#46, #47).

The bounds mirror the MCP playbook tool schemas so an API key holder cannot
write a row the bounded agent tools would refuse, and cannot exceed the
Tag.name column length. The precondition lets a read-then-write caller (the MCP
update tool) refuse to overwrite a playbook that changed between its read and
its write.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime

import pytest
from sqlalchemy import text

from api.services.timestamps import utcnow

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


def test_a_graph_only_export_round_trips_through_import(client, temp_db, api_key):
    # A playbook saved from the canvas has no Markdown but does carry a graph;
    # the export writes content_markdown: null and the import must accept it.
    from api.orm_models import Playbook

    now = utcnow()
    with temp_db() as session:
        playbook = Playbook(
            title="Canvas only",
            content_markdown=None,
            graph_json=LEGACY_GRAPH,
            created_at=now,
            updated_at=now,
        )
        session.add(playbook)
        session.commit()
        playbook_id = playbook.id

    exported = client.get(
        f"/api/playbooks/{playbook_id}/export?format=json", headers=_headers(api_key)
    ).json()
    assert exported["content_markdown"] is None
    assert exported["graph_json"]["nodes"]

    resp = client.post("/api/playbooks/import", headers=_headers(api_key), json=exported)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["id"] != playbook_id
    assert body["content_markdown"] is None
    assert body["graph_json"] == exported["graph_json"]
    assert body["node_count"] == 1

    read = client.get(f"/api/playbooks/{body['id']}", headers=_headers(api_key)).json()
    assert read["content_markdown"] is None


LEGACY_EXPORT = {
    "title": "Legacy export",
    "category": "Imported",
    "content_markdown": CONTENT,
}


@pytest.mark.parametrize("graph", [None, {"nodes": [], "edges": []}])
def test_import_rejects_null_content_without_a_usable_graph(client, temp_db, api_key, graph):
    resp = client.post(
        "/api/playbooks/import",
        headers=_headers(api_key),
        json={"title": "Empty canvas", "content_markdown": None, "graph_json": graph},
    )
    assert resp.status_code == 422
    body = json.dumps(resp.json())
    assert "content_markdown" in body
    assert client.get("/api/playbooks", headers=_headers(api_key)).json() == []


@pytest.mark.parametrize(
    "field,limit,value",
    [
        ("title", 200, "x" * 201),
        ("description", 8000, "x" * 8001),
        ("category", 100, "x" * 101),
        ("tags", 100, ["x" * 101]),
        ("tags", 18, [f"tag-{index}" for index in range(19)]),
    ],
)
def test_import_names_the_field_and_limit_of_an_over_limit_legacy_export(
    client, temp_db, api_key, field, limit, value
):
    resp = client.post(
        "/api/playbooks/import",
        headers=_headers(api_key),
        json={**LEGACY_EXPORT, field: value},
    )
    assert resp.status_code == 422
    detail = json.dumps(resp.json())
    # Names the field, the limit, and says it was not truncated.
    assert field.split("[")[0] in detail
    assert str(limit) in detail
    assert "truncat" in detail
    assert client.get("/api/playbooks", headers=_headers(api_key)).json() == []


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
    # A partial write must advance updated_at even though the route now assigns
    # it explicitly instead of relying on a column onupdate.
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


def test_a_legacy_whole_second_timestamp_still_satisfies_its_own_precondition(client, temp_db, api_key):
    playbook_id = _insert_legacy_playbook(temp_db, datetime(2026, 1, 1, 12, 0, 0))

    # Older rows carry SQLite's whole-second text, so the read loses the
    # fraction. It must still round-trip into the precondition.
    read = client.get(f"/api/playbooks/{playbook_id}", headers=_headers(api_key)).json()
    assert read["updated_at"].endswith(".000000")
    resp = client.put(
        f"/api/playbooks/{playbook_id}",
        headers=_headers(api_key),
        json={"title": "Renamed", "expected_updated_at": read["updated_at"]},
    )
    assert resp.status_code == 200
    assert _parse(resp.json()["updated_at"]) > _parse(read["updated_at"])


# --- share and revoke must not move updated_at backward --------------------


LEGACY_GRAPH = json.dumps(
    {"nodes": [{"id": "step-1", "type": "step", "label": "Review"}], "edges": []}
)


def _fresh_second() -> datetime:
    """The start of a freshly begun whole second.

    The regression needs the legacy row and the share/revoke write inside one
    real second: that is when SQLite's ``CURRENT_TIMESTAMP`` would have rewritten
    the same whole-second text. Waiting for the boundary costs at most one
    second and keeps the scenario deterministic.
    """
    now = utcnow()
    time.sleep(1 - now.microsecond / 1_000_000)
    return utcnow().replace(microsecond=0)


def _insert_legacy_playbook(temp_db, second: datetime, *, share_token=None) -> int:
    """Insert a row the way the pre-hardening API wrote it: whole-second text."""
    stamp = second.strftime("%Y-%m-%d %H:%M:%S")
    with temp_db() as session:
        result = session.execute(
            text(
                "INSERT INTO playbooks "
                "(title, content_markdown, graph_json, share_token, is_deleted, created_at, updated_at) "
                "VALUES ('Legacy', :content, :graph, :token, 0, :stamp, :stamp)"
            ),
            {
                "content": CONTENT,
                "graph": LEGACY_GRAPH,
                "token": share_token,
                "stamp": stamp,
            },
        )
        session.commit()
        return int(result.lastrowid)


def _stored_updated_at(temp_db, playbook_id: int) -> datetime:
    from api.orm_models import Playbook

    with temp_db() as session:
        return session.get(Playbook, playbook_id).updated_at


def test_a_share_cannot_move_updated_at_backward_past_a_human_edit(client, temp_db, api_key):
    # The bot reads a legacy whole-second timestamp.
    playbook_id = _insert_legacy_playbook(temp_db, _fresh_second())
    bot_read = client.get(f"/api/playbooks/{playbook_id}", headers=_headers(api_key)).json()

    # A human edits, then creates a share link, in the same second.
    human = client.put(
        f"/api/playbooks/{playbook_id}", headers=_headers(api_key), json={"title": "Human edit"}
    )
    assert human.status_code == 200
    assert _parse(human.json()["updated_at"]) > _parse(bot_read["updated_at"])

    shared = client.post(f"/api/playbooks/{playbook_id}/share", headers=_headers(api_key))
    assert shared.status_code == 200

    after_share = client.get(f"/api/playbooks/{playbook_id}", headers=_headers(api_key)).json()
    assert _parse(after_share["updated_at"]) > _parse(human.json()["updated_at"])

    # The bot's stale write must not slip past the share back to the version it read.
    stale = client.put(
        f"/api/playbooks/{playbook_id}",
        headers=_headers(api_key),
        json={"title": "Bot edit", "expected_updated_at": bot_read["updated_at"]},
    )
    assert stale.status_code == 409
    assert client.get(f"/api/playbooks/{playbook_id}", headers=_headers(api_key)).json()["title"] == "Human edit"


def test_a_revoke_cannot_move_updated_at_backward_past_a_human_edit(client, temp_db, api_key):
    playbook_id = _insert_legacy_playbook(
        temp_db, _fresh_second(), share_token=str(uuid.uuid4())
    )
    bot_read = client.get(f"/api/playbooks/{playbook_id}", headers=_headers(api_key)).json()

    human = client.put(
        f"/api/playbooks/{playbook_id}", headers=_headers(api_key), json={"title": "Human edit"}
    )
    assert human.status_code == 200

    revoked = client.delete(f"/api/playbooks/{playbook_id}/share", headers=_headers(api_key))
    assert revoked.status_code == 204

    after_revoke = _stored_updated_at(temp_db, playbook_id)
    assert after_revoke > _parse(human.json()["updated_at"])

    stale = client.put(
        f"/api/playbooks/{playbook_id}",
        headers=_headers(api_key),
        json={"title": "Bot edit", "expected_updated_at": bot_read["updated_at"]},
    )
    assert stale.status_code == 409
    assert client.get(f"/api/playbooks/{playbook_id}", headers=_headers(api_key)).json()["title"] == "Human edit"


def test_no_playbook_write_path_moves_updated_at_backward(client, temp_db, api_key):
    playbook_id = _create(client, api_key, tags=["draft"]).json()["id"]
    seen = [_stored_updated_at(temp_db, playbook_id)]

    def step(resp, expected_status):
        assert resp.status_code == expected_status, resp.text
        seen.append(_stored_updated_at(temp_db, playbook_id))
        assert seen[-1] > seen[-2], f"write went backward: {seen[-2]} -> {seen[-1]}"

    step(client.put(f"/api/playbooks/{playbook_id}", headers=_headers(api_key), json={"title": "Edited"}), 200)
    step(client.post(f"/api/playbooks/{playbook_id}/share", headers=_headers(api_key)), 200)
    step(client.put(f"/api/playbooks/{playbook_id}", headers=_headers(api_key), json={"tags": ["reviewed"]}), 200)
    step(client.delete(f"/api/playbooks/{playbook_id}/share", headers=_headers(api_key)), 204)
    step(client.post(f"/api/playbooks/{playbook_id}/share", headers=_headers(api_key)), 200)
    step(client.delete(f"/api/playbooks/{playbook_id}", headers=_headers(api_key)), 204)

    # Creates are new rows, so they only have to agree with what was asked for.
    created = _create(client, api_key, title="Fresh").json()
    assert _microseconds(created["updated_at"]) == 6
    assert created["updated_at"] == created["created_at"]
    imported = client.post(
        "/api/playbooks/import", headers=_headers(api_key), json=IMPORT_BASE
    ).json()
    assert _microseconds(imported["updated_at"]) == 6
    assert imported["updated_at"] == imported["created_at"]


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
