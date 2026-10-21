"""Tests for first-run database seeding."""

from __future__ import annotations

from pathlib import Path

import pytest

from api.orm_models import Playbook, WazuhMapping
from api.seed import (
    DEFAULT_PLAYBOOKS_DIR,
    SEED_WAZUH_MAPPING_NAME,
    SEED_WAZUH_PLAYBOOK_TITLE,
    get_playbooks_seed_dir,
    seed,
    seed_db,
    seed_wazuh_mappings,
)


def test_default_playbooks_seed_dir_points_to_shipped_data():
    assert get_playbooks_seed_dir() == DEFAULT_PLAYBOOKS_DIR
    assert DEFAULT_PLAYBOOKS_DIR.is_dir()
    assert any(DEFAULT_PLAYBOOKS_DIR.glob("*.md"))


def test_seed_inserts_shipped_playbooks_on_empty_db(temp_db, monkeypatch):
    monkeypatch.delenv("HOTWASH_PLAYBOOK_SEED_DIR", raising=False)
    monkeypatch.delenv("PLAYBOOK_FORGE_PLAYBOOK_SEED_DIR", raising=False)

    with temp_db() as session:
        inserted = seed(session)
        titles = [row[0] for row in session.query(Playbook.title).all()]

    assert inserted >= 1
    assert SEED_WAZUH_PLAYBOOK_TITLE in titles


def test_seed_uses_configured_playbooks_dir(temp_db, monkeypatch, tmp_path):
    custom_dir = tmp_path / "custom-playbooks"
    custom_dir.mkdir()
    (custom_dir / "custom.md").write_text(
        "# Custom Seed Playbook\n\nA short description for testing.\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HOTWASH_PLAYBOOK_SEED_DIR", str(custom_dir))

    with temp_db() as session:
        inserted = seed(session)
        playbook = session.query(Playbook).one()

    assert inserted == 1
    assert playbook.title == "Custom Seed Playbook"


def test_seed_skips_when_directory_missing(temp_db, monkeypatch, tmp_path):
    missing_dir = tmp_path / "missing-playbooks"
    monkeypatch.setenv("HOTWASH_PLAYBOOK_SEED_DIR", str(missing_dir))

    with temp_db() as session:
        inserted = seed(session)
        count = session.query(Playbook).count()

    assert inserted == 0
    assert count == 0


def test_seed_wazuh_mapping_created_after_playbook_seed(temp_db, monkeypatch):
    monkeypatch.delenv("HOTWASH_PLAYBOOK_SEED_DIR", raising=False)
    monkeypatch.delenv("PLAYBOOK_FORGE_PLAYBOOK_SEED_DIR", raising=False)
    monkeypatch.setenv("HOTWASH_WAZUH_SEED_SECRET", "test-seed-secret")

    with temp_db() as session:
        seed(session)
        mappings_inserted = seed_wazuh_mappings(session)
        mapping = session.query(WazuhMapping).one()

    assert mappings_inserted == 1
    assert mapping.name == SEED_WAZUH_MAPPING_NAME
    assert mapping.enabled is True


def test_seed_db_wrapper_seeds_playbooks_and_mappings(temp_db, monkeypatch):
    monkeypatch.delenv("HOTWASH_PLAYBOOK_SEED_DIR", raising=False)
    monkeypatch.delenv("PLAYBOOK_FORGE_PLAYBOOK_SEED_DIR", raising=False)
    monkeypatch.setenv("HOTWASH_WAZUH_SEED_SECRET", "test-seed-secret")
    monkeypatch.setattr("api.seed.SessionLocal", temp_db)

    inserted = seed_db()

    with temp_db() as session:
        playbook_count = session.query(Playbook).count()
        mapping_count = session.query(WazuhMapping).count()

    assert inserted >= 1
    assert playbook_count >= 1
    assert mapping_count == 1


def test_seed_includes_suspicious_binary_triage_playbook(temp_db, monkeypatch):
    import json

    monkeypatch.delenv("HOTWASH_PLAYBOOK_SEED_DIR", raising=False)
    monkeypatch.delenv("PLAYBOOK_FORGE_PLAYBOOK_SEED_DIR", raising=False)

    with temp_db() as session:
        seed(session)
        playbook = (
            session.query(Playbook).filter(Playbook.title == "Suspicious Binary Triage").one()
        )
        graph = json.loads(playbook.graph_json)

    labels = " ".join(node["label"] for node in graph["nodes"]).lower()
    decisions = [n for n in graph["nodes"] if n["type"] == "decision"]
    markdown = playbook.content_markdown

    assert len(decisions) == 4
    assert "run_analyzer" in labels
    assert "circlhashlookup_1_1" in labels and "misp_2_1" in labels
    assert "means unknown" in markdown
    assert "never evidence that a file is suspicious" in markdown
    assert "never evidence that it is clean" in markdown
    assert "relayed approvals" in markdown.lower() or "relayed by another" in markdown.lower()
    # The playbook must not give Hotwash a command-runner capability.
    assert "does not run commands on hosts" in markdown
