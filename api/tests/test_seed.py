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

    assert decisions
    assert "run_analyzer" in labels
    assert "circlhashlookup_1_1" in labels and "misp_2_1" in labels
    assert "means unknown" in markdown
    assert "never evidence that a file is suspicious" in markdown
    assert "never evidence that it is clean" in markdown
    assert "relayed approvals" in markdown.lower() or "relayed by another" in markdown.lower()
    # The playbook must not give Hotwash a command-runner capability.
    assert "does not run commands on hosts" in markdown


def test_suspicious_binary_triage_approval_gate_is_a_decision_node():
    from api.parsers.markdown_parser import MarkdownParser

    path = DEFAULT_PLAYBOOKS_DIR / "suspicious-binary-triage.md"
    markdown = path.read_text(encoding="utf-8")
    graph = MarkdownParser().parse(markdown)
    nodes = {n.id: n for n in graph.nodes}

    gate_header = next(n for n in graph.nodes if n.label == "SOC Owner Approval Gate")
    # The header leads to the unauthenticated-approval warning step, then the decision.
    warning = nodes[next(e.target for e in graph.edges if e.source == gate_header.id)]
    assert warning.type == "step"
    assert "does not authenticate approvers" in warning.label
    gate = nodes[next(e.target for e in graph.edges if e.source == warning.id)]
    assert gate.type == "decision"
    assert "SOC owner's own direct approval message" in gate.label

    branches = [nodes[e.target] for e in graph.edges if e.source == gate.id]
    assert {e.label for e in graph.edges if e.source == gate.id} == {"yes", "no"}
    assert all(b.type == "step" for b in branches)

    # The old numbered-list gate steps must be gone.
    assert not any(
        n.type == "step" and n.label.startswith("The SOC owner records approve or reject")
        for n in graph.nodes
    )
    assert "does not authenticate approvers" in markdown


def _parsed_triage_graph():
    from api.parsers.markdown_parser import MarkdownParser

    path = DEFAULT_PLAYBOOKS_DIR / "suspicious-binary-triage.md"
    graph = MarkdownParser().parse(path.read_text(encoding="utf-8"))
    nodes = {n.id: n for n in graph.nodes}
    out = {}
    for e in graph.edges:
        out.setdefault(e.source, []).append(e)
    return graph, nodes, out


def _decision(nodes, fragment):
    return next(n for n in nodes.values() if n.type == "decision" and fragment in n.label)


def test_triage_decisions_have_exactly_yes_and_no_edges_with_one_step_each():
    graph, nodes, out = _parsed_triage_graph()
    decisions = [n for n in graph.nodes if n.type == "decision"]
    assert decisions
    for d in decisions:
        labelled = [e.label for e in out[d.id] if e.label]
        assert sorted(labelled) == ["no", "yes"], (d.label, labelled)


def test_triage_terminal_branches_say_stop_and_never_propose_false_positive():
    graph, nodes, out = _parsed_triage_graph()
    for fragment in ("MISP analyzer reported a hit", "verdict is mismatch", "package-unknown"):
        d = _decision(nodes, fragment)
        yes = next(nodes[e.target] for e in out[d.id] if e.label == "yes")
        text = yes.label.lower()
        assert "stop here" in text
        assert "do not propose a false positive" in text
    no_match = _decision(nodes, "is match and there is no MISP hit")
    no_branch = next(nodes[e.target] for e in out[no_match.id] if e.label == "no")
    assert "stop here" in no_branch.label.lower()
    assert "do not draft a false-positive" in no_branch.label.lower()
    # Only the match branch drafts a false-positive entry.
    drafters = [n for n in graph.nodes if n.label.lower().startswith("draft a narrow")]
    assert len(drafters) == 1
    assert [e.label for e in out[no_match.id] if e.target == drafters[0].id] == ["yes"]


def test_triage_gate_no_branch_cannot_reach_case_closure_without_another_decision():
    graph, nodes, out = _parsed_triage_graph()
    gate = _decision(nodes, "direct approval message")
    close_steps = [n for n in graph.nodes if "close the thehive case" in n.label.lower()]
    assert len(close_steps) == 1
    closer = close_steps[0]

    # Walk from the gate's no branch, never expanding past a decision node.
    start = next(e.target for e in out[gate.id] if e.label == "no")
    seen, stack, reached_decisions = set(), [start], set()
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        assert cur != closer.id
        if nodes[cur].type == "decision":
            reached_decisions.add(cur)
            continue
        stack.extend(e.target for e in out.get(cur, []))
    assert reached_decisions, "the no branch must hit another decision before Close Out"

    # The closure step is only the yes branch of the Close Out decision.
    close_decision = _decision(nodes, "SOC owner approved directly")
    yes = next(e.target for e in out[close_decision.id] if e.label == "yes")
    assert yes == closer.id
    no = next(nodes[e.target] for e in out[close_decision.id] if e.label == "no")
    assert "leave the case open" in no.label.lower()
    assert "close the thehive case" not in no.label.lower()


def test_triage_unauthenticated_approval_warning_is_a_parsed_node():
    graph, nodes, out = _parsed_triage_graph()
    labels = [n.label for n in graph.nodes]
    assert any("does not authenticate approvers" in l for l in labels)
    gate = _decision(nodes, "direct approval message")
    assert "does not authenticate" in gate.label
    # The warning step sits immediately before the gate decision.
    pred = next(e.source for e in graph.edges if e.target == gate.id)
    assert "does not authenticate approvers" in nodes[pred].label
    assert any("Hashlookup miss" in l and "unknown" in l for l in labels)
