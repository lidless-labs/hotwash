"""Regression coverage for graph -> steps / export correctness (H4, H5)."""

from __future__ import annotations

import json

from api.routers.export import _to_markdown_from_graph
from api.services.executions import build_steps_from_playbook


def test_export_includes_subgraph_children_without_phase_edges():
    """H4: a Mermaid subgraph phase groups children via metadata.subgraph, not
    edges. The round-trip export must still emit those steps, not an empty phase."""
    graph = {
        "nodes": [
            {"id": "p1", "label": "Setup", "type": "phase", "metadata": {"is_subgraph": True}},
            {"id": "n1", "label": "Init", "type": "step", "metadata": {"subgraph": "p1"}},
            {"id": "n2", "label": "Config", "type": "step", "metadata": {"subgraph": "p1"}},
        ],
        # only a child-to-child edge; the phase itself has no outgoing edge
        "edges": [{"source": "n1", "target": "n2"}],
    }

    md = _to_markdown_from_graph(graph)

    assert "## Phase: Setup" in md
    assert "- Step: Init" in md
    assert "- Step: Config" in md


def test_build_steps_deduplicates_node_ids():
    """H5: a duplicate node id must not create a second, unreachable step that
    inflates steps_total so the run can never reach 100%."""
    from api.orm_models import Playbook

    graph = {
        "nodes": [
            {"id": "n1", "label": "First", "type": "step"},
            {"id": "n1", "label": "Duplicate", "type": "step"},
            {"id": "n2", "label": "Second", "type": "step"},
        ],
        "edges": [],
    }
    playbook = Playbook(title="dup", category="IR", content_markdown="# dup", graph_json=json.dumps(graph))

    steps = build_steps_from_playbook(playbook)

    node_ids = [s["node_id"] for s in steps]
    assert node_ids == ["n1", "n2"]  # deduped, first wins
    assert next(s for s in steps if s["node_id"] == "n1")["node_label"] == "First"
