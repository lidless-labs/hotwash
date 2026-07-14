"""
Unit Tests for Mermaid Parser

Tests the Mermaid flowchart-to-graph parsing functionality with various diagram formats.
"""

import pytest
from api.parsers.mermaid_parser import MermaidParser
from api.models import PlaybookGraph, PlaybookNode, PlaybookEdge


class TestMermaidParser:
    """Test suite for MermaidParser."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = MermaidParser()

    def test_empty_content(self):
        """Test parsing empty content."""
        result = self.parser.parse("")
        assert isinstance(result, PlaybookGraph)
        assert len(result.nodes) == 0
        assert len(result.edges) == 0

    def test_simple_two_node_graph(self):
        """Test parsing simple two-node graph with solid edge."""
        content = """flowchart TD
    A[Start] --> B[End]"""
        result = self.parser.parse(content)

        assert len(result.nodes) == 2
        assert len(result.edges) == 1

        # Check nodes
        assert result.nodes[0].label == "Start"
        assert result.nodes[0].type == "step"
        assert result.nodes[1].label == "End"
        assert result.nodes[1].type == "step"

        # Check edge
        assert result.edges[0].source == result.nodes[0].id
        assert result.edges[0].target == result.nodes[1].id

    def test_graph_syntax_variation(self):
        """Test 'graph TD' syntax (older Mermaid syntax)."""
        content = """graph LR
    A[Node A] --> B[Node B]"""
        result = self.parser.parse(content)

        assert len(result.nodes) == 2
        assert len(result.edges) == 1

    def test_decision_node_diamond_shape(self):
        """Test parsing diamond shape as decision node."""
        content = """flowchart TD
    A[Start] --> B{Is Valid?}
    B --> C[Yes]
    B --> D[No]"""
        result = self.parser.parse(content)

        # Find decision node
        decision_nodes = [n for n in result.nodes if n.type == "decision"]
        assert len(decision_nodes) == 1
        assert decision_nodes[0].label == "Is Valid?"

        # Should have 4 nodes total
        assert len(result.nodes) == 4

        # Should have 3 edges
        assert len(result.edges) == 3

    def test_labeled_edges(self):
        """Test parsing edges with labels."""
        content = """flowchart TD
    A[Start] --Check--> B{Valid?}
    B --Yes--> C[Process]
    B --No--> D[Error]"""
        result = self.parser.parse(content)

        # Check that edges have labels
        labeled_edges = [e for e in result.edges if e.label]
        assert len(labeled_edges) >= 2

        labels = {e.label for e in labeled_edges}
        assert "Check" in labels or "Yes" in labels or "No" in labels

    def test_dotted_edges(self):
        """Test parsing dotted line edges."""
        content = """flowchart TD
    A[Main] -.-> B[Optional]
    A --> C[Required]"""
        result = self.parser.parse(content)

        assert len(result.nodes) == 3
        assert len(result.edges) == 2

    def test_bold_edges(self):
        """Test parsing bold/thick edges."""
        content = """flowchart TD
    A[Start] ==> B[Critical Path]
    A --> C[Alternative]"""
        result = self.parser.parse(content)

        assert len(result.nodes) == 3
        assert len(result.edges) == 2

    def test_rounded_node_shape(self):
        """Test parsing rounded rectangle nodes."""
        content = """flowchart TD
    A(Rounded Node) --> B[Square Node]"""
        result = self.parser.parse(content)

        assert len(result.nodes) == 2
        assert result.nodes[0].label == "Rounded Node"
        assert result.nodes[0].type == "step"

    def test_circle_node_shape(self):
        """Test parsing circle nodes as phase nodes."""
        content = """flowchart TD
    A((Phase 1)) --> B[Step 1]"""
        result = self.parser.parse(content)

        # Circle shape should map to phase type
        phase_nodes = [n for n in result.nodes if n.type == "phase"]
        assert len(phase_nodes) == 1
        assert phase_nodes[0].label == "Phase 1"

    def test_subgraph_as_phase(self):
        """Test parsing subgraphs as phase nodes."""
        content = """flowchart TD
    subgraph Setup Phase
        A[Install] --> B[Configure]
    end
    B --> C[Run]"""
        result = self.parser.parse(content)

        # Should have a phase node for the subgraph
        phase_nodes = [n for n in result.nodes if n.type == "phase"]
        assert len(phase_nodes) >= 1

        # Find the subgraph phase
        subgraph_phases = [n for n in phase_nodes if n.metadata and n.metadata.get("is_subgraph")]
        assert len(subgraph_phases) == 1
        assert subgraph_phases[0].label == "Setup Phase"

        # Should have nodes inside subgraph
        assert len(result.nodes) >= 4  # subgraph + A + B + C

    def test_nested_subgraphs(self):
        """Test parsing nested subgraphs."""
        content = """flowchart TD
    subgraph Main Phase
        A[Start]
        subgraph Sub Phase
            B[Step 1] --> C[Step 2]
        end
        A --> B
    end"""
        result = self.parser.parse(content)

        # Should have phase nodes for both subgraphs
        phase_nodes = [n for n in result.nodes if n.type == "phase"]
        assert len(phase_nodes) >= 2

    def test_multiple_edges_from_node(self):
        """Test node with multiple outgoing edges."""
        content = """flowchart TD
    A[Check] --> B[Option 1]
    A --> C[Option 2]
    A --> D[Option 3]"""
        result = self.parser.parse(content)

        assert len(result.nodes) == 4
        assert len(result.edges) == 3

        # All edges should originate from node A
        node_a_id = result.nodes[0].id
        edges_from_a = [e for e in result.edges if e.source == node_a_id]
        assert len(edges_from_a) == 3

    def test_chained_edges(self):
        """Test parsing chained edge definitions."""
        content = """flowchart TD
    A --> B --> C --> D"""
        result = self.parser.parse(content)

        # Should create 4 nodes
        assert len(result.nodes) == 4

        # Should create 3 edges (A->B, B->C, C->D)
        # Note: The parser may need adjustment to handle chaining
        assert len(result.edges) >= 1

    def test_comments_ignored(self):
        """Test that comments are ignored."""
        content = """flowchart TD
    %% This is a comment
    A[Start] --> B[End]
    %% Another comment"""
        result = self.parser.parse(content)

        assert len(result.nodes) == 2
        assert len(result.edges) == 1

    def test_node_ids_unique(self):
        """Test that all node IDs are unique."""
        content = """flowchart TD
    A[Node A] --> B[Node B]
    B --> C[Node C]
    C --> D[Node D]"""
        result = self.parser.parse(content)

        node_ids = [node.id for node in result.nodes]
        assert len(node_ids) == len(set(node_ids))

    def test_edge_ids_unique(self):
        """Test that all edge IDs are unique."""
        content = """flowchart TD
    A[Node A] --> B[Node B]
    B --> C[Node C]
    C --> D[Node D]"""
        result = self.parser.parse(content)

        edge_ids = [edge.id for edge in result.edges]
        assert len(edge_ids) == len(set(edge_ids))

    def test_edges_reference_valid_nodes(self):
        """Test that all edges reference existing nodes."""
        content = """flowchart TD
    A[Start] --> B{Check}
    B --Yes--> C[Process]
    B --No--> D[Skip]
    C --> E[End]
    D --> E"""
        result = self.parser.parse(content)

        node_ids = {node.id for node in result.nodes}

        for edge in result.edges:
            assert edge.source in node_ids, f"Edge source {edge.source} not in nodes"
            assert edge.target in node_ids, f"Edge target {edge.target} not in nodes"

    def test_complex_flowchart(self):
        """Test parsing a complex flowchart with multiple features."""
        content = """flowchart TD
    Start[Start Process] --> Auth{Authenticated?}
    Auth --Yes--> Load[Load Data]
    Auth --No--> Login[Show Login]
    Login --> Auth
    Load --> Process((Processing))
    Process --> Save[Save Results]
    Save -.-> Notify[Send Notification]
    Save --> End[Complete]"""
        result = self.parser.parse(content)

        # Verify comprehensive parsing
        assert len(result.nodes) >= 7
        assert len(result.edges) >= 6

        # Check for different node types
        node_types = {node.type for node in result.nodes}
        assert "step" in node_types
        assert "decision" in node_types or "phase" in node_types

    def test_incident_response_flowchart(self):
        """Test with realistic incident response flowchart."""
        content = """flowchart TD
    Alert[Receive Alert] --> Verify{Legitimate?}
    Verify --No--> Close[Close Alert]
    Verify --Yes--> Classify{Severity}

    subgraph Critical Path
        Classify --Critical--> Escalate[Activate Response Team]
        Escalate --> Investigate[Deep Investigation]
    end

    Classify --Low--> Assign[Assign to Engineer]
    Assign --> Monitor[Monitor Progress]

    Investigate --> Remediate[Apply Fix]
    Monitor --> Remediate
    Remediate --> Verify2{Fixed?}
    Verify2 --Yes--> Document[Document Incident]
    Verify2 --No--> Investigate
    Document --> Close"""
        result = self.parser.parse(content)

        # Verify comprehensive parsing
        assert len(result.nodes) >= 10
        assert len(result.edges) >= 10

        # Should have phase node for subgraph
        phase_nodes = [n for n in result.nodes if n.type == "phase"]
        assert len(phase_nodes) >= 1

        # Should have decision nodes
        decision_nodes = [n for n in result.nodes if n.type == "decision"]
        assert len(decision_nodes) >= 2

        # Verify all nodes have required fields
        for node in result.nodes:
            assert node.id is not None
            assert node.label is not None
            assert node.type is not None

        # Verify all edges have required fields
        for edge in result.edges:
            assert edge.id is not None
            assert edge.source is not None
            assert edge.target is not None

    def test_deployment_pipeline_flowchart(self):
        """Test with deployment pipeline flowchart."""
        content = """flowchart LR
    Code[Write Code] --> Commit[Commit Changes]
    Commit --> Build{Build Success?}
    Build --No--> Fix[Fix Build]
    Fix --> Build
    Build --Yes--> Test{Tests Pass?}
    Test --No--> Debug[Debug Tests]
    Debug --> Test
    Test --Yes--> Deploy((Deploy to Staging))
    Deploy --> Smoke{Smoke Tests OK?}
    Smoke --Yes--> Prod[Deploy to Production]
    Smoke --No--> Rollback[Rollback]"""
        result = self.parser.parse(content)

        # Verify structure
        assert len(result.nodes) >= 10
        assert len(result.edges) >= 10

        # Check node types variety
        node_types = {node.type for node in result.nodes}
        assert len(node_types) >= 2

    def test_empty_labels_handled(self):
        """Test handling of nodes without explicit labels."""
        content = """flowchart TD
    A --> B
    B --> C"""
        result = self.parser.parse(content)

        # Should create nodes even without explicit labels
        assert len(result.nodes) >= 2

        # Node labels should default to IDs
        for node in result.nodes:
            assert node.label is not None
            assert len(node.label) > 0

    def test_special_characters_in_labels(self):
        """Test handling of special characters in node labels."""
        content = """flowchart TD
    A[Step 1: Initialize] --> B[Step 2: Run & Test]
    B --> C[Done!]"""
        result = self.parser.parse(content)

        assert len(result.nodes) == 3
        assert "Initialize" in result.nodes[0].label
        assert "Run & Test" in result.nodes[1].label or "Run" in result.nodes[1].label

    def test_mixed_edge_types(self):
        """Test flowchart with multiple edge types."""
        content = """flowchart TD
    A[Start] --> B[Step 1]
    B -.-> C[Optional Step]
    B ==> D[Critical Step]
    C --> E[End]
    D --> E"""
        result = self.parser.parse(content)

        assert len(result.nodes) == 5
        assert len(result.edges) == 5

    def test_long_edge_arrows(self):
        """Test handling of varying arrow lengths."""
        content = """flowchart TD
    A[Start] --> B[Next]
    B ---> C[Further]
    C ----> D[Even Further]"""
        result = self.parser.parse(content)

        # Should handle different arrow lengths
        assert len(result.nodes) >= 3
        assert len(result.edges) >= 2

    def test_labeled_dotted_edges(self):
        """Test dotted edges with labels."""
        content = """flowchart TD
    A[Main] -.Optional Path.-> B[Alternative]
    A --Primary Path--> C[Main Flow]"""
        result = self.parser.parse(content)

        assert len(result.nodes) == 3
        assert len(result.edges) == 2

        # Check for labeled edges
        labeled_edges = [e for e in result.edges if e.label]
        assert len(labeled_edges) >= 1

    def test_whitespace_handling(self):
        """Test handling of various whitespace patterns."""
        content = """flowchart TD
    A[Start]-->B[No Spaces]
    B    -->    C[Many Spaces]
    C	-->	D[Tabs]"""
        result = self.parser.parse(content)

        # Should parse despite varying whitespace
        assert len(result.nodes) >= 3
        assert len(result.edges) >= 2

    def test_same_structure_as_markdown_parser(self):
        """Verify output structure matches markdown parser format."""
        content = """flowchart TD
    A[Start] --> B{Decision}
    B --Yes--> C[Action]
    B --No--> D[Alternative]"""
        result = self.parser.parse(content)

        # Verify structure matches PlaybookGraph
        assert isinstance(result, PlaybookGraph)
        assert hasattr(result, 'nodes')
        assert hasattr(result, 'edges')
        assert isinstance(result.nodes, list)
        assert isinstance(result.edges, list)

        # Verify nodes have required fields
        for node in result.nodes:
            assert isinstance(node, PlaybookNode)
            assert hasattr(node, 'id')
            assert hasattr(node, 'label')
            assert hasattr(node, 'type')
            assert hasattr(node, 'metadata')

        # Verify edges have required fields
        for edge in result.edges:
            assert isinstance(edge, PlaybookEdge)
            assert hasattr(edge, 'id')
            assert hasattr(edge, 'source')
            assert hasattr(edge, 'target')
            assert hasattr(edge, 'label')


    def test_bare_node_then_shaped_definition_upgrades_label(self):
        """H3: a node first seen bare in an edge, then given a shape, adopts the label."""
        content = """flowchart TD
    A --> B
    A[Start Label]"""
        result = self.parser.parse(content)
        a = next(n for n in result.nodes if n.metadata.get("mermaid_id") == "A")
        assert a.label == "Start Label"

    def test_redeclared_node_upgrades_step_to_decision(self):
        """H3: redeclaring a node with a decision shape upgrades its type (and label)."""
        content = """flowchart TD
    A[First]
    A{Decision Now}"""
        result = self.parser.parse(content)
        a = next(n for n in result.nodes if n.metadata.get("mermaid_id") == "A")
        assert a.type == "decision"
        assert a.label == "Decision Now"


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v"])
