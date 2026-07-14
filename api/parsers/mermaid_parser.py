"""
Mermaid Parser for Hotwash

Converts Mermaid flowchart syntax into a node/edge graph format compatible with React Flow.

Parsing Rules:
- Supports 'flowchart TD/LR' and 'graph TD/LR' syntax
- Node shapes map to types: [] -> step, {} -> decision, () -> step, (()) -> phase
- Edge types: --> (solid), --text--> (labeled), -.-> (dotted), ==> (bold)
- Subgraphs become phase/group nodes
- Returns same JSON structure as markdown parser
"""

import re
from typing import List, Dict, Optional, Tuple
from api.models import PlaybookNode, PlaybookEdge, PlaybookGraph


class MermaidParser:
    """Parser for converting Mermaid flowcharts to graph format."""

    # Node shape patterns
    NODE_PATTERNS = {
        r'\[([^\]]+)\]': 'step',           # [text] -> square/step
        r'\{([^\}]+)\}': 'decision',       # {text} -> diamond/decision
        r'\(\(([^\)]+)\)\)': 'phase',      # ((text)) -> circle/phase
        r'\(([^\)]+)\)': 'step',           # (text) -> rounded/step
        r'>([^\]]+)\]': 'step',            # >text] -> flag/step
        r'\[\[([^\]]+)\]\]': 'step',       # [[text]] -> subroutine/step
    }

    # Edge patterns
    EDGE_PATTERNS = [
        # Labeled edges with various arrow types
        (r'--\s*([^-]+?)\s*-->', 'solid'),      # --text-->
        (r'-\.\s*([^-]+?)\s*\.->', 'dotted'),    # -.text.->
        (r'==\s*([^=]+?)\s*==>', 'bold'),        # ==text==>
        # Simple edges
        (r'-->', 'solid'),                       # -->
        (r'-\.->', 'dotted'),                    # .->
        (r'==>', 'bold'),                        # ==>
        (r'--->', 'solid'),                      # --->
        (r'---->', 'solid'),                     # ---->
    ]

    EDGE_RE = re.compile(
        r'--\s*(?P<solid_label>[^->\n]+?)\s*-->'
        r'|-\.\s*(?P<dotted_label>[^.\n]+?)\s*\.->'
        r'|==\s*(?P<bold_label>[^=\n]+?)\s*==>'
        r'|(?P<solid>-{2,}>)'
        r'|(?P<dotted>-\.->)'
        r'|(?P<bold>==>)'
    )

    def __init__(self):
        """Initialize the Mermaid parser."""
        self.nodes: List[PlaybookNode] = []
        self.edges: List[PlaybookEdge] = []
        self.node_counter = 0
        self.edge_counter = 0
        self.node_id_map: Dict[str, str] = {}  # Maps mermaid IDs to our node IDs
        self.subgraph_stack: List[Tuple[str, str]] = []  # Stack of (id, label) for nested subgraphs
        self.current_subgraph: Optional[str] = None

    def parse(self, content: str) -> PlaybookGraph:
        """
        Parse Mermaid flowchart content into a graph.

        Args:
            content: Mermaid flowchart string

        Returns:
            PlaybookGraph with nodes and edges
        """
        # Reset state for fresh parse
        self.nodes = []
        self.edges = []
        self.node_counter = 0
        self.edge_counter = 0
        self.node_id_map = {}
        self.subgraph_stack = []
        self.current_subgraph = None

        lines = content.split('\n')
        i = 0

        # Skip to flowchart/graph declaration
        while i < len(lines):
            line = lines[i].strip()
            if line.startswith('flowchart') or line.startswith('graph'):
                i += 1
                break
            i += 1

        # Parse lines
        while i < len(lines):
            line = lines[i].strip()

            # Skip empty lines and comments
            if not line or line.startswith('%%'):
                i += 1
                continue

            # Handle subgraph start
            if line.startswith('subgraph'):
                self._parse_subgraph_start(line)
                i += 1
                continue

            # Handle subgraph end
            if line == 'end':
                self._parse_subgraph_end()
                i += 1
                continue

            # Parse node definitions and edges
            self._parse_statement(line)
            i += 1

        return PlaybookGraph(nodes=self.nodes, edges=self.edges)

    def _parse_subgraph_start(self, line: str) -> None:
        """
        Parse subgraph declaration and create a phase node.

        Args:
            line: Subgraph line (e.g., "subgraph Setup Phase")
        """
        # Extract subgraph label
        match = re.match(r'subgraph\s+(.+)', line)
        if not match:
            return

        label = match.group(1).strip()

        # Create phase node for subgraph
        node_id = self._create_node_id()
        node = PlaybookNode(
            id=node_id,
            label=label,
            type="phase",
            metadata={"is_subgraph": True, "level": len(self.subgraph_stack) + 1}
        )
        self.nodes.append(node)

        # Push to stack
        self.subgraph_stack.append((node_id, label))
        self.current_subgraph = node_id

    def _parse_subgraph_end(self) -> None:
        """Handle end of subgraph block."""
        if self.subgraph_stack:
            self.subgraph_stack.pop()
            self.current_subgraph = self.subgraph_stack[-1][0] if self.subgraph_stack else None

    def _parse_statement(self, line: str) -> None:
        """
        Parse a Mermaid statement (node definition or edge).

        Args:
            line: Single line from Mermaid diagram
        """
        if self.EDGE_RE.search(line):
            self._parse_edge_statement(line)
        else:
            self._parse_node_definition(line)

    def _parse_edge_statement(self, line: str) -> None:
        """
        Parse a line containing an edge (e.g., "A-->B" or "A--text-->B").

        Args:
            line: Line containing edge definition
        """
        matches = list(self.EDGE_RE.finditer(line))
        if not matches:
            return

        node_parts = []
        cursor = 0
        for match in matches:
            node_parts.append(line[cursor:match.start()].strip())
            cursor = match.end()
        node_parts.append(line[cursor:].strip())

        if len(node_parts) != len(matches) + 1:
            return

        for idx, match in enumerate(matches):
            source_part = node_parts[idx]
            target_part = node_parts[idx + 1]
            if not source_part or not target_part:
                continue

            source_id, source_label, source_type = self._extract_node_info(source_part)
            target_id, target_label, target_type = self._extract_node_info(target_part)
            if not source_id or not target_id:
                continue

            self._ensure_node(source_id, source_label, source_type)
            self._ensure_node(target_id, target_label, target_type)

            self._create_edge(
                self.node_id_map[source_id],
                self.node_id_map[target_id],
                label=self._edge_label(match),
                edge_type=self._edge_type(match),
            )

    def _upgrade_node_shape(
        self,
        node_id: str,
        label: Optional[str],
        node_type: Optional[str],
    ) -> None:
        """Adopt a richer label/type when a node first seen bare (in an edge) is
        later given a shape. Only a shaped mention (both label and type present,
        per ``_extract_node_info``) upgrades; a bare re-mention is a no-op. This
        stops the first mention from permanently winning - e.g. ``A --> B`` then
        ``A[Start]`` keeping label "A", or ``A[x]`` then ``A{Decide}`` staying a
        step instead of becoming a decision (which also loses decision_options).
        """
        if label is None or node_type is None:
            return
        internal_id = self.node_id_map[node_id]
        for node in self.nodes:
            if node.id == internal_id:
                node.label = label
                node.type = node_type
                break

    def _ensure_node(
        self,
        node_id: str,
        label: Optional[str],
        node_type: Optional[str],
    ) -> None:
        if node_id in self.node_id_map:
            self._upgrade_node_shape(node_id, label, node_type)
            return
        internal_id = self._create_node_id()
        self.node_id_map[node_id] = internal_id
        node = PlaybookNode(
            id=internal_id,
            label=label or node_id,
            type=node_type or "step",
            metadata={"mermaid_id": node_id, "subgraph": self.current_subgraph}
        )
        self.nodes.append(node)

    def _edge_label(self, match: re.Match[str]) -> Optional[str]:
        for group in ("solid_label", "dotted_label", "bold_label"):
            label = match.group(group)
            if label:
                return label.strip()
        return None

    def _edge_type(self, match: re.Match[str]) -> str:
        if match.group("dotted") or match.group("dotted_label"):
            return "dotted"
        if match.group("bold") or match.group("bold_label"):
            return "bold"
        return "solid"

    def _parse_node_definition(self, line: str) -> None:
        """
        Parse a standalone node definition.

        Args:
            line: Line containing node definition (e.g., "A[Start Process]")
        """
        node_id, label, node_type = self._extract_node_info(line)

        if not node_id:
            return
        if node_id not in self.node_id_map:
            internal_id = self._create_node_id()
            self.node_id_map[node_id] = internal_id
            node = PlaybookNode(
                id=internal_id,
                label=label or node_id,
                type=node_type or "step",
                metadata={"mermaid_id": node_id, "subgraph": self.current_subgraph}
            )
            self.nodes.append(node)
        else:
            self._upgrade_node_shape(node_id, label, node_type)

    def _extract_node_info(self, text: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Extract node ID, label, and type from text.

        Args:
            text: Node definition text (e.g., "A[Start]" or "B{Is Valid?}")

        Returns:
            Tuple of (node_id, label, node_type)
        """
        text = text.strip()

        # Try to match node ID with shape pattern
        for pattern, node_type in self.NODE_PATTERNS.items():
            # Build regex to capture ID and label
            full_pattern = r'([A-Za-z0-9_]+)\s*' + pattern
            match = re.match(full_pattern, text)

            if match:
                node_id = match.group(1)
                label = match.group(2).strip()
                return (node_id, label, node_type)

        # If no shape pattern matched, check for just an ID
        id_match = re.match(r'^([A-Za-z0-9_]+)$', text)
        if id_match:
            node_id = id_match.group(1)
            return (node_id, None, None)

        return (None, None, None)

    def _create_node_id(self) -> str:
        """
        Generate unique internal node ID.

        Returns:
            Node ID string
        """
        node_id = f"node_{self.node_counter}"
        self.node_counter += 1
        return node_id

    def _create_edge(
        self,
        source: str,
        target: str,
        label: Optional[str] = None,
        edge_type: str = "solid"
    ) -> None:
        """
        Create an edge between two nodes.

        Args:
            source: Source node ID
            target: Target node ID
            label: Optional edge label
            edge_type: Edge type (solid, dotted, bold)
        """
        edge_id = f"edge_{self.edge_counter}"
        self.edge_counter += 1

        edge = PlaybookEdge(
            id=edge_id,
            source=source,
            target=target,
            label=label
        )
        self.edges.append(edge)
