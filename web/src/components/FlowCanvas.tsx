/**
 * FlowCanvas Component
 *
 * Main React Flow canvas component that renders nodes and edges from parser output.
 * Supports custom node types (Phase, Step, Decision, Execute) with distinct styling,
 * drag-and-drop, zoom/pan controls, and directional edges.
 */

import React, { useCallback, useMemo } from 'react';
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  Connection,
  addEdge,
  applyNodeChanges,
  applyEdgeChanges,
  NodeTypes,
  NodeChange,
  EdgeChange,
  MarkerType,
  BackgroundVariant,
} from 'react-flow-renderer';

import PhaseNode from './nodes/PhaseNode';
import StepNode from './nodes/StepNode';
import DecisionNode from './nodes/DecisionNode';
import ExecuteNode from './nodes/ExecuteNode';
import MergeNode from './nodes/MergeNode';
import { PlaybookGraph, PlaybookTheme, FlowNode, FlowEdge } from '../types';

import './FlowCanvas.css';

/** Default GitHub-dark theme (backward compatible) */
export const DEFAULT_THEME: PlaybookTheme = {
  name: 'github-dark',
  colors: {
    background: '#0d1117',
    surface: '#161b22',
    border: '#30363d',
    text: '#c9d1d9',
    textSecondary: '#8b949e',
    accent: '#58a6ff',
    accentHover: '#79c0ff',
  },
  fonts: {
    body: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
    heading: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
    mono: "source-code-pro, Menlo, Monaco, Consolas, 'Courier New', monospace",
  },
  nodeColors: {
    phase: { border: '#8957e5', bg: '#1c1f3d', badge: '#bc8cff' },
    step: { border: '#1f6feb', bg: '#1a2c4d', badge: '#58a6ff' },
    decision: { border: '#f78166', bg: '#3d2817', badge: '#ffa657' },
    execute: { border: '#238636', bg: '#162e1b', badge: '#3fb950' },
  },
  edgeColor: '#58a6ff',
};

interface FlowCanvasProps {
  graph: PlaybookGraph;
  /** Optional theme override — falls back to GitHub-dark defaults */
  theme?: PlaybookTheme;
  /** Optional custom nodeTypes map to override defaults */
  customNodeTypes?: NodeTypes;
  onNodesChange?: (nodes: FlowNode[]) => void;
  onEdgesChange?: (edges: FlowEdge[]) => void;
  /** Disable editing interactions (drag/connect) */
  readOnly?: boolean;
}

/**
 * Converts a playbook graph to React Flow format with proper positioning
 * Uses a simple vertical layout algorithm for node placement
 */
const convertToFlowFormat = (graph: PlaybookGraph, theme: PlaybookTheme = DEFAULT_THEME): { nodes: FlowNode[]; edges: FlowEdge[] } => {
  // Create a map to track node positions by level
  const levelMap = new Map<string, number>();
  const visited = new Set<string>();

  // Build adjacency list for traversal
  const adjList = new Map<string, string[]>();
  graph.edges.forEach(edge => {
    if (!adjList.has(edge.source)) {
      adjList.set(edge.source, []);
    }
    adjList.get(edge.source)!.push(edge.target);
  });

  // BFS to assign levels
  const queue: Array<{ id: string; level: number }> = [];

  // Find start nodes (nodes with no incoming edges)
  const hasIncoming = new Set(graph.edges.map(e => e.target));
  const startNodes = graph.nodes.filter(n => !hasIncoming.has(n.id));

  if (startNodes.length > 0) {
    startNodes.forEach(node => queue.push({ id: node.id, level: 0 }));
  } else if (graph.nodes.length > 0) {
    // If no clear start, use first node
    queue.push({ id: graph.nodes[0].id, level: 0 });
  }

  while (queue.length > 0) {
    const { id, level } = queue.shift()!;

    if (visited.has(id)) continue;
    visited.add(id);
    levelMap.set(id, level);

    const children = adjList.get(id) || [];
    children.forEach(childId => {
      if (!visited.has(childId)) {
        queue.push({ id: childId, level: level + 1 });
      }
    });
  }

  // Assign levels to any unvisited nodes
  graph.nodes.forEach(node => {
    if (!levelMap.has(node.id)) {
      levelMap.set(node.id, 0);
    }
  });

  // Count nodes per level for horizontal spacing
  const nodesPerLevel = new Map<number, number>();
  levelMap.forEach(level => {
    nodesPerLevel.set(level, (nodesPerLevel.get(level) || 0) + 1);
  });

  // Track horizontal position per level
  const levelCounters = new Map<number, number>();

  // Convert nodes with calculated positions
  const flowNodes: FlowNode[] = graph.nodes.map(node => {
    const level = levelMap.get(node.id) || 0;
    const nodesInLevel = nodesPerLevel.get(level) || 1;
    const horizontalIndex = levelCounters.get(level) || 0;
    levelCounters.set(level, horizontalIndex + 1);

    // Calculate position
    const verticalSpacing = 150;
    const horizontalSpacing = 250;
    const horizontalOffset = (horizontalIndex - (nodesInLevel - 1) / 2) * horizontalSpacing;

    return {
      id: node.id,
      type: node.type,
      data: {
        label: node.label,
        type: node.type,
        metadata: node.metadata,
      },
      position: {
        x: 400 + horizontalOffset,
        y: level * verticalSpacing + 50,
      },
    };
  });

  // Convert edges with arrow markers (themed)
  const flowEdges: FlowEdge[] = graph.edges.map(edge => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    label: edge.label,
    type: 'smoothstep',
    animated: true,
    style: {
      stroke: theme.edgeColor,
      strokeWidth: 2,
    },
    labelStyle: {
      fill: theme.colors.text,
      fontWeight: 500,
      fontSize: 12,
    },
    labelBgStyle: {
      fill: theme.colors.surface,
      fillOpacity: 0.9,
    },
    markerEnd: {
      type: MarkerType.ArrowClosed,
      width: 20,
      height: 20,
      color: theme.edgeColor,
    },
  }));

  return { nodes: flowNodes, edges: flowEdges };
};

const FlowCanvas: React.FC<FlowCanvasProps> = ({ graph, theme, customNodeTypes, readOnly = false }) => {
  const activeTheme = theme ?? DEFAULT_THEME;

  // Convert graph to flow format
  const { nodes: initialNodes, edges: initialEdges } = useMemo(
    () => convertToFlowFormat(graph, activeTheme),
    [graph, activeTheme]
  );

  const [nodes, setNodes] = React.useState<FlowNode[]>(initialNodes);
  const [edges, setEdges] = React.useState<FlowEdge[]>(initialEdges);

  // Update nodes when graph changes
  React.useEffect(() => {
    const converted = convertToFlowFormat(graph, activeTheme);
    setNodes(converted.nodes);
    setEdges(converted.edges);
  }, [graph, activeTheme]);

  // Define custom node types — merge custom over defaults
  const defaultNodeTypes: NodeTypes = useMemo(
    () => ({
      phase: PhaseNode,
      step: StepNode,
      decision: DecisionNode,
      execute: ExecuteNode,
      merge: MergeNode,
    }),
    []
  );

  const nodeTypes: NodeTypes = useMemo(
    () => (customNodeTypes ? { ...defaultNodeTypes, ...customNodeTypes } : defaultNodeTypes),
    [defaultNodeTypes, customNodeTypes]
  );

  // Handle node changes (drag, select, remove)
  const onNodesChange = useCallback(
    (changes: NodeChange[]) => {
      setNodes((nds) => applyNodeChanges(changes, nds));
    },
    []
  );

  // Handle edge changes (select, remove)
  const onEdgesChange = useCallback(
    (changes: EdgeChange[]) => {
      setEdges((eds) => applyEdgeChanges(changes, eds));
    },
    []
  );

  // Handle connection creation
  const onConnect = useCallback(
    (params: Connection) => {
      setEdges((eds) => addEdge(params, eds));
    },
    []
  );

  return (
    <div className="flow-canvas" data-tour="flow-canvas">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        nodesDraggable={!readOnly}
        nodesConnectable={!readOnly}
        elementsSelectable={!readOnly}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        attributionPosition="bottom-right"
        minZoom={0.1}
        maxZoom={2}
        defaultZoom={1}
      >
        <Background
          color={activeTheme.colors.border}
          gap={16}
          size={1}
          variant={BackgroundVariant.Dots}
        />
        <Controls
          showInteractive={false}
        />
        <MiniMap
          nodeColor={(node) => {
            const nc = activeTheme.nodeColors;
            switch (node.type) {
              case 'phase': return nc.phase.border;
              case 'step': return nc.step.border;
              case 'decision': return nc.decision.border;
              case 'execute': return nc.execute.border;
              case 'merge': return '#3bc9db';
              default: return activeTheme.colors.accent;
            }
          }}
          maskColor={`${activeTheme.colors.background}dd`}
          style={{
            backgroundColor: activeTheme.colors.surface,
            border: `1px solid ${activeTheme.colors.border}`,
          }}
        />
      </ReactFlow>
    </div>
  );
};

export default FlowCanvas;
