# Architecture

## System Overview

Hotwash is a dual-stack application: a React frontend for interactive flowchart visualization and an optional FastAPI backend for playbook storage and AI-powered generation.

## Tech Stack

### Frontend
- **React 18** with TypeScript for type-safe UI
- **Vite** for lightning-fast development and builds
- **Tailwind CSS** for styling with 5 theme variants
- **React Flow 11** for interactive node-edge graph visualization
- **Zustand** for global state management (persisted to localStorage)
- **Custom Markdown Parser** for inline playbook parsing
- Runs on **port 5177**

### Backend (Optional)
- **FastAPI** with async/await for REST APIs
- **Pydantic** for request/response validation
- **SQLite** or **PostgreSQL** for playbook storage
- **Gemini Flash** for AI-powered playbook generation
- Runs on **port 8000**

Both frontend and backend are optional. The frontend can work entirely standalone for visualization. The backend adds storage and AI generation capabilities.

## Data Flow

### Frontend-Only Mode

```
User Pastes/Uploads Playbook Markdown
    |
    v
Markdown Parser (client-side)
    |
    v
Extract Nodes and Edges
    |
    v
Validate Graph Structure
    |
    v
Render with React Flow
    |
    v
User Edits Nodes (inline properties)
    |
    v
Export JSON or Mermaid
```

### With Backend Mode

```
User Creates Playbook
    |
    v
Save to Backend API
    |
    v
Store in SQLite/PostgreSQL
    |
    v
Share with Team via URL
    |
    v
Backend Serves Playbook
    |
    v
Frontend Fetches and Renders
```

## State Management (Zustand)

Frontend store structure:

```typescript
interface PlaybookStore {
  // Current playbook
  currentPlaybook: Playbook | null;
  nodes: Node[];
  edges: Edge[];
  
  // UI State
  selectedNodeId: string | null;
  editingNodeId: string | null;
  viewMode: 'edit' | 'view' | 'library';
  
  // Actions
  loadPlaybook: (markdown: string) => void;
  addNode: (type: NodeType, position: XYPosition) => void;
  updateNode: (id: string, data: Partial<Node>) => void;
  deleteNode: (id: string) => void;
  updateEdge: (id: string, data: Partial<Edge>) => void;
  
  // Persistence
  saveToLocalStorage: () => void;
  loadFromLocalStorage: () => void;
}

// Persisted to localStorage under key: playbook-forge-v1
```

## Node Model

```typescript
interface Node {
  id: string;
  type: 'phase' | 'step' | 'decision' | 'execute' | 'merge';
  position: XYPosition;
  data: {
    label: string;
    description?: string;
    notes?: string;
    
    // Type-specific
    phase?: string;                    // For 'phase' nodes
    tool?: string;                     // For 'execute' nodes
    actionType?: 'manual' | 'soar' | 'alert';
    condition?: string;                // For 'decision' nodes (Yes/No branch)
  };
}

interface Edge {
  id: string;
  source: string;       // Node ID
  target: string;       // Node ID
  label?: string;       // "Yes", "No", "Then", etc.
  animated?: boolean;   // For emphasizing active path
}
```

## Markdown Parser

The custom parser converts Markdown playbooks to graphs:

```javascript
function parsePlaybookMarkdown(markdown: string) {
  const lines = markdown.split('\n');
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  let nodeIdCounter = 0;
  let currentPhase: string | null = null;
  let lastNodeId: string | null = null;
  
  for (const line of lines) {
    if (line.startsWith('# ')) {
      // Root title - skip
      continue;
    } else if (line.startsWith('## Phase: ')) {
      // Create phase node
      const phaseName = line.replace('## Phase: ', '');
      const nodeId = `phase-${nodeIdCounter++}`;
      nodes.push({
        id: nodeId,
        type: 'phase',
        data: { label: phaseName, phase: phaseName },
      });
      
      if (lastNodeId) {
        edges.push({
          id: `${lastNodeId}-${nodeId}`,
          source: lastNodeId,
          target: nodeId,
        });
      }
      
      lastNodeId = nodeId;
      currentPhase = phaseName;
    } else if (line.startsWith('- Step: ')) {
      // Create step node
      const stepName = line.replace('- Step: ', '');
      const nodeId = `step-${nodeIdCounter++}`;
      nodes.push({
        id: nodeId,
        type: 'step',
        data: { label: stepName },
      });
      
      if (lastNodeId) {
        edges.push({
          id: `${lastNodeId}-${nodeId}`,
          source: lastNodeId,
          target: nodeId,
        });
      }
      
      lastNodeId = nodeId;
    } else if (line.includes('Decision: ')) {
      // Create decision node with Yes/No branches
      const decisionText = line.replace(/.*Decision: /, '');
      const nodeId = `decision-${nodeIdCounter++}`;
      nodes.push({
        id: nodeId,
        type: 'decision',
        data: { label: decisionText, condition: decisionText },
      });
      
      if (lastNodeId) {
        edges.push({
          id: `${lastNodeId}-${nodeId}`,
          source: lastNodeId,
          target: nodeId,
        });
      }
      
      lastNodeId = nodeId;
    }
    // ... more line types
  }
  
  return { nodes, edges };
}
```

## Mermaid Parser

Converts Mermaid flowchart syntax to React Flow nodes:

```javascript
function parseMermaid(mermaidSyntax: string) {
  // Uses regex and line-by-line parsing to extract:
  // - Node definitions: A[Text]
  // - Connections: A --> B
  // - Conditionals: B -->|Yes| C
  // - Node types inferred from brackets: [rect], (circle), {diamond}, etc.
  
  // Output matches React Flow format
  return { nodes, edges };
}
```

## React Flow Integration

Canvas rendering with React Flow 11:

```typescript
<ReactFlow
  nodes={nodes}
  edges={edges}
  onNodesChange={onNodesChange}
  onEdgesChange={onEdgesChange}
  onConnect={onConnect}
>
  <Background />
  <Controls />
  <MiniMap />
</ReactFlow>
```

Custom node components for each type (Phase, Step, Decision, Execute, Merge) with variant-specific styling.

## Backend API (Optional)

### POST /playbook
Create a new playbook.

**Request:**
```json
{
  "title": "Ransomware Incident Response",
  "description": "...",
  "markdown": "# Incident Response...",
  "tags": ["ransomware", "incident-response"],
  "category": "incident-response"
}
```

**Response:**
```json
{
  "id": "uuid",
  "title": "Ransomware Incident Response",
  "created_at": "2026-02-09T10:00:00Z",
  "url": "http://localhost:5177/playbook/uuid"
}
```

### GET /playbook/{id}
Fetch playbook details.

**Response:**
```json
{
  "id": "uuid",
  "title": "...",
  "markdown": "...",
  "nodes": [...],
  "edges": [...],
  "created_at": "...",
  "updated_at": "..."
}
```

### POST /generate
Generate playbook using AI (optional).

**Request:**
```json
{
  "prompt": "Generate a playbook for detecting lateral movement",
  "category": "threat-hunting"
}
```

**Response:**
```json
{
  "markdown": "# Threat Hunting: Lateral Movement Detection\n...",
  "preview_nodes": [...]
}
```

## SOAR Connector Actions

Execute nodes can call backend connectors instead of only carrying template
strings. A connector declares a `tool_name`, an action-to-Pydantic-schema map,
`execute(action_name, validated_payload, integration_row)`, and
`test_connection(integration_row)`.

The integration router exposes the action surface:

- `GET /api/integrations/{tool}/actions` returns action names and JSON schemas.
- `POST /api/integrations/{tool}/actions/{action}` validates the action body,
  checks the configured integration row, then dispatches through the registry.
- Optional top-level `run_id` and `node_id` fields are removed from the
  connector payload. When both are present, the JSON action result is attached
  to that run step as evidence and emitted as a replayable
  `step_evidence_attached` event.

Implemented connectors:

- `thehive`: wraps the existing live `create_case`, `create_alert`, and
  `add_observable` actions with the same request and response shapes as the
  legacy routes.
- `http_webhook`: exposes `post_json`, joins an optional relative `path` to the
  integration `base_url`, posts the provided JSON `body`, honors `verify_ssl`,
  and sends `Authorization: Bearer <key>` when an API key is configured.

Outbound connector HTTP calls use `resolve_and_pin_integration_url` and
`apply_host_pinning`, so requests resolve once, validate every resolved
address, connect to the pinned literal IP, preserve Host/SNI where needed, and
do not follow redirects.

## 5 Variants

Each variant provides unique theming for the same React Flow canvas:

| Variant | Theme | Use Case |
|---------|-------|----------|
| **SOC** | Dark slate, red accents | Security operations |
| **Analyst** | Light white, blue | Professional policy |
| **Terminal** | Black, matrix green | Technical incident response |
| **Command** | OD green, amber | Military operations |
| **Cyber** | Neon cyan/magenta | Cyberpunk aesthetic |

All variants:
- Share the same Markdown parser
- Render identical graph structures
- Support full editing and export
- Can be toggled instantly

## Offline-First Architecture

Frontend works 100% offline:
1. Parse playbook from Markdown input
2. Edit nodes and edges locally
3. Export to JSON or Mermaid
4. Share as file or URL (if backend available)

Backend is optional for storage and team sharing.

## localStorage Schema

```json
{
  "playbook-forge-v1": {
    "recentPlaybooks": [
      {
        "id": "uuid",
        "title": "Ransomware IR",
        "nodes": [...],
        "edges": [...],
        "markdown": "...",
        "modified_at": "2026-02-09T10:00:00Z"
      }
    ],
    "theme": "soc",
    "windowLayout": {
      "editorWidth": 0.6
    }
  }
}
```

## Performance

- **Parsing:** <100ms for playbooks with 50+ nodes
- **Rendering:** 60fps with React Flow virtualization
- **Export:** <500ms for JSON, <1s for Mermaid
- **Editing:** Real-time updates, no lag

For very large playbooks (200+ nodes), consider splitting into multiple playbooks.
