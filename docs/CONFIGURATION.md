# Configuration

## Frontend Configuration

### Environment Variables

Create a `.env` file in the `web/` directory:

```bash
VITE_APP_PORT=5177
VITE_API_BASE=http://localhost:8000
VITE_STORAGE_KEY=playbook-forge-v1
VITE_ENABLE_BACKEND=false
VITE_THEME_DEFAULT=soc
```

| Variable | Description | Default |
|----------|-------------|---------|
| `VITE_APP_PORT` | Frontend port | 5177 |
| `VITE_API_BASE` | Backend API URL | http://localhost:8000 |
| `VITE_STORAGE_KEY` | localStorage key for playbooks | playbook-forge-v1 |
| `VITE_ENABLE_BACKEND` | Enable backend features (storage, sync) | false |
| `VITE_THEME_DEFAULT` | Default theme on first load | soc |

### Running Frontend Only

```bash
cd web
npm install
npm run dev
```

Starts on `http://localhost:5177`

The app works completely offline without backend. Users can parse Markdown, create flowcharts, and export locally.

### Running with Backend

If you want to enable playbook storage and sharing:

```bash
# Frontend
cd web
VITE_ENABLE_BACKEND=true npm run dev

# Backend (in another terminal)
cd ../api
pip install -r requirements.txt
python main.py
```

Backend runs on `http://localhost:8000`

## Backend Configuration

### Environment Variables

Create a `.env` file in the `api/` directory:

```bash
DATABASE_URL=sqlite:///./playbooks.db
CORS_ORIGINS=http://localhost:5177
GEMINI_API_KEY=your-api-key-here
ENABLE_AI_GENERATION=false
STORAGE_PATH=./data/playbooks
```

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Database connection string | sqlite:///./playbooks.db |
| `CORS_ORIGINS` | Allowed frontend origins (comma-separated) | http://localhost:5177 |
| `GEMINI_API_KEY` | Gemini API key for AI generation | (empty) |
| `ENABLE_AI_GENERATION` | Enable AI-powered playbook generation | false |
| `STORAGE_PATH` | Directory for playbook exports | ./data/playbooks |

### Database Setup

SQLite (default):
```bash
# Database is auto-created on first run
# Located at: ./playbooks.db
```

PostgreSQL:
```bash
DATABASE_URL=postgresql://user:password@localhost/playbook_forge
# Create database first:
# createdb playbook_forge
```

### API Keys

To enable AI generation:

1. Get Gemini API key from Google Cloud Console
2. Set `GEMINI_API_KEY` in `.env`
3. Set `ENABLE_AI_GENERATION=true`

## Backend Integration Variables

### `HOTWASH_PRIVATE_HOST_ALLOWLIST`

Comma-separated list of CIDRs that override the SSRF block on outbound integration URLs. Default: empty (all RFC1918, loopback, and link-local blocked).

<!-- content-guard: allow private-ipv4 -->
Use for lab/dev only. For example, `HOTWASH_PRIVATE_HOST_ALLOWLIST=192.168.1.0/24,10.0.0.0/8` lets the API talk to a TheHive VM at `192.168.1.50`. Loopback (`127.0.0.0/8`) and link-local (`169.254.0.0/16`) are never allowed, even if listed.

### `HOTWASH_LIVE_THEHIVE_URL` / `HOTWASH_LIVE_THEHIVE_API_KEY`

Optional. Required only to run the opt-in TheHive live smoke test:

```bash
pytest api/tests/test_thehive_live.py -m live -v -s
```

See `docs/THEHIVE-INTEGRATION.md` for details.

## Theme Variants

Access Hotwash variants directly:

- `http://localhost:5177/` - SOC theme (default)
- `http://localhost:5177/?theme=analyst` - Analyst theme
- `http://localhost:5177/?theme=terminal` - Terminal theme
- `http://localhost:5177/?theme=command` - Command theme
- `http://localhost:5177/?theme=cyber` - Cyber Noir theme

Theme preference is saved to localStorage and restored on next visit.

## Playbook Import Formats

### Markdown Format

Place Markdown playbooks in the library. Expected structure:

```markdown
# Incident Response: Ransomware

## Phase: Detection
- Step: Identify affected systems
  - Review EDR alerts
  - Check SIEM correlation
  
- Decision: Is it a critical system?
  - YES -> Execute: Isolate network
  - NO -> Execute: Preserve evidence

## Phase: Analysis
- Step: Begin forensic collection
```

### Mermaid Format

Paste Mermaid flowchart syntax:

```mermaid
flowchart TD
    A[Detection] --> B{Critical?}
    B -->|Yes| C[Isolate]
    B -->|No| D[Collect Evidence]
```

Both formats are automatically converted to the same internal node-edge graph.

## Playbook Storage

### Frontend-Only Storage

Playbooks are stored in localStorage with key `playbook-forge-v1`:

```json
{
  "recentPlaybooks": [
    {
      "id": "uuid",
      "title": "Ransomware IR",
      "markdown": "# Incident Response...",
      "nodes": [...],
      "edges": [...],
      "modified_at": "2026-02-09T10:00:00Z"
    }
  ]
}
```

Max size: ~5MB (depends on browser). Good for 50-100 playbooks.

### Backend Storage

With backend enabled, playbooks are stored in database:

```sql
CREATE TABLE playbooks (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT,
  markdown TEXT,
  category TEXT,
  tags TEXT,
  created_by TEXT,
  created_at TIMESTAMP,
  updated_at TIMESTAMP
);
```

Enables:
- Team sharing and collaboration
- Persistent storage across devices
- Version history
- Search and filtering

## SOAR Action Library

Configure available SOAR actions by editing `web/src/data/soarActions.ts`:

```typescript
export const SOAR_ACTIONS = [
  {
    id: 'isolate_host',
    name: 'Isolate Host',
    platform: 'generic',
    parameters: {
      hostname: { type: 'string', required: true },
    },
  },
  // Add more actions
];
```

Actions available in the Execute node type dropdown.

## Playbook Categories

Built-in categories for organizing playbooks:

- **incident-response** - Respond to security incidents
- **threat-hunting** - Proactive threat detection
- **vulnerability-management** - Patch and remediate
- **forensics** - Digital investigation
- **compliance** - Audit and regulatory
- **custom** - User-defined

Configure categories in `web/src/data/categories.ts`.

## Markdown Parsing Rules

The parser follows these rules when converting Markdown to nodes:

| Markdown | Node Type | Notes |
|----------|-----------|-------|
| `## Phase: Name` | Phase | Major response phase |
| `- Step: Name` | Step | Procedural step within phase |
| `- Decision: Name` | Decision | Yes/No conditional branch |
| `- Execute: Name` | Execute | SOAR action or tool |
| Indented bullet (3+ spaces) | Sub-item | Attached to parent as notes |

Example:

```markdown
## Phase: Containment
- Step: Isolate host
  - Remove from network
  - Disable user account
  - Capture RAM dump

- Decision: Is malware spreading?
  - YES -> Execute: Segment network
  - NO -> Execute: Continue analysis
```

Parses to:

```
Phase[Containment]
  └─ Step[Isolate host] (notes: Remove from network...)
      └─ Decision[Is malware spreading?]
          ├─ Edge(Yes) -> Execute[Segment network]
          └─ Edge(No) -> Execute[Continue analysis]
```

## Export Formats

### JSON Export

Full graph representation (nodes, edges, metadata):

```json
{
  "title": "Ransomware IR",
  "nodes": [
    {
      "id": "phase-1",
      "type": "phase",
      "data": { "label": "Detection" }
    }
  ],
  "edges": [...]
}
```

Use for backup and sharing with system that can import JSON.

### Mermaid Export

Mermaid flowchart syntax (human-readable):

```mermaid
flowchart TD
    A[Detection] --> B[Analysis]
    B --> C{Confirmed?}
```

Use for sharing with teams, embedding in documentation, or rendering in external tools.

### Markdown Export

Playbook as structured Markdown:

```markdown
# Ransomware Incident Response

## Phase: Detection
- Step: Identify affected systems
  - Check EDR alerts
  - Correlate SIEM events
```

Use for documentation, archival, and sharing.

## Guided Tour

First-time users see an interactive tour powered by driver.js. Configure in `web/src/components/GuidedTour.tsx`:

```typescript
const tourSteps = [
  {
    element: '.canvas-container',
    popover: {
      title: 'Interactive Canvas',
      description: 'Drag nodes, connect with edges, and build your flowchart',
    },
  },
];
```

Disable tour:

```typescript
localStorage.setItem('playbook-forge-tour-completed', 'true');
```

Or via environment:

```bash
VITE_ENABLE_TOUR=false npm run dev
```

## Performance Optimization

### For Large Playbooks

If you have 200+ nodes:

1. **Split into sub-playbooks** - Divide by phase or incident type
2. **Archive old playbooks** - Export to Markdown and delete locally
3. **Use Mermaid export** - Share as text rather than interactive graph

### Storage Quota

Monitor localStorage usage:

```javascript
navigator.storage.estimate().then(estimate => {
  console.log(`Usage: ${estimate.usage / 1024 / 1024} MB`);
  console.log(`Quota: ${estimate.quota / 1024 / 1024} MB`);
});
```

If nearing quota:
1. Export old playbooks to JSON
2. Delete from localStorage
3. Re-import as needed

### Canvas Rendering

React Flow uses virtualization for large graphs. If experiencing lag:

1. Reduce number of nodes (<200 recommended)
2. Disable minimap for playbooks >100 nodes
3. Use View-Only mode instead of Edit mode

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `D` | Add Decision node |
| `S` | Add Step node |
| `E` | Add Execute node |
| `Delete` | Delete selected node |
| `Ctrl+Z` / `Cmd+Z` | Undo (localStorage-based) |
| `Ctrl+S` / `Cmd+S` | Export playbook |

## Troubleshooting

### Playbook Not Loading from Backend

Check CORS configuration:

```python
# In api/main.py
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:5177").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### AI Generation Not Working

Verify Gemini API key:

```bash
# Test API key
curl -X POST "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"contents":[{"parts":[{"text":"test"}]}]}'
```

### Canvas Freezing on Large Playbooks

Reduce node count or switch to View-Only mode. For persistent issues, split into multiple playbooks.
