# Playbook Forge Roadmap

## Current State (Phase 1: Parser + Viewer) ✅

What exists today:
- Markdown/Mermaid parser (FastAPI backend, `/api/parse` endpoint)
- React Flow interactive flowchart viewer
- 5 visual themes (SOC, Analyst, Terminal, Command, Cyber)
- 5 demo playbooks (3 vulnerability remediation, 1 Wazuh export, 1 template)
- Import page: paste markdown, see flowchart
- Library page: browse demo playbooks by category
- Dashboard: executive summary stats
- Custom node types: Phase, Step, Decision, Execute, Merge

What's missing:
- No persistence (playbooks are hardcoded in `web/src/data/`)
- No CRUD (can't create, edit, save, or delete playbooks)
- No export (can't get playbooks back out in any format)
- No SOAR integration (README says it, code doesn't do it)
- Backend only has one real endpoint (`/api/parse`)
- `api/routers/playbooks.py` is an empty placeholder

---

## Phase 2: Playbook Management (Persistence + CRUD)

**Goal:** Make Playbook Forge a real tool, not a demo. Users create, save, edit, and organize playbooks.

### Backend (FastAPI)
- [ ] SQLite database with `playbooks` table (id, title, category, content_markdown, graph_json, created_at, updated_at, tags)
- [ ] `POST /api/playbooks` - Create new playbook (accepts markdown, auto-parses to graph)
- [ ] `GET /api/playbooks` - List all with filters (category, tags, search)
- [ ] `GET /api/playbooks/:id` - Get single playbook with full graph
- [ ] `PUT /api/playbooks/:id` - Update playbook (re-parses markdown on change)
- [ ] `DELETE /api/playbooks/:id` - Soft delete
- [ ] `GET /api/playbooks/:id/versions` - Version history (store previous versions on each update)
- [ ] Seed database with existing demo playbooks on first run
- [ ] Tags system: many-to-many with `tags` and `playbook_tags` tables

### Frontend
- [ ] Create page: markdown editor (left) + live flowchart preview (right)
- [ ] Edit page: load existing playbook into editor, save changes
- [ ] Library: switch from hardcoded data to API calls
- [ ] Delete confirmation modal
- [ ] Tag input component (autocomplete from existing tags)
- [ ] Search: full-text across title, content, and tags

### Data Migration
- [ ] Move demo playbooks from `web/src/data/*.ts` to SQLite seed data
- [ ] Keep demo data as fallback if API is unreachable (offline-first for S³ Stack)

---

## Phase 3: Export + Sharing

**Goal:** Get playbooks out of the tool in useful formats.

- [ ] Export to Markdown (reconstructed from graph)
- [ ] Export to Mermaid syntax
- [ ] Export to PDF (formatted with company/lab branding)
- [ ] Export to JSON (full graph for backup/restore)
- [ ] Import from JSON (restore from backup)
- [ ] Bulk import: upload a folder of markdown playbooks
- [ ] Share link: generate a read-only URL for a specific playbook
- [ ] Print-friendly view (CSS @media print)

---

## Phase 4: SOAR Integration (S³ Stack)

**Goal:** Wire Playbook Forge into the actual SOC tools. Playbooks stop being documents and start being executable.

### TheHive Integration
- [ ] Export playbook as TheHive case template (JSON format TheHive accepts)
- [ ] Map playbook phases to TheHive task groups
- [ ] Map playbook steps to TheHive tasks with descriptions
- [ ] Import from TheHive: pull existing case templates and convert to flowcharts
- [ ] Link: click a playbook step to open the related TheHive task

### Cortex Integration
- [ ] Map "Execute" nodes to Cortex analyzers (dropdown selector)
- [ ] Map "Execute" nodes to Cortex responders (for automated actions)
- [ ] Show analyzer/responder status next to mapped steps (available, running, failed)
- [ ] Trigger Cortex analysis directly from a playbook step (requires Cortex API access)

### Wazuh Integration
- [ ] Link playbook steps to Wazuh rule IDs (which rules trigger this playbook?)
- [ ] Auto-suggest playbooks when a Wazuh alert matches linked rules
- [ ] Export playbook as Wazuh active response config
- [ ] Show related Wazuh alerts alongside playbook (if connected to Wazuh API)

### MISP Integration
- [ ] Link playbook to MISP event types (what threat intel triggers this playbook?)
- [ ] Auto-populate IOC context from MISP when viewing a playbook
- [ ] Import MISP galaxy clusters as playbook tags

---

## Phase 5: Execution Tracking

**Goal:** Track which step you're on during an active incident. Playbook Forge becomes the IR runbook.

- [ ] "Start Execution" button: creates an execution instance of a playbook
- [ ] Step status tracking: not started, in progress, completed, skipped, blocked
- [ ] Assignee per step (who is handling this?)
- [ ] Timestamps: when each step was started, completed
- [ ] Notes per step: freeform text for what was found/done
- [ ] Evidence attachments per step (file upload, screenshots)
- [ ] Execution timeline: visual timeline of step completions
- [ ] Execution summary: auto-generated after-action report
- [ ] Multiple concurrent executions (different incidents, same playbook)
- [ ] WebSocket real-time updates (multiple analysts on same execution)

---

## Phase 6: AI-Assisted Authoring

**Goal:** Generate and improve playbooks with AI.

- [ ] Generate playbook from threat description ("APT29 phishing campaign targeting O365")
- [ ] Auto-suggest next steps based on MITRE ATT&CK technique mapping
- [ ] Import MISP event and auto-build response playbook from indicators
- [ ] "Improve this playbook" button: AI reviews and suggests additions
- [ ] Auto-map playbook steps to MITRE ATT&CK techniques
- [ ] Generate playbook from Wazuh alert cluster (group related alerts into a coherent response plan)
- [ ] Natural language editing: "Add a containment step after the detection phase that isolates the host"

### MCP Server Integration
- [ ] Playbook Forge MCP server: lets AI assistants create, read, and suggest playbooks
- [ ] Tools: `create_playbook`, `list_playbooks`, `get_playbook`, `suggest_steps`, `map_to_attack`
- [ ] Resources: playbook library, execution status, MITRE mapping

---

## Priority Order

| Phase | Value | Effort | Priority |
|-------|-------|--------|----------|
| Phase 2: CRUD + Persistence | High (makes it a real tool) | Medium | **Do first** |
| Phase 3: Export | Medium (sharing and backup) | Low | **Quick win** |
| Phase 4: SOAR Integration | Very high (differentiator for S³ Stack) | High | **Core value** |
| Phase 5: Execution Tracking | Very high (IR runbook mode) | High | **Production feature** |
| Phase 6: AI Authoring | Medium (nice to have) | Medium | **After core is solid** |

Phase 2 is the foundation. Everything else depends on having real persistence and CRUD.
Phase 4 is what makes Playbook Forge unique. Plenty of flowchart tools exist. None of them wire directly into TheHive, Cortex, Wazuh, and MISP.
