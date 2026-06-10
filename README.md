<p align="center">
  <img src="docs/assets/hotwash-banner.jpg" alt="Hotwash banner">
</p>

<h1 align="center">⚒️ Hotwash</h1>

<p align="center">
  <strong>IR runbook builder with visual flowcharts, SOAR execution, and AI playbook generation.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/React-18.2-61DAFB?style=for-the-badge&logo=react&logoColor=0f172a" alt="React 18.2">
  <img src="https://img.shields.io/badge/TypeScript-5.3-3178C6?style=for-the-badge&logo=typescript&logoColor=white" alt="TypeScript 5.3">
  <img src="https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/FastAPI-0.136-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI 0.136">
  <img src="https://img.shields.io/badge/Tailwind_CSS-3.4-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white" alt="Tailwind CSS 3.4">
  <img src="https://img.shields.io/badge/MCP-server-7c3aed?style=for-the-badge" alt="MCP server">
  <img src="https://img.shields.io/badge/Wazuh-ingest-2563eb?style=for-the-badge" alt="Wazuh ingest">
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="MIT license">
</p>

<p align="center">
  <a href="https://solomonneas.dev/projects/playbook-forge"><img src="https://img.shields.io/badge/Portfolio-solomonneas.dev-22c55e?style=for-the-badge" alt="Portfolio"></a>
</p>

Hotwash transforms incident response playbooks from Markdown and Mermaid syntax into interactive flowchart visualizations with a full execution engine. SOC teams can build, execute, and track playbook runs step-by-step. AI generation creates playbooks from natural language prompts. SOAR integrations connect to real response platforms.

---

## Features

- **Markdown to Flowchart** - Parse structured Markdown playbooks into node-edge graphs
- **Mermaid Syntax** - Native support for Mermaid flowchart syntax
- **Interactive Canvas** - Drag, pan, zoom with React Flow
- **Custom Node Types** - Phase, Step, Decision, Execute, Merge with 5 variant styles
- **Playbook Library** - Browse, categorize, and filter by type (Vulnerability, Incident Response, Threat Hunting)
- **Execution Engine** - Run playbooks step-by-step with live status tracking, timestamps, and execution history
- **AI Playbook Generation** - Generate complete playbooks from natural language incident descriptions
- **SOAR Integration** - Built-in action library with connections to real response platforms
- **MCP Integration** - Model Context Protocol hooks for AI-assisted execution
- **MiniMap & Controls** - Bird's-eye view and viewport navigation
- **Client-Side Parsing** - Zero-latency Markdown rendering in browser
- **5 Visual Themes** - SOC, Analyst, Terminal, Command, Cyber variants
- **Guided Tour** - Interactive walkthrough for first-time users
- **Offline-First** - No backend required for visualization

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/solomonneas/hotwash.git
cd hotwash

# Frontend
cd web && npm install && npm run dev

# Backend (optional, from the repo root)
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn api.main:app --port 8000
```

Frontend: **http://localhost:5177**
Backend: **http://localhost:8000** (optional)

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Frontend** | React 18.2 | Interactive dashboards |
| **Language** | TypeScript 5.3 | Type safety |
| **Styling** | Tailwind CSS 3.4 | Utility-first CSS |
| **Canvas** | React Flow Renderer 10.3 | Node-edge graph visualization |
| **State** | Zustand | Global state management |
| **Bundler** | Vite 5 | Dev server and build |
| **Backend** (Optional) | FastAPI 0.136 | Playbook storage, execution engine, integrations |
| **Parser** | Custom Markdown Parser | Inline playbook parsing |

---

## Playbook Syntax

### Markdown Format

```markdown
# Incident Response: Ransomware Attack

## Phase: Detection
- Step: Identify affected systems
  - Check EDR alerts
  - Correlate with SIEM events
  - Document initial indicators

## Phase: Analysis
- Decision: Is it a critical system?
  - YES -> Execute: Isolate from network
  - NO -> Execute: Begin forensic collection

## Phase: Containment
- Step: Isolate affected hosts
  - Segment network access
  - Disable user accounts
  - Preserve evidence

## Phase: Eradication
- Step: Remove malware
  - Scan with multiple AV engines
  - Remove registry keys
  - Patch vulnerabilities

## Phase: Recovery
- Step: Restore systems
  - Restore from clean backups
  - Apply security patches
  - Re-enable user access
```

### Mermaid Format

```mermaid
flowchart TD
    A[Detection] --> B{Critical System?}
    B -->|Yes| C[Isolate Network]
    B -->|No| D[Preserve Evidence]
    C --> E[Begin Analysis]
    D --> E
    E --> F[Eradicate Threat]
    F --> G[Recover Systems]
```

---

## Node Types

| Type | Purpose | Example |
|------|---------|---------|
| **Phase** | Major incident response phase | Detection, Analysis, Containment |
| **Step** | Procedural action | Execute EDR scan, Document findings |
| **Decision** | Conditional branch (Yes/No) | Is it critical? Is malware present? |
| **Execute** | SOAR action or tool integration | Isolate host, Disable account, Block IP |
| **Merge** | Convergence point | Rejoining analysis paths |

---

## 5 Variants

| Variant | Theme | Use Case |
|---------|-------|----------|
| **SOC** | Dark slate, red accents | Security operations center |
| **Analyst** | Clean white, blue | Professional analysis |
| **Terminal** | Black, matrix green | Technical incident response |
| **Command** | OD green, amber | Military-style operations |
| **Cyber** | Neon cyan/magenta | Cyberpunk aesthetic |

All variants use the same parsing engine and React Flow canvas. Switch themes instantly.

---

## Project Structure

```text
hotwash/
├── web/                      # React 18 + TypeScript + Vite frontend
│   ├── src/
│   │   ├── components/       # FlowCanvas (React Flow), panels, viewers
│   │   ├── pages/            # Editor, Library, Executions, Suggestions, ...
│   │   ├── parsers/          # Client-side Markdown/Mermaid parsing
│   │   ├── api/              # Backend API client
│   │   ├── hooks/            # useExecutionSocket and friends
│   │   └── variants/         # Theme layouts
│   ├── package.json
│   └── vite.config.ts
├── api/                      # FastAPI backend (optional)
│   ├── main.py               # Entry point
│   ├── routers/              # playbooks, executions, export, ingest, integrations, parse
│   ├── services/             # Execution engine, ingest matching, tags
│   ├── parsers/              # Markdown + Mermaid parsers
│   ├── integrations/         # SOAR integration clients (TheHive)
│   └── tests/                # pytest suite
├── mcp/                      # hotwash-mcp npm package (MCP server, Node >= 20)
│   ├── src/index.ts          # Entry point
│   └── src/tools/            # playbooks, runs, suggestions, artifacts tools
├── docs/                     # ARCHITECTURE, CONFIGURATION, THEHIVE-INTEGRATION, WAZUH-INGEST
└── requirements.txt
```

---

## SOAR Actions

Built-in action library for common SOAR platforms:

**Incident Response Actions:**
- `isolate_host` - Remove host from network
- `disable_account` - Disable user account
- `block_ioc` - Block IP/domain/hash
- `snapshot_vm` - Create VM snapshot
- `quarantine_email` - Isolate email message

**Reconnaissance:**
- `whois_lookup` - IP/domain registration info
- `virustotal_check` - File hash reputation
- `shodan_search` - Internet scan results

All actions are templates that teams can customize.

---

## Wazuh integration

Hotwash accepts Wazuh alerts via `POST /api/ingest/wazuh` (HMAC-authenticated)
and matches them against a mapping table that can `auto`-start a run, queue a
human-review suggestion, or log only. Mappings are managed via
`/api/ingest/mappings` CRUD. See [docs/WAZUH-INGEST.md](docs/WAZUH-INGEST.md)
for the integration script template, HMAC scheme, and cooldown semantics.

---

## Roadmap

Shipped: the `hotwash-mcp` Model Context Protocol server (on npm) that lets AI agents drive playbook runs, and the Wazuh alert ingestion path with HMAC auth, mapping rules, and a human-review suggestion queue. Next up: richer execution reporting, more SOAR targets beyond TheHive, and deeper suggestion-queue workflows.

See [docs/ROADMAP.md](docs/ROADMAP.md) for the full plan.

---

## License

MIT - see [LICENSE](LICENSE) for details.
