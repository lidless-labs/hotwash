# CLAUDE.md

## Project
- **Name:** Playbook Forge
- **Stack:** React 18, TypeScript, Vite, React Flow, FastAPI (optional backend)
- **Root:** This directory
- **Deploy:** Caddy static (serves `web/dist/`)

## Architecture
- Frontend: `web/` (React 18 + TypeScript + Vite + React Flow)
- Backend: `api/` (FastAPI, if present)
- Entry: `web/src/main.tsx`

## Build & Test
```bash
cd web && npm install && npm run dev      # Dev server
cd web && npm run build                    # Build to web/dist/
```

## Key Files
- `web/src/App.tsx` - React entry
- `web/src/` - All frontend source

## Gotchas
- **Frontend is in `web/`**, not root. Build output is `web/dist/`.
- **React Flow** for visual workflow/playbook editing.

## Style Guide
- Dark theme
- No em dashes. Ever.

## DO NOT
- Build from root (frontend is in `web/`)
- Assume dist/ is at root (it's `web/dist/`)

## Git Rules
- Conventional commits: `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`
- Never add Co-Authored-By lines or mention AI in commits
- No em dashes in commit messages

---

## OpenClaw Sync Protocol

An AI assistant (clawdbot) runs in OpenClaw and manages this workspace. It reads memory files on every session start. Follow this protocol so it stays in the loop about your changes.

### After completing a task, append to:
`~/.openclaw/workspace/memory/YYYY-MM-DD.md`

Use today's date. Create the file if it doesn't exist.

### Format:
```markdown
## Claude Code Session - [HH:MM AM/PM EST]
**Project:** Playbook Forge
**Branch:** [branch name]

### What changed
- [Bullet list of features/fixes/refactors]
- [Files added/modified/deleted]

### Decisions made
- [Any architectural choices, tradeoffs, library picks]

### Issues / TODO
- [Anything incomplete, broken, or needing follow-up]

### Git
- [Commit hashes or "pushed to main" / "on branch X"]
```

### Rules:
1. Always write the summary. Even for small changes.
2. Be specific about files.
3. Note decisions and why.
4. Don't edit MEMORY.md (clawdbot's long-term memory).
5. Don't edit other memory/ files. Only append to today's date file.
6. Commit and push your work.
