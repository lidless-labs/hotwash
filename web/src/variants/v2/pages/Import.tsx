/**
 * V2 Import — Terminal-style Markdown Input
 *
 * SOC operator terminal aesthetic for pasting and parsing markdown.
 * Dark input area, monospace everything, status-driven feedback.
 */

import React, { useState } from 'react';
import { useParser } from '../../../hooks/useParser';
import FlowCanvas from '../../../components/FlowCanvas';
import { v2Theme } from '../theme';
import { v2NodeTypes } from '../nodes';
import './Import.css';

const SAMPLE_MARKDOWN = `# Incident Response Playbook
**Type:** Incident Response
**Tooling:** SIEM + EDR + SOAR

---

## Phase 1: Detection & Triage
### Alert Assessment
- If alert severity is Critical then escalate to Tier 3
- If alert is false positive then close and document

### Context Gathering
\`\`\`bash
grep -i "malicious" /var/log/syslog | tail -50
\`\`\`

## Phase 2: Containment
1. Isolate affected endpoint from network
2. Block IOCs at perimeter firewall
3. Preserve forensic evidence

## Phase 3: Eradication
\`\`\`powershell
Remove-Item -Path C:\\malware -Recurse -Force
Get-Process | Where {$_.Path -like "*suspicious*"} | Stop-Process
\`\`\`

## Phase 4: Recovery & Lessons Learned
1. Restore systems from verified clean backup
2. Validate system integrity with baseline check
3. Conduct post-incident review within 48 hours
4. Update detection rules based on findings
`;

const Import: React.FC = () => {
  const [markdownInput, setMarkdownInput] = useState('');
  const { result, parse, parsed, clear } = useParser();

  const handleParse = () => {
    if (markdownInput.trim()) {
      parse(markdownInput);
    }
  };

  const handleLoadSample = () => {
    setMarkdownInput(SAMPLE_MARKDOWN);
  };

  const handleClear = () => {
    setMarkdownInput('');
    clear();
  };

  const lineCount = markdownInput.split('\n').length;

  return (
    <div className="v2-import">
      {/* Page Header */}
      <div className="v2-page-header">
        <h1>Import Terminal</h1>
        <span className="v2-page-subtitle">
          Paste markdown • Parse to graph
        </span>
      </div>

      {/* Terminal Input Area */}
      <div className="v2-terminal-block">
        <div className="v2-terminal-header">
          <div className="v2-terminal-dots">
            <span className="v2-dot v2-dot--red" />
            <span className="v2-dot v2-dot--amber" />
            <span className="v2-dot v2-dot--green" />
          </div>
          <span className="v2-terminal-title">pbf-import — markdown input</span>
          <div className="v2-terminal-stats">
            <span>{lineCount} lines</span>
            <span className="v2-terminal-sep">|</span>
            <span>{markdownInput.length} chars</span>
          </div>
        </div>
        <div className="v2-terminal-body">
          <div className="v2-terminal-prompt">$&gt; paste_playbook --format=markdown</div>
          <textarea
            className="v2-terminal-input"
            value={markdownInput}
            onChange={(e) => setMarkdownInput(e.target.value)}
            placeholder="# Paste operational playbook markdown here..."
            spellCheck={false}
          />
        </div>
      </div>

      {/* Action Bar */}
      <div className="v2-import-actions">
        <button
          className="v2-action-btn v2-action-btn--primary"
          onClick={handleParse}
          disabled={!markdownInput.trim()}
        >
          <span className="v2-action-icon">▶</span>
          Parse Document
        </button>
        <button
          className="v2-action-btn v2-action-btn--secondary"
          onClick={handleLoadSample}
        >
          Load Sample
        </button>
        <button
          className="v2-action-btn v2-action-btn--secondary"
          onClick={handleClear}
        >
          Clear
        </button>
      </div>

      {/* Parse Results */}
      {parsed && result && (
        <div className="v2-parse-results">
          {/* Result Header */}
          <div className="v2-result-header">
            <div className="v2-result-header-left">
              <span className="v2-status-dot v2-status-dot--green" />
              <span className="v2-result-title">Parse Complete</span>
            </div>
            <span className="v2-result-time">{result.parseTimeMs.toFixed(1)}ms</span>
          </div>

          {/* Errors */}
          {result.errors.length > 0 && (
            <div className="v2-parse-errors">
              <div className="v2-error-header">
                <span className="v2-status-dot v2-status-dot--amber" />
                <span>Warnings ({result.errors.length})</span>
              </div>
              <ul className="v2-error-list">
                {result.errors.map((err, i) => (
                  <li key={i}>{err}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Parse Stats */}
          <div className="v2-parse-stats">
            <div className="v2-parse-stat">
              <span className="v2-parse-stat-value">{result.graph.nodes.length}</span>
              <span className="v2-parse-stat-label">Nodes</span>
            </div>
            <div className="v2-parse-stat">
              <span className="v2-parse-stat-value">{result.graph.edges.length}</span>
              <span className="v2-parse-stat-label">Edges</span>
            </div>
            <div className="v2-parse-stat">
              <span className="v2-parse-stat-value">{result.metadata.title || 'Untitled'}</span>
              <span className="v2-parse-stat-label">Title</span>
            </div>
          </div>

          {/* Flow Canvas */}
          {result.graph.nodes.length > 0 && (
            <div className="v2-result-canvas">
              <div className="v2-pane-header">
                <span className="v2-pane-header-icon">⬡</span>
                <span>Parsed Flowchart — {result.metadata.title || 'Imported Document'}</span>
              </div>
              <div className="v2-result-flow">
                <FlowCanvas
                  graph={result.graph}
                  theme={v2Theme}
                  customNodeTypes={v2NodeTypes}
                />
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default Import;
