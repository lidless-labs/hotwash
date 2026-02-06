/**
 * V3 Import — Clean Import Form
 *
 * Minimal, documentation-style import page with syntax-highlighted
 * dark textarea, clean action buttons, and inline parse results.
 */

import React, { useState } from 'react';
import { useParser } from '../../../hooks/useParser';
import FlowCanvas from '../../../components/FlowCanvas';
import { v3Theme } from '../theme';
import { v3NodeTypes } from '../nodes';
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
  const charCount = markdownInput.length;

  return (
    <div className="v3-import">
      {/* Header */}
      <div className="v3-import-header">
        <h1>Import</h1>
        <p className="v3-import-subtitle">
          Paste a markdown playbook to parse it into a visual flowchart.
        </p>
      </div>

      {/* Input Section */}
      <div className="v3-input-section">
        <div className="v3-input-label">
          <span className="v3-input-label-text">Markdown Input</span>
          <span className="v3-input-stats">
            {lineCount} lines · {charCount} chars
          </span>
        </div>
        <div className="v3-textarea-wrapper">
          <textarea
            className="v3-import-textarea"
            value={markdownInput}
            onChange={(e) => setMarkdownInput(e.target.value)}
            placeholder="# Paste your playbook markdown here..."
            spellCheck={false}
          />
        </div>
      </div>

      {/* Action Buttons */}
      <div className="v3-import-actions">
        <button
          className="v3-btn v3-btn--primary"
          onClick={handleParse}
          disabled={!markdownInput.trim()}
        >
          Parse Document
        </button>
        <button
          className="v3-btn v3-btn--secondary"
          onClick={handleLoadSample}
        >
          Load Sample
        </button>
        <button
          className="v3-btn v3-btn--secondary"
          onClick={handleClear}
        >
          Clear
        </button>
      </div>

      {/* Parse Results */}
      {parsed && result && (
        <div className="v3-parse-results">
          {/* Success Header */}
          <div className="v3-parse-results-header">
            <div className="v3-parse-results-header-left">
              <span className="v3-parse-results-icon" />
              <span className="v3-parse-results-title">Parse Complete</span>
            </div>
            <span className="v3-parse-results-time">{result.parseTimeMs.toFixed(1)}ms</span>
          </div>

          {/* Warnings */}
          {result.errors.length > 0 && (
            <div className="v3-parse-warnings">
              <div className="v3-parse-warnings-header">
                ⚠ Warnings ({result.errors.length})
              </div>
              <ul className="v3-parse-warnings-list">
                {result.errors.map((err, i) => (
                  <li key={i}>{err}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Stats */}
          <div className="v3-parse-stats">
            <div className="v3-parse-stat">
              <span className="v3-parse-stat-value">{result.graph.nodes.length}</span>
              <span className="v3-parse-stat-label">Nodes</span>
            </div>
            <div className="v3-parse-stat">
              <span className="v3-parse-stat-value">{result.graph.edges.length}</span>
              <span className="v3-parse-stat-label">Edges</span>
            </div>
            <div className="v3-parse-stat">
              <span className="v3-parse-stat-value">{result.metadata.title || 'Untitled'}</span>
              <span className="v3-parse-stat-label">Title</span>
            </div>
          </div>

          {/* Flowchart */}
          {result.graph.nodes.length > 0 && (
            <div className="v3-parse-flow">
              <FlowCanvas
                graph={result.graph}
                theme={v3Theme}
                customNodeTypes={v3NodeTypes}
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default Import;
