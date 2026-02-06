/**
 * V3 PlaybookViewer — Tabbed Playbook Detail
 *
 * Clean, documentation-style viewer with three tabs:
 * - Content: Rendered markdown (Literata serif, clean typography)
 * - Flowchart: Embedded React Flow canvas with V3 node types
 * - Raw: Syntax-highlighted raw markdown with copy button
 */

import React, { useState, useCallback } from 'react';
import { usePlaybook } from '../../../hooks/usePlaybook';
import FlowCanvas from '../../../components/FlowCanvas';
import MarkdownRenderer from '../../../components/MarkdownRenderer';
import { v3Theme } from '../theme';
import { v3NodeTypes } from '../nodes';
import './PlaybookViewer.css';

interface PlaybookViewerProps {
  slug?: string;
  onNavigate: (path: string) => void;
}

type TabId = 'content' | 'flowchart' | 'raw';

const TABS: Array<{ id: TabId; label: string }> = [
  { id: 'content', label: 'Content' },
  { id: 'flowchart', label: 'Flowchart' },
  { id: 'raw', label: 'Raw' },
];

const PlaybookViewer: React.FC<PlaybookViewerProps> = ({ slug, onNavigate }) => {
  const { playbook, found } = usePlaybook(slug);
  const [activeTab, setActiveTab] = useState<TabId>('content');
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(async () => {
    if (!playbook) return;
    try {
      await navigator.clipboard.writeText(playbook.markdown);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback for clipboard API failure
      const textarea = document.createElement('textarea');
      textarea.value = playbook.markdown;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }, [playbook]);

  if (!found || !playbook) {
    return (
      <div className="v3-viewer">
        <div className="v3-viewer-notfound">
          <span className="v3-viewer-notfound-icon">📄</span>
          Playbook not found.
          <br />
          <button
            className="v3-viewer-notfound-link"
            onClick={() => onNavigate('#/3/library')}
          >
            Browse the library →
          </button>
        </div>
      </div>
    );
  }

  const { metadata, graph, markdown, tags, category } = playbook;

  return (
    <div className="v3-viewer">
      {/* Header */}
      <div className="v3-viewer-header">
        <h1 className="v3-viewer-title">{metadata.title}</h1>
        <div className="v3-viewer-meta">
          <span className="v3-viewer-meta-item">
            <span className="v3-viewer-meta-icon">📄</span>
            {metadata.type}
          </span>
          <span className="v3-viewer-meta-divider" />
          <span className="v3-viewer-meta-item">
            <span className="v3-viewer-meta-icon">🔧</span>
            {metadata.tooling}
          </span>
          <span className="v3-viewer-meta-divider" />
          <span className="v3-viewer-meta-item">
            {graph.nodes.length} nodes · {graph.edges.length} edges
          </span>
          {metadata.lastUpdated && (
            <>
              <span className="v3-viewer-meta-divider" />
              <span className="v3-viewer-meta-item">
                Updated {metadata.lastUpdated}
              </span>
            </>
          )}
        </div>
        {tags.length > 0 && (
          <div className="v3-viewer-tags">
            {tags.map((tag) => (
              <span key={tag} className="v3-viewer-tag">{tag}</span>
            ))}
          </div>
        )}
      </div>

      {/* Tab Bar */}
      <div className="v3-tab-bar">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            className={`v3-tab ${activeTab === tab.id ? 'v3-tab--active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'content' && (
        <div className="v3-content-view">
          <MarkdownRenderer content={markdown} className="v3-md" />
        </div>
      )}

      {activeTab === 'flowchart' && (
        <div className="v3-flowchart-view">
          <FlowCanvas
            graph={graph}
            theme={v3Theme}
            customNodeTypes={v3NodeTypes}
          />
        </div>
      )}

      {activeTab === 'raw' && (
        <div className="v3-raw-view">
          <div className="v3-raw-header">
            <span className="v3-raw-label">Raw Markdown</span>
            <button
              className={`v3-raw-copy-btn ${copied ? 'v3-raw-copy-btn--copied' : ''}`}
              onClick={handleCopy}
            >
              {copied ? '✓ Copied' : 'Copy'}
            </button>
          </div>
          <pre className="v3-raw-content">{markdown}</pre>
        </div>
      )}
    </div>
  );
};

export default PlaybookViewer;
