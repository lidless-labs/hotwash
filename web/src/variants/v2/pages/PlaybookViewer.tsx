/**
 * V2 PlaybookViewer — Split-pane Playbook Detail
 *
 * Left pane: Markdown content via MarkdownRenderer
 * Right pane: Flowchart via FlowCanvas with V2 node types
 * Resizable divider between panes.
 */

import React, { useState, useRef, useCallback, useEffect } from 'react';
import { usePlaybook } from '../../../hooks/usePlaybook';
import FlowCanvas from '../../../components/FlowCanvas';
import MarkdownRenderer from '../../../components/MarkdownRenderer';
import { v2Theme } from '../theme';
import { v2NodeTypes } from '../nodes';
import './PlaybookViewer.css';

interface PlaybookViewerProps {
  slug?: string;
  onNavigate: (path: string) => void;
}

const PlaybookViewer: React.FC<PlaybookViewerProps> = ({ slug, onNavigate }) => {
  const { playbook, found } = usePlaybook(slug);
  const [leftWidth, setLeftWidth] = useState(45); // percentage
  const isDragging = useRef(false);
  const containerRef = useRef<HTMLDivElement>(null);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    isDragging.current = true;
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  }, []);

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isDragging.current || !containerRef.current) return;
      const rect = containerRef.current.getBoundingClientRect();
      const newLeft = ((e.clientX - rect.left) / rect.width) * 100;
      setLeftWidth(Math.max(20, Math.min(80, newLeft)));
    };

    const handleMouseUp = () => {
      isDragging.current = false;
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
    return () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };
  }, []);

  if (!found || !playbook) {
    return (
      <div className="v2-viewer">
        <button className="v2-viewer-back" onClick={() => onNavigate('#/2/library')}>
          ◄ Back to Library
        </button>
        <div className="v2-viewer-notfound">
          <span className="v2-status-dot v2-status-dot--red" />
          PLAYBOOK NOT FOUND — CHECK REFERENCE
        </div>
      </div>
    );
  }

  const { metadata, graph, markdown, tags, category } = playbook;

  return (
    <div className="v2-viewer">
      {/* Header Bar */}
      <div className="v2-viewer-header">
        <button className="v2-viewer-back" onClick={() => onNavigate('#/2/library')}>
          ◄ Library
        </button>
        <div className="v2-viewer-title-block">
          <h1 className="v2-viewer-title">{metadata.title}</h1>
          <div className="v2-viewer-meta">
            <span className="v2-status-dot v2-status-dot--green" />
            <span>{metadata.type}</span>
            <span className="v2-viewer-meta-sep">|</span>
            <span>{metadata.tooling}</span>
            <span className="v2-viewer-meta-sep">|</span>
            <span>{graph.nodes.length} nodes / {graph.edges.length} edges</span>
            {metadata.lastUpdated && (
              <>
                <span className="v2-viewer-meta-sep">|</span>
                <span>Updated: {metadata.lastUpdated}</span>
              </>
            )}
          </div>
        </div>
        <div className="v2-viewer-tags">
          {tags.slice(0, 4).map((tag) => (
            <span key={tag} className="v2-tag">{tag}</span>
          ))}
        </div>
      </div>

      {/* Split Pane */}
      <div className="v2-split-pane" ref={containerRef}>
        {/* Left: Markdown */}
        <div className="v2-pane v2-pane-left" style={{ width: `${leftWidth}%` }}>
          <div className="v2-pane-header">
            <span className="v2-pane-header-icon">📄</span>
            <span>Documentation</span>
          </div>
          <div className="v2-pane-content v2-md-pane">
            <MarkdownRenderer content={markdown} className="v2-md" />
          </div>
        </div>

        {/* Resizable Divider */}
        <div className="v2-divider" onMouseDown={handleMouseDown}>
          <div className="v2-divider-grip" />
        </div>

        {/* Right: Flowchart */}
        <div className="v2-pane v2-pane-right" style={{ width: `${100 - leftWidth}%` }}>
          <div className="v2-pane-header">
            <span className="v2-pane-header-icon">⬡</span>
            <span>Flowchart</span>
          </div>
          <div className="v2-pane-content v2-flow-pane">
            <FlowCanvas
              graph={graph}
              theme={v2Theme}
              customNodeTypes={v2NodeTypes}
            />
          </div>
        </div>
      </div>
    </div>
  );
};

export default PlaybookViewer;
