/**
 * V3ExecuteNode — Clean documentation-style execute/command node
 *
 * White card with green top border, code preview, and copy button.
 * Clean and functional.
 */

import React, { memo, useState, useCallback } from 'react';
import { Handle, Position } from 'react-flow-renderer';

interface V3ExecuteNodeProps {
  data: {
    label: string;
    metadata?: Record<string, any>;
  };
}

const V3ExecuteNode: React.FC<V3ExecuteNodeProps> = ({ data }) => {
  const language = data.metadata?.language || '';
  const code = data.metadata?.code || '';
  const codePreview = code.length > 50 ? code.substring(0, 47) + '...' : code;
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    if (!code) return;
    try {
      navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // silent fallback
    }
  }, [code]);

  return (
    <div
      style={{
        background: '#FFFFFF',
        borderTop: '3px solid #16A34A',
        border: '1px solid #E2E8F0',
        borderTopWidth: '3px',
        borderTopColor: '#16A34A',
        borderRadius: '6px',
        padding: '10px 14px',
        minWidth: 190,
        maxWidth: 280,
        fontFamily: "'Inter', system-ui, -apple-system, sans-serif",
        color: '#1E293B',
        boxShadow: '0 1px 3px rgba(0, 0, 0, 0.04)',
        position: 'relative',
      }}
    >
      <Handle
        type="target"
        position={Position.Top}
        style={{ background: '#16A34A', width: 8, height: 8, border: '2px solid #FFFFFF' }}
      />
      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
        <span
          style={{
            fontSize: '10px',
            fontWeight: 600,
            letterSpacing: '0.05em',
            textTransform: 'uppercase' as const,
            color: '#16A34A',
          }}
        >
          Execute
        </span>
        {language && (
          <span
            style={{
              fontSize: '9px',
              fontWeight: 500,
              color: '#94A3B8',
              background: '#F8FAFC',
              padding: '1px 6px',
              borderRadius: '3px',
              border: '1px solid #E2E8F0',
              letterSpacing: '0.03em',
            }}
          >
            {language}
          </span>
        )}
        {code && (
          <button
            onClick={handleCopy}
            style={{
              marginLeft: 'auto',
              padding: '1px 6px',
              border: '1px solid #E2E8F0',
              borderRadius: '3px',
              background: copied ? '#F0FDF4' : '#FFFFFF',
              color: copied ? '#16A34A' : '#94A3B8',
              fontSize: '9px',
              fontWeight: 500,
              cursor: 'pointer',
              fontFamily: "'Inter', system-ui, sans-serif",
              transition: 'all 0.15s ease',
            }}
          >
            {copied ? '✓' : '⎘'}
          </button>
        )}
      </div>
      <div
        style={{
          fontSize: '12px',
          fontWeight: 500,
          lineHeight: 1.5,
          wordWrap: 'break-word' as const,
          color: '#334155',
          marginBottom: codePreview ? '6px' : 0,
        }}
      >
        {data.label}
      </div>
      {codePreview && (
        <div
          style={{
            fontSize: '11px',
            fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
            color: '#E2E8F0',
            background: '#1E293B',
            padding: '6px 8px',
            borderRadius: '4px',
            whiteSpace: 'pre-wrap' as const,
            wordBreak: 'break-all' as const,
            lineHeight: 1.4,
          }}
        >
          {codePreview}
        </div>
      )}
      <Handle
        type="source"
        position={Position.Bottom}
        style={{ background: '#16A34A', width: 8, height: 8, border: '2px solid #FFFFFF' }}
      />
    </div>
  );
};

export default memo(V3ExecuteNode);
