/**
 * V2ExecuteNode — SOC execute/command node
 *
 * Dark panel with red left-border, code preview, critical action indicator.
 */

import React, { memo } from 'react';
import { Handle, Position } from 'react-flow-renderer';

interface V2ExecuteNodeProps {
  data: {
    label: string;
    metadata?: Record<string, any>;
  };
}

const V2ExecuteNode: React.FC<V2ExecuteNodeProps> = ({ data }) => {
  const language = data.metadata?.language || '';
  const code = data.metadata?.code || '';
  const codePreview = code.length > 60 ? code.substring(0, 57) + '...' : code;

  return (
    <div
      style={{
        background: '#162035',
        borderLeft: '3px solid #EF4444',
        borderTop: '1px solid #1E3050',
        borderRight: '1px solid #1E3050',
        borderBottom: '1px solid #1E3050',
        borderRadius: '4px',
        padding: '8px 12px',
        minWidth: 200,
        maxWidth: 280,
        fontFamily: "'JetBrains Mono', monospace",
        color: '#E2E8F0',
        boxShadow: '0 2px 8px rgba(0, 0, 0, 0.4)',
        position: 'relative',
      }}
    >
      <Handle
        type="target"
        position={Position.Top}
        style={{ background: '#EF4444', width: 8, height: 8, border: '2px solid #0B1426' }}
      />
      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
        <span
          style={{
            display: 'inline-block',
            width: 6,
            height: 6,
            borderRadius: '50%',
            background: '#EF4444',
            boxShadow: '0 0 6px rgba(239, 68, 68, 0.5)',
          }}
        />
        <span
          style={{
            fontSize: '9px',
            fontFamily: "'Barlow Condensed', sans-serif",
            fontWeight: 600,
            letterSpacing: '1.5px',
            textTransform: 'uppercase' as const,
            color: '#EF4444',
          }}
        >
          EXECUTE
        </span>
        {language && (
          <span
            style={{
              fontSize: '8px',
              fontFamily: "'Barlow Condensed', sans-serif",
              fontWeight: 500,
              letterSpacing: '1px',
              textTransform: 'uppercase' as const,
              color: '#64748B',
              background: '#0B1426',
              padding: '1px 6px',
              borderRadius: '2px',
              border: '1px solid #1E3050',
            }}
          >
            {language}
          </span>
        )}
      </div>
      <div
        style={{
          fontSize: '11px',
          fontWeight: 500,
          lineHeight: 1.4,
          wordWrap: 'break-word' as const,
          marginBottom: codePreview ? '6px' : 0,
        }}
      >
        {data.label}
      </div>
      {codePreview && (
        <div
          style={{
            fontSize: '10px',
            fontFamily: "'JetBrains Mono', monospace",
            color: '#64748B',
            background: '#0B1426',
            padding: '4px 8px',
            borderRadius: '3px',
            border: '1px solid #1E3050',
            whiteSpace: 'pre-wrap' as const,
            wordBreak: 'break-all' as const,
            lineHeight: 1.3,
          }}
        >
          {codePreview}
        </div>
      )}
      <Handle
        type="source"
        position={Position.Bottom}
        style={{ background: '#EF4444', width: 8, height: 8, border: '2px solid #0B1426' }}
      />
    </div>
  );
};

export default memo(V2ExecuteNode);
