/**
 * V3PhaseNode — Clean documentation-style phase/section node
 *
 * White card with indigo top border, section header typography.
 * Bold and prominent — phase headers should stand out.
 */

import React, { memo } from 'react';
import { Handle, Position } from 'react-flow-renderer';

interface V3PhaseNodeProps {
  data: {
    label: string;
    metadata?: Record<string, any>;
  };
}

const V3PhaseNode: React.FC<V3PhaseNodeProps> = ({ data }) => {
  const level = data.metadata?.level || 2;
  const isH1 = level === 1;

  return (
    <div
      style={{
        background: isH1 ? '#EEF2FF' : '#FFFFFF',
        borderTop: `3px solid #4F46E5`,
        border: '1px solid #E2E8F0',
        borderTopWidth: '3px',
        borderTopColor: '#4F46E5',
        borderRadius: '6px',
        padding: isH1 ? '12px 16px' : '10px 14px',
        minWidth: isH1 ? 220 : 190,
        maxWidth: 300,
        fontFamily: "'Inter', system-ui, -apple-system, sans-serif",
        boxShadow: isH1
          ? '0 1px 4px rgba(79, 70, 229, 0.08)'
          : '0 1px 3px rgba(0, 0, 0, 0.04)',
        position: 'relative',
      }}
    >
      <Handle
        type="target"
        position={Position.Top}
        style={{ background: '#4F46E5', width: 8, height: 8, border: '2px solid #FFFFFF' }}
      />
      <div
        style={{
          fontSize: '10px',
          fontWeight: 600,
          letterSpacing: '0.05em',
          textTransform: 'uppercase' as const,
          color: '#4F46E5',
          marginBottom: '4px',
        }}
      >
        {isH1 ? 'Section' : `Phase`}
      </div>
      <div
        style={{
          fontSize: isH1 ? '14px' : '12px',
          fontWeight: 600,
          lineHeight: 1.3,
          color: '#1E293B',
          wordWrap: 'break-word' as const,
          letterSpacing: '-0.01em',
        }}
      >
        {data.label}
      </div>
      <Handle
        type="source"
        position={Position.Bottom}
        style={{ background: '#4F46E5', width: 8, height: 8, border: '2px solid #FFFFFF' }}
      />
    </div>
  );
};

export default memo(V3PhaseNode);
