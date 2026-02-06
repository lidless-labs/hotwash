/**
 * V3StepNode — Clean documentation-style step node
 *
 * White card with cyan top border, clean typography.
 * Content-first: label is the hero.
 */

import React, { memo } from 'react';
import { Handle, Position } from 'react-flow-renderer';

interface V3StepNodeProps {
  data: {
    label: string;
    metadata?: Record<string, any>;
  };
}

const V3StepNode: React.FC<V3StepNodeProps> = ({ data }) => {
  return (
    <div
      style={{
        background: '#FFFFFF',
        borderTop: '3px solid #0891B2',
        border: '1px solid #E2E8F0',
        borderTopWidth: '3px',
        borderTopColor: '#0891B2',
        borderRadius: '6px',
        padding: '10px 14px',
        minWidth: 180,
        maxWidth: 260,
        fontFamily: "'Inter', system-ui, -apple-system, sans-serif",
        color: '#1E293B',
        boxShadow: '0 1px 3px rgba(0, 0, 0, 0.04)',
        position: 'relative',
      }}
    >
      <Handle
        type="target"
        position={Position.Top}
        style={{ background: '#0891B2', width: 8, height: 8, border: '2px solid #FFFFFF' }}
      />
      <div
        style={{
          fontSize: '10px',
          fontWeight: 600,
          letterSpacing: '0.05em',
          textTransform: 'uppercase' as const,
          color: '#0891B2',
          marginBottom: '4px',
        }}
      >
        Step
      </div>
      <div
        style={{
          fontSize: '12px',
          fontWeight: 500,
          lineHeight: 1.5,
          wordWrap: 'break-word' as const,
          color: '#334155',
        }}
      >
        {data.label}
      </div>
      <Handle
        type="source"
        position={Position.Bottom}
        style={{ background: '#0891B2', width: 8, height: 8, border: '2px solid #FFFFFF' }}
      />
    </div>
  );
};

export default memo(V3StepNode);
