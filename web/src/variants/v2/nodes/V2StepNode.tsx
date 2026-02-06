/**
 * V2StepNode — SOC-style step node with status indicator
 *
 * Dark panel with green left-border, status dot, dense data display.
 */

import React, { memo } from 'react';
import { Handle, Position } from 'react-flow-renderer';

interface V2StepNodeProps {
  data: {
    label: string;
    metadata?: Record<string, any>;
  };
}

const V2StepNode: React.FC<V2StepNodeProps> = ({ data }) => {
  return (
    <div
      style={{
        background: '#162035',
        borderLeft: '3px solid #22C55E',
        borderTop: '1px solid #1E3050',
        borderRight: '1px solid #1E3050',
        borderBottom: '1px solid #1E3050',
        borderRadius: '4px',
        padding: '8px 12px',
        minWidth: 180,
        maxWidth: 260,
        fontFamily: "'JetBrains Mono', monospace",
        color: '#E2E8F0',
        boxShadow: '0 2px 8px rgba(0, 0, 0, 0.4)',
        position: 'relative',
      }}
    >
      <Handle
        type="target"
        position={Position.Top}
        style={{ background: '#22C55E', width: 8, height: 8, border: '2px solid #0B1426' }}
      />
      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
        <span
          style={{
            display: 'inline-block',
            width: 6,
            height: 6,
            borderRadius: '50%',
            background: '#22C55E',
            boxShadow: '0 0 6px rgba(34, 197, 94, 0.5)',
            flexShrink: 0,
          }}
        />
        <span
          style={{
            fontSize: '9px',
            fontFamily: "'Barlow Condensed', sans-serif",
            fontWeight: 600,
            letterSpacing: '1.5px',
            textTransform: 'uppercase' as const,
            color: '#22C55E',
          }}
        >
          PROCEDURE
        </span>
      </div>
      <div
        style={{
          fontSize: '11px',
          fontWeight: 500,
          lineHeight: 1.4,
          wordWrap: 'break-word' as const,
          color: '#E2E8F0',
        }}
      >
        {data.label}
      </div>
      <Handle
        type="source"
        position={Position.Bottom}
        style={{ background: '#22C55E', width: 8, height: 8, border: '2px solid #0B1426' }}
      />
    </div>
  );
};

export default memo(V2StepNode);
