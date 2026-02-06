/**
 * V2PhaseNode — SOC phase/section header node
 *
 * Dark panel with cyan accent, bold header typography, mission phase indicator.
 */

import React, { memo } from 'react';
import { Handle, Position } from 'react-flow-renderer';

interface V2PhaseNodeProps {
  data: {
    label: string;
    metadata?: Record<string, any>;
  };
}

const V2PhaseNode: React.FC<V2PhaseNodeProps> = ({ data }) => {
  const level = data.metadata?.level || 2;
  const isH1 = level === 1;

  return (
    <div
      style={{
        background: isH1 ? '#0B1E33' : '#162035',
        borderLeft: `3px solid #06B6D4`,
        borderTop: '1px solid #1E3050',
        borderRight: '1px solid #1E3050',
        borderBottom: '1px solid #1E3050',
        borderRadius: '4px',
        padding: isH1 ? '12px 16px' : '8px 12px',
        minWidth: isH1 ? 240 : 200,
        maxWidth: 300,
        boxShadow: isH1
          ? '0 0 16px rgba(6, 182, 212, 0.12), 0 2px 8px rgba(0,0,0,0.4)'
          : '0 2px 8px rgba(0, 0, 0, 0.4)',
        position: 'relative',
      }}
    >
      <Handle
        type="target"
        position={Position.Top}
        style={{ background: '#06B6D4', width: 8, height: 8, border: '2px solid #0B1426' }}
      />
      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
        <span
          style={{
            display: 'inline-block',
            width: 6,
            height: 6,
            borderRadius: '50%',
            background: '#06B6D4',
            boxShadow: '0 0 6px rgba(6, 182, 212, 0.5)',
          }}
        />
        <span
          style={{
            fontSize: '9px',
            fontFamily: "'Barlow Condensed', sans-serif",
            fontWeight: 600,
            letterSpacing: '1.5px',
            textTransform: 'uppercase' as const,
            color: '#06B6D4',
          }}
        >
          {isH1 ? 'MISSION PHASE' : `PHASE L${level}`}
        </span>
      </div>
      <div
        style={{
          fontSize: isH1 ? '13px' : '11px',
          fontFamily: "'Barlow Condensed', sans-serif",
          fontWeight: 600,
          lineHeight: 1.3,
          textTransform: 'uppercase' as const,
          letterSpacing: '0.5px',
          color: '#E2E8F0',
          wordWrap: 'break-word' as const,
        }}
      >
        {data.label}
      </div>
      <Handle
        type="source"
        position={Position.Bottom}
        style={{ background: '#06B6D4', width: 8, height: 8, border: '2px solid #0B1426' }}
      />
    </div>
  );
};

export default memo(V2PhaseNode);
