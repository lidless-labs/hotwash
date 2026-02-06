/**
 * V2DecisionNode — SOC decision node with amber warning styling
 *
 * Dark panel with amber left-border, warning indicator, branching handles.
 */

import React, { memo } from 'react';
import { Handle, Position } from 'react-flow-renderer';

interface V2DecisionNodeProps {
  data: {
    label: string;
    metadata?: Record<string, any>;
  };
}

const V2DecisionNode: React.FC<V2DecisionNodeProps> = ({ data }) => {
  return (
    <div
      style={{
        position: 'relative',
        width: 220,
        height: 120,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      {/* Diamond shape */}
      <div
        style={{
          position: 'absolute',
          width: 140,
          height: 140,
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%) rotate(45deg)',
          background: '#162035',
          border: '2px solid #F59E0B',
          boxShadow: '0 0 12px rgba(245, 158, 11, 0.15), 0 2px 8px rgba(0,0,0,0.4)',
        }}
      />
      <Handle
        type="target"
        position={Position.Top}
        style={{
          background: '#F59E0B',
          width: 8,
          height: 8,
          border: '2px solid #0B1426',
          zIndex: 10,
        }}
      />
      <div
        style={{
          position: 'relative',
          zIndex: 5,
          textAlign: 'center',
          padding: '4px 12px',
          maxWidth: 170,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '4px', marginBottom: '2px' }}>
          <span
            style={{
              display: 'inline-block',
              width: 6,
              height: 6,
              borderRadius: '50%',
              background: '#F59E0B',
              boxShadow: '0 0 6px rgba(245, 158, 11, 0.5)',
            }}
          />
          <span
            style={{
              fontSize: '9px',
              fontFamily: "'Barlow Condensed', sans-serif",
              fontWeight: 600,
              letterSpacing: '1.5px',
              textTransform: 'uppercase' as const,
              color: '#F59E0B',
            }}
          >
            DECISION
          </span>
        </div>
        <div
          style={{
            fontSize: '10px',
            fontFamily: "'JetBrains Mono', monospace",
            fontWeight: 500,
            lineHeight: 1.3,
            color: '#E2E8F0',
            wordWrap: 'break-word' as const,
          }}
        >
          {data.label}
        </div>
      </div>
      <Handle
        type="source"
        position={Position.Bottom}
        id="a"
        style={{
          background: '#F59E0B',
          width: 8,
          height: 8,
          border: '2px solid #0B1426',
          zIndex: 10,
        }}
      />
      <Handle
        type="source"
        position={Position.Right}
        id="b"
        style={{
          background: '#F59E0B',
          width: 8,
          height: 8,
          border: '2px solid #0B1426',
          zIndex: 10,
        }}
      />
    </div>
  );
};

export default memo(V2DecisionNode);
