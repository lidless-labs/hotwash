/**
 * V3DecisionNode — Clean documentation-style decision node
 *
 * White diamond with amber accent, clean typography.
 * Subtle and readable.
 */

import React, { memo } from 'react';
import { Handle, Position } from 'react-flow-renderer';

interface V3DecisionNodeProps {
  data: {
    label: string;
    metadata?: Record<string, any>;
  };
}

const V3DecisionNode: React.FC<V3DecisionNodeProps> = ({ data }) => {
  return (
    <div
      style={{
        position: 'relative',
        width: 200,
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
          width: 130,
          height: 130,
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%) rotate(45deg)',
          background: '#FFFFFF',
          border: '2px solid #D97706',
          borderRadius: '4px',
          boxShadow: '0 1px 3px rgba(0, 0, 0, 0.06)',
        }}
      />
      <Handle
        type="target"
        position={Position.Top}
        style={{
          background: '#D97706',
          width: 8,
          height: 8,
          border: '2px solid #FFFFFF',
          zIndex: 10,
        }}
      />
      <div
        style={{
          position: 'relative',
          zIndex: 5,
          textAlign: 'center',
          padding: '4px 12px',
          maxWidth: 160,
        }}
      >
        <div
          style={{
            fontSize: '10px',
            fontFamily: "'Inter', system-ui, -apple-system, sans-serif",
            fontWeight: 600,
            letterSpacing: '0.05em',
            textTransform: 'uppercase' as const,
            color: '#D97706',
            marginBottom: '2px',
          }}
        >
          Decision
        </div>
        <div
          style={{
            fontSize: '11px',
            fontFamily: "'Inter', system-ui, -apple-system, sans-serif",
            fontWeight: 500,
            lineHeight: 1.3,
            color: '#334155',
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
          background: '#D97706',
          width: 8,
          height: 8,
          border: '2px solid #FFFFFF',
          zIndex: 10,
        }}
      />
      <Handle
        type="source"
        position={Position.Right}
        id="b"
        style={{
          background: '#D97706',
          width: 8,
          height: 8,
          border: '2px solid #FFFFFF',
          zIndex: 10,
        }}
      />
    </div>
  );
};

export default memo(V3DecisionNode);
