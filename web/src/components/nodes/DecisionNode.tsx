/**
 * DecisionNode Component
 *
 * Represents a decision point or conditional branch in the playbook.
 * Decision nodes typically have multiple outgoing edges (yes/no, true/false, etc.).
 */

import React, { memo } from 'react';
import { Handle, Position } from 'react-flow-renderer';
import './NodeStyles.css';

interface DecisionNodeProps {
  data: {
    label: string;
    metadata?: Record<string, any>;
  };
}

const DecisionNode: React.FC<DecisionNodeProps> = ({ data }) => {
  return (
    <div className="custom-node decision-node" data-tour="decision-node">
      <Handle type="target" position={Position.Top} className="node-handle" />
      <div className="node-icon">❓</div>
      <div className="node-content">
        <div className="node-label">{data.label}</div>
        <div className="node-type-badge">Decision</div>
      </div>
      <Handle type="source" position={Position.Bottom} className="node-handle" id="a" />
      <Handle type="source" position={Position.Right} className="node-handle" id="b" />
    </div>
  );
};

export default memo(DecisionNode);
