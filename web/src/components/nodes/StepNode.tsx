/**
 * StepNode Component
 *
 * Represents a single step or action in the playbook flowchart.
 * Steps are individual actions or tasks within a phase.
 */

import React, { memo } from 'react';
import { Handle, Position } from 'react-flow-renderer';
import './NodeStyles.css';

interface StepNodeProps {
  data: {
    label: string;
    metadata?: Record<string, any>;
  };
}

const StepNode: React.FC<StepNodeProps> = ({ data }) => {
  return (
    <div className="custom-node step-node" data-tour="step-details">
      <Handle type="target" position={Position.Top} className="node-handle" />
      <div className="node-icon">▶️</div>
      <div className="node-content">
        <div className="node-label">{data.label}</div>
        <div className="node-type-badge">Step</div>
      </div>
      <Handle type="source" position={Position.Bottom} className="node-handle" />
    </div>
  );
};

export default memo(StepNode);
