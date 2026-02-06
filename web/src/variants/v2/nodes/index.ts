/**
 * V2 Node Types — Barrel Export
 *
 * Maps node type strings to V2-themed React Flow node components.
 * SOC operator / mission control aesthetic.
 */

import { NodeTypes } from 'react-flow-renderer';
import V2PhaseNode from './V2PhaseNode';
import V2StepNode from './V2StepNode';
import V2DecisionNode from './V2DecisionNode';
import V2ExecuteNode from './V2ExecuteNode';

export const v2NodeTypes: NodeTypes = {
  phase: V2PhaseNode,
  step: V2StepNode,
  decision: V2DecisionNode,
  execute: V2ExecuteNode,
};

export { V2PhaseNode, V2StepNode, V2DecisionNode, V2ExecuteNode };
