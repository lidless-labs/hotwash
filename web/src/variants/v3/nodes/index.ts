/**
 * V3 Node Types — Barrel Export
 *
 * Maps node type strings to V3-themed React Flow node components.
 * Clean documentation / knowledge base aesthetic.
 */

import { NodeTypes } from 'react-flow-renderer';
import V3PhaseNode from './V3PhaseNode';
import V3StepNode from './V3StepNode';
import V3DecisionNode from './V3DecisionNode';
import V3ExecuteNode from './V3ExecuteNode';

export const v3NodeTypes: NodeTypes = {
  phase: V3PhaseNode,
  step: V3StepNode,
  decision: V3DecisionNode,
  execute: V3ExecuteNode,
};

export { V3PhaseNode, V3StepNode, V3DecisionNode, V3ExecuteNode };
