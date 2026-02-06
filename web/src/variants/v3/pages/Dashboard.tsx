/**
 * V3 Dashboard — Clean Stats Overview
 *
 * GitBook-style overview with clean stat cards, coverage indicators,
 * and a minimal playbook inventory. Content-first, distraction-free.
 */

import React, { useMemo } from 'react';
import { usePlaybooks } from '../../../hooks/usePlaybooks';
import { PlaybookCategory } from '../../../types';
import './Dashboard.css';

const CATEGORY_LABELS: Record<PlaybookCategory, string> = {
  'vulnerability-remediation': 'Vulnerability Remediation',
  'incident-response': 'Incident Response',
  'threat-hunting': 'Threat Hunting',
  'compliance': 'Compliance',
  'siem-operations': 'SIEM Operations',
  'template': 'Templates',
};

const ALL_CATEGORIES: PlaybookCategory[] = [
  'vulnerability-remediation',
  'incident-response',
  'threat-hunting',
  'compliance',
  'siem-operations',
  'template',
];

const NODE_TYPE_COLORS: Record<string, string> = {
  phase: '#4F46E5',
  step: '#0891B2',
  decision: '#D97706',
  execute: '#16A34A',
};

const Dashboard: React.FC = () => {
  const { playbooks } = usePlaybooks();

  const stats = useMemo(() => {
    const totalNodes = playbooks.reduce((s, p) => s + p.graph.nodes.length, 0);
    const totalEdges = playbooks.reduce((s, p) => s + p.graph.edges.length, 0);
    const byCategory: Record<string, number> = {};
    ALL_CATEGORIES.forEach((cat) => {
      byCategory[cat] = playbooks.filter((p) => p.category === cat).length;
    });
    const coveredCategories = ALL_CATEGORIES.filter((cat) => byCategory[cat] > 0).length;

    return {
      totalPlaybooks: playbooks.length,
      totalNodes,
      totalEdges,
      avgNodes: playbooks.length > 0 ? Math.round(totalNodes / playbooks.length) : 0,
      byCategory,
      coveragePercent: Math.round((coveredCategories / ALL_CATEGORIES.length) * 100),
      coveredCategories,
    };
  }, [playbooks]);

  const nodeTypeBreakdown = useMemo(() => {
    const counts: Record<string, number> = { phase: 0, step: 0, decision: 0, execute: 0 };
    playbooks.forEach((p) =>
      p.graph.nodes.forEach((n) => {
        if (counts[n.type] !== undefined) counts[n.type]++;
      })
    );
    return counts;
  }, [playbooks]);

  return (
    <div className="v3-dashboard">
      {/* Header */}
      <div className="v3-dashboard-header">
        <h1>Overview</h1>
        <p className="v3-dashboard-subtitle">
          A summary of your playbook knowledge base.
        </p>
      </div>

      {/* Stats Row */}
      <div className="v3-stats-row">
        <div className="v3-stat-card">
          <div className="v3-stat-label">Playbooks</div>
          <div className="v3-stat-value">{stats.totalPlaybooks}</div>
          <div className="v3-stat-meta">
            <span className="v3-stat-accent">{stats.coveragePercent}%</span> category coverage
          </div>
        </div>
        <div className="v3-stat-card">
          <div className="v3-stat-label">Total Nodes</div>
          <div className="v3-stat-value">{stats.totalNodes}</div>
          <div className="v3-stat-meta">Across all playbooks</div>
        </div>
        <div className="v3-stat-card">
          <div className="v3-stat-label">Total Edges</div>
          <div className="v3-stat-value">{stats.totalEdges}</div>
          <div className="v3-stat-meta">Connections mapped</div>
        </div>
        <div className="v3-stat-card">
          <div className="v3-stat-label">Avg Nodes</div>
          <div className="v3-stat-value">{stats.avgNodes}</div>
          <div className="v3-stat-meta">Per playbook</div>
        </div>
      </div>

      {/* Coverage + Composition Grid */}
      <div className="v3-coverage-grid">
        {/* Category Coverage */}
        <div className="v3-coverage-card">
          <h3>
            Category Coverage
            <span style={{ float: 'right' }}>
              <span className="v3-coverage-badge">{stats.coveredCategories}/{ALL_CATEGORIES.length}</span>
            </span>
          </h3>
          {ALL_CATEGORIES.map((cat) => {
            const count = stats.byCategory[cat] || 0;
            return (
              <div key={cat} className="v3-coverage-item">
                <span className={`v3-coverage-indicator ${count > 0 ? 'v3-coverage-indicator--active' : 'v3-coverage-indicator--inactive'}`} />
                <span className="v3-coverage-label">{CATEGORY_LABELS[cat]}</span>
                <span className="v3-coverage-count">{count}</span>
              </div>
            );
          })}
        </div>

        {/* Node Composition */}
        <div className="v3-coverage-card">
          <h3>Node Composition</h3>
          {[
            { type: 'phase', label: 'Phase' },
            { type: 'step', label: 'Step' },
            { type: 'decision', label: 'Decision' },
            { type: 'execute', label: 'Execute' },
          ].map(({ type, label }) => {
            const count = nodeTypeBreakdown[type] || 0;
            const pct = stats.totalNodes > 0 ? (count / stats.totalNodes) * 100 : 0;
            return (
              <div key={type} className="v3-composition-bar-row">
                <span className="v3-composition-bar-label">{label}</span>
                <div className="v3-composition-bar-track">
                  <div
                    className="v3-composition-bar-fill"
                    style={{ width: `${pct}%`, background: NODE_TYPE_COLORS[type] }}
                  />
                </div>
                <span className="v3-composition-bar-value">{count}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Playbook List */}
      <h2 className="v3-section-title">All Playbooks</h2>
      <div className="v3-playbook-list">
        <div className="v3-playbook-list-header">
          <h3>Inventory</h3>
          <span className="v3-playbook-list-count">{playbooks.length} playbooks</span>
        </div>
        {playbooks.map((pb) => (
          <div key={pb.slug} className="v3-playbook-list-item">
            <span className={`v3-coverage-indicator v3-coverage-indicator--active`} />
            <span className="v3-playbook-list-title">{pb.metadata.title}</span>
            <span className="v3-playbook-list-type">{pb.metadata.type}</span>
            <span className="v3-playbook-list-nodes">{pb.graph.nodes.length} nodes</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default Dashboard;
