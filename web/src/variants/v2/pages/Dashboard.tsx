/**
 * V2 Dashboard — Multi-widget SOC Dashboard
 *
 * Dense grid of card-based widgets with status indicators,
 * category breakdown, playbook inventory, and system health.
 */

import React, { useMemo } from 'react';
import { usePlaybooks } from '../../../hooks/usePlaybooks';
import { PlaybookCategory } from '../../../types';
import './Dashboard.css';

const CATEGORY_LABELS: Record<PlaybookCategory, string> = {
  'vulnerability-remediation': 'Vuln Remediation',
  'incident-response': 'Incident Response',
  'threat-hunting': 'Threat Hunting',
  'compliance': 'Compliance',
  'siem-operations': 'SIEM Ops',
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

const SEVERITY_COLOR: Record<string, string> = {
  green: '#22C55E',
  amber: '#F59E0B',
  red: '#EF4444',
  cyan: '#06B6D4',
};

const Dashboard: React.FC = () => {
  const { playbooks, categories } = usePlaybooks();

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
  }, [playbooks, categories]);

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
    <div className="v2-dashboard">
      {/* Page header */}
      <div className="v2-page-header">
        <h1>Operations Dashboard</h1>
        <span className="v2-page-subtitle">
          System Overview • {new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}
        </span>
      </div>

      {/* KPI Row */}
      <div className="v2-kpi-row">
        <div className="v2-kpi-card v2-kpi-card--cyan">
          <div className="v2-kpi-value">{stats.totalPlaybooks}</div>
          <div className="v2-kpi-label">Total Playbooks</div>
          <div className="v2-kpi-indicator">
            <span className="v2-status-dot v2-status-dot--green" />
            <span>Active</span>
          </div>
        </div>
        <div className="v2-kpi-card v2-kpi-card--green">
          <div className="v2-kpi-value">{stats.totalNodes}</div>
          <div className="v2-kpi-label">Total Nodes</div>
          <div className="v2-kpi-indicator">
            <span className="v2-status-dot v2-status-dot--green" />
            <span>Mapped</span>
          </div>
        </div>
        <div className="v2-kpi-card v2-kpi-card--amber">
          <div className="v2-kpi-value">{stats.totalEdges}</div>
          <div className="v2-kpi-label">Total Edges</div>
          <div className="v2-kpi-indicator">
            <span className="v2-status-dot v2-status-dot--green" />
            <span>Connected</span>
          </div>
        </div>
        <div className="v2-kpi-card v2-kpi-card--red">
          <div className="v2-kpi-value">{stats.avgNodes}</div>
          <div className="v2-kpi-label">Avg Nodes/PB</div>
          <div className="v2-kpi-indicator">
            <span className="v2-status-dot v2-status-dot--green" />
            <span>Normal</span>
          </div>
        </div>
      </div>

      {/* Widget Grid */}
      <div className="v2-widget-grid">
        {/* Coverage Widget */}
        <div className="v2-widget v2-widget--coverage">
          <div className="v2-widget-header">
            <h3>Category Coverage</h3>
            <span className="v2-widget-badge">{stats.coveragePercent}%</span>
          </div>
          <div className="v2-coverage-list">
            {ALL_CATEGORIES.map((cat) => {
              const count = stats.byCategory[cat] || 0;
              const hasCoverage = count > 0;
              return (
                <div key={cat} className="v2-coverage-item">
                  <span className={`v2-coverage-dot ${hasCoverage ? 'v2-coverage-dot--active' : ''}`} />
                  <span className="v2-coverage-label">{CATEGORY_LABELS[cat]}</span>
                  <span className="v2-coverage-count">{count}</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Node Composition Widget */}
        <div className="v2-widget v2-widget--nodes">
          <div className="v2-widget-header">
            <h3>Node Composition</h3>
            <span className="v2-widget-badge">{stats.totalNodes}</span>
          </div>
          <div className="v2-node-bars">
            {[
              { type: 'phase', label: 'Phase', color: SEVERITY_COLOR.cyan },
              { type: 'step', label: 'Step', color: SEVERITY_COLOR.green },
              { type: 'decision', label: 'Decision', color: SEVERITY_COLOR.amber },
              { type: 'execute', label: 'Execute', color: SEVERITY_COLOR.red },
            ].map(({ type, label, color }) => {
              const count = nodeTypeBreakdown[type] || 0;
              const pct = stats.totalNodes > 0 ? (count / stats.totalNodes) * 100 : 0;
              return (
                <div key={type} className="v2-node-bar-row">
                  <div className="v2-node-bar-label">
                    <span className="v2-node-bar-dot" style={{ background: color, boxShadow: `0 0 4px ${color}50` }} />
                    <span>{label}</span>
                  </div>
                  <div className="v2-node-bar-track">
                    <div className="v2-node-bar-fill" style={{ width: `${pct}%`, background: color }} />
                  </div>
                  <span className="v2-node-bar-value">{count}</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Playbook Inventory Widget */}
        <div className="v2-widget v2-widget--inventory">
          <div className="v2-widget-header">
            <h3>Playbook Inventory</h3>
            <span className="v2-widget-badge">{playbooks.length} active</span>
          </div>
          <table className="v2-inventory-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Playbook</th>
                <th>Type</th>
                <th>Nodes</th>
                <th>Edges</th>
              </tr>
            </thead>
            <tbody>
              {playbooks.map((pb) => (
                <tr key={pb.slug}>
                  <td>
                    <span className="v2-status-dot v2-status-dot--green" />
                  </td>
                  <td className="v2-inventory-title">{pb.metadata.title}</td>
                  <td className="v2-inventory-type">{pb.metadata.type}</td>
                  <td className="v2-inventory-num">{pb.graph.nodes.length}</td>
                  <td className="v2-inventory-num">{pb.graph.edges.length}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* System Health Widget */}
        <div className="v2-widget v2-widget--health">
          <div className="v2-widget-header">
            <h3>System Status</h3>
            <span className="v2-widget-badge v2-widget-badge--green">Operational</span>
          </div>
          <div className="v2-health-list">
            {[
              { label: 'Parser Engine', status: 'green', detail: 'Online' },
              { label: 'Graph Renderer', status: 'green', detail: 'Online' },
              { label: 'Library Index', status: 'green', detail: `${playbooks.length} loaded` },
              { label: 'Coverage Monitor', status: stats.coveragePercent < 50 ? 'amber' : 'green', detail: `${stats.coveragePercent}%` },
            ].map((item) => (
              <div key={item.label} className="v2-health-item">
                <span className={`v2-status-dot v2-status-dot--${item.status}`} />
                <span className="v2-health-label">{item.label}</span>
                <span className="v2-health-detail">{item.detail}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
