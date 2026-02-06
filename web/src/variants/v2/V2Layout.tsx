/**
 * V2Layout — Dark SOC Operator / Mission Control Layout Shell
 *
 * Provides the SOC operations chrome:
 * - Persistent status bar (top) with playbook count + system status
 * - Compact sidebar with icon-style navigation
 * - Dense content area
 */

import React from 'react';
import { usePlaybooks } from '../../hooks/usePlaybooks';
import { STATUS_BAR_TEXT } from './theme';
import './V2Layout.css';

interface V2LayoutProps {
  /** Current page identifier */
  activePage: string;
  /** Navigation handler */
  onNavigate: (path: string) => void;
  /** Child content */
  children: React.ReactNode;
}

interface NavItem {
  id: string;
  icon: string;
  label: string;
  page: string;
}

const NAV_ITEMS: NavItem[] = [
  { id: 'dashboard', icon: '◈', label: 'Dashboard', page: 'dashboard' },
  { id: 'library', icon: '☰', label: 'Library', page: 'library' },
  { id: 'import', icon: '⌨', label: 'Import', page: 'import' },
];

const V2Layout: React.FC<V2LayoutProps> = ({
  activePage,
  onNavigate,
  children,
}) => {
  const { playbooks, categories } = usePlaybooks();

  const totalNodes = playbooks.reduce((s, p) => s + p.graph.nodes.length, 0);
  const coveragePercent = categories.length > 0
    ? Math.round((categories.length / 6) * 100)
    : 0;

  const isActive = (item: NavItem) =>
    activePage === item.page || (item.page === 'dashboard' && activePage === 'home');

  const now = new Date();
  const timeStr = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' });

  return (
    <div className="v2-layout">
      {/* Status Bar */}
      <div className="v2-status-bar">
        <div className="v2-status-bar-left">
          <span className="v2-status-dot v2-status-dot--green" />
          <span className="v2-status-bar-label">{STATUS_BAR_TEXT}</span>
        </div>
        <div className="v2-status-bar-metrics">
          <div className="v2-metric">
            <span className="v2-metric-value">{playbooks.length}</span>
            <span className="v2-metric-label">PLAYBOOKS</span>
          </div>
          <div className="v2-metric-divider" />
          <div className="v2-metric">
            <span className="v2-metric-value">{totalNodes}</span>
            <span className="v2-metric-label">NODES</span>
          </div>
          <div className="v2-metric-divider" />
          <div className="v2-metric">
            <span className="v2-metric-value">{coveragePercent}%</span>
            <span className="v2-metric-label">COVERAGE</span>
          </div>
          <div className="v2-metric-divider" />
          <div className="v2-metric">
            <span className="v2-metric-value v2-metric-value--dim">{timeStr}</span>
            <span className="v2-metric-label">UTC{now.getTimezoneOffset() === 0 ? '' : (now.getTimezoneOffset() > 0 ? '-' : '+') + Math.abs(now.getTimezoneOffset() / 60)}</span>
          </div>
        </div>
      </div>

      <div className="v2-layout-body">
        {/* Compact Sidebar */}
        <aside className="v2-sidebar">
          <div className="v2-sidebar-brand" onClick={() => onNavigate('#/2')}>
            <span className="v2-brand-icon">⬡</span>
            <span className="v2-brand-text">PBF</span>
          </div>

          <nav className="v2-sidebar-nav">
            {NAV_ITEMS.map((item) => (
              <button
                key={item.id}
                className={`v2-nav-btn ${isActive(item) ? 'v2-nav-btn--active' : ''}`}
                onClick={() => onNavigate(`#/2/${item.page}`)}
                title={item.label}
              >
                <span className="v2-nav-icon">{item.icon}</span>
                <span className="v2-nav-label">{item.label}</span>
              </button>
            ))}
          </nav>

          <button
            className="v2-sidebar-back"
            onClick={() => onNavigate('#/')}
            title="Back to Variants"
          >
            <span className="v2-nav-icon">◄</span>
            <span className="v2-nav-label">Exit</span>
          </button>
        </aside>

        {/* Main Content */}
        <main className="v2-content">
          {children}
        </main>
      </div>
    </div>
  );
};

export default V2Layout;
