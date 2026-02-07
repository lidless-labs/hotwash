/**
 * V3Layout — Clean Documentation / Knowledge Base Layout
 *
 * GitBook/Notion-inspired layout:
 * - Left sidebar with expandable category sections
 * - Breadcrumb navigation bar
 * - Clean white content area
 * - Content is the hero, UI gets out of the way
 */

import React, { useState } from 'react';
import GuidedTour, { resetTour } from '../../components/GuidedTour';
import './V3Layout.css';

interface NavItem {
  id: string;
  icon: string;
  label: string;
  page: string;
  slug?: string;
}

interface V3LayoutProps {
  /** Current page identifier */
  activePage: string;
  /** Active slug (for playbook viewer) */
  activeSlug?: string;
  /** Navigation handler */
  onNavigate: (path: string) => void;
  /** Playbook nav items for sidebar */
  playbookNavItems?: NavItem[];
  /** Breadcrumb trail */
  breadcrumbs?: Array<{ label: string; path?: string }>;
  /** Whether to use wide content area */
  wide?: boolean;
  /** Child content */
  children: React.ReactNode;
}

/** Core navigation items */
const CORE_NAV: NavItem[] = [
  { id: 'dashboard', icon: '📊', label: 'Overview', page: 'dashboard' },
  { id: 'library', icon: '📚', label: 'Library', page: 'library' },
  { id: 'import', icon: '📝', label: 'Import', page: 'import' },
  { id: 'docs', icon: '📖', label: 'Documentation', page: 'docs' },
];

const V3Layout: React.FC<V3LayoutProps> = ({
  activePage,
  activeSlug,
  onNavigate,
  playbookNavItems = [],
  breadcrumbs = [],
  wide = false,
  children,
}) => {
  const [playbooksExpanded, setPlaybooksExpanded] = useState(true);
  const [tourActive, setTourActive] = useState(false);

  const handleTakeTour = () => {
    resetTour();
    setTourActive(true);
  };

  const getNavPath = (item: NavItem) => {
    if (item.slug) return `#/3/playbook/${item.slug}`;
    return `#/3/${item.page}`;
  };

  const isActive = (item: NavItem) => {
    if (item.slug) return activePage === 'playbook' && activeSlug === item.slug;
    return activePage === item.page || (item.page === 'dashboard' && activePage === 'home');
  };

  return (
    <div className="v3-layout">
      <div className="v3-layout-body">
        {/* Sidebar */}
        <aside className="v3-sidebar">
          <div className="v3-sidebar-header">
            <button
              className="v3-sidebar-logo"
              onClick={() => onNavigate('#/3')}
            >
              <span className="v3-sidebar-logo-icon">⚒</span>
              <span className="v3-sidebar-logo-text">Playbook Forge</span>
              <span className="v3-sidebar-logo-version">v3</span>
            </button>
          </div>

          <nav className="v3-sidebar-nav">
            {/* Core navigation */}
            <div className="v3-nav-section">
              {CORE_NAV.map((item) => (
                <button
                  key={item.id}
                  className={`v3-nav-item ${isActive(item) ? 'v3-nav-item--active' : ''}`}
                  onClick={() => onNavigate(getNavPath(item))}
                  data-tour={item.id}
                >
                  <span className="v3-nav-item-icon">{item.icon}</span>
                  <span className="v3-nav-item-label">{item.label}</span>
                </button>
              ))}
            </div>

            <div className="v3-sidebar-divider" />

            {/* Playbooks section */}
            {playbookNavItems.length > 0 && (
              <div className="v3-nav-section">
                <button
                  className="v3-nav-section-toggle"
                  onClick={() => setPlaybooksExpanded(!playbooksExpanded)}
                >
                  <span className={`v3-nav-section-chevron ${playbooksExpanded ? 'v3-nav-section-chevron--open' : ''}`}>
                    ›
                  </span>
                  Playbooks
                </button>
                <div className={`v3-nav-section-items ${playbooksExpanded ? 'v3-nav-section-items--expanded' : 'v3-nav-section-items--collapsed'}`}>
                  {playbookNavItems.map((item) => (
                    <button
                      key={item.id}
                      className={`v3-nav-item ${isActive(item) ? 'v3-nav-item--active' : ''}`}
                      onClick={() => onNavigate(getNavPath(item))}
                    >
                      <span className="v3-nav-item-icon">{item.icon}</span>
                      <span className="v3-nav-item-label">{item.label}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </nav>

          {/* Take Tour */}
          <button
            className="v3-sidebar-back"
            onClick={handleTakeTour}
            style={{ borderTop: 'none' }}
          >
            ❓ Take Guided Tour
          </button>

          {/* Back to variants */}
          <button
            className="v3-sidebar-back"
            onClick={() => onNavigate('#/')}
            data-tour="variant-back"
          >
            ← Back to Variants
          </button>
        </aside>

        {/* Main Content Area */}
        <main className="v3-main">
          {/* Top bar with breadcrumbs */}
          <div className="v3-topbar">
            <div className="v3-breadcrumbs">
              <button
                className="v3-breadcrumb-link"
                onClick={() => onNavigate('#/3')}
              >
                Playbook Forge
              </button>
              {breadcrumbs.map((crumb, i) => (
                <React.Fragment key={i}>
                  <span className="v3-breadcrumb-sep">/</span>
                  {crumb.path ? (
                    <button
                      className="v3-breadcrumb-link"
                      onClick={() => onNavigate(crumb.path!)}
                    >
                      {crumb.label}
                    </button>
                  ) : (
                    <span className="v3-breadcrumb-current">{crumb.label}</span>
                  )}
                </React.Fragment>
              ))}
            </div>
          </div>

          {/* Content */}
          <div className={`v3-content ${wide ? 'v3-content--wide' : ''}`}>
            {children}
          </div>
        </main>
      </div>

      {/* Guided Tour */}
      <GuidedTour
        forceStart={tourActive}
        onComplete={() => setTourActive(false)}
      />
    </div>
  );
};

export default V3Layout;
