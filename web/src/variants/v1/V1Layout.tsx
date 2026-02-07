/**
 * V1Layout — Technical Manual / Field Guide Layout Shell
 *
 * Provides the military field manual chrome:
 * - Classification banners (top + bottom)
 * - Sidebar table of contents with section numbering
 * - Main content area
 */

import React, { useState } from 'react';
import { CLASSIFICATION_TEXT } from './theme';
import GuidedTour, { resetTour } from '../../components/GuidedTour';
import './V1Layout.css';

interface NavItem {
  id: string;
  number: string;
  label: string;
  page: string;
  slug?: string;
}

interface V1LayoutProps {
  /** Current page identifier */
  activePage: string;
  /** Active slug (for playbook viewer) */
  activeSlug?: string;
  /** Navigation handler */
  onNavigate: (path: string) => void;
  /** Additional nav items (e.g., playbook sub-items) */
  extraNavItems?: NavItem[];
  /** Child content */
  children: React.ReactNode;
}

/** Core navigation items */
const CORE_NAV: NavItem[] = [
  { id: 'dashboard', number: '1.0', label: 'Executive Summary', page: 'dashboard' },
  { id: 'library', number: '2.0', label: 'Playbook Library', page: 'library' },
  { id: 'import', number: '3.0', label: 'Import / Parse', page: 'import' },
  { id: 'docs', number: '4.0', label: 'Documentation', page: 'docs' },
];

const V1Layout: React.FC<V1LayoutProps> = ({
  activePage,
  activeSlug,
  onNavigate,
  extraNavItems = [],
  children,
}) => {
  const [tourActive, setTourActive] = useState(false);

  const handleTakeTour = () => {
    resetTour();
    setTourActive(true);
  };

  const getNavPath = (item: NavItem) => {
    if (item.slug) return `#/1/playbook/${item.slug}`;
    return `#/1/${item.page}`;
  };

  const isActive = (item: NavItem) => {
    if (item.slug) return activePage === 'playbook' && activeSlug === item.slug;
    return activePage === item.page || (item.page === 'dashboard' && activePage === 'home');
  };

  return (
    <div className="v1-layout">
      {/* Top Classification Banner */}
      <div className="v1-classification-banner v1-classification-banner--top">
        {CLASSIFICATION_TEXT}
      </div>

      <div className="v1-layout-body">
        {/* Sidebar TOC */}
        <aside className="v1-sidebar">
          <div className="v1-sidebar-header">
            PLAYBOOK FORGE
            <span className="v1-manual-title">FM 6-02 — Operational Playbook Reference</span>
          </div>

          <nav className="v1-sidebar-nav">
            {/* Core navigation */}
            <div className="v1-sidebar-section">
              <div className="v1-sidebar-section-label">Table of Contents</div>
              {CORE_NAV.map((item) => (
                <button
                  key={item.id}
                  className={`v1-nav-item ${isActive(item) ? 'v1-nav-item--active' : ''}`}
                  onClick={() => onNavigate(getNavPath(item))}
                  data-tour={item.id}
                >
                  <span className="v1-nav-number">{item.number}</span>
                  <span className="v1-nav-label">{item.label}</span>
                </button>
              ))}
            </div>

            {/* Dynamic playbook items */}
            {extraNavItems.length > 0 && (
              <div className="v1-sidebar-section">
                <div className="v1-sidebar-section-label">Appendices</div>
                {extraNavItems.map((item) => (
                  <button
                    key={item.id}
                    className={`v1-nav-item ${isActive(item) ? 'v1-nav-item--active' : ''}`}
                    onClick={() => onNavigate(getNavPath(item))}
                  >
                    <span className="v1-nav-number">{item.number}</span>
                    <span className="v1-nav-label">{item.label}</span>
                  </button>
                ))}
              </div>
            )}
          </nav>

          {/* Take Tour */}
          <button
            className="v1-sidebar-back"
            onClick={handleTakeTour}
            style={{ borderTop: 'none' }}
          >
            ❓ Take Guided Tour
          </button>

          {/* Back to variants */}
          <button
            className="v1-sidebar-back"
            onClick={() => onNavigate('#/')}
            data-tour="variant-back"
          >
            ◄ Return to Variant Selection
          </button>
        </aside>

        {/* Main Content */}
        <main className="v1-content">
          {children}
        </main>
      </div>

      {/* Bottom Classification Banner */}
      <div className="v1-classification-banner v1-classification-banner--bottom">
        {CLASSIFICATION_TEXT}
      </div>

      {/* Guided Tour */}
      <GuidedTour
        forceStart={tourActive}
        onComplete={() => setTourActive(false)}
      />
    </div>
  );
};

export default V1Layout;
