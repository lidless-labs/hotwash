/**
 * V4Layout — Interactive Blueprint / Engineering Schematic Layout
 *
 * Blueprint background with CSS grid overlay, drawing border with tick marks,
 * corner markers, top navigation bar, and floating title block in bottom-right.
 * Everything feels like reading an architectural drawing or engineering schematic.
 */

import React, { useMemo, useState } from 'react';
import GuidedTour, { resetTour } from '../../components/GuidedTour';
import './V4Layout.css';

interface V4LayoutProps {
  activePage: string;
  activeSlug?: string;
  onNavigate: (path: string) => void;
  /** Playbook metadata for title block */
  titleBlockData?: {
    title?: string;
    type?: string;
    tooling?: string;
    nodes?: number;
    edges?: number;
  };
  children: React.ReactNode;
}

/** Navigation items */
const NAV_ITEMS = [
  { id: 'dashboard', label: 'OVERVIEW', page: 'dashboard' },
  { id: 'library', label: 'PARTS CATALOG', page: 'library' },
  { id: 'import', label: 'NEW SCHEMATIC', page: 'import' },
  { id: 'docs', label: 'DOCUMENTATION', page: 'docs' },
];

const V4Layout: React.FC<V4LayoutProps> = ({
  activePage,
  activeSlug,
  onNavigate,
  titleBlockData,
  children,
}) => {
  const [tourActive, setTourActive] = useState(false);

  const handleTakeTour = () => {
    resetTour();
    setTourActive(true);
  };

  const isActive = (page: string) =>
    activePage === page || (page === 'dashboard' && activePage === 'home');

  // Generate tick marks
  const topTicks = useMemo(() => Array.from({ length: 40 }, (_, i) => i), []);
  const leftTicks = useMemo(() => Array.from({ length: 30 }, (_, i) => i), []);

  const now = new Date();
  const dateStr = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;

  return (
    <div className="v4-layout">
      <div className="v4-drawing-border">
        {/* Corner markers */}
        <div className="v4-corner-tl" />
        <div className="v4-corner-tr" />
        <div className="v4-corner-bl" />
        <div className="v4-corner-br" />

        {/* Tick marks */}
        <div className="v4-tick-bar-top">
          {topTicks.map((i) => (
            <div key={i} className="v4-tick" />
          ))}
        </div>
        <div className="v4-tick-bar-left">
          {leftTicks.map((i) => (
            <div key={i} className="v4-tick" />
          ))}
        </div>

        {/* Top navigation bar */}
        <div className="v4-topbar">
          <button
            className="v4-topbar-logo"
            onClick={() => onNavigate('#/4')}
          >
            <span className="v4-topbar-logo-icon">⚒</span>
            PLAYBOOK FORGE
          </button>
          <span className="v4-topbar-version">v4</span>

          <div className="v4-topbar-divider" />

          <div className="v4-topbar-nav">
            {NAV_ITEMS.map((item) => (
              <button
                key={item.id}
                className={`v4-nav-btn ${isActive(item.page) ? 'v4-nav-btn--active' : ''}`}
                onClick={() => onNavigate(`#/4/${item.page}`)}
                data-tour={item.id}
              >
                {item.label}
              </button>
            ))}
          </div>

          <button
            className="v4-nav-btn"
            onClick={handleTakeTour}
          >
            ? TOUR
          </button>

          <button
            className="v4-topbar-back"
            onClick={() => onNavigate('#/')}
            data-tour="variant-back"
          >
            ← VARIANTS
          </button>
        </div>

        {/* Main content */}
        <div className="v4-content-area">
          {children}
        </div>
      </div>

      {/* Floating title block — bottom-right */}
      <div className="v4-title-block">
        <div className="v4-title-block-header">
          PLAYBOOK FORGE — SCHEMATIC
        </div>
        <div className="v4-title-block-body">
          <div className="v4-title-block-row">
            <span className="v4-title-block-label">Project</span>
            <span className="v4-title-block-value">
              {titleBlockData?.title || 'Playbook Forge'}
            </span>
          </div>
          <div className="v4-title-block-row">
            <span className="v4-title-block-label">Type</span>
            <span className="v4-title-block-value">
              {titleBlockData?.type || 'Interactive Blueprint'}
            </span>
          </div>
          {titleBlockData?.tooling && (
            <div className="v4-title-block-row">
              <span className="v4-title-block-label">Tooling</span>
              <span className="v4-title-block-value">{titleBlockData.tooling}</span>
            </div>
          )}
          <div className="v4-title-block-divider" />
          <div className="v4-title-block-row">
            <span className="v4-title-block-label">Date</span>
            <span className="v4-title-block-value">{dateStr}</span>
          </div>
          <div className="v4-title-block-row">
            <span className="v4-title-block-label">View</span>
            <span className="v4-title-block-value" style={{ textTransform: 'uppercase' }}>
              {activePage === 'playbook' ? activeSlug || 'viewer' : activePage}
            </span>
          </div>
          {titleBlockData?.nodes !== undefined && (
            <>
              <div className="v4-title-block-divider" />
              <div className="v4-title-block-row">
                <span className="v4-title-block-label">Nodes</span>
                <span className="v4-title-block-value">{titleBlockData.nodes}</span>
              </div>
              <div className="v4-title-block-row">
                <span className="v4-title-block-label">Edges</span>
                <span className="v4-title-block-value">{titleBlockData.edges}</span>
              </div>
            </>
          )}
        </div>
      </div>

      {/* Guided Tour */}
      <GuidedTour
        forceStart={tourActive}
        onComplete={() => setTourActive(false)}
      />
    </div>
  );
};

export default V4Layout;
