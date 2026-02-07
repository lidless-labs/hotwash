/**
 * V5Layout — Minimal Academic / Research Paper Layout
 *
 * No sidebar. Horizontal top nav (clean, minimal). Single centered column
 * (720px max-width). Thin horizontal rules as section dividers.
 * Academic research paper aesthetic. Printable.
 */

import React, { useState } from 'react';
import GuidedTour, { resetTour } from '../../components/GuidedTour';
import './V5Layout.css';

interface V5LayoutProps {
  activePage: string;
  onNavigate: (path: string) => void;
  children: React.ReactNode;
}

/** Navigation items — understated, academic */
const NAV_ITEMS = [
  { id: 'dashboard', label: 'Summary', page: 'dashboard' },
  { id: 'library', label: 'Bibliography', page: 'library' },
  { id: 'import', label: 'Submit', page: 'import' },
  { id: 'docs', label: 'Reference', page: 'docs' },
];

const V5Layout: React.FC<V5LayoutProps> = ({
  activePage,
  onNavigate,
  children,
}) => {
  const [tourActive, setTourActive] = useState(false);

  const handleTakeTour = () => {
    resetTour();
    setTourActive(true);
  };

  const isActive = (page: string) =>
    activePage === page || (page === 'dashboard' && activePage === 'home');

  return (
    <div className="v5-layout">
      {/* Top navigation */}
      <header className="v5-header">
        <div className="v5-header-inner">
          <button
            className="v5-header-title"
            onClick={() => onNavigate('#/5')}
          >
            Playbook Forge
          </button>

          <nav className="v5-nav">
            {NAV_ITEMS.map((item) => (
              <button
                key={item.id}
                className={`v5-nav-link ${isActive(item.page) ? 'v5-nav-link--active' : ''}`}
                onClick={() => onNavigate(`#/5/${item.page}`)}
                data-tour={item.id}
              >
                {item.label}
              </button>
            ))}
          </nav>

          <button
            className="v5-nav-back"
            onClick={handleTakeTour}
            style={{ marginLeft: 0 }}
          >
            Tour
          </button>

          <button
            className="v5-nav-back"
            onClick={() => onNavigate('#/')}
            data-tour="variant-back"
          >
            Variants
          </button>
        </div>
      </header>

      <hr className="v5-rule v5-rule--header" />

      {/* Main content — centered column */}
      <main className="v5-main">
        {children}
      </main>

      {/* Footer */}
      <footer className="v5-footer">
        <hr className="v5-rule" />
        <div className="v5-footer-inner">
          <span>Playbook Forge — Variant 5: Minimal Academic</span>
          <span className="v5-footer-dot">·</span>
          <span>{new Date().getFullYear()}</span>
        </div>
      </footer>

      {/* Guided Tour */}
      <GuidedTour
        forceStart={tourActive}
        onComplete={() => setTourActive(false)}
      />
    </div>
  );
};

export default V5Layout;
