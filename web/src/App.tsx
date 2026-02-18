/**
 * Playbook Forge - Main Application Component
 *
 * Root component with hash-based routing.
 * Routes:
 *   #/          → VariantPicker (landing, or auto-redirect if default set)
 *   #/1 .. #/5  → Variant apps
 *   Legacy      → ImportView still accessible as a variant sub-page
 */

import React, { useEffect } from 'react';
import './App.css';
import { useHashRouter } from './router';
import KeyboardHints from './components/KeyboardHints';
import VariantSettings from './components/VariantSettings';
import { useDefaultVariant } from './hooks/useDefaultVariant';
import VariantPicker from './pages/VariantPicker';
import LibraryPage from './pages/LibraryPage';
import EditorPage from './pages/EditorPage';
import ImportPage from './pages/ImportPage';
import SharedPage from './pages/SharedPage';
import V1App from './variants/v1';
import V2App from './variants/v2';
import V3App from './variants/v3';
import V4App from './variants/v4';
import V5App from './variants/v5';

const APP_ID = 'playbook-forge';
const VARIANT_NAMES = [
  'Command Line',
  'Blueprint',
  'Tactical',
  'Network Flow',
  'Dark Grid',
];

const variantComponents: Record<number, React.FC<{ route: any; onNavigate: (path: string) => void }>> = {
  1: V1App,
  2: V2App,
  3: V3App,
  4: V4App,
  5: V5App,
};

function GitHubFooter() {
  return (
    <a
      href="https://github.com/solomonneas/playbook-forge"
      target="_blank"
      rel="noopener noreferrer"
      style={{
        position: 'fixed', bottom: 8, right: 12, zIndex: 50,
        display: 'flex', alignItems: 'center', gap: 6,
        fontSize: 11, color: '#888', textDecoration: 'none',
        opacity: 0.4, transition: 'opacity 0.2s',
      }}
      onMouseEnter={(e: React.MouseEvent<HTMLAnchorElement>) => (e.currentTarget.style.opacity = '0.8')}
      onMouseLeave={(e: React.MouseEvent<HTMLAnchorElement>) => (e.currentTarget.style.opacity = '0.4')}
    >
      <svg viewBox="0 0 16 16" fill="currentColor" width="16" height="16"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
      Solomon Neas
    </a>
  );
}

function App() {
  const { route, navigate, navigateTo } = useHashRouter();
  const { defaultVariant, setDefaultVariant } = useDefaultVariant(APP_ID);

  // Keyboard shortcuts
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
      const num = parseInt(e.key);
      if (num >= 1 && num <= 5) navigateTo(num);
      else if (e.key === 'Escape' || e.key === '0') window.location.hash = '#/';
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [navigateTo]);

  // Auto-redirect if default variant is set
  useEffect(() => {
    if (route.page === 'picker' && defaultVariant) {
      navigateTo(defaultVariant);
    }
  }, [route.page, route.variant, defaultVariant, navigateTo]);

  const sharedUI = (
    <>
      <KeyboardHints />
      <VariantSettings
        currentVariant={route.variant}
        defaultVariant={defaultVariant}
        onSetDefault={setDefaultVariant}
        variantNames={VARIANT_NAMES}
      />
    </>
  );

  // Variant picker (landing)
  if (route.page === 'picker' || route.variant === null) {
    if (route.page === 'library') {
      return (
        <div className="App">
          {sharedUI}
          <LibraryPage />
          <GitHubFooter />
        </div>
      );
    }

    if (route.page === 'editor') {
      return (
        <div className="App">
          {sharedUI}
          <EditorPage playbookId={route.params.id} />
          <GitHubFooter />
        </div>
      );
    }

    if (route.page === 'import') {
      return (
        <div className="App">
          {sharedUI}
          <ImportPage />
          <GitHubFooter />
        </div>
      );
    }

    if (route.page === 'shared') {
      return (
        <div className="App">
          <SharedPage token={route.params.token} />
          <GitHubFooter />
        </div>
      );
    }

    return (
      <div className="App">
        {sharedUI}
        <VariantPicker onSelect={(v) => navigateTo(v)} />
        <GitHubFooter />
      </div>
    );
  }

  // Variant app
  const VariantApp = variantComponents[route.variant];
  if (VariantApp) {
    return (
      <div className="App">
        {sharedUI}
        <VariantApp route={route} onNavigate={navigate} />
        <GitHubFooter />
      </div>
    );
  }

  // Fallback
  return (
    <div className="App">
      {sharedUI}
      <VariantPicker onSelect={(v) => navigateTo(v)} />
      <GitHubFooter />
    </div>
  );
}

export default App;
