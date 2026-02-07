/**
 * Variant 5: Minimal Academic / Research Paper
 *
 * White backgrounds, serif typography (Crimson Pro, Fraunces), centered column,
 * horizontal nav, thin rules as dividers. Academic research paper aesthetic.
 * Printable. No icons, no colors in flowcharts — shape communicates type.
 */

import React from 'react';
import { RouteMatch } from '../../router';
import V5Layout from './V5Layout';
import Dashboard from './pages/Dashboard';
import Library from './pages/Library';
import PlaybookViewer from './pages/PlaybookViewer';
import Import from './pages/Import';
import DocsPage from '../../pages/DocsPage';

interface V5AppProps {
  route: RouteMatch;
  onNavigate: (path: string) => void;
}

const V5App: React.FC<V5AppProps> = ({ route, onNavigate }) => {
  // Render the active page
  const renderPage = () => {
    switch (route.page) {
      case 'dashboard':
      case 'home':
        return <Dashboard />;
      case 'library':
        return <Library onNavigate={onNavigate} />;
      case 'playbook':
        return (
          <PlaybookViewer
            slug={route.params.slug}
            onNavigate={onNavigate}
          />
        );
      case 'import':
        return <Import />;
      case 'docs':
        return <DocsPage />;
      default:
        return <Dashboard />;
    }
  };

  return (
    <V5Layout
      activePage={route.page}
      onNavigate={onNavigate}
    >
      {renderPage()}
    </V5Layout>
  );
};

export default V5App;
